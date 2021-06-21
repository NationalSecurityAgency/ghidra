/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package agent.gdb.manager.impl;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.apache.commons.lang3.StringUtils;

import com.google.common.collect.RangeSet;

import agent.gdb.manager.*;
import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.manager.breakpoint.GdbBreakpointType;
import agent.gdb.manager.impl.cmd.*;
import agent.gdb.manager.parsing.GdbCValueParser;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import agent.gdb.manager.reason.GdbReason;
import ghidra.async.AsyncLazyValue;
import ghidra.async.AsyncReference;

/**
 * The implementation of {@link GdbThread}
 */
public class GdbThreadImpl implements GdbThread {
	private static class CauseReasonPair {
		private final GdbCause cause;
		private final GdbReason reason;

		CauseReasonPair(GdbCause cause, GdbReason reason) {
			this.cause = cause;
			this.reason = reason;
		}
	}

	protected final GdbManagerImpl manager;
	private final int id;
	private final GdbInferiorImpl inferior;

	private final AsyncReference<GdbState, CauseReasonPair> state =
		new AsyncReference<>(GdbState.RUNNING);

	private final AsyncLazyValue<GdbRegisterSet> registers =
		new AsyncLazyValue<>(this::doListRegisters);

	/**
	 * Construct a new thread
	 * 
	 * @param manager the manager creating the thread
	 * @param inferior the inferior to which the thread belongs
	 * @param id the GDB-assigned thread ID
	 */
	public GdbThreadImpl(GdbManagerImpl manager, GdbInferiorImpl inferior, int id) {
		this.manager = manager;
		this.id = id;
		this.inferior = inferior;
	}

	@Override
	public GdbInferiorImpl getInferior() {
		return inferior;
	}

	/**
	 * Add this thread to the inferior and manager
	 */
	public void add() {
		this.inferior.addThread(this);
		this.manager.addThread(this);
		state.addChangeListener((oldState, newState, pair) -> {
			manager.event(() -> manager.listenersEvent.fire.threadStateChanged(this, newState,
				pair.cause, pair.reason), "threadState");
		});
	}

	/**
	 * Remove this thread from the inferior and manager
	 */
	public void remove() {
		this.inferior.removeThread(id);
		this.manager.removeThread(id);
	}

	@Override
	public int getId() {
		return id;
	}

	@Override
	public String toString() {
		return "<GdbThread tid=" + id + ",inferior=" + inferior + ",state=" + state.get() + ">";
	}

	@Override
	public GdbState getState() {
		return state.get();
	}

	/**
	 * Set the state of this thread
	 * 
	 * @param state the new state
	 * @param cause the cause for the change
	 * @param reason the reason (usually a stop reason) for the change
	 * @return true if the state actually changed
	 */
	protected boolean setState(GdbState state, GdbCause cause, GdbReason reason) {
		return this.state.set(state, new CauseReasonPair(cause, reason));
	}

	protected <T> CompletableFuture<T> execute(AbstractGdbCommand<T> cmd) {
		switch (cmd.getInterpreter()) {
			case CLI:
				return setActive(true).thenCombine(manager.execute(cmd), (__, v) -> v);
			case MI2:
				return manager.execute(cmd);
			default:
				throw new AssertionError();
		}
	}

	@Override
	public CompletableFuture<Void> setActive(boolean internal) {
		// Bypass the select-me-first logic
		return manager.execute(new GdbSetActiveThreadCommand(manager, id, null, internal));
	}

	@Override
	public CompletableFuture<String> evaluate(String expression) {
		return execute(new GdbEvaluateCommand(manager, id, null, expression));
	}

	@Override
	public CompletableFuture<Void> setVar(String varName, String val) {
		return execute(new GdbSetVarCommand(manager, id, varName, val));
	}

	@Override
	// TODO: Is this per thread or per inferior?
	public CompletableFuture<GdbRegisterSet> listRegisters() {
		return registers.request();
	}

	private CompletableFuture<GdbRegisterSet> doListRegisters() {
		Map<Integer, String> namesByNumber = new TreeMap<>();
		return execute(new GdbListRegisterNamesCommand(manager, id)).thenCompose(names -> {
			for (int i = 0; i < names.size(); i++) {
				String n = names.get(i);
				if ("".equals(n)) {
					continue;
				}
				namesByNumber.put(i, n);
			}
			List<String> sizeofNames = namesByNumber.values()
					.stream()
					.map(n -> "sizeof($" + n + ")")
					.collect(Collectors.toList());
			String expr = "{" + StringUtils.join(sizeofNames, ",") + "}";
			return evaluate(expr);
		}).thenApply(value -> {
			List<GdbRegister> regs = new ArrayList<>();
			List<Integer> sizes;
			try {
				sizes = GdbCValueParser.parseArray(value).expectInts();
			}
			catch (GdbParseError e) {
				throw new AssertionError("GDB did not give an integer array!");
			}
			if (sizes.size() != namesByNumber.size()) {
				throw new AssertionError("GDB did not give all the sizes!");
			}
			Iterator<Integer> sit = sizes.iterator();
			Iterator<Map.Entry<Integer, String>> eit = namesByNumber.entrySet().iterator();
			while (sit.hasNext()) {
				int size = sit.next();
				Map.Entry<Integer, String> ent = eit.next();
				regs.add(new GdbRegister(ent.getValue(), ent.getKey(), size));
			}
			return new GdbRegisterSet(regs);
		});
	}

	@Override
	public CompletableFuture<List<GdbStackFrame>> listStackFrames() {
		return execute(new GdbStackListFramesCommand(manager, this));
	}

	@Override
	public CompletableFuture<Map<GdbRegister, BigInteger>> readRegisters(Set<GdbRegister> regs) {
		// TODO: Re-sync not ideal, but it works
		return inferior.syncEndianness().thenCompose(__ -> {
			return execute(new GdbReadRegistersCommand(manager, this, null, regs));
		});
	}

	@Override
	public CompletableFuture<Void> writeRegisters(Map<GdbRegister, BigInteger> regVals) {
		return execute(new GdbWriteRegistersCommand(manager, this, null, regVals));
	}

	@Override
	public CompletableFuture<RangeSet<Long>> readMemory(long addr, ByteBuffer buf, int len) {
		return execute(new GdbReadMemoryCommand(manager, id, addr, buf, len));
	}

	@Override
	public CompletableFuture<Void> writeMemory(long addr, ByteBuffer buf, int len) {
		return execute(new GdbWriteMemoryCommand(manager, id, addr, buf, len));
	}

	@Override
	public CompletableFuture<GdbBreakpointInfo> insertBreakpoint(String loc,
			GdbBreakpointType type) {
		return execute(new GdbInsertBreakpointCommand(manager, id, loc, type));
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		return execute(new GdbConsoleExecCommand(manager, id, null, command,
			GdbConsoleExecCommand.Output.CONSOLE)).thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return execute(new GdbConsoleExecCommand(manager, id, null, command,
			GdbConsoleExecCommand.Output.CAPTURE));
	}

	@Override
	public CompletableFuture<Void> cont() {
		return execute(new GdbContinueCommand(manager, id));
	}

	@Override
	public CompletableFuture<Void> step(StepCmd suffix) {
		return execute(new GdbStepCommand(manager, id, suffix));
	}

	@Override
	public CompletableFuture<Void> kill() {
		return execute(new GdbKillCommand(manager, id));
	}

	@Override
	public CompletableFuture<Void> detach() {
		return execute(new GdbDetachCommand(manager, inferior, id));
	}

	public void dispose(Throwable reason) {
		state.dispose(reason);
	}

	@Override
	public CompletableFuture<GdbThreadInfo> getInfo() {
		return manager.getThreadInfo(id);
	}

}
