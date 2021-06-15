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
package agent.dbgeng.manager.impl;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.google.common.collect.RangeSet;

import agent.dbgeng.dbgeng.DebugEventInformation;
import agent.dbgeng.dbgeng.DebugRegisters.DebugRegisterDescription;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.jna.dbgeng.WinNTExtra;
import agent.dbgeng.jna.dbgeng.WinNTExtra.Machine;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.breakpoint.DbgBreakpointType;
import agent.dbgeng.manager.cmd.*;
import ghidra.async.AsyncLazyValue;
import ghidra.async.AsyncReference;
import ghidra.util.Msg;

public class DbgThreadImpl implements DbgThread {

	DbgManagerImpl manager;
	private DbgProcessImpl process;
	private DebugThreadId id;
	private long tid;
	private DebugEventInformation info;

	private final AsyncReference<DbgState, CauseReasonPair> state =
		new AsyncReference<>(DbgState.STOPPED);

	private final AsyncLazyValue<DbgRegisterSet> registers =
		new AsyncLazyValue<>(this::doListRegisters);

	/**
	 * Construct a new thread
	 * 
	 * @param manager the manager creating the thread
	 * @param process the process to which the thread belongs
	 * @param id the dbgeng-assigned thread ID
	 */
	public DbgThreadImpl(DbgManagerImpl manager, DbgProcessImpl process, DebugThreadId id,
			long tid) {
		this.manager = manager;
		this.process = process;
		this.id = id;
		this.tid = tid;
	}

	@Override
	public String toString() {
		return "<DbgThread tid=" + id + ",process=" + process + ",state=" + state.get() + ">";
	}

	@Override
	public DebugThreadId getId() {
		return id;
	}

	@Override
	public DbgProcess getProcess() {
		return process;
	}

	@Override
	public Long getTid() {
		return tid;
	}

	/**
	 * Add this thread to the inferior and manager
	 */
	public void add() {
		manager.threads.put(id, this);
		//manager.getEventListeners().fire.threadCreated(this, DbgCause.Causes.UNCLAIMED);
		process.addThread(this);
		state.addChangeListener((oldState, newState, pair) -> {
			this.manager.getEventListeners().fire.threadStateChanged(this, newState, pair.cause,
				pair.reason);
		});
	}

	/**
	 * Remove this thread from the inferior and manager
	 */
	public void remove() {
		try {
			process.removeThread(id);
			manager.removeThread(id);
		}
		catch (IllegalArgumentException e) {
			Msg.warn(this, "Thread " + id + " already removed");
		}
	}

	@Override
	public DbgState getState() {
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
	@Override
	public boolean setState(DbgState state, DbgCause cause, DbgReason reason) {
		return this.state.set(state, new CauseReasonPair(cause, reason));
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return manager.setActiveThread(this);
	}

	@Override
	public CompletableFuture<String> evaluate(String expression) {
		return manager.execute(new DbgEvaluateCommand(manager, expression));
	}

	@Override
	// TODO: Is this per thread or per inferior?
	public CompletableFuture<DbgRegisterSet> listRegisters() {
		return registers.request();
	}

	private CompletableFuture<DbgRegisterSet> doListRegisters() {
		CompletableFuture<List<DebugRegisterDescription>> listCmd =
			manager.execute(new DbgListRegisterDescriptionsCommand(manager));
		return listCmd.thenApply(descs -> {
			if (descs == null) {
				return new DbgRegisterSet(Set.of());
			}
			List<DbgRegister> regs = new ArrayList<>();
			for (DebugRegisterDescription desc : descs) {
				regs.add(new DbgRegister(desc));
			}
			return new DbgRegisterSet(regs);
		});
	}

	@Override
	public CompletableFuture<List<DbgStackFrame>> listStackFrames() {
		return manager.execute(new DbgStackListFramesCommand(manager, this));
	}

	@Override
	public CompletableFuture<Map<DbgRegister, BigInteger>> readRegisters(Set<DbgRegister> regs) {
		return manager.execute(new DbgReadRegistersCommand(manager, this, null, regs));
	}

	@Override
	public CompletableFuture<Void> writeRegisters(Map<DbgRegister, BigInteger> regVals) {
		return manager.execute(new DbgWriteRegistersCommand(manager, this, null, regVals));
	}

	@Override
	public CompletableFuture<RangeSet<Long>> readMemory(long addr, ByteBuffer buf, int len) {
		return manager.execute(new DbgReadMemoryCommand(manager, addr, buf, len));
	}

	@Override
	public CompletableFuture<Void> writeMemory(long addr, ByteBuffer buf, int len) {
		return manager.execute(new DbgWriteMemoryCommand(manager, addr, buf, len));
	}

	@Override
	public CompletableFuture<DbgBreakpointInfo> insertBreakpoint(long loc, int len,
			DbgBreakpointType type) {
		return manager.execute(new DbgInsertBreakpointCommand(manager, loc, len, type));
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		return manager
				.execute(new DbgConsoleExecCommand(manager, command,
					DbgConsoleExecCommand.Output.CONSOLE))
				.thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return manager.execute(
			new DbgConsoleExecCommand(manager, command, DbgConsoleExecCommand.Output.CAPTURE));
	}

	@Override
	public CompletableFuture<Void> cont() {
		return setActive().thenCompose(__ -> {
			return manager.execute(new DbgContinueCommand(manager));
		});
	}

	@Override
	public CompletableFuture<Void> step(ExecSuffix suffix) {
		return setActive().thenCompose(__ -> {
			return manager.execute(new DbgStepCommand(manager, id, suffix));
		});
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return setActive().thenCompose(__ -> {
			return manager.execute(new DbgStepCommand(manager, id, args));
		});
	}

	@Override
	public CompletableFuture<Void> kill() {
		return setActive().thenCompose(__ -> {
			return manager.execute(new DbgKillCommand(manager));
		});
	}

	@Override
	public CompletableFuture<Void> detach() {
		return setActive().thenCompose(__ -> {
			return manager.execute(new DbgDetachCommand(manager, process));
		});
	}

	public DebugEventInformation getInfo() {
		return info;
	}

	public void setInfo(DebugEventInformation info) {
		Machine newType = WinNTExtra.Machine.getByNumber(info.getExecutingProcessorType());
		Machine oldType = getExecutingProcessorType();
		if (!newType.equals(oldType)) {
			registers.forget();
		}
		this.info = info;
	}

	private static class CauseReasonPair {
		private final DbgCause cause;
		private final DbgReason reason;

		CauseReasonPair(DbgCause cause, DbgReason reason) {
			this.cause = cause;
			this.reason = reason;
		}
	}

	@Override
	public Machine getExecutingProcessorType() {
		if (info == null) {
			return WinNTExtra.Machine.IMAGE_FILE_MACHINE_AMD64;
		}
		int executingProcessorType = info.getExecutingProcessorType();
		return WinNTExtra.Machine.getByNumber(executingProcessorType);
	}
}
