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
package agent.dbgeng.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.cmd.DbgThreadSelectCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import agent.dbgeng.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.DebugModelConventions;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.util.PathUtils;

public class DbgModelTargetThreadImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetThread {

	protected static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.ADVANCE, TargetStepKind.FINISH, TargetStepKind.LINE, TargetStepKind.OVER,
		TargetStepKind.OVER_LINE, TargetStepKind.RETURN, TargetStepKind.UNTIL);

	protected static String indexThread(DebugThreadId debugThreadId) {
		return PathUtils.makeIndex(debugThreadId.id);
	}

	protected static String indexThread(DbgThread thread) {
		return indexThread(thread.getId());
	}

	protected static String keyThread(DbgThread thread) {
		return PathUtils.makeKey(indexThread(thread));
	}

	protected final DbgThread thread;

	protected final DbgModelTargetRegisterContainerImpl registers;
	protected final DbgModelTargetStackImpl stack;

	private DbgModelTargetProcess process;

	public DbgModelTargetThreadImpl(DbgModelTargetThreadContainer threads,
			DbgModelTargetProcess process, DbgThread thread) {
		super(threads.getModel(), threads, keyThread(thread), "Thread");
		this.process = process;
		this.thread = thread;

		this.registers = new DbgModelTargetRegisterContainerImpl(this);
		this.stack = new DbgModelTargetStackImpl(this, process);

		changeAttributes(List.of(), List.of( //
			registers, //
			stack //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		), "Initialized");
		setExecutionState(convertState(thread.getState()), "Initialized");
		// TODO: Stack (Registers)

		getManager().addEventsListener(this);
	}

	@Override
	public String getDisplay() {
		if (getManager().isKernelMode()) {
			return "[PR" + thread.getId().id + "]";
		}
		return "[" + thread.getId().id + ":0x" + Long.toHexString(thread.getTid()) + "]";
	}

	@Override
	public void threadSelected(DbgThread eventThread, DbgStackFrame frame, DbgCause cause) {
		if (eventThread.equals(thread)) {
			AtomicReference<DbgModelTargetFocusScope<?>> scope = new AtomicReference<>();
			AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
				DebugModelConventions.findSuitable(DbgModelTargetFocusScope.class, this)
						.handle(seq::next);
			}, scope).then(seq -> {
				scope.get().setFocus(this);
			}).finish();
		}
	}

	@Override
	public void threadStateChanged(DbgState state, DbgReason reason) {
		TargetExecutionState targetState = convertState(state);
		String executionType = thread.getExecutingProcessorType().description;
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetEnvironment.ARCH_ATTRIBUTE_NAME, executionType //
		), reason.desc());
		setExecutionState(targetState, reason.desc());
	}

	@Override
	public ExecSuffix convertToDbg(TargetStepKind kind) {
		switch (kind) {
			case FINISH:
				return ExecSuffix.FINISH;
			case INTO:
				return ExecSuffix.STEP_INSTRUCTION;
			case LINE:
				return ExecSuffix.STEP;
			case OVER:
				return ExecSuffix.NEXT_INSTRUCTION;
			case OVER_LINE:
				return ExecSuffix.NEXT;
			case RETURN:
				return ExecSuffix.RETURN;
			case UNTIL:
				return ExecSuffix.UNTIL;
			default:
				throw new AssertionError();
		}
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in GDB/MI?
				return thread.console("advance");
			default:
				return thread.step(convertToDbg(kind));
		}
	}

	@Override
	public CompletableFuture<Void> select() {
		DbgManagerImpl manager = getManager();
		return manager.execute(new DbgThreadSelectCommand(manager, thread, null));
	}

	public DbgModelTargetRegisterContainerAndBank getRegisters() {
		return registers;
	}

	@Override
	public DbgModelTargetStackImpl getStack() {
		return stack;
	}

	@Override
	public DbgThread getThread() {
		return thread;
	}

	public DbgModelTargetProcess getProcess() {
		return process;
	}

	@Override
	public TargetAccessibility getAccessibility() {
		return accessibility;
	}

	@Override
	public String getExecutingProcessorType() {
		return thread.getExecutingProcessorType().description;
	}

}
