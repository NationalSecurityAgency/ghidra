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

import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.cmd.DbgSetActiveThreadCommand;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import agent.dbgeng.model.iface2.*;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(name = "Thread", elements = {
	@TargetElementType(type = Void.class) }, attributes = {
		@TargetAttributeType(name = "Registers", type = DbgModelTargetRegisterContainerImpl.class, required = true, fixed = true),
		@TargetAttributeType(name = "Stack", type = DbgModelTargetStackImpl.class, required = true, fixed = true),
		@TargetAttributeType(name = TargetEnvironment.ARCH_ATTRIBUTE_NAME, type = String.class),
		@TargetAttributeType(type = Void.class) })
public class DbgModelTargetThreadImpl extends DbgModelTargetObjectImpl
		implements DbgModelTargetThread {

	public static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.ADVANCE, //
		TargetStepKind.FINISH, //
		TargetStepKind.LINE, //
		TargetStepKind.OVER, //
		TargetStepKind.OVER_LINE, //
		TargetStepKind.RETURN, //
		TargetStepKind.UNTIL, //
		TargetStepKind.EXTENDED);

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
	private Integer base = 16;

	public DbgModelTargetThreadImpl(DbgModelTargetThreadContainer threads,
			DbgModelTargetProcess process, DbgThread thread) {
		super(threads.getModel(), threads, keyThread(thread), "Thread");
		this.getModel().addModelObject(thread, this);
		this.getModel().addModelObject(thread.getId(), this);
		this.process = process;
		this.thread = thread;

		this.registers = new DbgModelTargetRegisterContainerImpl(this);
		this.stack = new DbgModelTargetStackImpl(this, process);

		changeAttributes(List.of(), List.of( //
			registers, //
			stack //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
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
		String tidstr = Long.toString(thread.getTid(), base);
		if (base == 16) {
			tidstr = "0x" + tidstr;
		}
		return "[" + thread.getId().id + ":" + tidstr + "]";
	}

	@Override
	public void threadSelected(DbgThread eventThread, DbgStackFrame frame, DbgCause cause) {
		if (eventThread.equals(thread)) {
			((DbgModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void threadStateChangedSpecific(DbgState state, DbgReason reason) {
		TargetExecutionState targetState = convertState(state);
		String executionType = thread.getExecutingProcessorType().description;
		changeAttributes(List.of(), List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState, //
			TargetEnvironment.ARCH_ATTRIBUTE_NAME, executionType //
		), reason.desc());
		//setExecutionState(targetState, reason.desc());
		registers.threadStateChangedSpecific(state, reason);
		stack.threadStateChangedSpecific(state, reason);
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		switch (kind) {
			case SKIP:
				throw new UnsupportedOperationException(kind.name());
			case ADVANCE: // Why no exec-advance in GDB/MI?
				return thread.console("advance");
			default:
				return model.gateFuture(thread.step(convertToDbg(kind)));
		}
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return model.gateFuture(thread.step(args));
	}

	@Override
	public CompletableFuture<Void> setActive() {
		DbgManagerImpl manager = getManager();
		return manager.execute(new DbgSetActiveThreadCommand(manager, thread, null));
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
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public String getExecutingProcessorType() {
		return thread.getExecutingProcessorType().description;
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

}
