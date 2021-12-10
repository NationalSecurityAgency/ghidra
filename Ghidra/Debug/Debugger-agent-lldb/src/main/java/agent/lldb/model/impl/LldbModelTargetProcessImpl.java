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
package agent.lldb.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import SWIG.*;
import agent.lldb.lldb.DebugClient;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbReason;
import agent.lldb.manager.cmd.*;
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface2.*;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Process",
	attributeResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Memory",
			type = LldbModelTargetMemoryContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Threads",
			type = LldbModelTargetThreadContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Breakpoints",
			type = LldbModelTargetBreakpointLocationContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = LldbModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetProcessImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetProcess {

	public static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	public static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	protected static String indexProcess(SBProcess process) {
		return DebugClient.getId(process);
	}

	protected static String keyProcess(SBProcess process) {
		return PathUtils.makeKey(indexProcess(process));
	}

	protected final LldbModelTargetMemoryContainerImpl memory;
	protected final LldbModelTargetThreadContainerImpl threads;
	protected final LldbModelTargetBreakpointLocationContainerImpl breakpoints;
	// Note: not sure section info is available from the lldb
	//protected final LldbModelTargetProcessSectionContainer sections;

	private Integer base = 16;

	public LldbModelTargetProcessImpl(LldbModelTargetProcessContainer processes,
			SBProcess process) {
		super(processes.getModel(), processes, keyProcess(process), process, "Process");
		getModel().addModelObject(process, this);
		getManager().getClient().addBroadcaster(process);

		this.memory = new LldbModelTargetMemoryContainerImpl(this);
		this.threads = new LldbModelTargetThreadContainerImpl(this);
		this.breakpoints = new LldbModelTargetBreakpointLocationContainerImpl(this);
		TargetExecutionState state = DebugClient.convertState(process.GetState());

		changeAttributes(List.of(), List.of( //
			memory, //
			threads, //
			breakpoints //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, PARAMETERS, //
			STATE_ATTRIBUTE_NAME, state, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS, //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, LldbModelTargetThreadImpl.SUPPORTED_KINDS //
		), "Initialized");
		setExecutionState(state, "Initialized");

		getManager().addEventsListener(this);
	}

	@Override
	public void setModelObject(Object modelObject) {
		super.setModelObject(modelObject);
		getModel().addModelObject(modelObject, this);
	}

	@Override
	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBProcess process = (SBProcess) getModelObject();
		process.GetDescription(stream);
		return stream.GetData();
	}

	@Override
	public String getDisplay() {
		String pidstr = DebugClient.getId(getProcess());
		if (base == 16) {
			pidstr = "0x" + pidstr;
		}
		else {
			pidstr = Long.toString(Long.parseLong(pidstr, 16));
		}
		return "[" + pidstr + "]";
	}

	@Override
	public void processSelected(SBProcess eventProcess, LldbCause cause) {
		if (eventProcess.GetProcessID().equals(getProcess().GetProcessID())) {
			((LldbModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void threadStateChanged(SBThread thread, StateType state, LldbCause cause,
			LldbReason reason) {
		TargetExecutionState targetState = DebugClient.convertState(state);
		setExecutionState(targetState, "ThreadStateChanged");
		if (state.equals(StateType.eStateStopped)) {
			threads.requestElements(true);
			StopReason stopReason = getManager().getCurrentThread().GetStopReason();
			if (!stopReason.equals(StopReason.eStopReasonPlanComplete)) {
				memory.requestElements(true);			
			}
		}
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		model.gateFuture(getManager().execute(new LldbLaunchProcessCommand(getManager(),
			getProcess().GetProcessInfo().GetName(), args)));
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> resume() {
		return model.gateFuture(
			getManager().execute(new LldbContinueCommand(getManager(), getProcess())));
	}

	@Override
	public CompletableFuture<Void> kill() {
		return model.gateFuture(getManager().execute(new LldbKillCommand(getManager())));
	}

	@Override
	public CompletableFuture<Void> destroy() {
		return model.gateFuture(getManager().execute(new LldbDestroyCommand(getManager())));
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		getModel().assertMine(TargetObject.class, attachable);
		// NOTE: Get the object and type check it myself.
		// The typed ref could have been unsafely cast
		SBProcess proc = (SBProcess) getModelObject();
		long pid = proc.GetProcessID().longValue();
		return model.gateFuture(
			getManager().execute(new LldbAttachCommand(getManager(), Long.toString(pid)))
					.thenApply(__ -> null));
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return model.gateFuture(
			getManager().execute(new LldbAttachCommand(getManager(), Long.toString(pid)))
					.thenApply(__ -> null));
	}

	@Override
	public CompletableFuture<Void> detach() {
		return model.gateFuture(
			getManager().execute(new LldbDetachCommand(getManager(), getProcess())));
	}

	@Override
	public CompletableFuture<Void> delete() {
		return AsyncUtils.NIL;
		//return model.gateFuture(process.remove());
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		return getManager().execute(new LldbStepCommand(getManager(), null, kind, null));
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return getManager().execute(new LldbStepCommand(getManager(), null, null, args));
	}

	@Override
	public void processStarted(SBProcess proc) {
		if (proc != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				PID_ATTRIBUTE_NAME, getProcess().GetProcessID().longValue(), //
				DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.STOPPED //
			), "Started");
		}
		setExecutionState(TargetExecutionState.STOPPED, "Started");
	}

	@Override
	public void processExited(SBProcess proc, LldbCause cause) {
		if (proc.GetProcessID().equals(this.getProcess().GetProcessID())) {
			String exitDesc = proc.GetExitDescription();
			if (exitDesc == null) {
				exitDesc = "NONE";
			}
			changeAttributes(List.of(), List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, exitDesc //
			), "Exited");
			getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_EXITED,
				"Process " + DebugClient.getId(getProcess()) + " exited code=" + exitDesc,
				List.of(getProxy()));
		}
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return getManager().setActiveProcess(getProcess());
	}

	@Override
	public LldbModelTargetThreadContainer getThreads() {
		return threads;
	}

	@Override
	public SBProcess getProcess() {
		return (SBProcess) getModelObject();
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

	public void addBreakpointLocation(LldbModelTargetBreakpointLocation loc) {
		breakpoints.addBreakpointLocation(loc);
	}

	public void removeBreakpointLocation(LldbModelTargetBreakpointLocation loc) {
		breakpoints.removeBreakpointLocation(loc);
	}

}
