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
package agent.frida.model.impl;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.frida.frida.FridaClient;
import agent.frida.manager.*;
import agent.frida.manager.cmd.*;
import agent.frida.model.iface1.FridaModelTargetFocusScope;
import agent.frida.model.iface2.*;
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
			type = FridaModelTargetMemoryContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Memory (Heap)",
			type = FridaModelTargetMemoryContainerImpl.class,
			required = false,
			fixed = true),
		@TargetAttributeType(
			name = "Threads",
			type = FridaModelTargetThreadContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = FridaModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME,
			type = String.class),
		@TargetAttributeType(type = Void.class) })
public class FridaModelTargetProcessImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetProcess {

	public static final String PID_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "pid";
	public static final String EXIT_CODE_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "exit_code";

	public static final TargetAttachKindSet SUPPORTED_KINDS = TargetAttachKindSet.of( //
		TargetAttachKind.BY_OBJECT_REF, TargetAttachKind.BY_ID);

	protected static String indexProcess(FridaProcess process) {
		return FridaClient.getId(process);
	}

	protected static String keyProcess(FridaProcess process) {
		return PathUtils.makeKey(indexProcess(process));
	}

	protected final FridaModelTargetMemoryContainerImpl memory;
	protected final FridaModelTargetHeapMemoryContainerImpl heap;
	protected final FridaModelTargetThreadContainerImpl threads;

	private Integer base = 10;

	public FridaModelTargetProcessImpl(FridaModelTargetProcessContainer processes,
			FridaProcess process) {
		super(processes.getModel(), processes, keyProcess(process), process, "Process");
		getModel().addModelObject(process, this);

		this.memory = new FridaModelTargetMemoryContainerImpl(this);
		this.heap = new FridaModelTargetHeapMemoryContainerImpl(this);
		this.threads = new FridaModelTargetThreadContainerImpl(this);
		TargetExecutionState state = FridaClient.convertState(getManager().getState());

		changeAttributes(List.of(), List.of( //
			memory, //
			heap, //
			threads //
		), Map.of( //
			//ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, PARAMETERS, //
			STATE_ATTRIBUTE_NAME, state, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		//SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, FridaModelTargetThreadImpl.SUPPORTED_KINDS //
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
		FridaProcess process = (FridaProcess) getModelObject();
		return process.getDescription();
	}

	@Override
	public String getDisplay() {
		String pidstr = FridaClient.getId(getProcess());
		if (base == 16) {
			pidstr = "0x" + pidstr;
		}
		else {
			pidstr = Long.toString(Long.parseLong(pidstr, 16));
		}
		return "[" + pidstr + "]";
	}

	@Override
	public void processSelected(FridaProcess eventProcess, FridaCause cause) {
		if (eventProcess.getPID().equals(getProcess().getPID())) {
			((FridaModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void threadStateChanged(FridaThread thread, FridaState state, FridaCause cause,
			FridaReason reason) {
		TargetExecutionState targetState = FridaClient.convertState(state);
		setExecutionState(targetState, "ThreadStateChanged");
		// NB: Asking for threads on 32-bit Android targets will kill the server right now
		/*
		if (state.equals(FridaState.FRIDA_THREAD_STOPPED)) {
			threads.requestElements(true);
		}
		*/
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		model.gateFuture(getManager().execute(new FridaLaunchProcessCommand(getManager(),
			getProcess().getName(), args)));
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> resume() {
		return model.gateFuture(
			getManager().execute(new FridaContinueCommand(getManager(), getProcess())));
	}

	@Override
	public CompletableFuture<Void> kill() {
		return model.gateFuture(getManager().execute(new FridaKillCommand(getManager())));
	}

	@Override
	public CompletableFuture<Void> destroy() {
		return model.gateFuture(getManager().execute(new FridaDestroyCommand(getManager())));
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		getModel().assertMine(TargetObject.class, attachable);
		// NOTE: Get the object and type check it myself.
		// The typed ref could have been unsafely cast
		FridaProcess proc = (FridaProcess) getModelObject();
		long pid = proc.getPID().longValue();
		return model.gateFuture(
			getManager().execute(new FridaAttachCommand(getManager(), Long.toString(pid)))
					.thenApply(__ -> null));
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return model.gateFuture(
			getManager().execute(new FridaAttachCommand(getManager(), Long.toString(pid)))
					.thenApply(__ -> null));
	}

	@Override
	public CompletableFuture<Void> detach() {
		return model.gateFuture(
			getManager().execute(new FridaDetachCommand(getManager(), getProcess().getSession())));
	}

	@Override
	public CompletableFuture<Void> delete() {
		return AsyncUtils.NIL;
		//return model.gateFuture(process.remove());
	}

	/*
	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		return getManager().execute(new FridaStepCommand(getManager(), null, kind, null));
	}
	
	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return getManager().execute(new FridaStepCommand(getManager(), null, null, args));
	}
	*/

	@Override
	public void processStarted(FridaProcess proc) {
		if (proc != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				PID_ATTRIBUTE_NAME, getProcess().getPID().longValue(), //
				DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.STOPPED //
			), "Started");
		}
		setExecutionState(TargetExecutionState.STOPPED, "Started");
	}

	@Override
	public void processExited(FridaProcess proc, FridaCause cause) {
		if (proc.getPID().equals(this.getProcess().getPID())) {
			String exitDesc = "NONE";
			changeAttributes(List.of(), List.of(), Map.of( //
				STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
				EXIT_CODE_ATTRIBUTE_NAME, exitDesc //
			), "Exited");
			getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_EXITED,
				"Process " + FridaClient.getId(getProcess()) + " exited code=" + exitDesc,
				List.of(getProxy()));
		}
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public FridaModelTargetThreadContainer getThreads() {
		return threads;
	}

	@Override
	public FridaModelTargetMemoryContainer getMemory() {
		return memory;
	}

	@Override
	public FridaProcess getProcess() {
		return (FridaProcess) getModelObject();
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

}
