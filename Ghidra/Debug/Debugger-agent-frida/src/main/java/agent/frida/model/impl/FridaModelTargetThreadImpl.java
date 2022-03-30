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
import agent.frida.manager.FridaReason.Reasons;
import agent.frida.model.iface1.FridaModelTargetFocusScope;
import agent.frida.model.iface2.*;
import agent.frida.model.methods.FridaModelTargetThreadStalkImpl;
import agent.frida.model.methods.FridaModelTargetUnloadScriptImpl;
import ghidra.dbg.target.TargetEnvironment;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetSteppable.TargetStepKindSet;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.ResyncMode;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Thread",
	attributeResync = ResyncMode.ALWAYS,
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
				name = "Registers",
				type = FridaModelTargetRegisterContainerImpl.class,
				required = true,
				fixed = true),
		@TargetAttributeType(
				name = "Stack",
				type = FridaModelTargetStackImpl.class,
				required = true,
				fixed = true),
		@TargetAttributeType(name = TargetEnvironment.ARCH_ATTRIBUTE_NAME, type = String.class),
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetThreadImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetThread {

	public static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of(); /*
		TargetStepKind.ADVANCE, //
		TargetStepKind.FINISH, //
		TargetStepKind.LINE, //
		TargetStepKind.OVER, //
		TargetStepKind.OVER_LINE, //
		TargetStepKind.RETURN, //
		TargetStepKind.UNTIL, //
		TargetStepKind.EXTENDED);
	*/

	protected static String indexThread(Integer id) {
		return PathUtils.makeIndex(id);
	}

	protected static String indexThread(FridaThread thread) {
		return FridaClient.getId(thread);
	}

	protected static String keyThread(FridaThread thread) {
		return PathUtils.makeKey(indexThread(thread));
	}

	protected final FridaModelTargetStackImpl stack;

	private FridaModelTargetProcess process;
	private Integer base = 10;

	private FridaModelTargetRegisterContainerImpl registers;
	private FridaModelTargetThreadStalkImpl stalk;
	private FridaModelTargetUnloadScriptImpl unload;

	public FridaModelTargetThreadImpl(FridaModelTargetThreadContainer threads,
			FridaModelTargetProcess process, FridaThread thread) {
		super(threads.getModel(), threads, keyThread(thread), thread, "Thread");
		this.process = process;

		this.registers = new FridaModelTargetRegisterContainerImpl(this);
		this.stack = new FridaModelTargetStackImpl(this, process);

		this.stalk = new FridaModelTargetThreadStalkImpl(this);
		this.unload = new FridaModelTargetUnloadScriptImpl(this, stalk.getName());
		
		changeAttributes(List.of(), List.of( //
			registers,
			stack, //
			stalk, //
			unload //
		), Map.of( //
			//ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE //
			//SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
		), "Initialized");

		getManager().addStateListener(this);
		getManager().addEventsListener(this);
	}

	@Override
	public void setModelObject(Object modelObject) {
		super.setModelObject(modelObject);
		getModel().addModelObject(modelObject, this);
	}

	public String getDescription(int level) {
		FridaThread thread = (FridaThread) getModelObject();
		return thread.getDescription();
	}

	@Override
	public String getDisplay() {
		String tidstr = FridaClient.getId(getThread());
		if (base == 16) {
			tidstr = "0x" + tidstr;
		} else {
			tidstr = Long.toString(Long.parseLong(tidstr,16));
		}
		return "[" + tidstr + "]";
	}

	@Override
	public void threadSelected(FridaThread eventThread, FridaFrame frame, FridaCause cause) {
		if (eventThread.getTid().equals(getThread().getTid())) {
			((FridaModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void threadStateChangedSpecific(FridaState state, FridaReason reason) {
		TargetExecutionState targetState = FridaClient.convertState(state);
		changeAttributes(List.of(), List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState //
		), reason.desc());
		stack.threadStateChangedSpecific(state, reason);
		registers.threadStateChangedSpecific(state, reason);
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public FridaModelTargetStackImpl getStack() {
		return stack;
	}

	@Override
	public FridaThread getThread() {
		return (FridaThread) getModelObject();
	}

	public FridaModelTargetProcess getProcess() {
		return process;
	}

	@Override
	public String getExecutingProcessorType() {
		return null; //thread.getExecutingProcessorType().description;
	}

	public void setBase(Object value) {
		this.base = (Integer) value;
		changeAttributes(List.of(), List.of(), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDisplay()//
		), "Started");
	}

	@Override
	public void stateChanged(FridaState state, FridaCause cause) {
		FridaModelTargetThreadContainer container = (FridaModelTargetThreadContainer) getParent();
		Reasons unknown = FridaReason.Reasons.UNKNOWN;
		process.threadStateChanged(getThread(), state, cause, unknown);
		container.threadStateChanged(getThread(), state, cause, unknown);
		//registers.threadStateChanged(getThread(), state, cause, unknown);
		threadStateChangedSpecific(state, unknown);
	}

}
