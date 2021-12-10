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
import agent.lldb.manager.LldbReason.Reasons;
import agent.lldb.manager.cmd.LldbStepCommand;
import agent.lldb.model.iface1.LldbModelTargetFocusScope;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.*;
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
			name = "Stack",
			type = LldbModelTargetStackImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(name = TargetEnvironment.ARCH_ATTRIBUTE_NAME, type = String.class),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetThreadImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetThread {

	public static final TargetStepKindSet SUPPORTED_KINDS = TargetStepKindSet.of( //
		TargetStepKind.ADVANCE, //
		TargetStepKind.FINISH, //
		TargetStepKind.LINE, //
		TargetStepKind.OVER, //
		TargetStepKind.OVER_LINE, //
		TargetStepKind.RETURN, //
		TargetStepKind.UNTIL, //
		TargetStepKind.EXTENDED);

	protected static String indexThread(Integer id) {
		return PathUtils.makeIndex(id);
	}

	protected static String indexThread(SBThread thread) {
		return DebugClient.getId(thread);
	}

	protected static String keyThread(SBThread thread) {
		return PathUtils.makeKey(indexThread(thread));
	}

	protected final LldbModelTargetStackImpl stack;

	private LldbModelTargetProcess process;
	private Integer base = 16;

	public LldbModelTargetThreadImpl(LldbModelTargetThreadContainer threads,
			LldbModelTargetProcess process, SBThread thread) {
		super(threads.getModel(), threads, keyThread(thread), thread, "Thread");
		this.process = process;

		this.stack = new LldbModelTargetStackImpl(this, process);

		changeAttributes(List.of(), List.of( //
			stack //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible = false, //
			DISPLAY_ATTRIBUTE_NAME, getDisplay(), //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
			SUPPORTED_STEP_KINDS_ATTRIBUTE_NAME, SUPPORTED_KINDS //
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
		SBStream stream = new SBStream();
		SBThread thread = (SBThread) getModelObject();
		thread.GetDescription(stream);
		return stream.GetData();
	}

	@Override
	public String getDisplay() {
		String tidstr = DebugClient.getId(getThread());
		if (base == 16) {
			tidstr = "0x" + tidstr;
		} else {
			tidstr = Long.toString(Long.parseLong(tidstr,16));
		}
		return "[" + tidstr + "]";
	}

	@Override
	public void threadSelected(SBThread eventThread, SBFrame frame, LldbCause cause) {
		if (eventThread.GetThreadID().equals(getThread().GetThreadID())) {
			((LldbModelTargetFocusScope) searchForSuitable(TargetFocusScope.class)).setFocus(this);
		}
	}

	@Override
	public void threadStateChangedSpecific(StateType state, LldbReason reason) {
		TargetExecutionState targetState = DebugClient.convertState(state);
		changeAttributes(List.of(), List.of(), Map.of( //
			STATE_ATTRIBUTE_NAME, targetState //
		), reason.desc());
		stack.threadStateChangedSpecific(state, reason);
	}

	@Override
	public CompletableFuture<Void> step(TargetStepKind kind) {
		return getModel().gateFuture(getManager().execute(new LldbStepCommand(getManager(), null, kind, null)));
	}

	@Override
	public CompletableFuture<Void> step(Map<String, ?> args) {
		return getModel().gateFuture(getManager().execute(new LldbStepCommand(getManager(), null, null, args)));
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return getModel().gateFuture(getManager().setActiveThread(getThread()));
	}

	@Override
	public LldbModelTargetStackImpl getStack() {
		return stack;
	}

	@Override
	public SBThread getThread() {
		return (SBThread) getModelObject();
	}

	public LldbModelTargetProcess getProcess() {
		return process;
	}

	@Override
	public boolean isAccessible() {
		return accessible;
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
	public void stateChanged(StateType state, LldbCause cause) {
		LldbModelTargetThreadContainer container = (LldbModelTargetThreadContainer) getParent();
		LldbModelTargetProcess process = (LldbModelTargetProcess) container.getParent();
		Reasons unknown = LldbReason.Reasons.UNKNOWN;
		process.threadStateChanged(getThread(), state, cause, unknown);
		container.threadStateChanged(getThread(), state, cause, unknown);
		threadStateChangedSpecific(state, unknown);
	}

}
