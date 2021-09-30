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
import agent.lldb.manager.cmd.LldbContinueCommand;
import agent.lldb.model.iface1.LldbModelTargetInterpreter;
import agent.lldb.model.iface2.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Session",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Debug",
			type = LldbModelTargetDebugContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Attributes",
			type = LldbModelTargetSessionAttributesImpl.class,
			fixed = true),
		@TargetAttributeType(
			name = "Processes",
			type = LldbModelTargetProcessContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Modules",
			type = LldbModelTargetModuleContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetSessionImpl extends LldbModelTargetObjectImpl
		implements LldbModelTargetSession {

	protected static final String Lldb_PROMPT = "(kd)";
	//private Integer base = 16;

	// NB: This should almost certainly always be implemented by the root of the object tree

	protected static String indexSession(SBTarget session) {
		return DebugClient.getId(session);
	}

	protected static String keySession(SBTarget session) {
		return PathUtils.makeKey(indexSession(session));
	}

	protected final LldbModelTargetDebugContainer debug;
	protected final LldbModelTargetModuleContainer modules;
	protected final LldbModelTargetSessionAttributesImpl attributes;
	protected final LldbModelTargetProcessContainerImpl processes;
	//private LldbModelSelectableObject focus;

	protected String debugger = "kd"; // Used by LldbModelTargetEnvironment

	public LldbModelTargetSessionImpl(LldbModelTargetSessionContainerImpl sessions,
			SBTarget session) {
		super(sessions.getModel(), sessions, keySession(session), session, "Session");
		getManager().getClient().addBroadcaster(session);

		this.debug = new LldbModelTargetDebugContainerImpl(this);
		this.attributes = new LldbModelTargetSessionAttributesImpl(this);
		this.processes = new LldbModelTargetProcessContainerImpl(this);
		this.modules = new LldbModelTargetModuleContainerImpl(this);

		changeAttributes(List.of(), List.of( //
			debug, //
			attributes, //
			processes, //
			modules //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			PROMPT_ATTRIBUTE_NAME, LldbModelTargetInterpreter.LLDB_PROMPT, //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE //
		), "Initialized");

		getManager().addEventsListener(this);
	}

	public String getDescription(int level) {
		SBStream stream = new SBStream();
		SBTarget session = (SBTarget) getModelObject();
		DescriptionLevel detail = DescriptionLevel.swigToEnum(level);
		session.GetDescription(stream, detail);
		return stream.GetData();
	}

	@Override
	public CompletableFuture<Void> setActive() {
		return getManager().setActiveSession(getSession());
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public LldbModelTargetProcessContainer getProcesses() {
		return processes;
	}

	@Override
	public LldbModelTargetModuleContainer getModules() {
		return modules;
	}

	public SBTarget getSession() {
		return (SBTarget) getModelObject();
	}

	@Override
	public CompletableFuture<Void> resume() {
		SBProcess currentProcess = getManager().getCurrentProcess();
		return model.gateFuture(getManager().execute(new LldbContinueCommand(getManager(), currentProcess)));
	}

}
