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
import agent.frida.manager.FridaSession;
import agent.frida.manager.cmd.FridaContinueCommand;
import agent.frida.model.iface1.FridaModelTargetInterpreter;
import agent.frida.model.iface2.FridaModelTargetModuleContainer;
import agent.frida.model.iface2.FridaModelTargetProcessContainer;
import agent.frida.model.iface2.FridaModelTargetSession;
import agent.frida.model.methods.FridaModelTargetUnloadScriptImpl;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Session",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Attributes",
			type = FridaModelTargetSessionAttributesImpl.class,
			fixed = true),
		@TargetAttributeType(
			name = "Processes",
			type = FridaModelTargetProcessContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Modules",
			type = FridaModelTargetModuleContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Object.class) })
public class FridaModelTargetSessionImpl extends FridaModelTargetObjectImpl
		implements FridaModelTargetSession {

	protected static final String FRIDA_PROMPT = "(frida)";
	private Integer base = 10;

	// NB: This should almost certainly always be implemented by the root of the object tree

	protected static String indexSession(FridaSession session) {
		return FridaClient.getId(session);
	}

	protected static String keySession(FridaSession session) {
		return PathUtils.makeKey(indexSession(session));
	}

	protected final FridaModelTargetModuleContainer modules;
	protected final FridaModelTargetSessionAttributesImpl attrs;
	protected final FridaModelTargetProcessContainerImpl processes;
	
	private FridaModelTargetUnloadScriptImpl unload;
	private FridaModelTargetKernelImpl kernel;
	protected String debugger = "frida"; // Used by FridaModelTargetEnvironment

	public FridaModelTargetSessionImpl(FridaModelTargetSessionContainerImpl sessions,
			FridaSession session) {
		super(sessions.getModel(), sessions, keySession(session), session, "Session");

		this.attrs = new FridaModelTargetSessionAttributesImpl(this);
		this.processes = new FridaModelTargetProcessContainerImpl(this);
		this.modules = new FridaModelTargetModuleContainerImpl(this);

		this.unload = new FridaModelTargetUnloadScriptImpl(this, "");

		changeAttributes(List.of(), List.of( //
			attrs, //
			processes, //
			modules //
		), Map.of( //
			//DISPLAY_ATTRIBUTE_NAME, getDescription(0), //
			PROMPT_ATTRIBUTE_NAME, FridaModelTargetInterpreter.FRIDA_PROMPT, //
			STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE, //
			unload.getName(), unload //
		), "Initialized");
		
		if (session.getAttribute("kernel").equals("true")) {
			this.kernel = new FridaModelTargetKernelImpl(this);
			changeAttributes(List.of(), List.of( //
				kernel //
			), Map.of(), "Initialized");
		}

		getManager().addEventsListener(this);
	}

	@Override
	public String getDisplay() {
		FridaSession session = (FridaSession) getModelObject();
		String pidstr = FridaClient.getId(session.getProcess());
		if (base == 16) {
			pidstr = "0x" + pidstr;
		}
		else {
			pidstr = Long.toString(Long.parseLong(pidstr, 16));
		}
		return "[" + pidstr + "]";
	}
	
	@Override
	public CompletableFuture<Void> setActive() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public FridaModelTargetProcessContainer getProcesses() {
		return processes;
	}

	@Override
	public FridaModelTargetModuleContainer getModules() {
		return modules;
	}

	public FridaSession getSession() {
		return (FridaSession) getModelObject();
	}

	@Override
	public CompletableFuture<Void> resume() {
		return model.gateFuture(getManager().execute(new FridaContinueCommand(getManager())));
	}

}
