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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import agent.frida.manager.FridaCause;
import agent.frida.manager.FridaReason;
import agent.frida.manager.FridaThread;
import agent.frida.manager.FridaState;
import agent.frida.manager.cmd.FridaAttachCommand;
import agent.frida.model.iface1.FridaModelSelectableObject;
import agent.frida.model.iface2.FridaModelTargetConnector;
import agent.frida.model.iface2.FridaModelTargetRoot;
import agent.frida.model.iface2.FridaModelTargetThread;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetAttachable;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.schema.TargetAttributeType;
import ghidra.dbg.target.schema.TargetElementType;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.target.schema.TargetObjectSchemaInfo;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Debugger",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Available",
			type = FridaModelTargetAvailableContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Connectors",
			type = FridaModelTargetConnectorContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Sessions",
			type = FridaModelTargetSessionContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class) })
public class FridaModelTargetRootImpl extends FridaModelDefaultTargetModelRoot
		implements FridaModelTargetRoot {

	protected final FridaModelTargetAvailableContainerImpl available;
	protected final FridaModelTargetConnectorContainerImpl connectors;
	protected final FridaModelTargetSessionContainerImpl sessions;

	protected String debugger = "Frida"; // Used by FridaModelTargetEnvironment

	protected FridaModelSelectableObject focus;

	public FridaModelTargetRootImpl(FridaModelImpl impl, TargetObjectSchema schema) {
		super(impl, "Debugger", schema);

		this.available = new FridaModelTargetAvailableContainerImpl(this);
		this.connectors = new FridaModelTargetConnectorContainerImpl(this);
		this.sessions = new FridaModelTargetSessionContainerImpl(this);

		FridaModelTargetConnector defaultConnector = connectors.getDefaultConnector();
		changeAttributes(List.of(), List.of( //
			available, //
			connectors, //
			sessions //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			DISPLAY_ATTRIBUTE_NAME, "Debugger", //
			FOCUS_ATTRIBUTE_NAME, this, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, FridaModelTargetProcessImpl.SUPPORTED_KINDS, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters() //
		), "Initialized");
		impl.getManager().addEventsListener(this);
	}

	@Override
	public FridaModelSelectableObject getFocus() {
		return focus;
	}

	@Override
	public void setDefaultConnector(FridaModelTargetConnector defaultConnector) {
		changeAttributes(List.of(), List.of(),
			Map.of(TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters()),
			"Default connector changed");
	}

	@Override
	public boolean setFocus(FridaModelSelectableObject sel) {
		boolean doFire;
		synchronized (this) {
			doFire = !Objects.equals(this.focus, sel);
			if (doFire && focus != null) {
				List<String> focusPath = focus.getPath();
				List<String> selPath = sel.getPath();
				doFire = !PathUtils.isAncestor(selPath, focusPath);
			}
		}
		if (doFire) {
			this.focus = sel;
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetFocusScope.FOCUS_ATTRIBUTE_NAME, focus //
			), "Focus changed");
		}
		return doFire;
	}

	@Override
	public CompletableFuture<Void> launch(List<String> args) {
		FridaModelTargetProcessLaunchConnectorImpl targetConnector = connectors.processLauncher;
		return model.gateFuture(targetConnector.launch(args)).exceptionally(exc -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		FridaModelTargetConnector targetConnector = connectors.getDefaultConnector();
		return model.gateFuture(targetConnector.launch(args)).exceptionally(exc -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		FridaModelTargetProcessAttachByPidConnectorImpl targetConnector =
			connectors.processAttacherByPid;
		String key = attachable.getName();
		Map<String, String> map = new HashMap<>();
		map.put("Pid", key.substring(1, key.length() - 1));
		return model.gateFuture(targetConnector.launch(map)).exceptionally(exc -> {
			throw new DebuggerUserException("Launch failed for " + key);
		});
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return model.gateFuture(
			getManager().execute(new FridaAttachCommand(getManager(), Long.toString(pid)))
					.thenApply(__ -> null));
	}

	@Override
	public void threadStateChanged(FridaThread thread, FridaState state, FridaCause cause,
			FridaReason reason) {
		FridaModelTargetThread targetThread =
			(FridaModelTargetThread) getModel().getModelObject(thread);
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME, targetThread //
		), reason.desc());
	}

	@Override
	public boolean isAccessible() {
		return true;
	}

}
