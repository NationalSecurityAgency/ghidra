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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import SWIG.SBThread;
import SWIG.StateType;
import agent.lldb.manager.LldbCause;
import agent.lldb.manager.LldbReason;
import agent.lldb.manager.cmd.LldbAttachCommand;
import agent.lldb.model.iface1.LldbModelSelectableObject;
import agent.lldb.model.iface2.*;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Debugger",
	elements = {
		@TargetElementType(type = Void.class) },
	attributes = {
		@TargetAttributeType(
			name = "Available",
			type = LldbModelTargetAvailableContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Connectors",
			type = LldbModelTargetConnectorContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Sessions",
			type = LldbModelTargetSessionContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class) })
public class LldbModelTargetRootImpl extends LldbModelDefaultTargetModelRoot
		implements LldbModelTargetRoot {

	protected final LldbModelTargetAvailableContainerImpl available;
	protected final LldbModelTargetConnectorContainerImpl connectors;
	protected final LldbModelTargetSessionContainerImpl sessions;

	protected String debugger = "kd"; // Used by LldbModelTargetEnvironment

	protected LldbModelSelectableObject focus;

	public LldbModelTargetRootImpl(LldbModelImpl impl, TargetObjectSchema schema) {
		super(impl, "Debugger", schema);

		this.available = new LldbModelTargetAvailableContainerImpl(this);
		this.connectors = new LldbModelTargetConnectorContainerImpl(this);
		this.sessions = new LldbModelTargetSessionContainerImpl(this);

		LldbModelTargetConnector defaultConnector = connectors.getDefaultConnector();
		changeAttributes(List.of(), List.of( //
			available, //
			connectors, //
			sessions //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
			DISPLAY_ATTRIBUTE_NAME, "Debugger", //
			FOCUS_ATTRIBUTE_NAME, this, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, LldbModelTargetProcessImpl.SUPPORTED_KINDS, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters() //
		), "Initialized");
		impl.getManager().addEventsListener(this);
	}

	@Override
	public LldbModelSelectableObject getFocus() {
		return focus;
	}

	@Override
	public void setDefaultConnector(LldbModelTargetConnector defaultConnector) {
		changeAttributes(List.of(), List.of(),
			Map.of(TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters()),
			"Default connector changed");
	}

	@Override
	public boolean setFocus(LldbModelSelectableObject sel) {
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
		LldbModelTargetProcessLaunchConnectorImpl targetConnector = connectors.processLauncher;
		return model.gateFuture(targetConnector.launch(args)).exceptionally(exc -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		LldbModelTargetConnector targetConnector = connectors.getDefaultConnector();
		return model.gateFuture(targetConnector.launch(args)).exceptionally(exc -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}

	@Override
	public CompletableFuture<Void> attach(TargetAttachable attachable) {
		LldbModelTargetProcessAttachByPidConnectorImpl targetConnector =
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
			getManager().execute(new LldbAttachCommand(getManager(), Long.toString(pid)))
					.thenApply(__ -> null));
	}

	@Override
	public void threadStateChanged(SBThread thread, StateType state, LldbCause cause,
			LldbReason reason) {
		LldbModelTargetThread targetThread =
			(LldbModelTargetThread) getModel().getModelObject(thread);
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME, targetThread //
		), reason.desc());
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

}
