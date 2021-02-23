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

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.manager.*;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import agent.dbgeng.model.iface2.DbgModelTargetConnector;
import agent.dbgeng.model.iface2.DbgModelTargetRoot;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.*;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.util.PathUtils;

@TargetObjectSchemaInfo(
	name = "Debugger",
	elements = { //
		@TargetElementType(type = Void.class) //
	},
	attributes = { //
		@TargetAttributeType(
			name = "Available",
			type = DbgModelTargetAvailableContainerImpl.class,
			required = true,
			fixed = true), //
		@TargetAttributeType(
			name = "Connectors",
			type = DbgModelTargetConnectorContainerImpl.class,
			required = true,
			fixed = true), //
		@TargetAttributeType(
			name = "Sessions",
			type = DbgModelTargetSessionContainerImpl.class,
			required = true,
			fixed = true), //
		@TargetAttributeType(type = Void.class) //
	})
public class DbgModelTargetRootImpl extends DbgModelDefaultTargetModelRoot
		implements DbgModelTargetRoot {

	protected final DbgModelTargetAvailableContainerImpl available;
	protected final DbgModelTargetConnectorContainerImpl connectors;
	protected final DbgModelTargetSessionContainerImpl sessions;

	protected String debugger = "kd"; // Used by DbgModelTargetEnvironment

	protected DbgModelSelectableObject focus;

	public DbgModelTargetRootImpl(DbgModelImpl impl, TargetObjectSchema schema) {
		super(impl, "Debugger", schema);

		this.available = new DbgModelTargetAvailableContainerImpl(this);
		this.connectors = new DbgModelTargetConnectorContainerImpl(this);
		this.sessions = new DbgModelTargetSessionContainerImpl(this);

		DbgModelTargetConnector defaultConnector = connectors.getDefaultConnector();
		changeAttributes(List.of(), List.of( //
			available, //
			connectors, //
			sessions //
		), Map.of( //
			ACCESSIBLE_ATTRIBUTE_NAME, true, //
			DISPLAY_ATTRIBUTE_NAME, "Debugger", //
			FOCUS_ATTRIBUTE_NAME, this, //
			SUPPORTED_ATTACH_KINDS_ATTRIBUTE_NAME, DbgModelTargetProcessImpl.SUPPORTED_KINDS, //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters() //
		//  ARCH_ATTRIBUTE_NAME, "x86_64", //
		//  DEBUGGER_ATTRIBUTE_NAME, "dbgeng", //
		//  OS_ATTRIBUTE_NAME, "Windows", //
		), "Initialized");
		impl.getManager().addEventsListener(this);
	}

	@Override
	public DbgModelSelectableObject getFocus() {
		return focus;
	}

	@Override
	public void setDefaultConnector(DbgModelTargetConnector defaultConnector) {
		changeAttributes(List.of(), List.of(),
			Map.of(TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters()),
			"Default connector changed");
	}

	@Override
	public boolean setFocus(DbgModelSelectableObject sel) {
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
			listeners.fire(TargetFocusScopeListener.class).focusChanged(this, sel);
		}
		return doFire;
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		DbgModelTargetConnector targetConnector = connectors.getDefaultConnector();
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			targetConnector.launch(args).handle(seq::nextIgnore);
			//getManager().launch(args).handle(seq::nextIgnore);
		}).finish().exceptionally((exc) -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		return AsyncUtils.sequence(TypeSpec.VOID).then(seq -> {
			DbgProcess process = new DbgProcessImpl(getManager());
			process.attach(pid).handle(seq::nextIgnore);
		}).finish();
	}

	@Override
	public void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		DbgProcess process = thread.getProcess();
		changeAttributes(List.of(), List.of(), Map.of( //
			TargetEventScope.EVENT_PROCESS_ATTRIBUTE_NAME, Long.toHexString(process.getPid()), //
			TargetEventScope.EVENT_THREAD_ATTRIBUTE_NAME, Long.toHexString(thread.getTid()) //
		), reason.desc());
	}

	@Override
	public TargetAccessibility getAccessibility() {
		return accessibility;
	}

}
