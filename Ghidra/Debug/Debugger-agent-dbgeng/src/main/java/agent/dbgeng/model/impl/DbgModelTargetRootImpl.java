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

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.DbgReason;
import agent.dbgeng.manager.DbgSession;
import agent.dbgeng.manager.DbgStackFrame;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.impl.DbgManagerImpl;
import agent.dbgeng.manager.impl.DbgProcessImpl;
import agent.dbgeng.model.AbstractDbgModel;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import agent.dbgeng.model.iface1.DbgModelTargetExecutionStateful;
import agent.dbgeng.model.iface2.DbgModelTargetConnector;
import agent.dbgeng.model.iface2.DbgModelTargetRoot;
import agent.dbgeng.model.iface2.DbgModelTargetThread;
import ghidra.dbg.DebuggerObjectModel.RefreshBehavior;
import ghidra.dbg.error.DebuggerUserException;
import ghidra.dbg.target.TargetEventScope;
import ghidra.dbg.target.TargetExecutionStateful;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.TargetFocusScope;
import ghidra.dbg.target.TargetMethod;
import ghidra.dbg.target.TargetObject;
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
			type = DbgModelTargetAvailableContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Connectors",
			type = DbgModelTargetConnectorContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(
			name = "Sessions",
			type = DbgModelTargetSessionContainerImpl.class,
			required = true,
			fixed = true),
		@TargetAttributeType(type = Void.class) })
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
			ACCESSIBLE_ATTRIBUTE_NAME, accessible, //
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
		}
		return doFire;
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> args) {
		DbgModelTargetConnector targetConnector = connectors.getDefaultConnector();
		return model.gateFuture(targetConnector.launch(args)).exceptionally(exc -> {
			throw new DebuggerUserException("Launch failed for " + args);
		});
	}

	@Override
	public CompletableFuture<Void> attach(long pid) {
		DbgProcess process = new DbgProcessImpl(getManager());
		return model.gateFuture(process.attach(pid)).thenApply(__ -> null);
	}

	@Override
	public void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		DbgModelTargetThread targetThread =
			(DbgModelTargetThread) getModel().getModelObject(thread);
		if (targetThread != null) {
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME, targetThread //
			), reason.desc());
		}
	}

	@Override
	public void processSelected(DbgProcess process, DbgCause cause) {
		if (process != null) {
			objectSelected(process);
		}
	}

	@Override
	public void threadSelected(DbgThread thread, DbgStackFrame frame, DbgCause cause) {
		if (thread != null) {
			objectSelected(thread);
			if (frame != null) {
				objectSelected(frame);
			}
		}
	}

	public void objectSelected(Object object) {
		AbstractDbgModel model = getModel();
		List<String> objPath = findObject(object);
		model.fetchModelObject(objPath, RefreshBehavior.REFRESH_WHEN_ABSENT).thenAccept(obj -> 
			update(obj)
		);
	}

	private List<String> findObject(Object obj) {
		DbgManagerImpl manager = getManager();
		List<String> objpath = new ArrayList<>();
		if (obj == null) {
			return objpath;
		}
		DbgSession session = manager.getCurrentSession();
		if (obj instanceof DbgSession) {
			session = (DbgSession) obj;
		}
		if (session == null) {
			return objpath;
		}
		String skey = DbgModelTargetSessionImpl.keySession(session);
		if (obj instanceof DbgSession || obj instanceof String) {
			objpath = List.of("Sessions", skey);
			return objpath;
		}
		
		DbgProcess process = manager.getCurrentProcess();
		if (obj instanceof DbgProcess) {
			process = (DbgProcess) obj;
		}
		if (process == null) {
			return objpath;
		}
		String pkey = DbgModelTargetProcessImpl.keyProcess(process);
		if (obj instanceof DbgProcess || obj instanceof DebugProcessId) {
			objpath = List.of("Sessions", skey, "Processes", pkey);
			return objpath;
		}
		
		DbgThread thread = manager.getCurrentThread();
		if (obj instanceof DbgThread) {
			thread = (DbgThread) obj;
			process = thread.getProcess();
			pkey = DbgModelTargetProcessImpl.keyProcess(process);
		}
		if (thread == null) {
			return objpath;
		}
		String tkey = DbgModelTargetThreadImpl.keyThread(thread);
		if (getManager().isKernelMode()) {
			if (tkey.equals("[0x0]")) {
				// Weird, but necessary...
				pkey = "[0x0]";
			}
		}
		if (obj instanceof DbgThread || obj instanceof DebugThreadId) {
			objpath = List.of("Sessions", skey, "Processes", pkey, "Threads", tkey);
			return objpath;
		}

		if (obj instanceof DbgStackFrame) {
			DbgStackFrame frame = (DbgStackFrame) obj;
			thread = frame.getThread();
			process = thread.getProcess();
			String fkey = DbgModelTargetStackFrameImpl.keyFrame(frame);
			tkey = DbgModelTargetThreadImpl.keyThread(thread);
			pkey = DbgModelTargetProcessImpl.keyProcess(process);
			objpath = List.of("Sessions", skey, "Processes", pkey, "Threads", tkey, "Stack",
				"Frames", fkey);
			return objpath;
		}
		return objpath;
	}
	
	private void update(TargetObject obj) {
		if (obj instanceof DbgModelSelectableObject) {
			setFocus((DbgModelSelectableObject) obj);
		}
		if (obj instanceof DbgModelTargetExecutionStateful) {
			activate((DbgModelTargetExecutionStateful) obj);
		}
	}

	private void activate(DbgModelTargetExecutionStateful stateful) {
		TargetExecutionState state = stateful.getExecutionState();
		if (state.equals(TargetExecutionState.INACTIVE)) {
			stateful.changeAttributes(List.of(), Map.of( //
				TargetExecutionStateful.STATE_ATTRIBUTE_NAME, TargetExecutionState.ALIVE //
			), "Selected");
			stateful.fetchAttributes(RefreshBehavior.REFRESH_ALWAYS);
		}
	}

	@Override
	public boolean isAccessible() {
		return accessible;
	}

}
