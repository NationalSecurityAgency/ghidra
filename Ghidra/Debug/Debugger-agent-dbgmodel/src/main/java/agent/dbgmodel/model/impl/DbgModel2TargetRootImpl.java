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
package agent.dbgmodel.model.impl;

import java.util.*;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.*;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.reason.*;
import agent.dbgeng.model.iface1.DbgModelSelectableObject;
import agent.dbgeng.model.iface1.DbgModelTargetExecutionStateful;
import agent.dbgeng.model.iface2.*;
import agent.dbgeng.model.impl.DbgModelTargetConnectorContainerImpl;
import agent.dbgmodel.manager.DbgManager2Impl;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetBreakpointContainer.TargetBreakpointListener;
import ghidra.dbg.target.TargetExecutionStateful.TargetExecutionState;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathUtils;
import ghidra.util.Msg;

public class DbgModel2TargetRootImpl extends DbgModel2DefaultTargetModelRoot
		implements DbgModelTargetRoot {

	protected final DbgModel2Impl impl;

	protected final DbgModel2TargetAvailableContainerImpl available;
	protected final DbgModelTargetConnectorContainerImpl connectors;
	protected final DbgModel2TargetSystemMarkerImpl systemMarker;

	public DbgModel2TargetRootImpl(DbgModel2Impl impl) {
		super(impl, "Debugger");
		this.impl = impl;

		this.available = new DbgModel2TargetAvailableContainerImpl(this);
		this.connectors = new DbgModelTargetConnectorContainerImpl(this);
		this.systemMarker = new DbgModel2TargetSystemMarkerImpl(this);

		DbgModelTargetConnector defaultConnector = connectors.getDefaultConnector();
		changeAttributes(List.of(), List.of( //
			available, //
			connectors, //
			systemMarker //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, "Debugger", //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters() //
		//  ARCH_ATTRIBUTE_NAME, "x86_64", //
		//  DEBUGGER_ATTRIBUTE_NAME, "dbgeng", //
		//  OS_ATTRIBUTE_NAME, "Windows", //
		), "Initialized");
		impl.getManager().addEventsListener(this);
	}

	public DbgModel2TargetRootImpl(DbgModel2Impl impl, TargetObjectSchema schema) {
		super(impl, "Debugger", schema);
		this.impl = impl;

		this.available = new DbgModel2TargetAvailableContainerImpl(this);
		this.connectors = new DbgModelTargetConnectorContainerImpl(this);
		this.systemMarker = new DbgModel2TargetSystemMarkerImpl(this);

		DbgModelTargetConnector defaultConnector = connectors.getDefaultConnector();
		changeAttributes(List.of(), List.of( //
			available, //
			connectors, //
			systemMarker //
		), Map.of( //
			DISPLAY_ATTRIBUTE_NAME, "Debugger", //
			TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters() //
		//  ARCH_ATTRIBUTE_NAME, "x86_64", //
		//  DEBUGGER_ATTRIBUTE_NAME, "dbgeng", //
		//  OS_ATTRIBUTE_NAME, "Windows", //
		), "Initialized");
		impl.getManager().addEventsListener(this);
	}

	@Override
	public boolean setFocus(DbgModelSelectableObject sel) {
		boolean doFire;
		synchronized (this) {
			doFire = !Objects.equals(this.focus, sel);
			if (doFire && focus != null) {
				List<String> focusPath = focus.getPath();
				List<String> selPath = sel.getPath();
				for (int i = 0; i < focusPath.size(); i++) {
					if (i >= selPath.size()) {
						doFire = false;
						break;
					}
					if (!focusPath.get(i).equals(selPath.get(i))) {
						doFire = true;
						break;
					}
				}
				//doFire = !focusPath.containsAll(selPath);
			}
		}
		if (doFire) {
			this.focus = sel;
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetFocusScope.FOCUS_ATTRIBUTE_NAME, focus //
			), "Focus changed");
			intrinsics.put(TargetFocusScope.FOCUS_ATTRIBUTE_NAME, focus);
			DbgModelTargetSession session = focus.getParentSession();
			session.select();
			listeners.fire(TargetFocusScopeListener.class).focusChanged(this, sel);
		}
		return doFire;
	}

	@Override
	public void setDefaultConnector(DbgModelTargetConnector defaultConnector) {
		changeAttributes(List.of(), List.of(),
			Map.of(TargetMethod.PARAMETERS_ATTRIBUTE_NAME, defaultConnector.getParameters()),
			"Default connector changed");
	}

	@Override
	public void sessionSelected(DbgSession session, DbgCause cause) {
		objectSelected(session);
	}

	@Override
	public void processSelected(DbgProcess process, DbgCause cause) {
		objectSelected(process);
	}

	@Override
	public void threadSelected(DbgThread thread, DbgStackFrame frame, DbgCause cause) {
		objectSelected(thread);
		if (frame != null) {
			objectSelected(frame);
		}
	}

	public void objectSelected(Object object) {
		List<String> objPath = findObject(object);
		getModel().fetchModelValue(objPath, true).thenAccept(obj -> {
			if (obj instanceof DbgModelSelectableObject) {
				setFocus((DbgModelSelectableObject) obj);
			}
		}).exceptionally(ex -> {
			Msg.error("Could not set focus on selected object: " + PathUtils.toString(objPath), ex);
			return null;
		});
	}

	@Override
	public void sessionAdded(DbgSession session, DbgCause cause) {
		changeAttributes(List.of(), List.of( //
			new DbgModel2TargetSystemMarkerImpl(this) //
		), Map.of(), "System");
		getObject(session);
	}

	@Override
	public void processAdded(DbgProcess proc, DbgCause cause) {
		stateChanged(proc, DbgState.STARTING, "ProcessAdded");
		getObject(proc).thenAccept(obj -> {
			DbgModelTargetProcess process = (DbgModelTargetProcess) obj;
			if (process == null) {
				return;
			}
			getListeners().fire(TargetEventScopeListener.class)
					.event(
						this, null, TargetEventType.PROCESS_CREATED, "Process " + proc.getId() +
							" started " + "notepad.exe" + " pid=" + proc.getPid(),
						List.of(process));
		});
	}

	@Override
	public void threadCreated(DbgThread thread, DbgCause cause) {
		stateChanged(thread, DbgState.STARTING, "ThreadCreated");
		getObject(thread).thenAccept(obj -> {
			DbgModelTargetThread targetThread = (DbgModelTargetThread) obj;
			if (targetThread == null) {
				return;
			}
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, targetThread, TargetEventType.THREAD_CREATED,
						"Thread " + thread.getId() + " started", List.of(targetThread));
		});
	}

	@Override
	public void moduleLoaded(DbgProcess proc, String name, DbgCause cause) {
		getObject(proc, List.of("Modules"), name).thenAccept(obj -> {
			DbgModelTargetModule mod = (DbgModelTargetModule) obj;
			if (mod == null) {
				return;
			}
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, null, TargetEventType.MODULE_LOADED, "Library " + name + " loaded",
						List.of(mod));
		});
	}

	@Override
	public void moduleUnloaded(DbgProcess proc, String name, DbgCause cause) {
		getObject(proc, List.of("Modules"), name).thenAccept(obj -> {
			DbgModelTargetModule mod = (DbgModelTargetModule) obj;
			if (mod == null) {
				return;
			}
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, null, TargetEventType.MODULE_UNLOADED,
						"Library " + name + " unloaded", List.of(mod));
		});
	}

	private CompletableFuture<DbgModelTargetObject> getObject(Object object) {
		List<String> objPath = findObject(object);
		if (objPath == null) {
			return CompletableFuture.completedFuture(null);
		}
		// NB: fetchModelObject uses overriden DbgModel2TargetObjectImpl::fetchChild
		//   which forces refresh for empty containers
		return AsyncUtils.sequence(TypeSpec.cls(DbgModelTargetObject.class)).then(seq -> {
			getModel().fetchModelObject(objPath).handle(seq::next);
		}, TypeSpec.cls(TargetObject.class)).then((pobj, seq) -> {
			DbgModelTargetObject pimpl = (DbgModelTargetObject) pobj;
			seq.exit(pimpl);
		}).finish();
	}

	private CompletableFuture<DbgModelTargetObject> getObject(Object object, List<String> ext,
			String name) {
		List<String> objPath = findObject(object);
		if (objPath == null) {
			return CompletableFuture.completedFuture(null);
		}
		List<String> xpath = new ArrayList<>();
		xpath.addAll(objPath);
		xpath.addAll(ext);
		return AsyncUtils.sequence(TypeSpec.cls(DbgModelTargetObject.class)).then(seq -> {
			getModel().fetchModelObject(xpath).handle(seq::next);
		}, TypeSpec.cls(TargetObject.class)).then((pobj, seq) -> {
			if (pobj == null) {
				seq.exit();
				return;
			}
			DbgModelTargetObject proxy = (DbgModelTargetObject) pobj;
			DelegateDbgModel2TargetObject delegate =
				DelegateDbgModel2TargetObject.getDelegate(proxy);
			delegate.requestElements(true).thenAccept(__ -> {
				Map<String, TargetObject> cachedElements = delegate.getCachedElements();
				for (TargetObject val : cachedElements.values()) {
					DbgModelTargetObject obj = (DbgModelTargetObject) val;
					if (obj.getDisplay().contains(name)) {
						seq.exit(obj);
					}
				}
				seq.exit((DbgModelTargetObject) null);
			});
		}).finish();
	}

	@Override
	public void sessionRemoved(DebugSessionId sessionId, DbgCause cause) {
		getObject(sessionId);
	}

	@Override
	public void processRemoved(DebugProcessId processId, DbgCause cause) {
		getObject(processId).thenAccept(obj -> {
			DbgModelTargetProcess process = obj.as(DbgModelTargetProcess.class);
			if (process == null) {
				return;
			}
			DbgProcess proc = process.getProcess();
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, null, TargetEventType.PROCESS_EXITED,
						"Process " + proc.getId() + " exited code=" + proc.getExitCode(),
						List.of(process));
		});
	}

	@Override
	public void threadExited(DebugThreadId threadId, DbgProcess process, DbgCause cause) {
		getObject(threadId).thenAccept(obj -> {
			DbgModelTargetThread targetThread = obj.as(DbgModelTargetThread.class);
			if (targetThread == null) {
				return;
			}
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, targetThread, TargetEventType.THREAD_EXITED,
						"Thread " + threadId + " exited", List.of(targetThread));
		});
	}

	@Override
	public void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		stateChanged(thread, state, reason.desc()).thenAccept(obj -> {
			DbgModelTargetThread targetThread = (DbgModelTargetThread) obj;
			if (targetThread == null) {
				return;
			}
			DbgProcess process = thread.getProcess();
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetEventScope.EVENT_PROCESS_ATTRIBUTE_NAME, Long.toHexString(process.getPid()), //
				TargetEventScope.EVENT_THREAD_ATTRIBUTE_NAME, Long.toHexString(thread.getTid()) //
			), reason.desc());
			intrinsics.put(TargetEventScope.EVENT_PROCESS_ATTRIBUTE_NAME,
				Long.toHexString(process.getPid()));
			intrinsics.put(TargetEventScope.EVENT_THREAD_ATTRIBUTE_NAME,
				Long.toHexString(thread.getTid()));
			TargetEventType eventType = getEventType(state, cause, reason);
			getListeners().fire(TargetEventScopeListener.class)
					.event(this, targetThread, eventType,
						"Thread " + thread.getId() + " state changed", List.of(targetThread));
		});
	}

	private CompletableFuture<DbgModelTargetObject> stateChanged(Object object, DbgState state,
			String reason) {
		List<String> objPath = findObject(object);
		return AsyncUtils.sequence(TypeSpec.cls(DbgModelTargetObject.class)).then(seq -> {
			getModel().fetchModelValue(objPath).handle(seq::next);
		}, TypeSpec.cls(Object.class)).then((obj, seq) -> {
			if (obj instanceof DbgModelTargetExecutionStateful) {
				DbgModelTargetExecutionStateful<?> stateful =
					(DbgModelTargetExecutionStateful<?>) obj;
				TargetExecutionState execState = stateful.convertState(state);
				stateful.setExecutionState(execState, reason);
			}
			seq.exit((DbgModelTargetObject) obj);
		}).finish();
	}

	@Override
	public void breakpointCreated(DbgBreakpointInfo info, DbgCause cause) {
		int id = info.getDebugBreakpoint().getId();
		bptInfoMap.put(id, info);
		getObject(info.getProc(), List.of("Debug", "Breakpoints"), Integer.toHexString(id));
		/*
		getObject(info).thenAccept(obj -> {
			DbgModelTargetBreakpointSpec bpt = (DbgModelTargetBreakpointSpec) obj;
			if (bpt == null) {
				return;
			}
			bpt.setBreakpointInfo(info);
			bpt.setEnabled(true, "Created");
		});
		*/
	}

	@Override
	public void breakpointModified(DbgBreakpointInfo newInfo, DbgBreakpointInfo oldInfo,
			DbgCause cause) {
		int id = newInfo.getDebugBreakpoint().getId();
		bptInfoMap.put(id, newInfo);
		getObject(newInfo.getProc(), List.of("Debug", "Breakpoints"), Integer.toHexString(id));
	}

	@Override
	public void breakpointDeleted(DbgBreakpointInfo info, DbgCause cause) {
		int id = info.getDebugBreakpoint().getId();
		bptInfoMap.remove(id);
		getObject(info.getProc(), List.of("Debug", "Breakpoints"), Integer.toHexString(id));
	}

	@Override
	public void breakpointHit(DbgBreakpointInfo info, DbgCause cause) {
		int id = info.getDebugBreakpoint().getId();
		getObject(info.getProc(), List.of("Debug", "Breakpoints"), Integer.toHexString(id))
				.thenAccept(obj -> {
					DbgModelTargetBreakpointSpec bpt = (DbgModelTargetBreakpointSpec) obj;
					if (bpt == null) {
						Msg.error(this, "Stopped for breakpoint unknown to the agent: " +
							info.getNumber() + " (pc=" + info.getLocation() + ")");
						return;
					}

					listeners.fire(TargetBreakpointListener.class)
							.breakpointHit((TargetBreakpointContainer<?>) bpt.getParent(),
								getParentProcess(), null, bpt, bpt);
					bpt.breakpointHit();
				});
	}

	/*
	@Override
	public void consoleOutput(String output, int mask) {
		Channel chan = TargetConsole.Channel.STDOUT;
		if (((mask & DebugOutputFlags.DEBUG_OUTPUT_ERROR.getValue()) //
				== DebugOutputFlags.DEBUG_OUTPUT_ERROR.getValue()) || //
			((mask & DebugOutputFlags.DEBUG_OUTPUT_WARNING.getValue()) // 
					== DebugOutputFlags.DEBUG_OUTPUT_WARNING.getValue())) {
			chan = TargetConsole.Channel.STDERR;
		}
		final Channel channel = chan;
		getObject("cursession").thenAccept(session -> {
			listeners.fire(TargetInterpreterListener.class).consoleOutput(session, channel, output);
		});
	}
	*/

	private List<String> findObject(Object obj) {
		DebugSystemObjects so = getManager().getSystemObjects();
		List<String> objpath = new ArrayList<>();
		DebugSessionId sid = so.getCurrentSystemId();
		String skey = sid.id < 0 ? PathUtils.makeKey("0x0")
				: PathUtils.makeKey("0x" + Integer.toHexString(sid.id));
		if (obj instanceof DbgSession) {
			DbgSession session = (DbgSession) obj;
			skey = PathUtils.makeKey("0x" + Long.toHexString(session.getId().id));
		}
		if (obj instanceof DbgSession || obj instanceof String) {
			objpath = List.of("Sessions", skey);
			return objpath;
		}
		int pid = so.getCurrentProcessSystemId();
		String pkey = PathUtils.makeKey("0x" + Integer.toHexString(pid));
		if (obj instanceof DbgProcess) {
			DbgProcess process = (DbgProcess) obj;
			pkey = PathUtils.makeKey("0x" + Long.toHexString(process.getPid()));
		}
		if (obj instanceof DbgProcess || obj instanceof DebugProcessId) {
			objpath = List.of("Sessions", skey, "Processes", pkey);
			return objpath;
		}
		int tid = so.getCurrentThreadSystemId();
		String tkey = PathUtils.makeKey("0x" + Integer.toHexString(tid));
		if (obj instanceof DbgThread) {
			DbgThread thread = (DbgThread) obj;
			DbgProcess process = thread.getProcess();
			tkey = PathUtils.makeKey("0x" + Long.toHexString(thread.getTid()));
			pkey = PathUtils.makeKey("0x" + Long.toHexString(process.getPid()));
		}
		if (obj instanceof DbgStackFrame) {
			DbgStackFrame frame = (DbgStackFrame) obj;
			DbgThread thread = frame.getThread();
			DbgProcess process = thread.getProcess();
			int level = frame.getLevel();
			String fkey = "[0x" + Integer.toHexString(level) + "]";
			tkey = PathUtils.makeKey("0x" + Long.toHexString(thread.getTid()));
			pkey = PathUtils.makeKey("0x" + Long.toHexString(process.getPid()));
			objpath = List.of("Sessions", skey, "Processes", pkey, "Threads", tkey, "Stack",
				"Frames", fkey);
		}
		if (obj instanceof DbgThread || obj instanceof DebugThreadId) {
			objpath = List.of("Sessions", skey, "Processes", pkey, "Threads", tkey);
		}
		return objpath;
	}

	private TargetEventType getEventType(DbgState state, DbgCause cause, DbgReason reason) {
		switch (state) {
			case RUNNING:
				return TargetEventType.RUNNING;
			case STOPPED:
			case EXIT:
				if (reason instanceof DbgEndSteppingRangeReason) {
					return TargetEventType.STEP_COMPLETED;
				}
				if (reason instanceof DbgSignalReceivedReason) {
					return TargetEventType.SIGNAL;
				}
				if (reason instanceof DbgExitedReason) {
					return TargetEventType.EXCEPTION;
				}
				if (reason instanceof DbgExitNormallyReason) {
					return TargetEventType.THREAD_EXITED;
				}
				return TargetEventType.STOPPED;
			default:
				break;
		}
		return null;
	}

	@Override
	public CompletableFuture<Void> requestAttributes(boolean refresh) {
		DbgManager2Impl manager2 = (DbgManager2Impl) getManager();
		List<String> pathX = PathUtils.extend(List.of("Debugger"), path);
		intrinsics.put(available.getName(), available);
		intrinsics.put(connectors.getName(), connectors);
		intrinsics.put(systemMarker.getName(), systemMarker);
		return manager2.listAttributes(pathX, this).thenAccept(map -> {
			if (map == null) {
				return;
			}
			changeAttributes(List.of(), map, "Refreshed");
		});
	}

	//@Override
	public void refresh() {
		// TODO ???
		System.err.println("root:refresh");
	}

	@Override
	public TargetAccessibility getAccessibility() {
		return accessibility;
	}

	@Override
	public void setAccessibility(TargetAccessibility accessibility) {
		this.accessibility = accessibility;
	}

}
