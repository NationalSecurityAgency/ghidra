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
import agent.dbgeng.model.impl.DbgModelTargetProcessImpl;
import agent.dbgmodel.dbgmodel.main.ModelObject;
import agent.dbgmodel.manager.DbgManager2Impl;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.dbg.target.*;
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
			ACCESSIBLE_ATTRIBUTE_NAME, true, //
			DISPLAY_ATTRIBUTE_NAME, "Debugger", //
			FOCUS_ATTRIBUTE_NAME, this, //
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
			ACCESSIBLE_ATTRIBUTE_NAME, true, //
			DISPLAY_ATTRIBUTE_NAME, "Debugger", //
			FOCUS_ATTRIBUTE_NAME, this, //
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
				doFire = !PathUtils.isAncestor(selPath, focusPath);
			}
		}
		if (doFire) {
			this.focus = sel;
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetFocusScope.FOCUS_ATTRIBUTE_NAME, focus //
			), "Focus changed");
			intrinsics.put(TargetFocusScope.FOCUS_ATTRIBUTE_NAME, focus);
			//DbgModelTargetSession session = focus.getParentSession();
			//session.setActive();
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
		TargetObject obj = getModel().getModelObject(objPath);
		if (obj instanceof DbgModelSelectableObject) {
			setFocus((DbgModelSelectableObject) obj);
		}
		/*
		getModel().fetchModelValue(objPath, true).thenAccept(obj -> {
			if (obj instanceof DbgModelSelectableObject) {
				setFocus((DbgModelSelectableObject) obj);
			}
		}).exceptionally(ex -> {
			Msg.error("Could not set focus on selected object: " + PathUtils.toString(objPath), ex);
			return null;
		});
		*/
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
		getObject(proc).thenAccept(obj -> {
			DbgModelTargetProcess targetProcess = (DbgModelTargetProcess) obj;
			if (targetProcess == null) {
				System.err.println("processAdded - null");
				return;
			}
			getListeners().fire.event(getProxy(), null, TargetEventType.PROCESS_CREATED,
				"Process " + proc.getId() + " started " + "notepad.exe" + " pid=" + proc.getPid(),
				List.of(targetProcess));
		});
	}

	@Override
	public void threadCreated(DbgThread thread, DbgCause cause) {
		getObject(thread).thenAccept(obj -> {
			DbgModelTargetThread targetThread = (DbgModelTargetThread) obj;
			if (targetThread == null) {
				System.err.println("threadCreated - null");
				return;
			}
			getListeners().fire.event(getProxy(), targetThread, TargetEventType.THREAD_CREATED,
				"Thread " + thread.getId() + " started", List.of(targetThread));
			DelegateDbgModel2TargetObject delegate =
				(DelegateDbgModel2TargetObject) targetThread.getDelegate();
			delegate.threadStateChangedSpecific(DbgState.STARTING, DbgReason.Reasons.UNKNOWN);
		});
	}

	@Override
	public void moduleLoaded(DbgProcess proc, DebugModuleInfo info, DbgCause cause) {
		getObjectRevisited(proc, List.of("Modules"), info).thenAccept(obj -> {
			DbgModelTargetModule mod = (DbgModelTargetModule) obj;
			if (mod == null) {
				return;
			}
			getObject(getManager().getEventThread()).thenAccept(t -> {
				TargetThread eventThread = (TargetThread) t;
				getListeners().fire.event(getProxy(), eventThread, TargetEventType.MODULE_LOADED,
					"Library " + info.getModuleName() + " loaded", List.of(mod));
			});
			getObject(getManager().getEventProcess()).thenAccept(p -> {
				DbgModelTargetProcess eventProcess = (DbgModelTargetProcess) p;
				DbgModel2TargetObjectImpl memory =
					(DbgModel2TargetObjectImpl) eventProcess.getCachedAttribute("Memory");
				memory.requestElements(false);
			});
		});
	}

	@Override
	public void moduleUnloaded(DbgProcess proc, DebugModuleInfo info, DbgCause cause) {
		getObjectRevisited(proc, List.of("Modules"), info).thenAccept(obj -> {
			DbgModelTargetModule mod = (DbgModelTargetModule) obj;
			if (mod == null) {
				return;
			}
			getObject(getManager().getEventThread()).thenAccept(t -> {
				TargetThread eventThread = (TargetThread) t;
				getListeners().fire.event(getProxy(), eventThread, TargetEventType.MODULE_UNLOADED,
					"Library " + info.getModuleName() + " unloaded", List.of(mod));
			});
			getObject(getManager().getEventProcess()).thenAccept(p -> {
				DbgModelTargetProcess eventProcess = (DbgModelTargetProcess) p;
				DbgModel2TargetObjectImpl memory =
					(DbgModel2TargetObjectImpl) eventProcess.getCachedAttribute("Memory");
				memory.requestElements(false);
			});
		});
	}

	private CompletableFuture<DbgModelTargetObject> getObject(Object object) {
		DbgModelTargetObject modelObject = (DbgModelTargetObject) getModel().getModelObject(object);
		if (modelObject != null) {
			return CompletableFuture.completedFuture(modelObject);
		}
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
			getModel().addModelObject(object, pimpl);
			seq.exit(pimpl);
		}).finish();
	}

	//TODO: fix this
	private CompletableFuture<DbgModelTargetObject> getObjectRevisited(Object object,
			List<String> ext, Object info) {
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
			DbgModel2TargetProxy proxy = (DbgModel2TargetProxy) pobj;
			DelegateDbgModel2TargetObject delegate = proxy.getDelegate();
			Map<String, ? extends TargetObject> existingElements =
				delegate.getCachedElements();

			xpath.add(0, "Debugger");
			DbgManager2Impl manager = (DbgManager2Impl) getManager();
			List<ModelObject> list = manager.getAccess().getElements(xpath);
			for (ModelObject obj : list) {
				String searchKey = obj.getSearchKey();
				if (searchKey.equals(info.toString())) {
					String elKey = PathUtils.makeKey(searchKey);
					DbgModel2TargetProxy proxyElement;
					if (existingElements.containsKey(searchKey)) {
						proxyElement = (DbgModel2TargetProxy) existingElements.get(searchKey);
						DelegateDbgModel2TargetObject elementDelegate = proxyElement.getDelegate();
						elementDelegate.setModelObject(obj);
					}
					else {
						proxyElement = (DbgModel2TargetProxy) DelegateDbgModel2TargetObject
								.makeProxy((DbgModel2Impl) proxy.getModel(), proxy, elKey, obj);
					}
					//DbgModel2TargetProxy proxyElement =
					//	(DbgModel2TargetProxy) DelegateDbgModel2TargetObject
					//			.makeProxy(delegate.getModel(), delegate, elKey, obj);
					delegate.changeElements(List.of(), List.of(proxyElement), "Created");
					seq.exit(proxyElement);
				}
			}
		}).finish();
	}

	private CompletableFuture<Void> getObjectAndRemove(Object object,
			List<String> ext, Object info) {
		List<String> objPath = findObject(object);
		if (objPath == null) {
			return CompletableFuture.completedFuture(null);
		}
		List<String> xpath = new ArrayList<>();
		xpath.addAll(objPath);
		xpath.addAll(ext);
		return AsyncUtils.sequence(TypeSpec.cls(Void.class)).then(seq -> {
			getModel().fetchModelObject(xpath).handle(seq::next);
		}, TypeSpec.cls(TargetObject.class)).then((pobj, seq) -> {
			if (pobj == null) {
				return;
			}
			DbgModel2TargetProxy proxy = (DbgModel2TargetProxy) pobj;
			DelegateDbgModel2TargetObject delegate = proxy.getDelegate();
			delegate.changeElements(List.of(info.toString()), List.of(), "Deleted");
		}).finish();
	}

	@Override
	public void sessionRemoved(DebugSessionId sessionId, DbgCause cause) {
		getObject(sessionId);
	}

	@Override
	public void processRemoved(DebugProcessId processId, DbgCause cause) {
		getObject(processId).thenAccept(object -> {
			if (object == null) {
				return;
			}
			DbgModelTargetProcess process = (DbgModelTargetProcess) object.getProxy();
			if (!process.getExecutionState().equals(TargetExecutionState.TERMINATED)) {
				process.setExecutionState(TargetExecutionState.INACTIVE, "Detached");
			}
			DbgModelTargetObject container = (DbgModelTargetObject) process.getParent();
			DelegateDbgModel2TargetObject delegate =
				(DelegateDbgModel2TargetObject) container.getDelegate();
			delegate.changeElements(List.of( //
				process.getIndex() //
			), List.of(), Map.of(), "Removed");
			process.getParent().resync();
		});
	}

	@Override
	public void processExited(DbgProcess proc, DbgCause cause) {
		DbgModelTargetProcess targetProcess =
			(DbgModelTargetProcess) getModel().getModelObject(proc);
		if (targetProcess != null) {
			if (targetProcess.isValid()) {
				targetProcess.changeAttributes(List.of(), Map.of( //
					TargetExecutionStateful.STATE_ATTRIBUTE_NAME, TargetExecutionState.TERMINATED, //
					DbgModelTargetProcessImpl.EXIT_CODE_ATTRIBUTE_NAME, proc.getExitCode() //
				), "Exited");
			}
			getListeners().fire.event(targetProcess.getProxy(), null,
				TargetEventType.PROCESS_EXITED,
				"Process " + proc.getId() + " exited code=" + proc.getExitCode(),
				List.of(getProxy()));
		}
	}

	@Override
	public void threadExited(DebugThreadId threadId, DbgProcess process, DbgCause cause) {
		getObject(threadId).thenAccept(thread -> {
			if (thread == null) {
				return;
			}
			DbgModelTargetThread targetThread = (DbgModelTargetThread) thread.getProxy();
			getListeners().fire.event(getProxy(), targetThread, TargetEventType.THREAD_EXITED,
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
			changeAttributes(List.of(), List.of(), Map.of( //
				TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME, targetThread //
			), reason.desc());
			intrinsics.put(TargetEventScope.EVENT_OBJECT_ATTRIBUTE_NAME, targetThread);
			TargetEventType eventType = getEventType(state, cause, reason);
			getListeners().fire.event(getProxy(), targetThread, eventType,
				"Thread " + thread.getId() + " state changed", List.of(targetThread));
			DelegateDbgModel2TargetObject delegate =
				(DelegateDbgModel2TargetObject) targetThread.getDelegate();
			delegate.threadStateChangedSpecific(state, reason);
		});
	}

	private CompletableFuture<DbgModelTargetObject> stateChanged(Object object, DbgState state,
			String reason) {
		List<String> objPath = findObject(object);
		DbgModelTargetObject obj = (DbgModelTargetObject) getModel().getModelObject(objPath);
		if (obj instanceof DbgModelTargetExecutionStateful) {
			DbgModelTargetExecutionStateful stateful =
				(DbgModelTargetExecutionStateful) obj;
			TargetExecutionState execState = stateful.convertState(state);
			stateful.setExecutionState(execState, reason);
		}
		return CompletableFuture.completedFuture(obj);
		/*
		return AsyncUtils.sequence(TypeSpec.cls(DbgModelTargetObject.class)).then(seq -> {
			getModel().fetchModelValue(objPath).handle(seq::next);
		}, TypeSpec.cls(Object.class))
				.then((obj, seq) -> {
					// This is quite possibly redundant
					if (obj instanceof DbgModelTargetExecutionStateful) {
						DbgModelTargetExecutionStateful stateful =
							(DbgModelTargetExecutionStateful) obj;
						TargetExecutionState execState = stateful.convertState(state);
						stateful.setExecutionState(execState, reason);
					}
					seq.exit((DbgModelTargetObject) obj);
				})
				.finish();
		*/
	}

	@Override
	public void breakpointCreated(DbgBreakpointInfo info, DbgCause cause) {
		int id = info.getId();
		bptInfoMap.put(id, info);
		getObjectRevisited(info.getProc(), List.of("Debug", "Breakpoints"), info);
	}

	@Override
	public void breakpointModified(DbgBreakpointInfo newInfo, DbgBreakpointInfo oldInfo,
			DbgCause cause) {
		int id = newInfo.getId();
		bptInfoMap.put(id, newInfo);
		getObjectRevisited(newInfo.getProc(), List.of("Debug", "Breakpoints"), newInfo);
	}

	@Override
	public void breakpointDeleted(DbgBreakpointInfo info, DbgCause cause) {
		bptInfoMap.remove((int) info.getNumber());
		getObjectAndRemove(info.getProc(), List.of("Debug", "Breakpoints"), info);
	}

	@Override
	public void breakpointHit(DbgBreakpointInfo info, DbgCause cause) {
		getObjectRevisited(info.getProc(), List.of("Debug", "Breakpoints"), info)
				.thenAccept(obj -> {
					DbgModelTargetBreakpointSpec bpt = (DbgModelTargetBreakpointSpec) obj;
					if (bpt == null) {
						Msg.error(this, "Stopped for breakpoint unknown to the agent: " +
							info.getNumber() + " (pc=" + info.getExpression() + ")");
						return;
					}

					DbgThread thread = info.getEventThread();
					TargetObject targetThread = getModel().getModelObject(thread);
					listeners.fire.breakpointHit(bpt.getParent(), targetThread, null, bpt, bpt);
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
			case SESSION_EXIT:
				return TargetEventType.PROCESS_EXITED;
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

	@Override
	public boolean isAccessible() {
		return accessible;
	}

	@Override
	public void setAccessible(boolean accessible) {
		this.accessible = accessible;
	}
}
