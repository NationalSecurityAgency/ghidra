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
package agent.lldb.manager.impl;

import static ghidra.async.AsyncUtils.*;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.Pair;

import SWIG.*;
import agent.lldb.gadp.impl.AbstractClientThreadExecutor;
import agent.lldb.gadp.impl.LldbClientThreadExecutor;
import agent.lldb.lldb.*;
import agent.lldb.lldb.DebugClient.DebugEndSessionFlags;
import agent.lldb.lldb.DebugClient.DebugStatus;
import agent.lldb.manager.*;
import agent.lldb.manager.LldbCause.Causes;
import agent.lldb.manager.breakpoint.LldbBreakpointInfo;
import agent.lldb.manager.breakpoint.LldbBreakpointType;
import agent.lldb.manager.cmd.*;
import agent.lldb.manager.evt.*;
import agent.lldb.model.iface1.*;
import ghidra.async.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.HandlerMap;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public class LldbManagerImpl implements LldbManager {

	private String LldbSrvTransport;

	public DebugStatus status;

	protected AbstractClientThreadExecutor executor;
	protected DebugClientReentrant reentrantClient;

	private List<LldbPendingCommand<?>> activeCmds = new ArrayList<>();

	protected final Map<String, SBTarget> sessions = new LinkedHashMap<>();
	protected SBTarget curSession = null;
	private final Map<String, SBTarget> unmodifiableSessions =
		Collections.unmodifiableMap(sessions);

	protected final Map<String, Map<String, SBProcess>> processes = new LinkedHashMap<>();
	protected final Map<String, Map<String, SBThread>> threads = new LinkedHashMap<>();
	protected final Map<String, Map<String, SBModule>> modules = new LinkedHashMap<>();
	private final Map<String, Map<String, Object>> breakpoints = new LinkedHashMap<>();

	protected final AsyncReference<StateType, LldbCause> state = new AsyncReference<>(null);
	private final HandlerMap<LldbEvent<?>, Void, DebugStatus> handlerMap = new HandlerMap<>();
	private final Map<Class<?>, DebugStatus> statusMap = new LinkedHashMap<>();
	private final ListenerSet<LldbEventsListener> listenersEvent =
		new ListenerSet<>(LldbEventsListener.class);

	private SBEvent currentEvent;
	private SBTarget currentSession;
	private SBProcess currentProcess;
	private SBThread currentThread;
	private SBTarget eventSession;
	private SBProcess eventProcess;
	private SBThread eventThread;
	private volatile boolean waiting = false;
	private boolean kernelMode = false;
	private CompletableFuture<String> continuation;

	/**
	 * Instantiate a new manager
	 */
	public LldbManagerImpl() {
		defaultHandlers();
	}

	/**
	 * Use {@link SBThreadImpl#remove()} instead
	 * 
	 * @param id the thread ID to remove
	 */
	public void removeThread(String processId, String id) {
		synchronized (threads) {
			if (threads.get(processId).remove(id) == null) {
				throw new IllegalArgumentException("There is no thread with id " + id);
			}
		}
	}

	@Override
	public SBThread getThread(SBProcess process, String tid) {
		synchronized (threads) {
			return threads.get(DebugClient.getId(process)).get(tid);
		}
	}

	public void addThreadIfAbsent(SBProcess process, SBThread thread) {
		synchronized (threads) {
			if (!process.IsValid())
				return;
			Map<String, SBThread> map = threads.get(DebugClient.getId(process));
			if (map == null) {
				map = new HashMap<>();
				threads.put(DebugClient.getId(process), map);
			}
			String id = DebugClient.getId(thread);
			SBThread pred = map.get(id);
			if (!map.containsKey(id) || !thread.equals(pred)) {
				if (thread.IsValid()) {
					DebugThreadInfo info = new DebugThreadInfo(thread);
					if (!map.containsKey(id)) {
						getClient().processEvent(new LldbThreadCreatedEvent(info));
					}
					else {
						getClient().processEvent(new LldbThreadReplacedEvent(info));
					}
					map.put(id, thread);
				}
			}
		}
	}

	/**
	 * Use {@link SBProcessImpl#remove(LldbCause)} instead
	 * 
	 * @param id the process ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeProcess(String sessionId, String id, LldbCause cause) {
		synchronized (processes) {
			SBProcess proc = processes.get(sessionId).remove(id);
			if (proc == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			Set<String> toRemove = new HashSet<>();
			String processId = DebugClient.getId(proc);
			for (String tid : threads.get(processId).keySet()) {
				SBThread thread = threads.get(processId).get(tid);
				String pid = DebugClient.getId(thread.GetProcess());
				if (pid.equals(id)) {
					toRemove.add(tid);
				}
			}
			for (String tid : toRemove) {
				removeThread(processId, tid);
			}
			getEventListeners().fire.processRemoved(id, cause);
		}
	}

	/**
	 * Update the selected process
	 * 
	 * @param process the process that now has focus
	 * @param cause the cause of the focus change
	 * @param fire signal listeners
	 * @return success status
	 */
	@Override
	public SBProcess getProcess(SBTarget session, String id) {
		synchronized (processes) {
			String sessionId = DebugClient.getId(session);
			SBProcess result = processes.get(sessionId).get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			return result;
		}
	}

	public void addProcessIfAbsent(SBTarget session, SBProcess process) {
		synchronized (processes) {
			if (!session.IsValid())
				return;
			String sessionId = DebugClient.getId(session);
			Map<String, SBProcess> map = processes.get(sessionId);
			if (map == null) {
				map = new HashMap<>();
				processes.put(sessionId, map);
			}
			String id = DebugClient.getId(process);
			SBProcess pred = map.get(id);
			if (!map.containsKey(id) || !process.equals(pred)) {
				if (process.IsValid()) {
					DebugProcessInfo info = new DebugProcessInfo(process);
					if (!map.containsKey(id)) {
						getClient().processEvent(new LldbProcessCreatedEvent(info));
					}
					else {
						getClient().processEvent(new LldbProcessReplacedEvent(info));
					}
					map.put(id, process);
				}
			}
		}
	}

	/**
	 * Use {@link SBTargetImpl#remove(LldbCause)} instead
	 * 
	 * @param id the session ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeSession(String id, LldbCause cause) {
		synchronized (sessions) {
			if (sessions.remove(id) == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			getEventListeners().fire.sessionRemoved(id, cause);
		}
	}

	@Override
	public SBTarget getSession(String id) {
		synchronized (sessions) {
			SBTarget result = sessions.get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			return result;
		}
	}

	public void addSessionIfAbsent(SBTarget session) {
		synchronized (sessions) {
			String id = DebugClient.getId(session);
			SBTarget pred = sessions.get(id);
			if (!sessions.containsKey(id) || !session.equals(pred)) {
				if (session.IsValid()) {
					DebugSessionInfo info = new DebugSessionInfo(session);
					if (sessions.containsKey(id)) {
						//removeSession(sessions.get(id));
						getClient().processEvent(new LldbSessionReplacedEvent(info));
					}
					else {
						getClient().processEvent(new LldbSessionCreatedEvent(info));
					}
					sessions.put(id, session);
				}
			}
		}
	}

	/**
	 * Use {@link SBModule#remove()} instead
	 * 
	 * @param id the module name to remove
	 */
	public void removeModule(SBTarget session, String id) {
		synchronized (modules) {
			if (modules.get(DebugClient.getId(session)).remove(id) == null) {
				throw new IllegalArgumentException("There is no module with id " + id);
			}
		}
	}

	@Override
	public SBModule getModule(SBTarget session, String id) {
		synchronized (modules) {
			return modules.get(DebugClient.getId(session)).get(id);
		}
	}

	public void addModuleIfAbsent(SBTarget session, SBModule module) {
		synchronized (modules) {
			if (!session.IsValid())
				return;
			String sessionId = DebugClient.getId(session);
			Map<String, SBModule> map = modules.get(sessionId);
			if (map == null) {
				map = new HashMap<>();
				modules.put(sessionId, map);
			}
			String id = DebugClient.getId(module);
			if (!map.containsKey(id)) {
				map.put(id, module);
				getClient().processEvent(
					new LldbModuleLoadedEvent(new DebugModuleInfo(eventProcess, module)));
			}
		}
	}

	/**
	 * @param id the module name to remove
	 */
	public void removeBreakpoint(SBTarget session, String id) {
		synchronized (breakpoints) {
			String sessionId = DebugClient.getId(session);
			if (breakpoints.get(sessionId).remove(id) == null) {
				throw new IllegalArgumentException("There is no module with id " + id);
			}
		}
	}

	public Object getBreakpoint(SBTarget session, String id) {
		synchronized (breakpoints) {
			return getKnownBreakpoints(session).get(id);
		}
	}

	public void addBreakpointIfAbsent(SBTarget session, Object bpt) {
		synchronized (breakpoints) {
			if (!session.IsValid())
				return;
			String sessionId = DebugClient.getId(session);
			Map<String, Object> map = breakpoints.get(sessionId);
			if (map == null) {
				map = new HashMap<>();
				breakpoints.put(sessionId, map);
			}
			String id = DebugClient.getId(bpt);
			if (!map.containsKey(id)) {
				map.put(id, bpt);
				getClient().processEvent(
					new LldbBreakpointCreatedEvent(new DebugBreakpointInfo(null, bpt)));
			}
		}
	}

	@Override
	public Map<String, SBThread> getKnownThreads(SBProcess process) {
		String processId = DebugClient.getId(process);
		Map<String, SBThread> map = threads.get(processId);
		if (map == null) {
			map = new HashMap<>();
			threads.put(DebugClient.getId(process), map);
		}
		return map;
	}

	@Override
	public Map<String, SBProcess> getKnownProcesses(SBTarget session) {
		String sessionId = DebugClient.getId(session);
		Map<String, SBProcess> map = processes.get(sessionId);
		if (map == null) {
			map = new HashMap<>();
			processes.put(sessionId, map);
		}
		return map;
	}

	@Override
	public Map<String, SBTarget> getKnownSessions() {
		return unmodifiableSessions;
	}

	@Override
	public Map<String, SBModule> getKnownModules(SBTarget session) {
		String sessionId = DebugClient.getId(session);
		Map<String, SBModule> map = modules.get(sessionId);
		if (map == null) {
			map = new HashMap<>();
			modules.put(sessionId, map);
		}
		return map;
	}

	@Override
	public Map<String, Object> getKnownBreakpoints(SBTarget session) {
		String sessionId = DebugClient.getId(session);
		Map<String, Object> map = breakpoints.get(sessionId);
		if (map == null) {
			map = new HashMap<>();
			breakpoints.put(sessionId, map);
		}
		return map;
	}

	private Object addKnownBreakpoint(SBTarget session, Object info, boolean expectExisting) {
		String bptId = DebugClient.getId(info);
		Object old = getKnownBreakpoints(session).put(bptId, info);
		if (expectExisting && old == null) {
			Msg.warn(this, "Breakpoint " + bptId + " is not known");
		}
		else if (!expectExisting && old != null) {
			Msg.warn(this, "Breakpoint " + bptId + " is already known");
		}
		return old;
	}

	private Object getKnownBreakpoint(SBTarget session, String id) {
		Object info = getKnownBreakpoints(session).get(id);
		if (info == null) {
			Msg.warn(this, "Breakpoint " + id + " is not known");
		}
		return info;
	}

	private Object removeKnownBreakpoint(SBTarget session, String id) {
		Object del = getKnownBreakpoints(session).remove(id);
		if (del == null) {
			Msg.warn(this, "Breakpoint " + id + " is not known");
		}
		return del;
	}

	@Override
	public CompletableFuture<LldbBreakpointInfo> insertBreakpoint(String loc,
			LldbBreakpointType type) {
		return execute(new LldbInsertBreakpointCommand(this, loc, type));
	}

	@Override
	public CompletableFuture<LldbBreakpointInfo> insertBreakpoint(long loc, int len,
			LldbBreakpointType type) {
		return execute(new LldbInsertBreakpointCommand(this, loc, len, type));
	}

	@Override
	public CompletableFuture<Void> disableBreakpoints(String... ids) {
		return execute(new LldbDisableBreakpointsCommand(this, ids));
	}

	@Override
	public CompletableFuture<Void> enableBreakpoints(String... ids) {
		return execute(new LldbEnableBreakpointsCommand(this, ids));
	}

	@Override
	public CompletableFuture<Void> deleteBreakpoints(String... ids) {
		return execute(new LldbDeleteBreakpointsCommand(this, ids));
	}

	@Override
	public CompletableFuture<Map<String, Object>> listBreakpoints(SBTarget session) {
		return execute(new LldbListBreakpointsCommand(this, session));
	}

	@Override
	public CompletableFuture<Map<String, SBBreakpointLocation>> listBreakpointLocations(
			SBBreakpoint spec) {
		return execute(new LldbListBreakpointLocationsCommand(this, spec));
	}

	@Override
	public CompletableFuture<Void> start(String[] args) {
		state.set(null, Causes.UNCLAIMED);
		boolean create = true;
		if (args.length == 0) {
			executor =
				new LldbClientThreadExecutor(() -> DebugClient.debugCreate().createClient());
		}
		else {
			// TODO - process args
			executor =
				new LldbClientThreadExecutor(() -> DebugClient.debugCreate().createClient());
			create = false;
		}
		executor.setManager(this);
		AtomicReference<Boolean> creat = new AtomicReference<>(create);
		return sequence(TypeSpec.VOID).then(executor, (seq) -> {
			doExecute(creat.get());
			seq.exit();
		}).finish().exceptionally((exc) -> {
			Msg.error(this, "start failed");
			return null;
		});
	}

	protected void doExecute(Boolean create) {
		DebugClient client = executor.getClient();
		reentrantClient = client;

		status = client.getExecutionStatus();
		client.setOutputCallbacks(new LldbDebugOutputCallbacks(this));
	}

	@Override
	public boolean isRunning() {
		return !executor.isShutdown() && !executor.isTerminated();
	}

	@Override
	public void terminate() {
		executor.execute(100, client -> {
			Msg.debug(this, "Disconnecting DebugClient from session");
			client.endSession(DebugEndSessionFlags.DEBUG_END_DISCONNECT);
			//client.setOutputCallbacks(null);
		});
		executor.shutdown();
		try {
			executor.awaitTermination(5000, TimeUnit.MILLISECONDS);
		}
		catch (InterruptedException e) {
			// Eh, just go on
		}
	}

	@Override
	public void close() throws Exception {
		terminate();
	}

	/**
	 * Schedule a command for execution
	 * 
	 * @param cmd the command to execute
	 * @return the pending command, which acts as a future for later completion
	 */
	//@Override
	@Override
	public <T> CompletableFuture<T> execute(LldbCommand<? extends T> cmd) {
		assert cmd != null;
		LldbPendingCommand<T> pcmd = new LldbPendingCommand<>(cmd);

		if (executor.isCurrentThread()) {
			try {
				addCommand(cmd, pcmd);
			}
			catch (Throwable exc) {
				pcmd.completeExceptionally(exc);
			}
		}
		else {
			CompletableFuture.runAsync(() -> {
				addCommand(cmd, pcmd);
			}, executor).exceptionally((exc) -> {
				pcmd.completeExceptionally(exc);
				return null;
			});
		}
		return pcmd;
	}

	private <T> void addCommand(LldbCommand<? extends T> cmd, LldbPendingCommand<T> pcmd) {
		synchronized (this) {
			if (!cmd.validInState(state.get())) {
				throw new LldbCommandError("Command " + cmd + " is not valid while " + state.get());
			}
			activeCmds.add(pcmd);
		}
		cmd.invoke();
		processEvent(new LldbCommandDoneEvent(cmd));
	}

	@Override
	public DebugStatus processEvent(LldbEvent<?> evt) {
		if (state == null) {
			state.set(StateType.eStateStopped, Causes.UNCLAIMED);
		}
		StateType newState = evt.newState();
		//System.err.println(evt+":"+newState);
		if (newState != null && !(evt instanceof LldbCommandDoneEvent)) {
			Msg.debug(this, evt + " transitions state to " + newState);
			state.set(newState, evt.getCause());
		}

		boolean cmdFinished = false;
		List<LldbPendingCommand<?>> toRemove = new ArrayList<LldbPendingCommand<?>>();
		for (LldbPendingCommand<?> pcmd : activeCmds) {
			cmdFinished = pcmd.handle(evt);
			if (cmdFinished) {
				pcmd.finish();
				toRemove.add(pcmd);
			}
		}
		for (LldbPendingCommand<?> pcmd : toRemove) {
			activeCmds.remove(pcmd);
		}

		synchronized (this) {
			boolean waitState = isWaiting();
			waiting = false;
			DebugStatus ret = evt.isStolen() ? null : handlerMap.handle(evt, null);
			if (ret == null) {
				ret = DebugStatus.NO_CHANGE;
			}
			waiting = ret.equals(DebugStatus.NO_DEBUGGEE) ? false : waitState;
			return ret;
		}
	}

	@Override
	public void addStateListener(LldbStateListener listener) {
		state.addChangeListener(listener);
	}

	@Override
	public void removeStateListener(LldbStateListener listener) {
		state.removeChangeListener(listener);
	}

	public ListenerSet<LldbEventsListener> getEventListeners() {
		return listenersEvent;
	}

	@Override
	public void addEventsListener(LldbEventsListener listener) {
		getEventListeners().add(listener);
	}

	@Override
	public void removeEventsListener(LldbEventsListener listener) {
		getEventListeners().remove(listener);
	}

	private void defaultHandlers() {
		handlerMap.put(LldbBreakpointHitEvent.class, this::processBreakpoint);
		handlerMap.put(LldbExceptionEvent.class, this::processException);
		handlerMap.put(LldbInterruptEvent.class, this::processInterrupt);
		handlerMap.put(LldbThreadCreatedEvent.class, this::processThreadCreated);
		handlerMap.put(LldbThreadReplacedEvent.class, this::processThreadReplaced);
		handlerMap.put(LldbThreadExitedEvent.class, this::processThreadExited);
		handlerMap.put(LldbThreadSelectedEvent.class, this::processThreadSelected);
		handlerMap.put(LldbProcessCreatedEvent.class, this::processProcessCreated);
		handlerMap.put(LldbProcessReplacedEvent.class, this::processProcessReplaced);
		handlerMap.put(LldbProcessExitedEvent.class, this::processProcessExited);
		handlerMap.put(LldbSessionCreatedEvent.class, this::processSessionCreated);
		handlerMap.put(LldbSessionReplacedEvent.class, this::processSessionReplaced);
		handlerMap.put(LldbSessionExitedEvent.class, this::processSessionExited);
		handlerMap.put(LldbProcessSelectedEvent.class, this::processProcessSelected);
		handlerMap.put(LldbSelectedFrameChangedEvent.class, this::processFrameSelected);
		handlerMap.put(LldbModuleLoadedEvent.class, this::processModuleLoaded);
		handlerMap.put(LldbModuleUnloadedEvent.class, this::processModuleUnloaded);
		handlerMap.put(LldbStateChangedEvent.class, this::processStateChanged);
		//handlerMap.put(LldbTargetSelectedEvent.class, this::processSessionSelected);
		handlerMap.put(LldbSystemsEvent.class, this::processSystemsEvent);
		handlerMap.putVoid(LldbCommandDoneEvent.class, this::processDefault);
		handlerMap.putVoid(LldbStoppedEvent.class, this::processDefault);
		handlerMap.putVoid(LldbRunningEvent.class, this::processDefault);
		handlerMap.putVoid(LldbConsoleOutputEvent.class, this::processConsoleOutput);
		handlerMap.putVoid(LldbBreakpointCreatedEvent.class, this::processBreakpointCreated);
		handlerMap.putVoid(LldbBreakpointModifiedEvent.class, this::processBreakpointModified);
		handlerMap.putVoid(LldbBreakpointDeletedEvent.class, this::processBreakpointDeleted);
		handlerMap.putVoid(LldbBreakpointEnabledEvent.class, this::processBreakpointEnabled);
		handlerMap.putVoid(LldbBreakpointDisabledEvent.class, this::processBreakpointDisabled);
		handlerMap.putVoid(LldbBreakpointInvalidatedEvent.class,
			this::processBreakpointInvalidated);
		handlerMap.putVoid(LldbBreakpointLocationsAddedEvent.class,
			this::processBreakpointLocationsAdded);
		handlerMap.putVoid(LldbBreakpointLocationsResolvedEvent.class,
			this::processBreakpointLocationsResolved);
		handlerMap.putVoid(LldbBreakpointLocationsRemovedEvent.class,
			this::processBreakpointLocationsRemoved);
		handlerMap.putVoid(LldbBreakpointAutoContinueChangedEvent.class,
			this::processBreakpointAutoContinueChanged);
		handlerMap.putVoid(LldbBreakpointCommandChangedEvent.class,
			this::processBreakpointCommandChanged);
		handlerMap.putVoid(LldbBreakpointConditionChangedEvent.class,
			this::processBreakpointConditionChanged);
		handlerMap.putVoid(LldbBreakpointConditionChangedEvent.class,
			this::processBreakpointConditionChanged);
		handlerMap.putVoid(LldbBreakpointIgnoreChangedEvent.class,
			this::processBreakpointIgnoreChanged);
		handlerMap.putVoid(LldbBreakpointThreadChangedEvent.class,
			this::processBreakpointThreadChanged);
		handlerMap.putVoid(LldbBreakpointTypeChangedEvent.class,
			this::processBreakpointTypeChanged);
		handlerMap.putVoid(LldbProfileDataEvent.class, this::processDefault);
		handlerMap.putVoid(LldbStructuredDataEvent.class, this::processDefault);
		handlerMap.putVoid(LldbSymbolsLoadedEvent.class, this::processDefault);

		statusMap.put(LldbBreakpointHitEvent.class, DebugStatus.BREAK);
		statusMap.put(LldbExceptionEvent.class, DebugStatus.BREAK);
		statusMap.put(LldbProcessCreatedEvent.class, DebugStatus.BREAK);
		statusMap.put(LldbProcessExitedEvent.class, DebugStatus.NO_DEBUGGEE);
		statusMap.put(LldbStateChangedEvent.class, DebugStatus.NO_CHANGE);
		statusMap.put(LldbStoppedEvent.class, DebugStatus.BREAK);
		statusMap.put(LldbInterruptEvent.class, DebugStatus.BREAK);
	}

	public void updateState(SBEvent event) {
		DebugClientImpl client = (DebugClientImpl) executor.getClient();
		currentProcess = eventProcess = SBProcess.GetProcessFromEvent(event);
		SBTarget candidateSession = SBTarget.GetTargetFromEvent(event);
		if (candidateSession != null && candidateSession.IsValid()) {
			currentSession = eventSession = candidateSession;
		}
		else {
			candidateSession = currentProcess.GetTarget();
			if (candidateSession != null && candidateSession.IsValid()) {
				currentSession = eventSession = candidateSession;
			}
		}
		SBThread candidateThread = SBThread.GetThreadFromEvent(event);
		if (candidateThread != null && candidateThread.IsValid()) {
			currentThread = eventThread = candidateThread;
		}
		else {
			candidateThread = currentProcess.GetSelectedThread();
			if (candidateThread != null && candidateThread.IsValid()) {
				currentThread = eventThread = candidateThread;
			}
		}
		addSessionIfAbsent(eventSession);
		addProcessIfAbsent(eventSession, eventProcess);
		addThreadIfAbsent(eventProcess, eventThread);
		client.translateAndFireEvent(event);
	}

	@Override
	public void updateState(SBProcess process) {
		currentProcess = eventProcess = process;
		if (currentSession == null ||
			!currentSession.IsValid() ||
			!currentSession.equals(process.GetTarget())) {
			SBTarget candidateSession = currentProcess.GetTarget();
			if (candidateSession != null && candidateSession.IsValid()) {
				currentSession = eventSession = candidateSession;
			}
		}
		if (currentThread == null ||
			!currentThread.IsValid() ||
			!currentThread.equals(process.GetSelectedThread())) {
			SBThread candidateThread = currentProcess.GetSelectedThread();
			if (candidateThread != null && candidateThread.IsValid()) {
				currentThread = eventThread = candidateThread;
			}
		}
		addSessionIfAbsent(eventSession);
		addProcessIfAbsent(eventSession, eventProcess);
		addThreadIfAbsent(eventProcess, eventThread);
	}

	/**
	 * Default handler for events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected <T> DebugStatus processDefault(AbstractLldbEvent<T> evt, Void v) {
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processBreakpoint(LldbBreakpointHitEvent evt, Void v) {
		BigInteger id = eventThread.GetStopReasonDataAtIndex(0);
		for (int i = 0; i < currentSession.GetNumBreakpoints(); i++) {
			SBBreakpoint bpt = currentSession.GetBreakpointAtIndex(i);
			if (bpt.IsValid() && (bpt.GetID() == id.intValue())) {
				getEventListeners().fire.breakpointHit(bpt, evt.getCause());
			}
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processException(LldbExceptionEvent evt, Void v) {
		/*
		Integer eventId = updateState(evt);
		
		DebugExceptionRecord64 info = evt.getInfo();
		String key = Integer.toHexString(info.code);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		*/
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processInterrupt(LldbInterruptEvent evt, Void v) {
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadCreated(LldbThreadCreatedEvent evt, Void v) {
		SBThread thread = evt.getInfo().thread;
		getEventListeners().fire.threadCreated(thread, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadReplaced(LldbThreadReplacedEvent evt, Void v) {
		SBThread thread = evt.getInfo().thread;
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadExited(LldbThreadExitedEvent evt, Void v) {
		getEventListeners().fire.threadExited(eventThread, eventProcess, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadSelected(LldbThreadSelectedEvent evt, Void v) {
		currentThread = evt.getThread();
		getEventListeners().fire.threadSelected(currentThread, evt.getFrame(), evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for frame selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processFrameSelected(LldbSelectedFrameChangedEvent evt, Void v) {
		currentThread = evt.getThread();
		getEventListeners().fire.threadSelected(currentThread, evt.getFrame(), evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessCreated(LldbProcessCreatedEvent evt, Void v) {
		DebugProcessInfo info = evt.getInfo();
		SBProcess proc = info.process;
		getEventListeners().fire.processAdded(proc, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.processSelected(proc, evt.getCause());

		SBThread thread = proc.GetSelectedThread();
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process replaced events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessReplaced(LldbProcessReplacedEvent evt, Void v) {
		DebugProcessInfo info = evt.getInfo();
		SBProcess proc = info.process;
		getEventListeners().fire.processReplaced(proc, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.processSelected(proc, evt.getCause());

		SBThread thread = proc.GetSelectedThread();
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessExited(LldbProcessExitedEvent evt, Void v) {
		SBThread thread = getCurrentThread();
		SBProcess process = getCurrentProcess();
		getEventListeners().fire.threadExited(thread, process, evt.getCause());
		getEventListeners().fire.processExited(process, evt.getCause());
		getEventListeners().fire.processRemoved(process.GetProcessID().toString(), evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessSelected(LldbProcessSelectedEvent evt, Void v) {
		currentProcess = evt.getProcess();
		getEventListeners().fire.processSelected(currentProcess, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for session created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSessionCreated(LldbSessionCreatedEvent evt, Void v) {
		DebugSessionInfo info = evt.getInfo();
		getEventListeners().fire.sessionAdded(info.session, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.sessionSelected(info.session, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for session replaced events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSessionReplaced(LldbSessionReplacedEvent evt, Void v) {
		DebugSessionInfo info = evt.getInfo();
		getEventListeners().fire.sessionReplaced(info.session, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.sessionSelected(info.session, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for session exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSessionExited(LldbSessionExitedEvent evt, Void v) {
		removeSession(evt.sessionId, LldbCause.Causes.UNCLAIMED);
		getEventListeners().fire.sessionRemoved(evt.sessionId, evt.getCause());
		getEventListeners().fire.threadExited(eventThread, eventProcess, evt.getCause());
		getEventListeners().fire.processExited(eventProcess, evt.getCause());
		getEventListeners().fire.processRemoved(eventProcess.GetProcessID().toString(),
			evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for module loaded events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processModuleLoaded(LldbModuleLoadedEvent evt, Void v) {
		DebugModuleInfo info = evt.getInfo();
		long n = info.getNumberOfModules();
		SBProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.moduleLoaded(process, info, i, evt.getCause());
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for module unloaded events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processModuleUnloaded(LldbModuleUnloadedEvent evt, Void v) {
		DebugModuleInfo info = evt.getInfo();
		long n = info.getNumberOfModules();
		SBProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.moduleUnloaded(process, info, i, evt.getCause());
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for state changed events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processStateChanged(LldbStateChangedEvent evt, Void v) {
		StateType state = evt.getInfo().state;
		status = DebugStatus.fromArgument(state);

		if (status.equals(DebugStatus.NO_DEBUGGEE)) {
			waiting = false;
			if (state.equals(StateType.eStateExited)) {
				processEvent(new LldbRunningEvent(DebugClient.getId(eventThread)));
				processEvent(new LldbProcessExitedEvent(0));
				processEvent(new LldbSessionExitedEvent(DebugClient.getId(currentSession), 0));
			}
			return DebugStatus.NO_DEBUGGEE;
		}
		if (status.equals(DebugStatus.BREAK)) {
			waiting = false;
			SBProcess process = getCurrentProcess();
			if (process != null) {
				processEvent(new LldbProcessSelectedEvent(process));
				DebugProcessInfo info = evt.getInfo();
				StopReason stopReason = eventThread.GetStopReason();
				if (stopReason.equals(StopReason.eStopReasonThreadExiting)) {
					processEvent(new LldbThreadExitedEvent(0));
				}
				if (stopReason.equals(StopReason.eStopReasonBreakpoint)) {
					processEvent(new LldbBreakpointHitEvent(info));
				}
				if (stopReason.equals(StopReason.eStopReasonWatchpoint)) {
					processEvent(new LldbWatchpointHitEvent(info));
				}
				if (stopReason.equals(StopReason.eStopReasonException)) {
					processEvent(new LldbExceptionEvent(info));
				}
			}
			DebugThreadInfo info = new DebugThreadInfo(eventThread);
			processEvent(new LldbThreadSelectedEvent(info));
			processEvent(new LldbStoppedEvent(DebugClient.getId(eventThread)));
			return DebugStatus.BREAK;
		}
		if (status.equals(DebugStatus.GO)) {
			waiting = true;
			processEvent(new LldbRunningEvent(DebugClient.getId(eventThread)));
			return DebugStatus.GO;
		}

		waiting = false;
		return DebugStatus.NO_CHANGE;
	}

	/**
	 * Handler for session selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSessionSelected(LldbSessionSelectedEvent evt, Void v) {
		SBTarget session = evt.getSession();
		getEventListeners().fire.sessionSelected(session, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for systems events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSystemsEvent(LldbSystemsEvent evt, Void v) {
		return statusMap.get(evt.getClass());
	}

	protected void processConsoleOutput(LldbConsoleOutputEvent evt, Void v) {
		if (evt.getOutput() != null) {
			getEventListeners().fire.consoleOutput(evt.getOutput(), evt.getMask());
		}
	}

	/**
	 * Handler for breakpoint-created event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointCreated(LldbBreakpointCreatedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointCreated(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointModified(LldbBreakpointModifiedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-deleted event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointDeleted(LldbBreakpointDeletedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		doBreakpointDeleted(session, evt.getInfo().id, evt.getCause());
	}

	/**
	 * Handler for breakpoint-enable event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointEnabled(LldbBreakpointEnabledEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		doBreakpointEnabled(session, evt.getInfo().id, evt.getCause());
	}

	/**
	 * Handler for breakpoint-deleted event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointDisabled(LldbBreakpointDisabledEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		doBreakpointDisabled(session, evt.getInfo().id, evt.getCause());
	}

	/**
	 * Handler for breakpoint-invalidated event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointInvalidated(LldbBreakpointInvalidatedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		//TODO: not sure this is the right thing to do
		doBreakpointDisabled(session, evt.getInfo().id, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointLocationsResolved(LldbBreakpointLocationsResolvedEvent evt,
			Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-locations added event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointLocationsAdded(LldbBreakpointLocationsAddedEvent evt,
			Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-locations removed event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointLocationsRemoved(LldbBreakpointLocationsRemovedEvent evt,
			Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointAutoContinueChanged(LldbBreakpointAutoContinueChangedEvent evt,
			Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointCommandChanged(LldbBreakpointCommandChangedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointConditionChanged(LldbBreakpointConditionChangedEvent evt,
			Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointIgnoreChanged(LldbBreakpointIgnoreChangedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointThreadChanged(LldbBreakpointThreadChangedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointTypeChanged(LldbBreakpointTypeChangedEvent evt, Void v) {
		SBTarget session = getCurrentSession();
		Object info = evt.getBreakpointInfo();
		doBreakpointModified(session, info, evt.getCause());
	}

	/**
	 * Fire breakpoint created event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the creation
	 */
	@Internal
	public void doBreakpointCreated(SBTarget session, Object info, LldbCause cause) {
		addKnownBreakpoint(session, info, false);
		getEventListeners().fire.breakpointCreated(info, cause);
	}

	/**
	 * Fire breakpoint modified event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the modification
	 */
	@Internal
	public void doBreakpointModified(SBTarget session, Object info, LldbCause cause) {
		addKnownBreakpoint(session, info, true);
		getEventListeners().fire.breakpointModified(info, cause);
	}

	/**
	 * Fire breakpoint deleted event
	 * 
	 * @param number the deleted breakpoint number
	 * @param cause the cause of the deletion
	 */
	@Internal
	public void doBreakpointDeleted(SBTarget session, String id, LldbCause cause) {
		Object oldInfo = removeKnownBreakpoint(session, id);
		if (oldInfo == null) {
			return;
		}
		getEventListeners().fire.breakpointDeleted(oldInfo, cause);
	}

	protected void doBreakpointModifiedSameLocations(SBTarget session, Object info,
			LldbCause cause) {
		addKnownBreakpoint(session, info, true);
		getEventListeners().fire.breakpointModified(info, cause);
	}

	@Internal
	public void doBreakpointDisabled(SBTarget session, String id, LldbCause cause) {
		Object info = getKnownBreakpoint(session, id);
		if (info == null) {
			return;
		}
		if (info instanceof SBBreakpoint) {
			((SBBreakpoint) info).SetEnabled(false);
		}
		if (info instanceof SBWatchpoint) {
			((SBWatchpoint) info).SetEnabled(false);
		}
		doBreakpointModifiedSameLocations(session, info, cause);
	}

	@Internal
	public void doBreakpointEnabled(SBTarget session, String id, LldbCause cause) {
		Object info = getKnownBreakpoint(session, id);
		if (info == null) {
			return;
		}
		if (info instanceof SBBreakpoint) {
			((SBBreakpoint) info).SetEnabled(true);
		}
		if (info instanceof SBWatchpoint) {
			((SBWatchpoint) info).SetEnabled(true);
		}
		doBreakpointModifiedSameLocations(session, info, cause);
	}

	@Override
	public CompletableFuture<Map<String, SBThread>> listThreads(SBProcess process) {
		return execute(new LldbListThreadsCommand(this, process));
	}

	@Override
	public CompletableFuture<Map<String, SBProcess>> listProcesses(SBTarget session) {
		return execute(new LldbListProcessesCommand(this, session));
	}

	@Override
	public CompletableFuture<List<Pair<String, String>>> listAvailableProcesses() {
		return execute(new LldbListAvailableProcessesCommand(this));
	}

	@Override
	public CompletableFuture<Map<String, SBTarget>> listSessions() {
		return execute(new LldbListSessionsCommand(this));
	}

	@Override
	public CompletableFuture<Map<String, SBFrame>> listStackFrames(SBThread thread) {
		return execute(new LldbListStackFramesCommand(this, thread));
	}

	@Override
	public CompletableFuture<Map<String, SBValue>> listStackFrameRegisterBanks(SBFrame frame) {
		return execute(new LldbListStackFrameRegisterBanksCommand(this, frame));
	}

	@Override
	public CompletableFuture<Map<String, SBValue>> listStackFrameRegisters(SBValue bank) {
		return execute(new LldbListStackFrameRegistersCommand(this, bank));
	}

	@Override
	public CompletableFuture<Map<String, SBModule>> listModules(SBTarget session) {
		return execute(new LldbListModulesCommand(this, session));
	}

	@Override
	public CompletableFuture<Map<String, SBSection>> listModuleSections(SBModule module) {
		return execute(new LldbListModuleSectionsCommand(this, module));
	}

	@Override
	public CompletableFuture<Map<String, SBSymbol>> listModuleSymbols(SBModule module) {
		return execute(new LldbListModuleSymbolsCommand(this, module));
	}

	@Override
	public CompletableFuture<List<SBMemoryRegionInfo>> listMemory(SBProcess process) {
		return execute(new LldbListMemoryRegionsCommand(this, process));
	}

	@Override
	public CompletableFuture<Map<String, String>> listEnvironment(SBTarget session) {
		return execute(new LldbListEnvironmentCommand(this, session));
	}

	@Override
	public void sendInterruptNow() {
		Msg.info(this, "Interrupting");
		currentSession.GetProcess().SendAsyncInterrupt();
	}

	@Override
	public CompletableFuture<SBProcess> addProcess() {
		return execute(new LldbAddProcessCommand(this));
	}

	@Override
	public CompletableFuture<Void> removeProcess(SBProcess process) {
		return execute(new LldbRemoveProcessCommand(this, process.GetTarget(),
			process.GetProcessID().toString()));
	}

	@Override
	public CompletableFuture<SBTarget> addSession() {
		return execute(new LldbAddSessionCommand(this));
	}

	@Override
	public CompletableFuture<?> attach(String pid) {
		return execute(new LldbAttachCommand(this, pid));
	}

	@Override
	public CompletableFuture<?> attach(String name, boolean wait) {
		return execute(new LldbAttachCommand(this, name, wait));
	}

	@Override
	public CompletableFuture<?> attach(String url, boolean wait, boolean async) {
		return execute(new LldbAttachCommand(this, url, wait));
	}

	@Override
	public CompletableFuture<?> launch(String fileName, List<String> args) {
		return execute(new LldbLaunchProcessCommand(this, fileName, args));
	}

	@Override
	public CompletableFuture<?> launch(Map<String, ?> args) {
		return execute(new LldbLaunchProcessWithOptionsCommand(this, args));
	}

	public CompletableFuture<?> openFile(Map<String, ?> args) {
		return execute(new LldbOpenDumpCommand(this, args));
	}

	public CompletableFuture<?> attachKernel(Map<String, ?> args) {
		setKernelMode(true);
		return execute(new LldbAttachKernelCommand(this, args));
	}

	static class ExitEvent {
		final Integer tid;
		final long exitCode;

		public ExitEvent(Integer tid, long exitCode) {
			this.tid = tid;
			this.exitCode = exitCode;
		}
	}

	static class BreakId {
		final Integer tid;
		final int bpid;

		public BreakId(Integer tid, int bpid) {
			this.tid = tid;
			this.bpid = bpid;
		}
	}

	static class BreakpointTag {
		long offset;

		public BreakpointTag(long offset) {
			this.offset = offset;
		}
	}

	class SavedFocus implements AutoCloseable {
		Integer tid = null;

		@Override
		public void close() {
			// Nothing to do
		}
	}

	public DebugClient getClient() {
		return executor.getClient();
	}

	public SBThread getCurrentThread() {
		if (!currentThread.IsValid()) {
			currentProcess = currentSession.GetProcess();
			for (int i = 0; i < currentProcess.GetNumThreads(); i++) {
				SBThread thread = currentProcess.GetThreadAtIndex(i);
				System.err.println(thread + ":" + thread.IsValid());
			}
			currentThread = SBThread.GetThreadFromEvent(currentEvent);
			System.err.println(currentThread.IsValid());
		}
		return currentThread != null ? currentThread : eventThread;
	}

	public void setCurrentThread(SBThread thread) {
		currentThread = thread;
	}

	public SBProcess getCurrentProcess() {
		return currentProcess != null ? currentProcess : eventProcess;
	}

	public SBTarget getCurrentSession() {
		return currentSession != null ? currentSession : eventSession;
	}

	public SBThread getEventThread() {
		return eventThread;
	}

	public SBProcess getEventProcess() {
		return eventProcess;
	}

	public SBTarget getEventSession() {
		return eventSession;
	}

	public CompletableFuture<Void> setActiveFrame(SBThread thread, int index) {
		currentThread = thread;
		return execute(new LldbSetActiveThreadCommand(this, thread, index));
	}

	public CompletableFuture<Void> setActiveThread(SBThread thread) {
		currentThread = thread;
		return execute(new LldbSetActiveThreadCommand(this, thread, -1L));
	}

	public CompletableFuture<Void> setActiveProcess(SBProcess process) {
		currentProcess = process;
		return execute(new LldbSetActiveProcessCommand(this, process));
	}

	public CompletableFuture<Void> setActiveSession(SBTarget session) {
		currentSession = session;
		return execute(new LldbSetActiveSessionCommand(this, session));
	}

	public CompletableFuture<Void> requestFocus(LldbModelTargetFocusScope scope, TargetObject obj) {
		return execute(new LldbRequestFocusCommand(this, scope, obj));
	}

	public CompletableFuture<Void> requestActivation(LldbModelTargetActiveScope activator,
			TargetObject obj) {
		return execute(new LldbRequestActivationCommand(this, activator, obj));
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		if (continuation != null) {
			String prompt = command.equals("") ? LldbModelTargetInterpreter.LLDB_PROMPT : ">>>";
			getEventListeners().fire.promptChanged(prompt);
			continuation.complete(command);
			setContinuation(null);
			return AsyncUtils.NIL;
		}
		return execute(
			new LldbConsoleExecCommand(this, command, LldbConsoleExecCommand.Output.CONSOLE))
					.thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return execute(
			new LldbConsoleExecCommand(this, command, LldbConsoleExecCommand.Output.CAPTURE));
	}

	@Override
	public StateType getState() {
		if (currentProcess == null) {
			return null;
		}
		if (currentThread != null && !currentThread.IsValid()) {
			return StateType.eStateRunning;
		}
		return currentProcess.GetState();
	}

	@Override
	public SBProcess currentProcess() {
		return getCurrentProcess();
	}

	@Override
	public CompletableFuture<Void> waitForEventEx() {
		//System.err.println("ENTER");
		waiting = true;
		SBEvent event = getClient().waitForEvent();
		//System.err.println("EXIT");
		waiting = false;
		updateState(event);
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> waitForPrompt() {
		return CompletableFuture.completedFuture(null);
	}

	public CompletableFuture<? extends Map<String, ?>> getRegisterMap(List<String> path) {
		return null;
	}

	public boolean isWaiting() {
		return waiting;
	}

	public boolean isKernelMode() {
		return kernelMode;
	}

	public void setKernelMode(boolean kernelMode) {
		this.kernelMode = kernelMode;
	}

	public void setContinuation(CompletableFuture<String> continuation) {
		this.continuation = continuation;
	}

	@Override
	public DebugStatus getStatus() {
		return status;
	}

	@Override
	public void setCurrentEvent(SBEvent evt) {
		this.currentEvent = evt;
	}

}
