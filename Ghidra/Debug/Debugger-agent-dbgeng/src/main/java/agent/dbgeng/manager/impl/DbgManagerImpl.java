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
package agent.dbgeng.manager.impl;

import static ghidra.async.AsyncUtils.sequence;

import java.util.ArrayList;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.Pair;

import com.sun.jna.platform.win32.COM.COMException;

import agent.dbgeng.dbgeng.DbgEng;
import agent.dbgeng.dbgeng.DebugAdvanced;
import agent.dbgeng.dbgeng.DebugBreakpoint;
import agent.dbgeng.dbgeng.DebugBreakpoint.BreakFlags;
import agent.dbgeng.dbgeng.DebugBreakpoint.BreakType;
import agent.dbgeng.dbgeng.DebugClient;
import agent.dbgeng.dbgeng.DebugClient.ChangeDebuggeeState;
import agent.dbgeng.dbgeng.DebugClient.ChangeEngineState;
import agent.dbgeng.dbgeng.DebugClient.DebugCreateFlags;
import agent.dbgeng.dbgeng.DebugClient.DebugEndSessionFlags;
import agent.dbgeng.dbgeng.DebugClient.DebugEngCreateFlags;
import agent.dbgeng.dbgeng.DebugClient.DebugStatus;
import agent.dbgeng.dbgeng.DebugClient.DebugVerifierFlags;
import agent.dbgeng.dbgeng.DebugClient.ExecutionState;
import agent.dbgeng.dbgeng.DebugClientReentrant;
import agent.dbgeng.dbgeng.DebugControl;
import agent.dbgeng.dbgeng.DebugControl.DebugInterrupt;
import agent.dbgeng.dbgeng.DebugDataSpaces;
import agent.dbgeng.dbgeng.DebugEventInformation;
import agent.dbgeng.dbgeng.DebugExceptionRecord64;
import agent.dbgeng.dbgeng.DebugModuleInfo;
import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugProcessInfo;
import agent.dbgeng.dbgeng.DebugProcessRecord;
import agent.dbgeng.dbgeng.DebugRegisters;
import agent.dbgeng.dbgeng.DebugSessionId;
import agent.dbgeng.dbgeng.DebugSymbols;
import agent.dbgeng.dbgeng.DebugSystemObjects;
import agent.dbgeng.dbgeng.DebugSystemProcessRecord;
import agent.dbgeng.dbgeng.DebugSystemThreadRecord;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.dbgeng.DebugThreadInfo;
import agent.dbgeng.dbgeng.DebugThreadRecord;
import agent.dbgeng.gadp.impl.AbstractClientThreadExecutor;
import agent.dbgeng.gadp.impl.DbgEngClientThreadExecutor;
import agent.dbgeng.impl.dbgeng.DbgEngUtil;
import agent.dbgeng.jna.dbgeng.WinNTExtra;
import agent.dbgeng.manager.DbgCause;
import agent.dbgeng.manager.DbgCause.Causes;
import agent.dbgeng.manager.DbgCommand;
import agent.dbgeng.manager.DbgEvent;
import agent.dbgeng.manager.DbgEventsListener;
import agent.dbgeng.manager.DbgManager;
import agent.dbgeng.manager.DbgModuleMemory;
import agent.dbgeng.manager.DbgProcess;
import agent.dbgeng.manager.DbgSession;
import agent.dbgeng.manager.DbgState;
import agent.dbgeng.manager.DbgStateListener;
import agent.dbgeng.manager.DbgThread;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.breakpoint.DbgBreakpointType;
import agent.dbgeng.manager.cmd.DbgAddProcessCommand;
import agent.dbgeng.manager.cmd.DbgAddSessionCommand;
import agent.dbgeng.manager.cmd.DbgAttachKernelCommand;
import agent.dbgeng.manager.cmd.DbgCommandError;
import agent.dbgeng.manager.cmd.DbgConsoleExecCommand;
import agent.dbgeng.manager.cmd.DbgDeleteBreakpointsCommand;
import agent.dbgeng.manager.cmd.DbgDisableBreakpointsCommand;
import agent.dbgeng.manager.cmd.DbgEnableBreakpointsCommand;
import agent.dbgeng.manager.cmd.DbgInsertBreakpointCommand;
import agent.dbgeng.manager.cmd.DbgLaunchProcessCommand;
import agent.dbgeng.manager.cmd.DbgListAvailableProcessesCommand;
import agent.dbgeng.manager.cmd.DbgListBreakpointsCommand;
import agent.dbgeng.manager.cmd.DbgListOSMemoryRegionsCommand;
import agent.dbgeng.manager.cmd.DbgListOSProcessesCommand;
import agent.dbgeng.manager.cmd.DbgListOSThreadsCommand;
import agent.dbgeng.manager.cmd.DbgListProcessesCommand;
import agent.dbgeng.manager.cmd.DbgOpenDumpCommand;
import agent.dbgeng.manager.cmd.DbgPendingCommand;
import agent.dbgeng.manager.cmd.DbgRemoveProcessCommand;
import agent.dbgeng.manager.cmd.DbgRemoveSessionCommand;
import agent.dbgeng.manager.cmd.DbgRequestActivationCommand;
import agent.dbgeng.manager.cmd.DbgRequestFocusCommand;
import agent.dbgeng.manager.cmd.DbgResolveProcessCommand;
import agent.dbgeng.manager.cmd.DbgResolveThreadCommand;
import agent.dbgeng.manager.cmd.DbgSetActiveProcessCommand;
import agent.dbgeng.manager.cmd.DbgSetActiveSessionCommand;
import agent.dbgeng.manager.cmd.DbgSetActiveThreadCommand;
import agent.dbgeng.manager.evt.AbstractDbgEvent;
import agent.dbgeng.manager.evt.DbgBreakpointCreatedEvent;
import agent.dbgeng.manager.evt.DbgBreakpointDeletedEvent;
import agent.dbgeng.manager.evt.DbgBreakpointEvent;
import agent.dbgeng.manager.evt.DbgBreakpointModifiedEvent;
import agent.dbgeng.manager.evt.DbgCommandDoneEvent;
import agent.dbgeng.manager.evt.DbgConsoleOutputEvent;
import agent.dbgeng.manager.evt.DbgDebuggeeStateChangeEvent;
import agent.dbgeng.manager.evt.DbgExceptionEvent;
import agent.dbgeng.manager.evt.DbgModuleLoadedEvent;
import agent.dbgeng.manager.evt.DbgModuleUnloadedEvent;
import agent.dbgeng.manager.evt.DbgProcessCreatedEvent;
import agent.dbgeng.manager.evt.DbgProcessExitedEvent;
import agent.dbgeng.manager.evt.DbgProcessSelectedEvent;
import agent.dbgeng.manager.evt.DbgPromptChangedEvent;
import agent.dbgeng.manager.evt.DbgRunningEvent;
import agent.dbgeng.manager.evt.DbgSessionSelectedEvent;
import agent.dbgeng.manager.evt.DbgStateChangedEvent;
import agent.dbgeng.manager.evt.DbgStoppedEvent;
import agent.dbgeng.manager.evt.DbgSystemErrorEvent;
import agent.dbgeng.manager.evt.DbgSystemsEvent;
import agent.dbgeng.manager.evt.DbgThreadCreatedEvent;
import agent.dbgeng.manager.evt.DbgThreadExitedEvent;
import agent.dbgeng.manager.evt.DbgThreadSelectedEvent;
import agent.dbgeng.model.iface1.DbgModelTargetActiveScope;
import agent.dbgeng.model.iface1.DbgModelTargetFocusScope;
import agent.dbgeng.model.iface2.DbgModelTargetObject;
import agent.dbgeng.model.iface2.DbgModelTargetThread;
import ghidra.async.AsyncClaimQueue;
import ghidra.async.AsyncReference;
import ghidra.async.AsyncUtils;
import ghidra.async.TypeSpec;
import ghidra.comm.util.BitmaskSet;
import ghidra.dbg.target.TargetLauncher.CmdLineParser;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.HandlerMap;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public class DbgManagerImpl implements DbgManager {

	private String dbgSrvTransport;

	//private final AsyncClaimQueue<DebugThreadInfo> claimsCreateThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugThreadId> claimsContinueThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugThreadId> claimsStopThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<ExitEvent> claimsExitThread = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugModuleInfo> claimsLoadModule = new AsyncClaimQueue<>();
	private final AsyncClaimQueue<DebugThreadId> claimsBreakpointAdded = new AsyncClaimQueue<>();
	private final AsyncClaimQueue<BreakId> claimsBreakpointRemoved = new AsyncClaimQueue<>();
	//private final AsyncClaimQueue<DebugThreadId> claimsFocusThread = new AsyncClaimQueue<>();

	public DebugStatus status;

	public final Set<DebugStatus> statiAccessible =
		Collections.unmodifiableSet(EnumSet.of(DebugStatus.NO_DEBUGGEE, DebugStatus.BREAK));

	private final Map<Integer, BreakpointTag> breaksById = new LinkedHashMap<>();

	protected AbstractClientThreadExecutor engThread;
	protected DebugClientReentrant reentrantClient;

	private List<DbgPendingCommand<?>> activeCmds = new ArrayList<>();

	protected final Map<DebugSessionId, DbgSessionImpl> sessions = new LinkedHashMap<>();
	protected DbgSessionImpl curSession = null;
	private final Map<DebugSessionId, DbgSession> unmodifiableSessions =
		Collections.unmodifiableMap(sessions);

	protected final Map<DebugProcessId, DbgProcessImpl> processes = new LinkedHashMap<>();
	private final Map<DebugProcessId, DbgProcess> unmodifiableProcesses =
		Collections.unmodifiableMap(processes);

	protected final Map<DebugThreadId, DbgThreadImpl> threads = new LinkedHashMap<>();
	private final Map<DebugThreadId, DbgThread> unmodifiableThreads =
		Collections.unmodifiableMap(threads);

	private final Map<Long, DbgBreakpointInfo> breakpoints = new LinkedHashMap<>();
	private final Map<Long, DbgBreakpointInfo> unmodifiableBreakpoints =
		Collections.unmodifiableMap(breakpoints);

	private final NavigableMap<Long, DbgModuleMemory> memory = new TreeMap<>();
	private final NavigableMap<Long, DbgModuleMemory> unmodifiableMemory =
		Collections.unmodifiableNavigableMap(memory);

	protected final AsyncReference<DbgState, DbgCause> state =
		new AsyncReference<>(DbgState.NOT_STARTED);
	private final HandlerMap<DbgEvent<?>, Void, DebugStatus> handlerMap = new HandlerMap<>();
	private final Map<Class<?>, DebugStatus> statusMap = new LinkedHashMap<>();
	private final Map<String, DebugStatus> statusByNameMap = new LinkedHashMap<>();
	private final ListenerSet<DbgEventsListener> listenersEvent =
		new ListenerSet<>(DbgEventsListener.class);

	private DebugEventInformation lastEventInformation;
	private DbgSession currentSession;
	private DbgProcess currentProcess;
	private DbgThread currentThread;
	private DbgSession eventSession;
	private DbgProcess eventProcess;
	private DbgThread eventThread;
	private volatile boolean waiting = false;
	private boolean kernelMode = false;
	private boolean altMemoryQuery = false;
	private boolean ignoreEventThread = false;
	private CompletableFuture<String> continuation;
	private long processCount = 0;

	/**
	 * Instantiate a new manager
	 */
	public DbgManagerImpl() {
		state.filter(this::stateFilter);
		state.addChangeListener(this::trackRunningInterpreter);
		defaultHandlers();
		//TODO: this.server = createSctlSide(addr);
		//TODO: this.dbgSrvTransport = dbgSrvTransport;
	}

	@Override
	public DbgThreadImpl getThread(DebugThreadId tid) {
		synchronized (threads) {
			return threads.get(tid);
		}
	}

	public DbgThreadImpl getThreadComputeIfAbsent(DebugThreadId id, DbgProcessImpl process,
			long tid, boolean fire) {
		synchronized (threads) {
			if (threads.containsKey(id)) {
				DbgThreadImpl existingThread = threads.get(id);
				return existingThread;
			}
			DbgThreadImpl thread = new DbgThreadImpl(this, process, id, tid);
			thread.add();
			if (fire) {
				Causes cause = DbgCause.Causes.UNCLAIMED;
				getEventListeners().fire.threadCreated(thread, cause);
				getEventListeners().fire.threadSelected(thread, null, cause);
			}
			return threads.get(id);
		}
	}

	/**
	 * Use {@link DbgThreadImpl#remove()} instead
	 * 
	 * @param id the thread ID to remove
	 */
	public void removeThread(DebugThreadId id) {
		synchronized (threads) {
			if (threads.remove(id) == null) {
				throw new IllegalArgumentException("There is no thread with id " + id);
			}
		}
	}

	/**
	 * Use {@link DbgProcessImpl#remove(DbgCause)} instead
	 * 
	 * @param id the process ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeProcess(DebugProcessId id, DbgCause cause) {
		synchronized (processes) {
			DbgProcessImpl proc = processes.remove(id);
			if (proc == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			Set<DebugThreadId> toRemove = new HashSet<>();
			for (DebugThreadId tid : threads.keySet()) {
				DbgThreadImpl thread = threads.get(tid);
				if (thread.getProcess().getId().equals(id)) {
					toRemove.add(tid);
				}
			}
			for (DebugThreadId tid : toRemove) {
				removeThread(tid);
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
	public DbgProcessImpl getProcess(DebugProcessId id) {
		synchronized (processes) {
			DbgProcessImpl result = processes.get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			return result;
		}
	}

	public DbgProcessImpl getProcessComputeIfAbsent(DebugProcessId id, long pid, boolean fire) {
		synchronized (processes) {
			if (processes.containsKey(id)) {
				DbgProcessImpl existingProc = processes.get(id);
				return existingProc;
			}
			DbgProcessImpl process = new DbgProcessImpl(this, id, pid);
			process.add();
			if (fire) {
				getEventListeners().fire.processAdded(process, DbgCause.Causes.UNCLAIMED);
			}
			return processes.get(id);
		}
	}

	/**
	 * Use {@link DbgSessionImpl#remove(DbgCause)} instead
	 * 
	 * @param id the session ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeSession(DebugSessionId id, DbgCause cause) {
		synchronized (sessions) {
			if (sessions.remove(id) == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			getEventListeners().fire.sessionRemoved(id, cause);
		}
	}

	@Override
	public DbgSession getSession(DebugSessionId id) {
		synchronized (sessions) {
			DbgSession result = sessions.get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			return result;
		}
	}

	public DbgSessionImpl getSessionComputeIfAbsent(DebugSessionId id, boolean fire) {
		synchronized (sessions) {
			if (!sessions.containsKey(id) && id.value() >= 0) {
				DbgSessionImpl session = new DbgSessionImpl(this, id);
				session.add();
				if (fire) {
					getEventListeners().fire.sessionAdded(session, DbgCause.Causes.UNCLAIMED);
				}
			}
			return sessions.get(id);
		}
	}

	@Override
	public Map<DebugThreadId, DbgThread> getKnownThreads() {
		return unmodifiableThreads;
	}

	@Override
	public Map<DebugProcessId, DbgProcess> getKnownProcesses() {
		return unmodifiableProcesses;
	}

	@Override
	public Map<DebugSessionId, DbgSession> getKnownSessions() {
		return unmodifiableSessions;
	}

	@Override
	public Map<Long, DbgBreakpointInfo> getKnownBreakpoints() {
		return unmodifiableBreakpoints;
	}

	@Override
	public Map<Long, DbgModuleMemory> getKnownMemoryRegions() {
		return unmodifiableMemory;
	}

	private DbgBreakpointInfo addKnownBreakpoint(DbgBreakpointInfo bkpt, boolean expectExisting) {
		DbgBreakpointInfo old = breakpoints.put(bkpt.getNumber(), bkpt);
		if (expectExisting && old == null) {
			Msg.warn(this, "Breakpoint " + bkpt.getNumber() + " is not known");
		}
		else if (!expectExisting && old != null) {
			Msg.warn(this, "Breakpoint " + bkpt.getNumber() + " is already known");
		}
		return old;
	}

	private DbgBreakpointInfo getKnownBreakpoint(long number) {
		DbgBreakpointInfo info = breakpoints.get(number);
		if (info == null) {
			Msg.warn(this, "Breakpoint " + number + " is not known");
		}
		return info;
	}

	private DbgBreakpointInfo removeKnownBreakpoint(long number) {
		DbgBreakpointInfo del = breakpoints.remove(number);
		if (del == null) {
			Msg.warn(this, "Breakpoint " + number + " is not known");
		}
		return del;
	}

	@Override
	public CompletableFuture<DbgBreakpointInfo> insertBreakpoint(String loc,
			DbgBreakpointType type) {
		return execute(new DbgInsertBreakpointCommand(this, loc, type));
	}

	@Override
	public CompletableFuture<DbgBreakpointInfo> insertBreakpoint(long loc, int len,
			DbgBreakpointType type) {
		return execute(new DbgInsertBreakpointCommand(this, loc, len, type));
	}

	@Override
	public CompletableFuture<Void> disableBreakpoints(long... numbers) {
		return execute(new DbgDisableBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Void> enableBreakpoints(long... numbers) {
		return execute(new DbgEnableBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Void> deleteBreakpoints(long... numbers) {
		return execute(new DbgDeleteBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Map<Long, DbgBreakpointInfo>> listBreakpoints() {
		return execute(new DbgListBreakpointsCommand(this));
	}

	private void checkStarted() {
		if (state.get() == DbgState.NOT_STARTED) {
			throw new IllegalStateException(
				"dbgeng has not been started or has not finished starting");
		}
	}

	@Override
	public CompletableFuture<Void> start(String[] args) {
		state.set(DbgState.STARTING, Causes.UNCLAIMED);
		boolean create = true;
		if (args.length == 0) {
			engThread = new DbgEngClientThreadExecutor(() -> DbgEng.debugCreate().createClient());
		}
		else {
			String remoteOptions = String.join(" ", args);
			engThread = new DbgEngClientThreadExecutor(
				() -> DbgEng.debugConnect(remoteOptions).createClient());
			create = false;
		}
		engThread.setManager(this);
		AtomicReference<Boolean> creat = new AtomicReference<>(create);
		return sequence(TypeSpec.VOID).then(engThread, (seq) -> {
			doExecute(creat.get());
			seq.exit();
		}).finish().exceptionally((exc) -> {
			Msg.error(this, "start failed");
			return null;
		});
	}

	protected void doExecute(Boolean create) {
		DebugClient dbgeng = engThread.getClient();
		reentrantClient = dbgeng;

		status = dbgeng.getControl().getExecutionStatus();
		// Take control of the session.
		// Helps if the JVM is using it for SA, or when starting a new server during testing.
		if (create) {
			dbgeng.endSession(DebugEndSessionFlags.DEBUG_END_ACTIVE_TERMINATE);
		}

		status = dbgeng.getControl().getExecutionStatus();
		dbgeng.setOutputCallbacks(new DbgDebugOutputCallbacks(this));
		dbgeng.setEventCallbacks(new DbgDebugEventCallbacksAdapter(this));
		dbgeng.setInputCallbacks(new DbgDebugInputCallbacks(this));
		dbgeng.flushCallbacks();

		if (!create) {
			dbgeng.connectSession(0);
		}

		if (dbgSrvTransport != null && !"none".equalsIgnoreCase(dbgSrvTransport)) {
			dbgeng.startServer(dbgSrvTransport);
		}
	}

	@Override
	public boolean isRunning() {
		return !engThread.isShutdown() && !engThread.isTerminated();
	}

	@Override
	public void terminate() {
		//TODO: server.terminate();
		engThread.execute(100, dbgeng -> {
			Msg.debug(this, "Disconnecting DebugClient from session");
			dbgeng.endSession(DebugEndSessionFlags.DEBUG_END_PASSIVE);
			dbgeng.setOutputCallbacks(null);
			dbgeng.setEventCallbacks(null);
			dbgeng.setInputCallbacks(null);
			engThread.shutdown();
		});
		try {
			engThread.awaitTermination(5000, TimeUnit.MILLISECONDS);
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
	public <T> CompletableFuture<T> execute(DbgCommand<? extends T> cmd) {
		assert cmd != null;
		checkStarted();
		DbgPendingCommand<T> pcmd = new DbgPendingCommand<>(cmd);
		//if (isWaiting()) {
		//	throw new DebuggerModelAccessException(
		//		"Cannot process command " + cmd.toString() + " while engine is waiting for events");
		//}

		if (engThread.isCurrentThread()) {
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
			}, engThread).exceptionally((exc) -> {
				pcmd.completeExceptionally(exc);
				return null;
			});
		}
		return pcmd;
	}
	
	private <T> void addCommand(DbgCommand<? extends T> cmd, DbgPendingCommand<T> pcmd) {
		synchronized (this) {
			if (!cmd.validInState(state.get())) {
				throw new DbgCommandError("Command " + cmd + " is not valid while " + state.get());
			}
			activeCmds.add(pcmd);
		}
		cmd.invoke();
		processEvent(new DbgCommandDoneEvent(cmd));
	}

	public DebugStatus processEvent(DbgEvent<?> evt) {
		if (state.get() == DbgState.STARTING) {
			state.set(DbgState.STOPPED, Causes.UNCLAIMED);
		}
		DbgState newState = evt.newState();
		if (newState != null && !(evt instanceof DbgCommandDoneEvent)) {
			Msg.debug(this, evt + " transitions state to " + newState);
			state.set(newState, evt.getCause());
		}

		boolean cmdFinished = false;
		List<DbgPendingCommand<?>> toRemove = new ArrayList<DbgPendingCommand<?>>();
		for (DbgPendingCommand<?> pcmd : activeCmds) {
			cmdFinished = pcmd.handle(evt);
			if (cmdFinished) {
				pcmd.finish();
				toRemove.add(pcmd);
			}
		}
		for (DbgPendingCommand<?> pcmd : toRemove) {
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
	public void addStateListener(DbgStateListener listener) {
		state.addChangeListener(listener);
	}

	@Override
	public void removeStateListener(DbgStateListener listener) {
		state.removeChangeListener(listener);
	}

	public ListenerSet<DbgEventsListener> getEventListeners() {
		return listenersEvent;
	}

	@Override
	public void addEventsListener(DbgEventsListener listener) {
		getEventListeners().add(listener);
	}

	@Override
	public void removeEventsListener(DbgEventsListener listener) {
		getEventListeners().remove(listener);
	}

	private DbgState stateFilter(DbgState cur, DbgState set, DbgCause cause) {
		if (set == null) {
			return cur;
		}
		return set;
	}

	private void trackRunningInterpreter(DbgState oldSt, DbgState st, DbgCause cause) {
		if (st == DbgState.RUNNING && cause instanceof DbgPendingCommand) {
			DbgPendingCommand<?> pcmd = (DbgPendingCommand<?>) cause;
			DbgCommand<?> command = pcmd.getCommand();
			Msg.debug(this, "Entered " + st + " from " + command);
		}
	}

	private void defaultHandlers() {
		handlerMap.put(DbgBreakpointEvent.class, this::processBreakpoint);
		handlerMap.put(DbgExceptionEvent.class, this::processException);
		handlerMap.put(DbgThreadCreatedEvent.class, this::processThreadCreated);
		handlerMap.put(DbgThreadExitedEvent.class, this::processThreadExited);
		handlerMap.put(DbgThreadSelectedEvent.class, this::processThreadSelected);
		handlerMap.put(DbgProcessCreatedEvent.class, this::processProcessCreated);
		handlerMap.put(DbgProcessExitedEvent.class, this::processProcessExited);
		handlerMap.put(DbgProcessSelectedEvent.class, this::processProcessSelected);
		handlerMap.put(DbgModuleLoadedEvent.class, this::processModuleLoaded);
		handlerMap.put(DbgModuleUnloadedEvent.class, this::processModuleUnloaded);
		handlerMap.put(DbgStateChangedEvent.class, this::processStateChanged);
		handlerMap.put(DbgSessionSelectedEvent.class, this::processSessionSelected);
		handlerMap.put(DbgSystemsEvent.class, this::processSystemsEvent);
		handlerMap.putVoid(DbgDebuggeeStateChangeEvent.class, this::processDebuggeeStateChanged);
		handlerMap.putVoid(DbgSystemErrorEvent.class, this::processSystemErrorEvent);
		handlerMap.putVoid(DbgCommandDoneEvent.class, this::processDefault);
		handlerMap.putVoid(DbgStoppedEvent.class, this::processDefault);
		handlerMap.putVoid(DbgRunningEvent.class, this::processDefault);
		handlerMap.putVoid(DbgConsoleOutputEvent.class, this::processConsoleOutput);
		handlerMap.putVoid(DbgPromptChangedEvent.class, this::processPromptChanged);
		handlerMap.putVoid(DbgBreakpointCreatedEvent.class, this::processBreakpointCreated);
		handlerMap.putVoid(DbgBreakpointModifiedEvent.class, this::processBreakpointModified);
		handlerMap.putVoid(DbgBreakpointDeletedEvent.class, this::processBreakpointDeleted);

		statusMap.put(DbgBreakpointEvent.class, DebugStatus.BREAK);
		statusMap.put(DbgExceptionEvent.class, DebugStatus.NO_CHANGE);
		statusMap.put(DbgProcessCreatedEvent.class, DebugStatus.BREAK);
		statusMap.put(DbgStateChangedEvent.class, DebugStatus.NO_CHANGE);
		statusMap.put(DbgStoppedEvent.class, DebugStatus.BREAK);
	}

	private DebugThreadId updateState() {
		DebugClient dbgeng = engThread.getClient();
		DebugSystemObjects so = dbgeng.getSystemObjects();
		DebugThreadId etid = so.getEventThread();
		DebugProcessId epid = so.getEventProcess();
		DebugSessionId esid = so.getCurrentSystemId();
		
		DebugControl control = dbgeng.getControl();
		int execType = WinNTExtra.Machine.IMAGE_FILE_MACHINE_AMD64.val;
		try {
			//so.setCurrentProcessId(epid);
			//so.setCurrentThreadId(etid);
			execType = control.getExecutingProcessorType();
		}
		catch (Exception e) {
			// Ignore for now
		}

		lastEventInformation = control.getLastEventInformation();
		lastEventInformation.setSession(esid);
		lastEventInformation.setExecutingProcessorType(execType);
		updateStateFromSystemObject(etid, epid, esid);
		if (eventThread != null) {
			((DbgThreadImpl) eventThread).setInfo(lastEventInformation);
		}
		return currentThread == null ? new DebugThreadRecord(-1) : currentThread.getId();
	}

	/**
	 * Default handler for events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected <T> DebugStatus processDefault(AbstractDbgEvent<T> evt, Void v) {
		//updateState();
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processBreakpoint(DbgBreakpointEvent evt, Void v) {
		updateState();

		DebugBreakpoint bp = evt.getInfo();
		DbgBreakpointInfo info = new DbgBreakpointInfo(bp, getEventProcess(), getEventThread());
		getEventListeners().fire.threadSelected(eventThread, null, evt.getCause());
		getEventListeners().fire.breakpointHit(info, evt.getCause());

		String key = Integer.toHexString(bp.getId());
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
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
	protected DebugStatus processException(DbgExceptionEvent evt, Void v) {
		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.threadSelected(eventThread, null, evt.getCause());

		DebugExceptionRecord64 info = evt.getInfo();
		String key = Integer.toHexString(info.code);
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadCreated(DbgThreadCreatedEvent evt, Void v) {
		DebugThreadId eventId = updateState();
		DbgProcessImpl process = getCurrentProcess();
		DbgThreadImpl thread = getThreadFromDebugProcessInfo(process, evt.getInfo());

		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.threadCreated(thread, DbgCause.Causes.UNCLAIMED);
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());

		String key = eventId.id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadExited(DbgThreadExitedEvent evt, Void v) {
		DebugThreadId eventId = updateState();
		DbgProcessImpl process = getCurrentProcess();
		DbgThreadImpl thread = getCurrentThread();
		if (thread != null) {
			thread.remove();
		}
		process.threadExited(eventId);
		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.threadExited(eventId, process, evt.getCause());

		String key = eventId.id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadSelected(DbgThreadSelectedEvent evt, Void v) {
		if (evt.getState() == DbgState.RUNNING) {
			currentThread = evt.getThread();
			currentThread.setState(evt.getState(), evt.getCause(), evt.getReason());
			return statusMap.get(evt.getClass());
		}
		DebugThreadId eventId = updateState();

		//currentThread = evt.getThread();
		currentThread.setState(evt.getState(), evt.getCause(), evt.getReason());
		getEventListeners().fire.threadSelected(currentThread, evt.getFrame(), evt.getCause());

		String key = eventId.id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessCreated(DbgProcessCreatedEvent evt, Void v) {
		DebugProcessInfo info = evt.getInfo();
		DbgProcessImpl proc = getProcessFromDebugProcessInfo(info);
		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.processAdded(proc, evt.getCause());
		getEventListeners().fire.processSelected(proc, evt.getCause());

		getThreadFromDebugProcessInfo(proc, info.initialThreadInfo);
		//getEventListeners().fire.threadCreated(thread, evt.getCause());
		//getEventListeners().fire.threadSelected(thread, null, evt.getCause());

		//proc.moduleLoaded(info.moduleInfo);
		//getEventListeners().fire.moduleLoaded(proc, info.moduleInfo, evt.getCause());

		String key = proc.getId().id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessExited(DbgProcessExitedEvent evt, Void v) {
		DebugThreadId eventId = updateState();
		DbgThreadImpl thread = getCurrentThread();
		DbgProcessImpl process = getCurrentProcess();
		process.setExitCode(Long.valueOf(evt.getInfo()));

		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.threadExited(eventId, process, evt.getCause());
		getEventListeners().fire.processExited(process, evt.getCause());

		for (DebugBreakpoint bpt : getBreakpoints()) {
			breaksById.remove(bpt.getId());
		}
		if (thread != null) {
			thread.remove();
		}
		process.remove(evt.getCause());
		getEventListeners().fire.processRemoved(process.getId(), evt.getCause());

		String key = process.getId().id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessSelected(DbgProcessSelectedEvent evt, Void v) {
		DebugThreadId eventId = updateState();

		currentProcess = evt.getProcess();
		getEventListeners().fire.processSelected(currentProcess, evt.getCause());

		String key = eventId.id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for module loaded events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processModuleLoaded(DbgModuleLoadedEvent evt, Void v) {
		updateState();
		DbgProcessImpl process = getCurrentProcess();
		DebugModuleInfo info = evt.getInfo();
		process.moduleLoaded(info);
		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.moduleLoaded(process, info, evt.getCause());

		String key = info.getModuleName();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
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
	protected DebugStatus processModuleUnloaded(DbgModuleUnloadedEvent evt, Void v) {
		updateState();
		DbgProcessImpl process = getCurrentProcess();
		DebugModuleInfo info = evt.getInfo();
		process.moduleUnloaded(info);
		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.moduleUnloaded(process, info, evt.getCause());

		String key = info.getModuleName();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
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
	protected DebugStatus processStateChanged(DbgStateChangedEvent evt, Void v) {
		BitmaskSet<ChangeEngineState> flags = evt.getInfo();
		long argument = evt.getArgument();
		if (flags.contains(ChangeEngineState.EXECUTION_STATUS)) {
			if (DebugStatus.isInsideWait(argument)) {
				return DebugStatus.NO_CHANGE;
			}
			status = DebugStatus.fromArgument(argument);

			if (status.equals(DebugStatus.NO_DEBUGGEE)) {
				waiting = false;
				return DebugStatus.NO_DEBUGGEE;
			}
			if (!threads.isEmpty()) {
				//DbgSessionImpl session = getCurrentSession();
				//DbgProcessImpl process = getCurrentProcess();
				eventThread = getCurrentThread();
				DbgState dbgState = null;
				if (eventThread != null) {
					if (status.threadState.equals(ExecutionState.STOPPED)) {
						dbgState = DbgState.STOPPED;
						//System.err.println("STOPPED " + id);
						processEvent(new DbgStoppedEvent(eventThread.getId()));
						processEvent(new DbgPromptChangedEvent(getControl().getPromptText()));
					}
					if (status.threadState.equals(ExecutionState.RUNNING)) {
						//System.err.println("RUNNING " + id);
						dbgState = DbgState.RUNNING;
						// NB: Needed by GADP variants, but not IN-VM
						getEventListeners().fire.memoryChanged(currentProcess, 0L, 0,
							evt.getCause());
						processEvent(new DbgRunningEvent(eventThread.getId()));
					}
					if (!threads.containsValue(eventThread)) {
						dbgState = DbgState.EXIT;
					}
					// Don't fire 
					if (dbgState != null && dbgState != DbgState.EXIT) {
						processEvent(new DbgThreadSelectedEvent(dbgState, eventThread,
							evt.getFrame(eventThread)));
					}
					return DebugStatus.NO_CHANGE;
				}
			}
			if (status.equals(DebugStatus.BREAK)) {
				waiting = false;
				processEvent(new DbgStoppedEvent(getSystemObjects().getCurrentThreadId()));
				DbgProcessImpl process = getCurrentProcess();
				if (process != null) {
					processEvent(new DbgProcessSelectedEvent(process));
				}
				processEvent(new DbgPromptChangedEvent(getControl().getPromptText()));
				return DebugStatus.BREAK;
			}
			if (status.equals(DebugStatus.GO)) {
				waiting = true;
				processEvent(new DbgRunningEvent(getSystemObjects().getCurrentThreadId()));
				return DebugStatus.GO;
			}
			waiting = false;
			return DebugStatus.NO_CHANGE;
		}
		if (flags.contains(ChangeEngineState.BREAKPOINTS)) {
			long bptId = evt.getArgument();
			//System.err.println("BPT: " + bptId + ":" + flags + ":" + argument);
			processEvent(new DbgBreakpointModifiedEvent(bptId));
		}
		if (flags.contains(ChangeEngineState.CURRENT_THREAD)) {
			long id = evt.getArgument();
			for (DebugThreadId key : getThreads()) {
				if (key.value() == id) {
					DbgThread thread = getThread(key);
					if (thread != null) {
						getEventListeners().fire.threadSelected(thread, null, evt.getCause());
					}
					processEvent(new DbgPromptChangedEvent(getControl().getPromptText()));
					break;
				}
			}
		}
		if (flags.contains(ChangeEngineState.SYSTEMS)) {
			processEvent(new DbgSystemsEvent(argument));
		}
		return DebugStatus.NO_CHANGE;
	}

	/**
	 * Handler for session selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSessionSelected(DbgSessionSelectedEvent evt, Void v) {
		DebugThreadId eventId = updateState();

		currentSession = evt.getSession();
		getEventListeners().fire.sessionSelected(currentSession, evt.getCause());

		String key = eventId.id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for systems events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processSystemsEvent(DbgSystemsEvent evt, Void v) {

		waiting = true;

		Long info = evt.getInfo();
		if (info.intValue() >= 0) {
			processCount++;
		}
		else {
			processCount--;
		}
		DebugProcessId id = new DebugProcessRecord(info.intValue());

		String key = id.id();
		if (statusByNameMap.containsKey(key)) {
			return statusByNameMap.get(key);
		}
		return statusMap.get(evt.getClass());
	}

	protected void processDebuggeeStateChanged(DbgDebuggeeStateChangeEvent evt, Void v) {
		if (evt.getFlags().contains(ChangeDebuggeeState.DATA)) {
			getEventListeners().fire.memoryChanged(currentProcess, 0L, 0, evt.getCause());
		}
	}

	protected void processSystemErrorEvent(DbgSystemErrorEvent evt, Void v) {
		getEventListeners().fire.eventSelected(evt, evt.getCause());
		String error = "SystemError " + evt.getError() + ":" + evt.getLevel();
		getEventListeners().fire.consoleOutput(error, 0);
	}

	protected void processConsoleOutput(DbgConsoleOutputEvent evt, Void v) {
		getEventListeners().fire.eventSelected(evt, evt.getCause());
		getEventListeners().fire.consoleOutput(evt.getInfo(), evt.getMask());
	}

	protected void processPromptChanged(DbgPromptChangedEvent evt, Void v) {
		getEventListeners().fire.promptChanged(evt.getPrompt());
	}

	/**
	 * Handler for breakpoint-created event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointCreated(DbgBreakpointCreatedEvent evt, Void v) {
		doBreakpointCreated(evt.getBreakpointInfo(), evt.getCause());
	}

	/**
	 * Handler for breakpoint-modified event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointModified(DbgBreakpointModifiedEvent evt, Void v) {
		DbgBreakpointInfo breakpointInfo = evt.getBreakpointInfo();
		if (breakpointInfo == null) {
			long bptId = evt.getId();
			if (bptId == DbgEngUtil.DEBUG_ANY_ID.longValue()) {
				changeBreakpoints();
				for (DbgBreakpointInfo bptInfo : breakpoints.values()) {
					if (bptInfo.getProc().equals(currentProcess)) {
						doBreakpointDeleted(bptInfo.getNumber(), evt.getCause());
					}
				}
			}
			else {
				DebugBreakpoint bpt = getControl().getBreakpointById((int) bptId);
				if (bpt == null && bptId != DbgEngUtil.DEBUG_ANY_ID.longValue()) {
					doBreakpointDeleted(bptId, evt.getCause());
					return;
				}
				DbgBreakpointInfo knownBreakpoint = breakpoints.get(bptId);
				if (knownBreakpoint == null) {
					breakpointInfo = new DbgBreakpointInfo(bpt, getCurrentProcess());
					if (breakpointInfo.getOffset() != null) {
						addKnownBreakpoint(breakpointInfo, false);
						// NB: we don't want to create this here as the address is 0s
						//doBreakpointCreated(breakpointInfo, evt.getCause());
					}
					return;
				}
				breakpointInfo = knownBreakpoint;
				Long initOffset = breakpointInfo.getOffset();
				breakpointInfo.setBreakpoint(bpt);
				if (!breakpointInfo.getOffset().equals(0L)) {
					if (initOffset.equals(0L)) {
						doBreakpointCreated(breakpointInfo, evt.getCause());
					}
					else {
						doBreakpointModified(breakpointInfo, evt.getCause());
					}
				}
			}
		}
	}

	/**
	 * Handler for breakpoint-deleted event
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointDeleted(DbgBreakpointDeletedEvent evt, Void v) {
		doBreakpointDeleted(evt.getNumber(), evt.getCause());
	}

	/**
	 * Fire breakpoint created event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the creation
	 */
	@Internal
	public void doBreakpointCreated(DbgBreakpointInfo newInfo, DbgCause cause) {
		addKnownBreakpoint(newInfo, true);
		getEventListeners().fire.breakpointCreated(newInfo, cause);
	}

	/**
	 * Fire breakpoint modified event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the modification
	 */
	@Internal
	public void doBreakpointModified(DbgBreakpointInfo newInfo, DbgCause cause) {
		DbgBreakpointInfo oldInfo = addKnownBreakpoint(newInfo, true);
		getEventListeners().fire.breakpointModified(newInfo, oldInfo, cause);
	}

	/**
	 * Fire breakpoint deleted event
	 * 
	 * @param number the deleted breakpoint number
	 * @param cause the cause of the deletion
	 */
	@Internal
	public void doBreakpointDeleted(long number, DbgCause cause) {
		DbgBreakpointInfo oldInfo = removeKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		getEventListeners().fire.breakpointDeleted(oldInfo, cause);
		oldInfo.dispose();
	}

	protected void doBreakpointModifiedSameLocations(DbgBreakpointInfo newInfo,
			DbgBreakpointInfo oldInfo, DbgCause cause) {
		if (Objects.equals(newInfo, oldInfo)) {
			return;
		}
		getEventListeners().fire.breakpointModified(newInfo, oldInfo, cause);
	}

	@Internal
	public void doBreakpointDisabled(long number, DbgCause cause) {
		DbgBreakpointInfo oldInfo = getKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		DbgBreakpointInfo newInfo = oldInfo.withEnabled(false);
		doBreakpointModifiedSameLocations(newInfo, oldInfo, cause);
	}

	@Internal
	public void doBreakpointEnabled(long number, DbgCause cause) {
		DbgBreakpointInfo oldInfo = getKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		DbgBreakpointInfo newInfo = oldInfo.withEnabled(true);
		doBreakpointModifiedSameLocations(newInfo, oldInfo, cause);
	}

	private long orZero(Long l) {
		if (l == null) {
			return 0;
		}
		return l;
	}

	private void changeBreakpoints() {
		Set<Integer> retained = new HashSet<>();
		DebugSystemObjects so = getSystemObjects();
		try (SavedFocus focus = new SavedFocus(so)) {
			for (DebugProcessId pid : so.getProcesses()) {
				try {
					Msg.debug(this, "BREAKPOINTS: Changing current process to " + pid);
					so.setCurrentProcessId(pid);
				}
				catch (COMException e) {
					Msg.debug(this, e.getMessage());
					continue;
				}
				List<DebugThreadId> tids = so.getThreads();
				for (DebugBreakpoint bpt : getControl().getBreakpoints()) {
					BitmaskSet<BreakFlags> f = bpt.getFlags();
					if (!f.contains((BreakFlags.ENABLED)) || f.contains(BreakFlags.DEFERRED)) {
						continue;
					}
					if (bpt.getType().breakType != BreakType.CODE) {
						continue; // TODO: Extend SCTL to handle R/W breakpoints
					}
					int id = bpt.getId();
					retained.add(id);
					long newOffset = orZero(bpt.getOffset());
					BreakpointTag tag = breaksById.get(id);
					if (tag == null) {
						for (DebugThreadId tid : tids) {
							Msg.debug(this, "TRAP Added: " + id + " on " + tid);
							if (claimsBreakpointAdded.satisfy(tid)) {
								Msg.debug(this, "  claimed");
							}
							breaksById.put(id, new BreakpointTag(newOffset));
						}
					}
					else if (tag.offset != newOffset) {
						tag.offset = newOffset;
					} // else the breakpoint is unchanged
				}
				Iterator<Integer> it = breaksById.keySet().iterator();
				while (it.hasNext()) {
					int id = it.next();
					if (retained.contains(id)) {
						continue;
					}
					for (DebugThreadId tid : tids) {
						Msg.debug(this, "TRAP Removed: " + id + " on " + tid);
						if (claimsBreakpointRemoved.satisfy(new BreakId(tid, id))) {
							Msg.debug(this, "  claimed");
						}
					}
					it.remove();
				}
			}
		}
		catch (COMException e) {
			Msg.error(this, "Error retrieving processes: " + e);
		}
	}

	@Override
	public CompletableFuture<Map<DebugProcessId, DbgProcess>> listProcesses() {
		return execute(new DbgListProcessesCommand(this));
	}

	@Override
	public CompletableFuture<Map<DebugProcessId, DbgProcess>> listOSProcesses() {
		return execute(new DbgListOSProcessesCommand(this));
	}

	@Override
	public CompletableFuture<List<DbgModuleMemory>> listOSMemory() {
		return execute(new DbgListOSMemoryRegionsCommand(this));
	}

	@Override
	public CompletableFuture<Map<DebugThreadId, DbgThread>> listOSThreads(DbgProcessImpl proc) {
		return execute(new DbgListOSThreadsCommand(this, proc));
	}

	@Override
	public CompletableFuture<List<Pair<Integer, String>>> listAvailableProcesses() {
		return execute(new DbgListAvailableProcessesCommand(this));
	}

	@Override
	public CompletableFuture<Map<String, DbgSession>> listSessions() {
		return CompletableFuture.completedFuture(null);
		///return execute(new DbgListSessionsCommand(this));
	}

	@Override
	public void sendInterruptNow() {
		checkStarted();
		Msg.info(this, "Interrupting");
		// NB: don't use "execute" here - engThread is paused on waitForEvents
		//  and execute::sequence blocks on engThread 
		reentrantClient.getControl().setInterrupt(DebugInterrupt.ACTIVE);
	}

	@Override
	public CompletableFuture<DbgProcess> addProcess() {
		return execute(new DbgAddProcessCommand(this));
	}

	@Override
	public CompletableFuture<Void> removeProcess(DbgProcess process) {
		return execute(new DbgRemoveProcessCommand(this, process.getId()));
	}

	@Override
	public CompletableFuture<DbgSession> addSession() {
		return execute(new DbgAddSessionCommand(this));
	}

	@Override
	public CompletableFuture<Void> removeSession(DbgSession session) {
		return execute(new DbgRemoveSessionCommand(this, session.getId()));
	}

	@Override
	public CompletableFuture<Void> addMemory(DbgModuleMemory region) {
		memory.put(region.getId(), region);
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<Void> removeMemory(Long id) {
		memory.remove(id);
		return AsyncUtils.NIL;
	}

	@Override
	public CompletableFuture<?> launch(List<String> args) {
		BitmaskSet<DebugCreateFlags> cf = BitmaskSet.of(DebugCreateFlags.DEBUG_PROCESS);
		BitmaskSet<DebugEngCreateFlags> ef =
			BitmaskSet.of(DebugEngCreateFlags.DEBUG_ECREATE_PROCESS_DEFAULT);
		BitmaskSet<DebugVerifierFlags> vf =
			BitmaskSet.of(DebugVerifierFlags.DEBUG_VERIFIER_DEFAULT);
		return execute(new DbgLaunchProcessCommand(this, args,
			null, null, cf, ef, vf));
	}

	@Override
	public CompletableFuture<Void> launch(Map<String, ?> map) {
		List<String> args =
			CmdLineParser.tokenize(TargetCmdLineLauncher.PARAMETER_CMDLINE_ARGS.get(map));
		String initDir = (String) map.get("dir");
		String env = (String) map.get("env");

		Integer cfVal = (Integer) map.get("cf");
		Integer efVal = (Integer) map.get("ef");
		Integer vfVal = (Integer) map.get("vf");
		BitmaskSet<DebugCreateFlags> cf =
			new BitmaskSet<DebugCreateFlags>(DebugCreateFlags.class,
				cfVal == null ? 1 : cfVal);
		BitmaskSet<DebugEngCreateFlags> ef =
			new BitmaskSet<DebugEngCreateFlags>(DebugEngCreateFlags.class,
				efVal == null ? 0 : efVal);
		BitmaskSet<DebugVerifierFlags> vf =
			new BitmaskSet<DebugVerifierFlags>(DebugVerifierFlags.class,
				vfVal == null ? 0 : vfVal);
		return execute(new DbgLaunchProcessCommand(this, args,
			initDir, env, cf, ef, vf)).thenApply(__ -> null);
	}

	public CompletableFuture<?> openFile(Map<String, ?> args) {
		return execute(new DbgOpenDumpCommand(this, args));
	}

	public CompletableFuture<?> attachKernel(Map<String, ?> args) {
		setKernelMode(true);
		return execute(new DbgAttachKernelCommand(this, args));
	}

	static class ExitEvent {
		final DebugThreadId tid;
		final long exitCode;

		public ExitEvent(DebugThreadId tid, long exitCode) {
			this.tid = tid;
			this.exitCode = exitCode;
		}
	}

	static class BreakId {
		final DebugThreadId tid;
		final int bpid;

		public BreakId(DebugThreadId tid, int bpid) {
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
		final DebugSystemObjects so;
		DebugThreadId tid = null;

		public SavedFocus(DebugSystemObjects so) {
			this.so = so;
			try {
				tid = so.getCurrentThreadId();
			}
			catch (COMException e) {
				Msg.debug(this, "Cannot save current thread id: " + e);
			}
		}

		@Override
		public void close() {
			if (tid != null) {
				try {
					so.setCurrentThreadId(tid);
				}
				catch (COMException e) {
					Msg.debug(this, "Could not restore current thread id: " + e);
				}
			}
		}
	}

	public DebugClient getClient() {
		return engThread.getClient();
	}

	public DebugAdvanced getAdvanced() {
		DebugClient dbgeng = getClient();
		return dbgeng.getAdvanced();
	}

	public DebugControl getControl() {
		DebugClient dbgeng = getClient();
		return dbgeng.getControl();
	}

	public DebugDataSpaces getDataSpaces() {
		DebugClient dbgeng = getClient();
		return dbgeng.getDataSpaces();
	}

	public DebugRegisters getRegisters() {
		DebugClient dbgeng = getClient();
		return dbgeng.getRegisters();
	}

	public DebugSymbols getSymbols() {
		DebugClient dbgeng = getClient();
		return dbgeng.getSymbols();
	}

	public DebugSystemObjects getSystemObjects() {
		DebugClient dbgeng = getClient();
		return dbgeng.getSystemObjects();
	}

	public List<DebugThreadId> getThreads() {
		DebugSystemObjects so = getSystemObjects();
		return so.getThreads();
	}

	private List<DebugBreakpoint> getBreakpoints() {
		DebugControl control = getControl();
		return control.getBreakpoints();
	}

	public DbgThreadImpl getCurrentThread() {
		return (DbgThreadImpl) (currentThread != null ? currentThread : eventThread);
	}

	public void setCurrentThread(DbgThreadImpl thread) {
		currentThread = thread;
	}

	public DbgProcessImpl getCurrentProcess() {
		return (DbgProcessImpl) (currentProcess != null ? currentProcess : eventProcess);
	}

	public void setCurrentProcess(DbgProcessImpl process) {
		currentProcess = process;
	}

	public DbgSessionImpl getCurrentSession() {
		return (DbgSessionImpl) (currentSession != null ? currentSession : eventSession);
	}

	public DbgThreadImpl getEventThread() {
		return (DbgThreadImpl) eventThread;
	}

	public DbgProcessImpl getEventProcess() {
		return (DbgProcessImpl) eventProcess;
	}

	public DbgSessionImpl getEventSession() {
		return (DbgSessionImpl) eventSession;
	}

	public CompletableFuture<Void> setActiveFrame(DbgThread thread, int index) {
		currentThread = thread;
		currentProcess = thread.getProcess();
		return execute(new DbgSetActiveThreadCommand(this, thread, index));
	}

	public CompletableFuture<Void> setActiveThread(DbgThread thread) {
		if (currentThread != null) {
			if (thread == null || thread.getTid().equals(currentThread.getTid())) {
				return CompletableFuture.completedFuture(null);
			}
		}
		currentThread = thread;
		currentProcess = thread.getProcess();
		return execute(new DbgSetActiveThreadCommand(this, thread, null));
	}

	public CompletableFuture<Void> setActiveProcess(DbgProcess process) {
		if (currentProcess != null) {
			if (process == null || process.getPid().equals(currentProcess.getPid())) {
				return CompletableFuture.completedFuture(null);
			}
		}
		currentProcess = process;
		return execute(new DbgSetActiveProcessCommand(this, process));
	}

	public CompletableFuture<Void> setActiveSession(DbgSession session) {
		currentSession = session;
		return execute(new DbgSetActiveSessionCommand(this, session));
	}

	public CompletableFuture<Void> requestFocus(DbgModelTargetFocusScope scope, TargetObject obj) {
		return execute(new DbgRequestFocusCommand(this, scope, obj));
	}

	public CompletableFuture<Void> requestActivation(DbgModelTargetActiveScope activator,
			TargetObject obj) {
		return execute(new DbgRequestActivationCommand(this, activator, obj));
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		if (continuation != null) {
			//String prompt = command.equals("") ? DbgModelTargetInterpreter.DBG_PROMPT : ">>>";
			//getEventListeners().fire.promptChanged(prompt);
			continuation.complete(command);
			setContinuation(null);
			return AsyncUtils.NIL;
		}
		return execute(
			new DbgConsoleExecCommand(this, command, DbgConsoleExecCommand.Output.CONSOLE))
					.thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return execute(
			new DbgConsoleExecCommand(this, command, DbgConsoleExecCommand.Output.CAPTURE));
	}

	public void fireThreadExited(DebugThreadId id, DbgProcessImpl process, DbgCause cause) {
		getEventListeners().fire.threadExited(id, process, cause);
	}

	@Override
	public DbgState getState() {
		return state.get();
	}

	@Override
	public DbgProcess currentProcess() {
		return getCurrentProcess();
	}

	@Override
	public CompletableFuture<Void> waitForEventEx() {
		//System.err.println("ENTER");
		DebugControl control = getControl();
		waiting = true;
		control.waitForEvent();
		//System.err.println("EXIT");
		waiting = false;
		updateState();
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public CompletableFuture<Void> waitForState(DbgState forState) {
		checkStarted();
		return state.waitValue(forState);
	}

	@Override
	public CompletableFuture<Void> waitForPrompt() {
		return CompletableFuture.completedFuture(null);
	}

	@Override
	public DebugEventInformation getLastEventInformation() {
		return lastEventInformation;
	}

	public boolean shouldUpdate(TargetObject object) {
		if (ignoreEventThread || !(object instanceof DbgModelTargetObject)) {
			return true;
		}
		DbgModelTargetObject modelObject = (DbgModelTargetObject) object;
		DbgModelTargetThread parentThread = modelObject.getParentThread();
		if (parentThread == null) {
			return true;
		}
		return parentThread.getThread().equals(eventThread);
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

	public boolean useAltMemoryQuery() {
		return altMemoryQuery;
	}

	public void setAltMemoryQuery(boolean altMemoryQuery) {
		this.altMemoryQuery = altMemoryQuery;
	}

	public void setContinuation(CompletableFuture<String> continuation) {
		this.continuation = continuation;
	}

	public long getProcessCount() {
		return processCount;
	}

	public DebugThreadId getThreadIdBySystemId(Integer tid) {
		return getSystemObjects().getThreadIdBySystemId(tid);
	}
	
	public DebugProcessId getProcessIdBySystemId(Integer pid) {
		return getSystemObjects().getProcessIdBySystemId(pid);
	}
	
	private DbgProcessImpl getProcessFromDebugProcessInfo(DebugProcessInfo info) {
		DebugSystemObjects so = getSystemObjects();
		DebugProcessId id = so.getProcessIdByHandle(info.handle);
		if (kernelMode) {
			// Unnecessary? Are these events transmitted in kernel-mode?
			return null;
		} else {
			int pid = so.getCurrentProcessSystemId();
			return getProcessComputeIfAbsent(id, pid, true);
		}
	}

	private DbgThreadImpl getThreadFromDebugProcessInfo(DbgProcessImpl proc, DebugThreadInfo info) {
		DebugSystemObjects so = getSystemObjects();
		DebugThreadId id = so.getThreadIdByHandle(info.handle);
		if (kernelMode) {
			// Unnecessary? Are these events transmitted in kernel-mode?
			return null;
		} else {
			int pid = so.getCurrentThreadSystemId();
			return getThreadComputeIfAbsent(id, proc, pid, true);
		}
	}

	private void updateStateFromSystemObject(DebugThreadId etid, DebugProcessId epid, DebugSessionId esid) {
		DebugSystemObjects so = getSystemObjects();
		currentSession = eventSession = getSessionComputeIfAbsent(esid, true);
		if (kernelMode) {
			DbgProcessImpl cp = getProcessComputeIfAbsent(new DebugSystemProcessRecord(epid.value()), -1, true);
			cp.setOffset(so.getCurrentProcessDataOffset());
			currentProcess = eventProcess = cp;
			if (currentProcess.getId().isSystem()) {
				execute(new DbgResolveProcessCommand(this, currentProcess)).thenAccept(proc -> {
					currentProcess = eventProcess = proc;
					// As you now have both pid & offset, update the id==pid version
					DbgProcessImpl mirror = getProcessComputeIfAbsent(new DebugProcessRecord(proc.getPid()), proc.getPid(), true);
					if (mirror != null) {
						mirror.setOffset(currentProcess.getOffset());
						currentProcess = eventProcess = mirror;
						getEventListeners().fire.processSelected(eventProcess, Causes.UNCLAIMED);
					}
				});
			}
			DbgThreadImpl ct = getThreadComputeIfAbsent(new DebugSystemThreadRecord(etid.value()), cp, -1, false);
			ct.setOffset(so.getCurrentThreadDataOffset());
			currentThread = eventThread = ct;
			if (currentThread.getId().isSystem()) {
				execute(new DbgResolveThreadCommand(this, currentThread)).thenAccept(thread -> {
					currentThread = eventThread = thread;
					// As you now have both tid & offset, update the id==tid version
					DbgThreadImpl mirror = getThreadComputeIfAbsent(new DebugThreadRecord(thread.getTid()), (DbgProcessImpl) eventProcess, thread.getTid(), true);
					if (mirror != null) {
						mirror.setOffset(currentThread.getOffset());
						currentThread = eventThread = mirror;
						getEventListeners().fire.threadSelected(eventThread, null, Causes.UNCLAIMED);
					}
				});
			}
		} else {
			currentProcess =
				eventProcess = getProcessComputeIfAbsent(epid, so.getCurrentProcessSystemId(), true);
			currentThread = eventThread = getThreadComputeIfAbsent(etid, (DbgProcessImpl) eventProcess,
				so.getCurrentThreadSystemId(), false);
			getEventListeners().fire.threadSelected(eventThread, null, Causes.UNCLAIMED);
		}
	}

}
