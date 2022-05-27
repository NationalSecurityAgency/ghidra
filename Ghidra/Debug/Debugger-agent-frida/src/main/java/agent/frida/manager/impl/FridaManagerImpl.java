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
package agent.frida.manager.impl;

import static ghidra.async.AsyncUtils.*;

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.apache.commons.lang3.tuple.Pair;

import com.google.gson.JsonElement;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

import agent.frida.frida.*;
import agent.frida.frida.FridaClient.DebugEndSessionFlags;
import agent.frida.frida.FridaClient.DebugStatus;
import agent.frida.gadp.impl.AbstractClientThreadExecutor;
import agent.frida.gadp.impl.FridaClientThreadExecutor;
import agent.frida.manager.*;
import agent.frida.manager.FridaCause.Causes;
import agent.frida.manager.cmd.*;
import agent.frida.manager.evt.*;
import agent.frida.model.iface1.*;
import ghidra.async.*;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.util.HandlerMap;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public class FridaManagerImpl implements FridaManager {

	public DebugStatus status;

	protected AbstractClientThreadExecutor executor;
	protected FridaClientReentrant reentrantClient;

	private List<FridaPendingCommand<?>> activeCmds = new ArrayList<>();

	protected final Map<String, FridaSession> sessions = new LinkedHashMap<>();
	protected FridaTarget curSession = null;
	private final Map<String, FridaSession> unmodifiableSessions =
		Collections.unmodifiableMap(sessions);

	protected final Map<String, Map<String, FridaProcess>> processes = new LinkedHashMap<>();
	protected final Map<String, Map<String, FridaThread>> threads = new LinkedHashMap<>();
	protected final Map<String, Map<String, FridaModule>> modules = new LinkedHashMap<>();
	protected final Map<String, Map<String, FridaMemoryRegionInfo>> regions = new LinkedHashMap<>();

	protected final Map<String, FridaKernelModule> kmodules = new LinkedHashMap<>();
	protected final Map<String, FridaKernelMemoryRegionInfo> kregions = new LinkedHashMap<>();

	protected final AsyncReference<FridaState, FridaCause> state = new AsyncReference<>(null);
	private final HandlerMap<FridaEvent<?>, Void, DebugStatus> handlerMap = new HandlerMap<>();
	private final Map<Class<?>, DebugStatus> statusMap = new LinkedHashMap<>();
	private final ListenerSet<FridaEventsListener> listenersEvent =
		new ListenerSet<>(FridaEventsListener.class);

	private FridaTarget currentTarget;
	private FridaSession currentSession;
	private FridaProcess currentProcess;
	private FridaThread currentThread;
	private volatile boolean waiting = false;
	private boolean kernelMode = false;
	private CompletableFuture<String> continuation;

	private Map<String, FridaScript> scripts = new HashMap<>();

	/**
	 * Instantiate a new manager
	 */
	public FridaManagerImpl() {
		defaultHandlers();
	}

	/**
	 * @param processId the process ID to remove
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
	public FridaThread getThread(FridaProcess process, String tid) {
		synchronized (threads) {
			return threads.get(FridaClient.getId(process)).get(tid);
		}
	}

	public void addThreadIfAbsent(FridaProcess process, FridaThread thread) {
		synchronized (threads) {
			Map<String, FridaThread> map = threads.get(FridaClient.getId(process));
			if (map == null) {
				map = new HashMap<>();
				threads.put(FridaClient.getId(process), map);
			}
			if (thread == null) {
				return;
			}
			String id = FridaClient.getId(thread);
			FridaThread pred = map.get(id);
			if (!map.containsKey(id) || !thread.equals(pred)) {
				FridaThreadInfo info = new FridaThreadInfo(thread);
				if (!map.containsKey(id)) {
					getClient().processEvent(new FridaThreadCreatedEvent(info));
				}
				else {
					getClient().processEvent(new FridaThreadReplacedEvent(info));
				}
				map.put(id, thread);
			}
		}
	}

	/**
	 * @param sessionId the session ID to remove
	 * @param id the process ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeProcess(String sessionId, String id, FridaCause cause) {
		synchronized (processes) {
			FridaProcess proc = processes.get(sessionId).remove(id);
			if (proc == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			Set<String> toRemove = new HashSet<>();
			String processId = FridaClient.getId(proc);
			for (String tid : threads.get(processId).keySet()) {
				FridaThread thread = threads.get(processId).get(tid);
				String pid = FridaClient.getId(thread.getProcess());
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
	 * @param session wrapper for Frida pointer
	 * @param id process pid
	 * @return success status
	 */
	@Override
	public FridaProcess getProcess(FridaSession session, String id) {
		synchronized (processes) {
			String sessionId = FridaClient.getId(session);
			FridaProcess result = processes.get(sessionId).get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no process with id " + id);
			}
			return result;
		}
	}

	public void addProcessIfAbsent(FridaSession session, FridaProcess process) {
		synchronized (processes) {
			String sessionId = FridaClient.getId(session);
			Map<String, FridaProcess> map = processes.get(sessionId);
			if (map == null) {
				map = new HashMap<>();
				processes.put(sessionId, map);
			}
			String id = FridaClient.getId(process);
			FridaProcess pred = map.get(id);
			if (!map.containsKey(id) || !process.equals(pred)) {
				FridaProcessInfo info = new FridaProcessInfo(process);
				if (!map.containsKey(id)) {
					getClient().processEvent(new FridaProcessCreatedEvent(info));
				}
				else {
					getClient().processEvent(new FridaProcessReplacedEvent(info));
				}
				map.put(id, process);
			}
		}
	}

	/**
	 * @param id the session ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeSession(String id, FridaCause cause) {
		synchronized (sessions) {
			if (sessions.remove(id) == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			getEventListeners().fire.sessionRemoved(id, cause);
		}
	}

	@Override
	public FridaSession getSession(String id) {
		synchronized (sessions) {
			FridaSession result = sessions.get(id);
			if (result == null) {
				throw new IllegalArgumentException("There is no session with id " + id);
			}
			return result;
		}
	}

	public void addSessionIfAbsent(FridaSession session) {
		synchronized (sessions) {
			String id = FridaClient.getId(session);
			FridaSession pred = sessions.get(id);
			if (!sessions.containsKey(id) || !session.equals(pred)) {
				FridaSessionInfo info = new FridaSessionInfo(session);
				if (sessions.containsKey(id)) {
					//removeSession(sessions.get(id));
					getClient().processEvent(new FridaSessionReplacedEvent(info));
				}
				else {
					getClient().processEvent(new FridaSessionCreatedEvent(info));
				}
				sessions.put(id, session);
			}
		}
	}

	/**
	 * @param process wrapper for Frida pointer
	 * @param id the module name to remove
	 */
	public void removeModule(FridaProcess process, String id) {
		synchronized (modules) {
			if (modules.get(FridaClient.getId(process)).remove(id) == null) {
				throw new IllegalArgumentException("There is no module with id " + id);
			}
		}
	}

	@Override
	public FridaModule getModule(FridaProcess process, String id) {
		synchronized (modules) {
			return modules.get(FridaClient.getId(process)).get(id);
		}
	}

	public void addModuleIfAbsent(FridaProcess process, FridaModule module) {
		synchronized (modules) {
			String sessionId = FridaClient.getId(process);
			Map<String, FridaModule> map = modules.get(sessionId);
			if (map == null) {
				map = new HashMap<>();
				modules.put(sessionId, map);
			}
			if (module == null) {
				return;
			}
			String id = FridaClient.getId(module);
			FridaModule pred = map.get(id);
			if (!map.containsKey(id) || !module.equals(pred)) {
				FridaModuleInfo info = new FridaModuleInfo(process, module);
				if (!map.containsKey(id)) {
					getClient().processEvent(new FridaModuleLoadedEvent(info));
				}
				else {
					getClient().processEvent(new FridaModuleReplacedEvent(info));
				}
				map.put(id, module);
			}
		}
	}

	public void addKernelModuleIfAbsent(FridaKernelModule module) {
		synchronized (kmodules) {
			if (module == null) {
				return;
			}
			String id = FridaClient.getId(module);
			FridaKernelModule pred = kmodules.get(id);
			if (!kmodules.containsKey(id) || !module.equals(pred)) {
				FridaModuleInfo info = new FridaModuleInfo(module);
				if (!kmodules.containsKey(id)) {
					getClient().processEvent(new FridaModuleLoadedEvent(info));
				}
				else {
					getClient().processEvent(new FridaModuleReplacedEvent(info));
				}
				kmodules.put(id, module);
			}
		}
	}

	/**
	 * @param process wrapper for Frida pointer
	 * @param id the module name to remove
	 */
	public void removeMemoryRegion(FridaProcess process, String id) {
		synchronized (regions) {
			if (regions.get(FridaClient.getId(process)).remove(id) == null) {
				throw new IllegalArgumentException("There is no region with id " + id);
			}
		}
	}

	@Override
	public FridaMemoryRegionInfo getMemoryRegion(FridaProcess process, String id) {
		synchronized (regions) {
			return regions.get(FridaClient.getId(process)).get(id);
		}
	}

	public void addMemoryRegionIfAbsent(FridaProcess process, FridaMemoryRegionInfo region) {
		synchronized (regions) {
			String sessionId = FridaClient.getId(process);
			Map<String, FridaMemoryRegionInfo> map = regions.get(sessionId);
			if (map == null) {
				map = new HashMap<>();
				regions.put(sessionId, map);
			}
			String id = FridaClient.getId(region);
			FridaMemoryRegionInfo pred = map.get(id);
			if (!map.containsKey(id) || !region.equals(pred)) {
				FridaRegionInfo info = new FridaRegionInfo(process, region);
				if (!map.containsKey(id)) {
					getClient().processEvent(new FridaMemoryRegionAddedEvent(info));
				}
				else {
					getClient().processEvent(new FridaMemoryRegionReplacedEvent(info));
				}
				map.put(id, region);
			}
		}
	}

	public void addKernelMemoryRegionIfAbsent(FridaKernelMemoryRegionInfo region) {
		synchronized (kregions) {
			String id = FridaClient.getId(region);
			FridaKernelMemoryRegionInfo pred = kregions.get(id);
			if (!kregions.containsKey(id) || !region.equals(pred)) {
				FridaRegionInfo info = new FridaRegionInfo(region);
				if (!kregions.containsKey(id)) {
					getClient().processEvent(new FridaMemoryRegionAddedEvent(info));
				}
				else {
					getClient().processEvent(new FridaMemoryRegionReplacedEvent(info));
				}
				kregions.put(id, region);
			}
		}
	}

	@Override
	public Map<String, FridaThread> getKnownThreads(FridaProcess process) {
		String processId = FridaClient.getId(process);
		Map<String, FridaThread> map = threads.get(processId);
		if (map == null) {
			map = new HashMap<>();
			threads.put(FridaClient.getId(process), map);
		}
		return map;
	}

	@Override
	public Map<String, FridaProcess> getKnownProcesses(FridaSession target) {
		String sessionId = FridaClient.getId(target);
		Map<String, FridaProcess> map = processes.get(sessionId);
		if (map == null) {
			map = new HashMap<>();
			processes.put(sessionId, map);
		}
		return map;
	}

	@Override
	public Map<String, FridaSession> getKnownSessions() {
		return unmodifiableSessions;
	}

	@Override
	public Map<String, FridaModule> getKnownModules(FridaProcess process) {
		String processId = FridaClient.getId(process);
		Map<String, FridaModule> map = modules.get(processId);
		if (map == null) {
			map = new HashMap<>();
			modules.put(processId, map);
		}
		return map;
	}

	@Override
	public Map<String, FridaMemoryRegionInfo> getKnownRegions(FridaProcess process) {
		String processId = FridaClient.getId(process);
		Map<String, FridaMemoryRegionInfo> map = regions.get(processId);
		if (map == null) {
			map = new HashMap<>();
			regions.put(processId, map);
		}
		return map;
	}

	@Override
	public CompletableFuture<Void> start(String[] args) {
		state.set(null, Causes.UNCLAIMED);
		boolean create = true;
		if (args.length == 0) {
			executor =
				new FridaClientThreadExecutor(() -> FridaClient.debugCreate().createClient());
		}
		else {
			// TODO - process args?
			executor =
				new FridaClientThreadExecutor(() -> FridaClient.debugCreate().createClient());
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
		FridaClient client = executor.getClient();
		reentrantClient = client;

		status = client.getExecutionStatus();
	}

	@Override
	public boolean isRunning() {
		return !executor.isShutdown() && !executor.isTerminated();
	}

	@Override
	public void terminate() {
		executor.execute(100, client -> {
			Msg.debug(this, "Disconnecting DebugClient from session");
			client.endSession(getCurrentTarget(), DebugEndSessionFlags.DEBUG_END_DISCONNECT);
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
	public <T> CompletableFuture<T> execute(FridaCommand<? extends T> cmd) {
		assert cmd != null;
		FridaPendingCommand<T> pcmd = new FridaPendingCommand<>(cmd);

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

	private <T> void addCommand(FridaCommand<? extends T> cmd, FridaPendingCommand<T> pcmd) {
		synchronized (this) {
			if (!cmd.validInState(state.get())) {
				throw new FridaCommandError("Command " + cmd + " is not valid while " + state.get());
			}
			activeCmds.add(pcmd);
		}
		cmd.invoke();
		processEvent(new FridaCommandDoneEvent(cmd));
	}

	@Override
	public DebugStatus processEvent(FridaEvent<?> evt) {
		if (state == null) {
			state.set(FridaState.FRIDA_THREAD_STOPPED, Causes.UNCLAIMED);
		}
		FridaState newState = evt.newState();
		if (newState != null && !(evt instanceof FridaCommandDoneEvent)) {
			Msg.debug(this, evt + " transitions state to " + newState);
			state.set(newState, evt.getCause());
		}

		boolean cmdFinished = false;
		List<FridaPendingCommand<?>> toRemove = new ArrayList<FridaPendingCommand<?>>();
		for (FridaPendingCommand<?> pcmd : activeCmds) {
			cmdFinished = pcmd.handle(evt);
			if (cmdFinished) {
				pcmd.finish();
				toRemove.add(pcmd);
			}
		}
		for (FridaPendingCommand<?> pcmd : toRemove) {
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
	public void addStateListener(FridaStateListener listener) {
		state.addChangeListener(listener);
	}

	@Override
	public void removeStateListener(FridaStateListener listener) {
		state.removeChangeListener(listener);
	}

	public ListenerSet<FridaEventsListener> getEventListeners() {
		return listenersEvent;
	}

	@Override
	public void addEventsListener(FridaEventsListener listener) {
		getEventListeners().add(listener);
	}

	@Override
	public void removeEventsListener(FridaEventsListener listener) {
		getEventListeners().remove(listener);
	}

	private void defaultHandlers() {
		handlerMap.put(FridaInterruptEvent.class, this::processInterrupt);
		handlerMap.put(FridaThreadCreatedEvent.class, this::processThreadCreated);
		handlerMap.put(FridaThreadReplacedEvent.class, this::processThreadReplaced);
		handlerMap.put(FridaThreadExitedEvent.class, this::processThreadExited);
		handlerMap.put(FridaThreadSelectedEvent.class, this::processThreadSelected);
		handlerMap.put(FridaProcessCreatedEvent.class, this::processProcessCreated);
		handlerMap.put(FridaProcessReplacedEvent.class, this::processProcessReplaced);
		handlerMap.put(FridaProcessExitedEvent.class, this::processProcessExited);
		handlerMap.put(FridaSessionCreatedEvent.class, this::processSessionCreated);
		handlerMap.put(FridaSessionReplacedEvent.class, this::processSessionReplaced);
		handlerMap.put(FridaSessionExitedEvent.class, this::processSessionExited);
		handlerMap.put(FridaProcessSelectedEvent.class, this::processProcessSelected);
		handlerMap.put(FridaSelectedFrameChangedEvent.class, this::processFrameSelected);
		handlerMap.put(FridaModuleLoadedEvent.class, this::processModuleLoaded);
		handlerMap.put(FridaModuleReplacedEvent.class, this::processModuleReplaced);
		handlerMap.put(FridaModuleUnloadedEvent.class, this::processModuleUnloaded);
		handlerMap.put(FridaMemoryRegionAddedEvent.class, this::processMemoryRegionAdded);
		handlerMap.put(FridaMemoryRegionReplacedEvent.class, this::processMemoryRegionReplaced);
		handlerMap.put(FridaModuleUnloadedEvent.class, this::processModuleUnloaded);
		handlerMap.put(FridaStateChangedEvent.class, this::processStateChanged);
		handlerMap.putVoid(FridaCommandDoneEvent.class, this::processDefault);
		handlerMap.putVoid(FridaStoppedEvent.class, this::processDefault);
		handlerMap.putVoid(FridaRunningEvent.class, this::processDefault);
		handlerMap.putVoid(FridaConsoleOutputEvent.class, this::processConsoleOutput);

		statusMap.put(FridaProcessCreatedEvent.class, DebugStatus.BREAK);
		statusMap.put(FridaProcessExitedEvent.class, DebugStatus.NO_DEBUGGEE);
		statusMap.put(FridaStateChangedEvent.class, DebugStatus.NO_CHANGE);
		statusMap.put(FridaStoppedEvent.class, DebugStatus.BREAK);
		statusMap.put(FridaInterruptEvent.class, DebugStatus.BREAK);
	}

	@Override
	public void updateState(FridaSession session) {
		getSessionAttributes(session);
		currentSession = session;
		FridaProcess process = session.getProcess();
		currentProcess = process;
		if (currentSession == null ||
			!currentSession.equals(process.getSession())) {
			FridaSession candidateSession = currentProcess.getSession();
			if (candidateSession != null) {
				currentSession = candidateSession;
			}
		}
		/*
		if (currentThread == null ||
			!currentThread.equals(process.GetSelectedThread())) {
			FridaThread candidateThread = currentProcess.GetSelectedThread();
			if (candidateThread != null) {
				currentThread = candidateThread;
			}
		}
		*/
		addSessionIfAbsent(currentSession);
		addProcessIfAbsent(currentSession, currentProcess);
		addThreadIfAbsent(currentProcess, currentThread);
	}

	/**
	 * Default handler for events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected <T> DebugStatus processDefault(AbstractFridaEvent<T> evt, Void v) {
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processInterrupt(FridaInterruptEvent evt, Void v) {
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread created events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadCreated(FridaThreadCreatedEvent evt, Void v) {
		FridaThread thread = evt.getInfo().thread;
		currentThread = thread;
		getEventListeners().fire.threadCreated(thread, FridaCause.Causes.UNCLAIMED);
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
	protected DebugStatus processThreadReplaced(FridaThreadReplacedEvent evt, Void v) {
		FridaThread thread = evt.getInfo().thread;
		getEventListeners().fire.threadReplaced(thread, FridaCause.Causes.UNCLAIMED);
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
	protected DebugStatus processThreadExited(FridaThreadExitedEvent evt, Void v) {
		getEventListeners().fire.threadExited(currentThread, currentProcess, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for thread selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processThreadSelected(FridaThreadSelectedEvent evt, Void v) {
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
	protected DebugStatus processFrameSelected(FridaSelectedFrameChangedEvent evt, Void v) {
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
	protected DebugStatus processProcessCreated(FridaProcessCreatedEvent evt, Void v) {
		FridaProcessInfo info = evt.getInfo();
		FridaProcess proc = info.process;
		getEventListeners().fire.processAdded(proc, FridaCause.Causes.UNCLAIMED);
		getEventListeners().fire.processSelected(proc, evt.getCause());

		/*
		FridaThread thread = proc.GetSelectedThread();
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());
		*/
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process replaced events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessReplaced(FridaProcessReplacedEvent evt, Void v) {
		FridaProcessInfo info = evt.getInfo();
		FridaProcess proc = info.process;
		getEventListeners().fire.processReplaced(proc, FridaCause.Causes.UNCLAIMED);
		getEventListeners().fire.processSelected(proc, evt.getCause());

		/*
		FridaThread thread = proc.GetSelectedThread();
		getEventListeners().fire.threadSelected(thread, null, evt.getCause());
		*/
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process exited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessExited(FridaProcessExitedEvent evt, Void v) {
		FridaThread thread = getCurrentThread();
		FridaProcess process = getCurrentProcess();
		getEventListeners().fire.threadExited(thread, process, evt.getCause());
		getEventListeners().fire.processExited(process, evt.getCause());
		getEventListeners().fire.processRemoved(process.getPID().toString(), evt.getCause());
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for process selected events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processProcessSelected(FridaProcessSelectedEvent evt, Void v) {
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
	protected DebugStatus processSessionCreated(FridaSessionCreatedEvent evt, Void v) {
		FridaSessionInfo info = evt.getInfo();
		getEventListeners().fire.sessionAdded(info.session, FridaCause.Causes.UNCLAIMED);
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
	protected DebugStatus processSessionReplaced(FridaSessionReplacedEvent evt, Void v) {
		FridaSessionInfo info = evt.getInfo();
		getEventListeners().fire.sessionReplaced(info.session, FridaCause.Causes.UNCLAIMED);
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
	protected DebugStatus processSessionExited(FridaSessionExitedEvent evt, Void v) {
		removeSession(evt.sessionId, FridaCause.Causes.UNCLAIMED);
		getEventListeners().fire.sessionRemoved(evt.sessionId, evt.getCause());
		getEventListeners().fire.threadExited(currentThread, currentProcess, evt.getCause());
		getEventListeners().fire.processExited(currentProcess, evt.getCause());
		getEventListeners().fire.processRemoved(currentProcess.getPID().toString(),
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
	protected DebugStatus processModuleLoaded(FridaModuleLoadedEvent evt, Void v) {
		FridaModuleInfo info = evt.getInfo();
		long n = info.getNumberOfModules();
		FridaProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.moduleLoaded(process, info, i, evt.getCause());
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for module replaced events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processModuleReplaced(FridaModuleReplacedEvent evt, Void v) {
		FridaModuleInfo info = evt.getInfo();
		long n = info.getNumberOfModules();
		FridaProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.moduleReplaced(process, info, i, evt.getCause());
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
	protected DebugStatus processModuleUnloaded(FridaModuleUnloadedEvent evt, Void v) {
		FridaModuleInfo info = evt.getInfo();
		long n = info.getNumberOfModules();
		FridaProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.moduleUnloaded(process, info, i, evt.getCause());
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
	protected DebugStatus processMemoryRegionAdded(FridaMemoryRegionAddedEvent evt, Void v) {
		FridaRegionInfo info = evt.getInfo();
		long n = info.getNumberOfRegions();
		FridaProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.regionAdded(process, info, i, evt.getCause());
		}
		return statusMap.get(evt.getClass());
	}

	/**
	 * Handler for module replaced events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return retval handling/break status
	 */
	protected DebugStatus processMemoryRegionReplaced(FridaMemoryRegionReplacedEvent evt, Void v) {
		FridaRegionInfo info = evt.getInfo();
		long n = info.getNumberOfRegions();
		FridaProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.regionReplaced(process, info, i, evt.getCause());
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
	protected DebugStatus processMemoryRegionRemoved(FridaMemoryRegionRemovedEvent evt, Void v) {
		FridaRegionInfo info = evt.getInfo();
		long n = info.getNumberOfRegions();
		FridaProcess process = info.getProcess();
		for (int i = 0; i < n; i++) {
			getEventListeners().fire.regionRemoved(process, info, i, evt.getCause());
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
	protected DebugStatus processStateChanged(FridaStateChangedEvent evt, Void v) {
		status = DebugStatus.fromArgument(evt.newState());

		String id = currentThread == null ? FridaClient.getId(currentProcess) :  FridaClient.getId(currentThread);
		if (status.equals(DebugStatus.NO_DEBUGGEE)) {
			waiting = false;
			if (state.get().equals(FridaState.FRIDA_THREAD_HALTED)) {
				if (currentThread != null) {
					processEvent(new FridaRunningEvent(id));
				}
				processEvent(new FridaProcessExitedEvent(0));
				processEvent(new FridaSessionExitedEvent(FridaClient.getId(currentSession), 0));
			}
			return DebugStatus.NO_DEBUGGEE;
		}
		if (status.equals(DebugStatus.BREAK)) {
			waiting = false;
			FridaProcess process = getCurrentProcess();
			if (process != null) {
				processEvent(new FridaProcessSelectedEvent(process));
				if (currentThread != null) {
					FridaThreadInfo tinfo = new FridaThreadInfo(currentThread);
					processEvent(new FridaThreadSelectedEvent(tinfo));
				}
			}
			processEvent(new FridaStoppedEvent(id));
			return DebugStatus.BREAK;
		}
		if (status.equals(DebugStatus.GO)) {
			waiting = true;
			processEvent(new FridaRunningEvent(id));
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
	protected DebugStatus processSessionSelected(FridaSessionSelectedEvent evt, Void v) {
		FridaSession session = evt.getSession();
		getEventListeners().fire.sessionSelected(session, evt.getCause());
		return statusMap.get(evt.getClass());
	}

	protected void processConsoleOutput(FridaConsoleOutputEvent evt, Void v) {
		if (evt.getOutput() != null) {
			getEventListeners().fire.consoleOutput(evt.getOutput(), evt.getMask());
		}
	}

	@Override
	public CompletableFuture<Void> listThreads(FridaProcess process) {
		return execute(new FridaListThreadsCommand(this, process));
	}

	@Override
	public CompletableFuture<Map<String, FridaProcess>> listProcesses(FridaSession session) {
		return execute(new FridaListProcessesCommand(this, session));
	}

	@Override
	public CompletableFuture<List<Pair<String, String>>> listAvailableProcesses() {
		return execute(new FridaListAvailableProcessesCommand(this));
	}

	@Override
	public CompletableFuture<Map<String, FridaSession>> listSessions() {
		return execute(new FridaListSessionsCommand(this));
	}

	@Override
	public CompletableFuture<Map<String, FridaFrame>> listStackFrames(FridaThread thread) {
		return execute(new FridaListStackFramesCommand(this, thread));
	}

	@Override
	public CompletableFuture<Map<String, String>> listRegisters(FridaThread thread) {
		return execute(new FridaListRegistersCommand(this, thread));
	}

	@Override
	public CompletableFuture<Void> listModules(FridaProcess process) {
		return execute(new FridaListModulesCommand(this, process));
	}
	public CompletableFuture<Void> listKernelModules() {
		return execute(new FridaListKernelModulesCommand(this));
	}

	@Override
	public CompletableFuture<Map<String, FridaSection>> listModuleSections(FridaModule module) {
		return execute(new FridaListModuleSectionsCommand(this, module));
	}

	@Override
	public CompletableFuture<Map<String, FridaSymbol>> listModuleSymbols(FridaModule module) {
		return execute(new FridaListModuleSymbolsCommand(this, module));
	}

	@Override
	public CompletableFuture<Map<String, FridaImport>> listModuleImports(FridaModule module) {
		return execute(new FridaListModuleImportsCommand(this, module));
	}

	@Override
	public CompletableFuture<Map<String, FridaExport>> listModuleExports(FridaModule module) {
		return execute(new FridaListModuleExportsCommand(this, module));
	}

	@Override
	public CompletableFuture<Void> listMemory(FridaProcess process) {
		return execute(new FridaListMemoryRegionsCommand(this, process));
	}
	public CompletableFuture<Void> listKernelMemory() {
		return execute(new FridaListKernelMemoryRegionsCommand(this));
	}

	@Override
	public CompletableFuture<Void> listHeapMemory(FridaProcess process) {
		return execute(new FridaListHeapMemoryRegionsCommand(this, process));
	}
	
	@Override
	public CompletableFuture<Void> setExceptionHandler(FridaProcess process) {
		return execute(new FridaSetExceptionHandlerCommand(this, process));
	}

	@Override
	public CompletableFuture<Void> getSessionAttributes(FridaSession session) {
		return execute(new FridaGetSessionAttributesCommand(this, session));
	}

	@Override
	public CompletableFuture<FridaProcess> addProcess() {
		return execute(new FridaAddProcessCommand(this));
	}

	@Override
	public CompletableFuture<Void> removeProcess(FridaProcess process) {
		return execute(new FridaRemoveProcessCommand(this, process.getSession(),
			process.getPID().toString()));
	}

	@Override
	public CompletableFuture<FridaSession> addSession() {
		return execute(new FridaAddSessionCommand(this));
	}

	@Override
	public CompletableFuture<?> attach(String pid) {
		return execute(new FridaAttachCommand(this, pid));
	}

	@Override
	public CompletableFuture<?> launch(String fileName, List<String> args) {
		return execute(new FridaLaunchProcessCommand(this, fileName, args));
	}

	@Override
	public CompletableFuture<?> launch(Map<String, ?> args) {
		return execute(new FridaLaunchProcessWithOptionsCommand(this, args));
	}

	public FridaClient getClient() {
		return executor.getClient();
	}

	public FridaThread getCurrentThread() {
		return currentThread;
	}

	public void setCurrentThread(FridaThread thread) {
		currentThread = thread;
	}
	
	public void setCurrentThreadById(String tid) {
		currentProcess = currentSession.getProcess();
		if (currentProcess != null) {
			String key = FridaClient.getId(currentProcess);
			currentThread = threads.get(key).get(tid);
		}
	}

	public FridaProcess getCurrentProcess() {
		return currentProcess;
	}

	public FridaSession getCurrentSession() {
		return currentSession;
	}

	public void setCurrentSession(FridaSession session) {
		currentSession = session;
	}
	
	public FridaTarget getCurrentTarget() {
		return currentTarget;
	}

	public void setCurrentTarget(FridaTarget target) {
		currentTarget = target;
	}

	public CompletableFuture<Void> requestFocus(FridaModelTargetFocusScope scope, TargetObject obj) {
		return execute(new FridaRequestFocusCommand(this, scope, obj));
	}

	public CompletableFuture<Void> requestActivation(FridaModelTargetActiveScope activator,
			TargetObject obj) {
		return execute(new FridaRequestActivationCommand(this, activator, obj));
	}

	@Override
	public CompletableFuture<Void> console(String command) {
		if (continuation != null) {
			String prompt = command.equals("") ? FridaModelTargetInterpreter.FRIDA_PROMPT : ">>>";
			getEventListeners().fire.promptChanged(prompt);
			continuation.complete(command);
			setContinuation(null);
			return AsyncUtils.NIL;
		}
		return execute(
			new FridaConsoleExecCommand(this, command, FridaConsoleExecCommand.Output.CONSOLE))
					.thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command) {
		return execute(
			new FridaConsoleExecCommand(this, command, FridaConsoleExecCommand.Output.CAPTURE));
	}

	@Override
	public FridaState getState() {
		if (currentThread == null) {
			return null;
		}
		if (currentThread != null) {
			return FridaState.FRIDA_THREAD_RUNNING;
		}
		return currentThread.getState();
	}

	@Override
	public FridaProcess currentProcess() {
		return getCurrentProcess();
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

	public FridaScript loadPermanentScript(AbstractFridaCommand<?> caller, String name, String scriptText) {
		caller.setName(name);
		Pointer options = FridaEng.createOptions(name);
		FridaScript script = FridaEng.createScript(currentSession, scriptText, options);
		NativeLong signal = FridaEng.connectSignal(script, "message", (__s, message, data, userData) -> {
			caller.parse(message, data);
		}, null);
		script.setSignal(signal);
		FridaEng.loadScript(script);
		scripts.put(name, script);
		return script;
	}

	public void unloadPermanentScript(String name) {
		FridaScript script = scripts.get(name);
		NativeLong signal = script.getSignal();
		FridaEng.disconnectSignal(script, signal);
		FridaEng.unloadScript(script);
		FridaEng.unref(script);
	}

	public FridaScript loadScript(AbstractFridaCommand<?> caller, String name, String scriptText) {
		caller.setName(name);
		Pointer options = FridaEng.createOptions(name);
		String wrapperText = scriptText.contains("result") ?
				"var result = '';" + scriptText +
				"var msg = { key: '" + name + "', value: result};" +
				"send(JSON.stringify(msg));" :
				"send(JSON.stringify(" + scriptText + "));";
		FridaScript script = FridaEng.createScript(currentSession, wrapperText, options);
		if (script != null) {
			NativeLong signal = FridaEng.connectSignal(script, "message", (__s, message, data, userData) -> {
				caller.parse(message, data);
			}, null);
			script.setSignal(signal);
			FridaEng.loadScript(script);
			caller.setScript(script);
			FridaEng.disconnectSignal(script, signal);
			FridaEng.unloadScript(script);
			FridaEng.unref(script);
		}
		return script;
	}

	@Override
	public void enableDebugger(FridaSession session, int port) {
		FridaEng.enableDebugger(session, new NativeLong(port));
	}

	public CompletableFuture<Void> stalkThread(String tid, Map<String, ?> arguments) {
		return execute(new FridaStalkThreadCommand(this, tid, arguments));
	}

	public CompletableFuture<Void>  interceptFunction(String address, Map<String, ?> arguments) {
		return execute(new FridaInterceptFunctionCommand(this, address, arguments));		
	}

	public CompletableFuture<Void>  watchMemory(Map<String, ?> arguments) {
		return execute(new FridaWatchMemoryCommand(this, arguments));		
	}

}
