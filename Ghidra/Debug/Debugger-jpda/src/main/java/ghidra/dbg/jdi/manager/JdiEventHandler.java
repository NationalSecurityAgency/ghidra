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
package ghidra.dbg.jdi.manager;

import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.*;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.sun.jdi.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.EventRequest;

import ghidra.async.AsyncReference;
import ghidra.dbg.jdi.manager.impl.DebugStatus;
import ghidra.util.Msg;

public class JdiEventHandler implements Runnable {

	volatile boolean connected = true;
	boolean completed = false;
	String shutdownMessageKey;

	private VirtualMachine vm;
	private Thread handlerThread;
	private JdiEventHandler global;

	protected final AsyncReference<Integer, JdiCause> state =
		new AsyncReference<>(ThreadReference.THREAD_STATUS_NOT_STARTED);
	public final Set<JdiEventsListener> listenersEvent = new HashSet<>();
	protected final ExecutorService eventThread = Executors.newSingleThreadExecutor();

	public JdiEventHandler() {
		// Nothing to do here
	}

	public JdiEventHandler(VirtualMachine vm, JdiEventHandler global) {
		this.vm = vm;
		this.global = global;
		state.filter(this::stateFilter);
	}

	public void start() {
		this.handlerThread = new Thread(this, "event-handler");
		handlerThread.start();
	}

	synchronized void shutdown() {
		connected = false;  // force run() loop termination
		handlerThread.interrupt();
		while (!completed) {
			try {
				wait();
			}
			catch (InterruptedException exc) {
				// IGNORE
			}
		}
	}

	public CompletableFuture<Void> event(Runnable r, String text) {
		//Msg.debug(this, "Queueing event: " + text);
		return CompletableFuture.runAsync(r, eventThread).exceptionally(ex -> {
			Msg.error(this, "Error in event callback:", ex);
			return ExceptionUtils.rethrow(ex);
		});
	}

	public void addStateListener(JdiStateListener listener) {
		state.addChangeListener(listener);
	}

	public void removeStateListener(JdiStateListener listener) {
		state.removeChangeListener(listener);
	}

	public void addEventsListener(JdiEventsListener listener) {
		listenersEvent.add(listener);
	}

	public void removeEventsListener(JdiEventsListener listener) {
		listenersEvent.remove(listener);
	}

	@Override
	public void run() {
		EventQueue queue = vm.eventQueue();
		while (connected) {
			try {
				EventSet eventSet = queue.remove();
				DebugStatus status = DebugStatus.BREAK;
				state.set(ThreadReference.THREAD_STATUS_WAIT, JdiCause.Causes.UNCLAIMED);
				EventIterator it = eventSet.eventIterator();
				while (it.hasNext()) {
					Event nextEvent = it.nextEvent();
					global.processEvent(nextEvent);
					status = DebugStatus.update(processEvent(nextEvent));
				}

				if (status.equals(DebugStatus.GO)) {
					state.set(ThreadReference.THREAD_STATUS_RUNNING, JdiCause.Causes.UNCLAIMED);
					eventSet.resume();
				}
				else if (eventSet.suspendPolicy() == EventRequest.SUSPEND_ALL) {
					setCurrentThread(eventSet);
					for (JdiEventsListener listener : listenersEvent) {
						listener.processStop(eventSet, JdiCause.Causes.UNCLAIMED);
					}
				}
			}
			catch (InterruptedException exc) {
				// Do nothing. Any changes will be seen at top of loop.
			}
			catch (VMDisconnectedException discExc) {
				handleDisconnectedException();
				break;
			}
		}
		synchronized (this) {
			completed = true;
			notifyAll();
		}
	}

	private DebugStatus processEvent(Event event) {
		//System.err.println(event + ":" + vm);
		return switch (event) {
			case ExceptionEvent ev -> processException(ev);
			case BreakpointEvent ev -> processBreakpoint(ev);
			case AccessWatchpointEvent ev -> processAccessWatchpoint(ev);
			case ModificationWatchpointEvent ev -> processWatchpointModification(ev);
			case WatchpointEvent ev -> processWatchpoint(ev);
			case StepEvent ev -> processStep(ev);
			case MethodEntryEvent ev -> processMethodEntry(ev);
			case MethodExitEvent ev -> processMethodExit(ev);
			case MonitorContendedEnteredEvent ev -> processMCEntered(ev);
			case MonitorContendedEnterEvent ev -> processMCEnter(ev);
			case MonitorWaitedEvent ev -> processMonitorWaited(ev);
			case MonitorWaitEvent ev -> processMonitorWait(ev);
			case ClassPrepareEvent ev -> processClassPrepare(ev);
			case ClassUnloadEvent ev -> processClassUnload(ev);
			case ThreadStartEvent ev -> processThreadStart(ev);
			case ThreadDeathEvent ev -> processThreadDeath(ev);
			case VMStartEvent ev -> processVMStart(ev);
			case VMDisconnectEvent ev -> processVMDisconnect(ev);
			case VMDeathEvent ev -> processVMDeath(ev);
			default -> processUnknown(event);
		};
	}

	private DebugStatus processUnknown(Event event) {
		System.err.println("Unknown event: " + event);
		return null;
	}

	private boolean vmDied = false;

	private DebugStatus handleExitEvent(Event event) {
		if (event instanceof VMDeathEvent) {
			vmDied = true;
			return processVMDeath((VMDeathEvent) event);
		}
		else if (event instanceof VMDisconnectEvent) {
			connected = false;
			if (!vmDied) {
				processVMDisconnect((VMDisconnectEvent) event);
			}
			/*
			 * Inform jdb command line processor that jdb is being shutdown. JDK-8154144.
			 */
			DebugStatus status = DebugStatus.NO_CHANGE;
			for (JdiEventsListener listener : listenersEvent) {
				status = update(status, listener.processShutdown(event, JdiCause.Causes.UNCLAIMED));
			}
			return status;
		}
		else {
			throw new InternalError();
		}
	}

	synchronized void handleDisconnectedException() {
		/*
		 * A VMDisconnectedException has happened while dealing with
		 * another event. We need to flush the event queue, dealing only
		 * with exit events (VMDeath, VMDisconnect) so that we terminate
		 * correctly.
		 */
		EventQueue queue = vm.eventQueue();
		while (connected) {
			try {
				EventSet eventSet = queue.remove();
				EventIterator iter = eventSet.eventIterator();
				while (iter.hasNext()) {
					handleExitEvent(iter.next());
				}
			}
			catch (VMDisconnectedException exc) {
				// ignore
			}
			catch (InterruptedException exc) {
				// ignore
			}
			catch (InternalError exc) {
				// ignore
			}
		}
	}

	private ThreadReference eventThread(Event event) {
		if (event instanceof ClassPrepareEvent) {
			return ((ClassPrepareEvent) event).thread();
		}
		else if (event instanceof LocatableEvent) {
			return ((LocatableEvent) event).thread();
		}
		else if (event instanceof ThreadStartEvent) {
			return ((ThreadStartEvent) event).thread();
		}
		else if (event instanceof ThreadDeathEvent) {
			return ((ThreadDeathEvent) event).thread();
		}
		else if (event instanceof VMStartEvent) {
			return ((VMStartEvent) event).thread();
		}
		else {
			return null;
		}
	}

	private void setCurrentThread(EventSet set) {
		ThreadReference thread;
		if (set.size() > 0) {
			/*
			 * If any event in the set has a thread associated with it,
			 * they all will, so just grab the first one.
			 */
			Event event = set.iterator().next(); // Is there a better way?
			thread = eventThread(event);
		}
		else {
			thread = null;
		}
		setCurrentThread(thread);
	}

	private void setCurrentThread(ThreadReference thread) {
		JdiThreadInfo.invalidateAll();
		JdiThreadInfo.setCurrentThread(thread);
	}

	private DebugStatus update(DebugStatus status, DebugStatus update) {
		if (update == null) {
			update = DebugStatus.BREAK;
		}
		return update.equals(DebugStatus.NO_CHANGE) ? status : update;
	}

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processBreakpoint(BreakpointEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.breakpointHit(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for exception events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processException(ExceptionEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.exceptionHit(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for method entry events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processMethodEntry(MethodEntryEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.methodEntry(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for method exit events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processMethodExit(MethodExitEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.methodExit(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for class prepared events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processClassPrepare(ClassPrepareEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.classPrepare(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for class unload events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processClassUnload(ClassUnloadEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.classUnload(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for monitor contended entered events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processMCEntered(MonitorContendedEnteredEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status =
				update(status, listener.monitorContendedEntered(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for monitor contended enter events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processMCEnter(MonitorContendedEnterEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.monitorContendedEnter(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for monitor waited events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processMonitorWaited(MonitorWaitedEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.monitorWaited(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for monitor waited events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processMonitorWait(MonitorWaitEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.monitorWait(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for step events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processStep(StepEvent evt) {
		evt.request().disable();
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.stepComplete(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for watchpoint events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processWatchpoint(WatchpointEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.watchpointHit(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for access watchpoint events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processAccessWatchpoint(AccessWatchpointEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.accessWatchpointHit(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for watchpoint modified events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processWatchpointModification(ModificationWatchpointEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.watchpointModified(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for thread death events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processThreadDeath(ThreadDeathEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.threadExited(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for vm start events
	 * 
	 * @param thread eventThread
	 * @param threadState state
	 * @param reason reason
	 * @return status
	 */
	public DebugStatus processThreadStateChanged(ThreadReference thread, int threadState,
			JdiReason reason) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.threadStateChanged(thread, threadState,
				JdiCause.Causes.UNCLAIMED, reason));
		}
		return status;
	}

	/**
	 * Handler for thread start events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processThreadStart(ThreadStartEvent evt) {
		JdiThreadInfo.addThread(evt.thread());
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.threadStarted(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for vm death events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processVMDeath(VMDeathEvent evt) {
		shutdownMessageKey = "The application exited";
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.vmDied(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for vm disconnect events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processVMDisconnect(VMDisconnectEvent evt) {
		shutdownMessageKey = "The application has been disconnected";
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.vmDisconnected(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	/**
	 * Handler for vm start events
	 * 
	 * @param evt the event
	 * @return status
	 */
	protected DebugStatus processVMStart(VMStartEvent evt) {
		DebugStatus status = DebugStatus.NO_CHANGE;
		for (JdiEventsListener listener : listenersEvent) {
			status = update(status, listener.vmStarted(evt, JdiCause.Causes.UNCLAIMED));
		}
		return status;
	}

	public Integer getState() {
		return state.get();
	}

	public void setState(Integer val, JdiCause cause) {
		state.set(val, cause);
	}

	private Integer stateFilter(Integer cur, Integer set, JdiCause cause) {
		if (set == null) {
			return cur;
		}
		return set;
	}

}
