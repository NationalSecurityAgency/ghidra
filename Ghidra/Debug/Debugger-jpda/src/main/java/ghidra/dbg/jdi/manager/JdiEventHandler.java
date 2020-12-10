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

import java.util.concurrent.*;

import org.apache.commons.lang3.exception.ExceptionUtils;

import com.sun.jdi.*;
import com.sun.jdi.event.*;
import com.sun.jdi.request.EventRequest;

import ghidra.async.AsyncReference;
import ghidra.dbg.jdi.manager.impl.DebugStatus;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListenerSet;

public class JdiEventHandler implements Runnable {

	volatile boolean connected = true;
	boolean completed = false;
	String shutdownMessageKey;

	private VirtualMachine vm;
	private Thread thread;
	private JdiEventHandler global;

	protected final AsyncReference<Integer, JdiCause> state =
		new AsyncReference<>(ThreadReference.THREAD_STATUS_NOT_STARTED);
	public final ListenerSet<JdiEventsListener> listenersEvent =
		new ListenerSet<>(JdiEventsListener.class);
	protected final ExecutorService eventThread = Executors.newSingleThreadExecutor();

	public JdiEventHandler() {
	}

	public JdiEventHandler(VirtualMachine vm, JdiEventHandler global) {
		this.vm = vm;
		this.global = global;
		state.filter(this::stateFilter);
	}

	public void start() {
		this.thread = new Thread(this, "event-handler");
		thread.start();
	}

	synchronized void shutdown() {
		connected = false;  // force run() loop termination
		thread.interrupt();
		while (!completed) {
			try {
				wait();
			}
			catch (InterruptedException exc) {
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
					event(
						() -> listenersEvent.fire.processStop(eventSet, JdiCause.Causes.UNCLAIMED),
						"processStopped");
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
		System.err.println(event + ":" + vm);
		if (event instanceof ExceptionEvent) {
			return processException((ExceptionEvent) event);
		}
		else if (event instanceof BreakpointEvent) {
			return processBreakpoint((BreakpointEvent) event);
		}
		else if (event instanceof WatchpointEvent) {
			return processWatchpoint((WatchpointEvent) event);
		}
		else if (event instanceof AccessWatchpointEvent) {
			return processAccessWatchpoint((AccessWatchpointEvent) event);
		}
		else if (event instanceof ModificationWatchpointEvent) {
			return processWatchpointModification((ModificationWatchpointEvent) event);
		}
		else if (event instanceof StepEvent) {
			return processStep((StepEvent) event);
		}
		else if (event instanceof MethodEntryEvent) {
			return processMethodEntry((MethodEntryEvent) event);
		}
		else if (event instanceof MethodExitEvent) {
			return processMethodExit((MethodExitEvent) event);
		}
		else if (event instanceof MonitorContendedEnteredEvent) {
			return processMCEntered((MonitorContendedEnteredEvent) event);
		}
		else if (event instanceof MonitorContendedEnterEvent) {
			return processMCEnter((MonitorContendedEnterEvent) event);
		}
		else if (event instanceof MonitorWaitedEvent) {
			return processMonitorWaited((MonitorWaitedEvent) event);
		}
		else if (event instanceof MonitorWaitEvent) {
			return processMonitorWait((MonitorWaitEvent) event);
		}
		else if (event instanceof ClassPrepareEvent) {
			return processClassPrepare((ClassPrepareEvent) event);
		}
		else if (event instanceof ClassUnloadEvent) {
			return processClassUnload((ClassUnloadEvent) event);
		}
		else if (event instanceof ThreadStartEvent) {
			return processThreadStart((ThreadStartEvent) event);
		}
		else if (event instanceof ThreadDeathEvent) {
			return processThreadDeath((ThreadDeathEvent) event);
		}
		else if (event instanceof VMStartEvent) {
			return processVMStart((VMStartEvent) event);
		}
		else if (event instanceof VMDisconnectEvent) {
			return processVMDisconnect((VMDisconnectEvent) event);
		}
		else if (event instanceof VMDeathEvent) {
			return processVMDeath((VMDeathEvent) event);
		}
		else {
			System.err.println("Unknown event: " + event);
			return null;
		}
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
			event(() -> listenersEvent.fire.processShutdown(event, JdiCause.Causes.UNCLAIMED),
				"processStopped");
			return null; ///false;
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

	/**
	 * Handler for breakpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processBreakpoint(BreakpointEvent evt) {
		event(() -> listenersEvent.fire.breakpointHit(evt, JdiCause.Causes.UNCLAIMED),
			"breakpointHit");
		return DebugStatus.BREAK;
	}

	/**
	 * Handler for exception events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processException(ExceptionEvent evt) {
		event(() -> listenersEvent.fire.exceptionHit(evt, JdiCause.Causes.UNCLAIMED),
			"exceptionHit");
		return DebugStatus.BREAK;
	}

	/**
	 * Handler for method entry events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processMethodEntry(MethodEntryEvent evt) {
		event(() -> listenersEvent.fire.methodEntry(evt, JdiCause.Causes.UNCLAIMED), "methodEntry");
		return DebugStatus.GO;
	}

	/**
	 * Handler for method exit events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processMethodExit(MethodExitEvent evt) {
		event(() -> listenersEvent.fire.methodExit(evt, JdiCause.Causes.UNCLAIMED), "methodExit");
		return DebugStatus.GO;
	}

	/**
	 * Handler for class prepared events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processClassPrepare(ClassPrepareEvent evt) {
		event(() -> listenersEvent.fire.classPrepare(evt, JdiCause.Causes.UNCLAIMED),
			"classPrepare");
		/*
		if (!Env.specList.resolve(cle)) {
		    MessageOutput.lnprint("Stopping due to deferred breakpoint errors.");
		    return true;
		} else {
		    return false;
		}
		*/
		return DebugStatus.GO;
	}

	/**
	 * Handler for class unload events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processClassUnload(ClassUnloadEvent evt) {
		event(() -> listenersEvent.fire.classUnload(evt, JdiCause.Causes.UNCLAIMED), "classUnload");
		return DebugStatus.GO;
	}

	/**
	 * Handler for monitor contended entered events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processMCEntered(MonitorContendedEnteredEvent evt) {
		event(() -> listenersEvent.fire.monitorContendedEntered(evt, JdiCause.Causes.UNCLAIMED),
			"monitorContendedEntered");
		return DebugStatus.GO;
	}

	/**
	 * Handler for monitor contended enter events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processMCEnter(MonitorContendedEnterEvent evt) {
		event(() -> listenersEvent.fire.monitorContendedEnter(evt, JdiCause.Causes.UNCLAIMED),
			"monitorContendedEnter");
		return DebugStatus.GO;
	}

	/**
	 * Handler for monitor waited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processMonitorWaited(MonitorWaitedEvent evt) {
		event(() -> listenersEvent.fire.monitorWaited(evt, JdiCause.Causes.UNCLAIMED),
			"monitorWaited");
		return DebugStatus.GO;
	}

	/**
	 * Handler for monitor waited events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processMonitorWait(MonitorWaitEvent evt) {
		event(() -> listenersEvent.fire.monitorWait(evt, JdiCause.Causes.UNCLAIMED), "monitorWait");
		return DebugStatus.GO;
	}

	/**
	 * Handler for step events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processStep(StepEvent evt) {
		evt.request().disable();
		event(() -> listenersEvent.fire.stepComplete(evt, JdiCause.Causes.UNCLAIMED), "step");
		return DebugStatus.STEP_INTO;
	}

	/**
	 * Handler for watchpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processWatchpoint(WatchpointEvent evt) {
		event(() -> listenersEvent.fire.watchpointHit(evt, JdiCause.Causes.UNCLAIMED),
			"watchpointHit");
		return DebugStatus.BREAK;
	}

	/**
	 * Handler for access watchpoint events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processAccessWatchpoint(AccessWatchpointEvent evt) {
		event(() -> listenersEvent.fire.accessWatchpointHit(evt, JdiCause.Causes.UNCLAIMED),
			"accessWatchpointHit");
		return DebugStatus.BREAK;
	}

	/**
	 * Handler for watchpoint modified events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processWatchpointModification(ModificationWatchpointEvent evt) {
		event(() -> listenersEvent.fire.watchpointModified(evt, JdiCause.Causes.UNCLAIMED),
			"watchpointModified");
		return DebugStatus.GO;
	}

	/**
	 * Handler for thread death events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processThreadDeath(ThreadDeathEvent evt) {
		event(() -> listenersEvent.fire.threadExited(evt, JdiCause.Causes.UNCLAIMED),
			"threadExited");
		JdiThreadInfo.removeThread(evt.thread());
		return DebugStatus.GO;
	}

	/**
	 * Handler for thread start events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processThreadStart(ThreadStartEvent evt) {
		JdiThreadInfo.addThread(evt.thread());
		event(() -> listenersEvent.fire.threadStarted(evt, JdiCause.Causes.UNCLAIMED),
			"threadStarted");
		return DebugStatus.GO;
	}

	/**
	 * Handler for vm death events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processVMDeath(VMDeathEvent evt) {
		shutdownMessageKey = "The application exited";
		event(() -> listenersEvent.fire.vmDied(evt, JdiCause.Causes.UNCLAIMED), "vmDied");
		return DebugStatus.BREAK;
	}

	/**
	 * Handler for vm disconnect events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processVMDisconnect(VMDisconnectEvent evt) {
		shutdownMessageKey = "The application has been disconnected";
		event(() -> listenersEvent.fire.vmDisconnected(evt, JdiCause.Causes.UNCLAIMED),
			"vmDisconnected");
		return DebugStatus.BREAK;
	}

	/**
	 * Handler for vm start events
	 * 
	 * @param evt the event
	 * @param v nothing
	 * @return
	 */
	protected DebugStatus processVMStart(VMStartEvent evt) {
		event(() -> listenersEvent.fire.vmStarted(evt, JdiCause.Causes.UNCLAIMED), "vmStarted");
		return DebugStatus.BREAK;
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
