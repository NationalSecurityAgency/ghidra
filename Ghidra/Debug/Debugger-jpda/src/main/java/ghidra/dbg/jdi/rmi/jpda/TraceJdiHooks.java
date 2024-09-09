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
package ghidra.dbg.jdi.rmi.jpda;

import java.util.*;

import com.sun.jdi.*;
import com.sun.jdi.event.*;

import ghidra.app.plugin.core.debug.client.tracermi.RmiTrace;
import ghidra.app.plugin.core.debug.client.tracermi.RmiTransaction;
import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.manager.impl.DebugStatus;
import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;

class HookState {

	private TraceJdiCommands cmds;
	private Object batch;

	public HookState(TraceJdiCommands cmds) {
		this.cmds = cmds;
		this.batch = null;
	}

	public void ensureBatch() {
		if (batch == null) {
			batch = cmds.state.client.startBatch();
		}
	}

	public void endBatch() {
		if (batch == null) {
			return;
		}
		batch = null;
		cmds.state.client.endBatch();
	}

}

class VmState {

	private TraceJdiManager manager;
	private TraceJdiCommands cmds;
	private boolean firstPass;
	boolean classes;
	boolean modules;
	boolean regions;
	boolean threads;
	boolean breaks;
	boolean events;
	Set<Object> visited;

	public VmState(TraceJdiManager manager) {
		this.manager = manager;
		this.cmds = manager.getCommands();
		this.firstPass = true;
		this.classes = false;
		this.modules = false;
		this.regions = false;
		this.threads = false;
		this.breaks = false;
		this.events = false;
		this.visited = new HashSet<>();
	}

	public void recordState(String description) {
		boolean first = this.firstPass;
		if (description != null) {
			cmds.state.trace.snapshot(description, "", null);
		}
		this.firstPass = false;
		if (first) {
			cmds.putProcesses();
		}

		VirtualMachine vm = manager.getJdi().getCurrentVM();
		cmds.putVM("VMs", vm);
		setState(vm);

		if (first || threads) {
			String path = cmds.getPath(vm);
			cmds.putThreadContainer(path, vm.allThreads(), false);
			cmds.putThreadGroupContainer(path, vm.topLevelThreadGroups());
			threads = false;
		}

		cmds.putCurrentLocation();
		ThreadReference thread = manager.getJdi().getCurrentThread();
		if (thread != null) {
			cmds.createLink(vm, "_event_thread", thread);
			if (first || !visited.contains(thread)) {
				cmds.putFrames();
				visited.add(thread);
			}
			StackFrame frame = manager.getJdi().getCurrentFrame();
			if (frame != null) {
				if (first || !visited.contains(frame)) {
					cmds.putReg(frame);
					visited.add(frame);
				}
			}
		}

		if (classes) {
			classes = false;
			cmds.putReferenceTypeContainer(cmds.getPath(vm) + ".Classes", vm.allClasses());
		}
		if (first || modules) {
			modules = false;
			cmds.putModuleReferenceContainer();
		}
		if (first || breaks) {
			breaks = false;
			cmds.putBreakpoints();
		}
		if (first || events) {
			events = false;
			cmds.putEvents();
		}
	}

	public void setState(VirtualMachine vm) {
		boolean stopped = false;
		for (ThreadReference thread : vm.allThreads()) {
			stopped |= cmds.setStatus(thread, stopped);
		}
		cmds.setStatus(vm, stopped);
		Process process = vm.process();
		if (process != null) {
			cmds.setStatus(process, stopped);
		}
		if (stopped) {
			breaks = true;
			events = true;
		}
	}

	public void recordStateContinued(VirtualMachine vm) {
		Process proc = vm.process();
		String path = cmds.getPath(proc);
		if (path != null) {
			cmds.setValue(path, "Alive", proc.isAlive());
		}
		setState(vm);
	}

	public void recordStateExited(VirtualMachine eventVM, String description) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		String path = cmds.getPath(vm);
		int exitCode = -1;
		try {
			Process process = eventVM.process();
			if (process != null) {
				exitCode = process.exitValue();
				String procpath = cmds.getPath(vm.process());
				cmds.setValue(procpath, "ExitCode", exitCode);
				cmds.setValue(procpath, TraceJdiManager.STATE_ATTRIBUTE_NAME, "TERMINATED");
			}
		}
		catch (IllegalThreadStateException e) {
			// IGNORE
		}
		if (description != null) {
			cmds.state.trace.snapshot(description, "", null);
		}
		cmds.setValue(path, "ExitCode", exitCode);
		cmds.setValue(path, TraceJdiManager.STATE_ATTRIBUTE_NAME, "TERMINATED");
	}

}

public class TraceJdiHooks implements JdiEventsListenerAdapter {

	private TraceJdiManager manager;
	private TraceJdiCommands cmds;
	private HookState hookState;
	private Map<VirtualMachine, VmState> vmStates = new HashMap<>();

	public TraceJdiHooks(TraceJdiManager manager) {
		this.manager = manager;
		this.cmds = manager.getCommands();
	}

	private void setCommands(TraceJdiCommands commands) {
		this.cmds = commands;
		hookState = new HookState(commands);
	}

	@Override
	public DebugStatus vmStarted(VMStartEvent event, JdiCause cause) {
		setCommands(manager.getCommands());
		hookState.ensureBatch();
		RmiTrace trace = cmds.state.trace;
		JdiManagerImpl jdi = manager.getJdi();
		VirtualMachine vm = event == null ? jdi.getCurrentVM() : event.virtualMachine();
		try (RmiTransaction tx = trace.openTx("New VM " + vm.description())) {
			jdi.setCurrentVM(vm);
			jdi.addVM(vm);
			cmds.putVMs();
			enableCurrentVM();
		}
		hookState.endBatch();
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus vmDied(VMDeathEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("VMDeathEvent");
	}

	@Override
	public DebugStatus vmDisconnected(VMDisconnectEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		VirtualMachine eventVM = evt.virtualMachine();
		VmState state = vmStates.get(eventVM);
		try (RmiTransaction tx = trace.openTx("VM disconnected: " + eventVM.description())) {
			state.recordStateExited(eventVM, "VM disconnected");
		}
		disableCurrentVM();
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus threadStarted(ThreadStartEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("ThreadStartEvent");
	}

	@Override
	public DebugStatus threadExited(ThreadDeathEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("ThreadDeathEvent");
	}

	@Override
	public DebugStatus stepComplete(StepEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return DebugStatus.BREAK;
	}

	@Override
	public DebugStatus breakpointHit(BreakpointEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return DebugStatus.BREAK;
	}

	@Override
	public DebugStatus accessWatchpointHit(AccessWatchpointEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return DebugStatus.BREAK;
	}

	@Override
	public DebugStatus watchpointHit(WatchpointEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return DebugStatus.BREAK;
	}

	@Override
	public DebugStatus watchpointModified(ModificationWatchpointEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return DebugStatus.BREAK;
	}

	@Override
	public DebugStatus exceptionHit(ExceptionEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("ExceptionEvent");
	}

	@Override
	public DebugStatus methodEntry(MethodEntryEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("MethodEntryEvent");
	}

	@Override
	public DebugStatus methodExit(MethodExitEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("MethodExitEvent");
	}

	@Override
	public DebugStatus classPrepare(ClassPrepareEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("ClassPrepareEvent");
	}

	@Override
	public DebugStatus classUnload(ClassUnloadEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("ClassUnloadEvent");
	}

	@Override
	public DebugStatus monitorContendedEnter(MonitorContendedEnterEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("MonitorContendedEnterEvent");
	}

	@Override
	public DebugStatus monitorContendedEntered(MonitorContendedEnteredEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("MonitorContendedEnteredEvent");
	}

	@Override
	public DebugStatus monitorWait(MonitorWaitEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("MonitorWaitEvent");
	}

	@Override
	public DebugStatus monitorWaited(MonitorWaitedEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return manager.getReturnStatus("MonitorWaitedEvent");
	}

	@Override
	public DebugStatus threadStateChanged(ThreadReference thread, Integer state, JdiCause cause,
			JdiReason reason) {
		return DebugStatus.NO_CHANGE;
	}

	void onStop(Event evt, RmiTrace trace) {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		if (evt != null) {
			setCurrent(evt);
			vm = evt.virtualMachine();
		}
		VmState state = vmStates.get(vm);
		state.visited.clear();
		hookState.ensureBatch();
		try (RmiTransaction tx = trace.openTx("Stopped")) {
			state.recordState("Stopped");
			cmds.activate(null);
		}
		hookState.endBatch();
	}

	private void setCurrent(Event event) {
		VirtualMachine eventVM = event.virtualMachine();
		JdiManagerImpl jdi = manager.getJdi();
		jdi.setCurrentEvent(event);
		jdi.setCurrentVM(eventVM);
		if (event instanceof LocatableEvent locEvt) {
			jdi.setCurrentLocation(locEvt.location());
			ThreadReference eventThread = locEvt.thread();
			jdi.setCurrentThread(eventThread);
			try {
				jdi.setCurrentFrame(eventThread.frame(0));
			}
			catch (IncompatibleThreadStateException e) {
				// IGNORE
			}
		}
	}

	void onContinue() {
		VirtualMachine currentVM = manager.getJdi().getCurrentVM();
		VmState state = vmStates.get(currentVM);
		hookState.ensureBatch();
		try (RmiTransaction tx = cmds.state.trace.openTx("Continue")) {
			state.recordStateContinued(currentVM);
			cmds.activate(null);
		}
		hookState.endBatch();
	}

	public void installHooks() {
		manager.getJdi().addEventsListener(null, this);
	}

	public void removeHooks() {
		manager.getJdi().removeEventsListener(null, this);
	}

	public void enableCurrentVM() {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		VmState state = new VmState(manager);
		vmStates.put(vm, state);
		state.recordState("VM started");
		cmds.activate(null);
	}

	public void disableCurrentVM() {
		VirtualMachine vm = manager.getJdi().getCurrentVM();
		VmState state = vmStates.get(vm);
		state.visited.clear();
		vmStates.remove(vm);
		vm.dispose();
	}

	public void setState(VirtualMachine vm) {
		VmState state = vmStates.get(vm);
		state.setState(vm);
	}

}
