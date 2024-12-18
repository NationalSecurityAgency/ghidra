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

import static ghidra.dbg.jdi.rmi.jpda.JdiConnector.*;

import java.util.*;

import com.sun.jdi.*;
import com.sun.jdi.event.*;

import ghidra.app.plugin.core.debug.client.tracermi.*;
import ghidra.dbg.jdi.manager.*;
import ghidra.dbg.jdi.manager.impl.DebugStatus;
import ghidra.dbg.jdi.manager.impl.JdiManagerImpl;

class HookState {

	private JdiCommands cmds;

	public HookState(JdiCommands cmds) {
		this.cmds = cmds;
	}

	public RmiBatch batch() {
		return cmds.state.client.startBatch();
	}
}

class VmState {

	private JdiConnector connector;
	private JdiCommands cmds;
	private boolean firstPass;
	boolean classes;
	boolean modules;
	boolean regions;
	boolean threads;
	boolean breaks;
	boolean events;
	Set<Object> visited;

	public VmState(JdiConnector connector) {
		this.connector = connector;
		this.cmds = connector.getCommands();
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

		VirtualMachine vm = connector.getJdi().getCurrentVM();
		cmds.putVM("VMs", vm);
		setState(vm);

		if (first || threads) {
			String path = cmds.getPath(vm);
			cmds.putThreadContainer(path, vm.allThreads(), false);
			cmds.putThreadGroupContainer(path, vm.topLevelThreadGroups());
			threads = false;
		}

		cmds.putCurrentLocation();
		ThreadReference thread = connector.getJdi().getCurrentThread();
		if (thread != null) {
			cmds.createLink(vm, "_event_thread", thread);
			if (first || !visited.contains(thread)) {
				cmds.putFrames();
				visited.add(thread);
			}
			StackFrame frame = connector.getJdi().getCurrentFrame();
			if (frame != null) {
				try {
					if (first || !visited.contains(frame)) {
						cmds.putReg(frame);
						visited.add(frame);
					}
				}
				catch (InvalidStackFrameException e) {
					connector.getJdi().setCurrentFrame(null);
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
			cmds.setValue(path, ATTR_ALIVE, proc.isAlive());
		}
		setState(vm);
	}

	public void recordStateExited(VirtualMachine eventVM, String description) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		String path = cmds.getPath(vm);
		int exitCode = -1;
		try {
			Process process = eventVM.process();
			if (process != null) {
				exitCode = process.exitValue();
				String procpath = cmds.getPath(vm.process());
				cmds.setValue(procpath, ATTR_EXIT_CODE, exitCode);
				cmds.setValue(procpath, ATTR_STATE, "TERMINATED");
			}
		}
		catch (IllegalThreadStateException e) {
			// IGNORE
		}
		if (description != null) {
			cmds.state.trace.snapshot(description, "", null);
		}
		cmds.setValue(path, ATTR_EXIT_CODE, exitCode);
		cmds.setValue(path, ATTR_STATE, "TERMINATED");
	}

}

public class JdiHooks implements JdiEventsListenerAdapter {

	private JdiConnector connector;
	private JdiCommands cmds;
	private HookState hookState;
	private Map<VirtualMachine, VmState> vmStates = new HashMap<>();

	public JdiHooks(JdiConnector connector, JdiCommands cmds) {
		this.connector = connector;
		this.cmds = cmds;
	}

	private void setCommands(JdiCommands commands) {
		this.cmds = commands;
		hookState = new HookState(commands);
	}

	@Override
	public DebugStatus vmStarted(VMStartEvent event, JdiCause cause) {
		setCommands(connector.getCommands());
		JdiManagerImpl jdi = connector.getJdi();
		VirtualMachine vm = event == null ? jdi.getCurrentVM() : event.virtualMachine();
		jdi.setCurrentVM(vm);
		jdi.addVM(vm);
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		try (RmiBatch batch = hookState.batch();
				RmiTransaction tx = trace.openTx("New VM " + vm.description())) {
			cmds.putVMs();
			enableCurrentVM();
		}
		return DebugStatus.NO_CHANGE;
	}

	@Override
	public DebugStatus vmDied(VMDeathEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("VMDeathEvent");
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
		return connector.getReturnStatus("ThreadStartEvent");
	}

	@Override
	public DebugStatus threadExited(ThreadDeathEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("ThreadDeathEvent");
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
		return connector.getReturnStatus("ExceptionEvent");
	}

	@Override
	public DebugStatus methodEntry(MethodEntryEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("MethodEntryEvent");
	}

	@Override
	public DebugStatus methodExit(MethodExitEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("MethodExitEvent");
	}

	@Override
	public DebugStatus classPrepare(ClassPrepareEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("ClassPrepareEvent");
	}

	@Override
	public DebugStatus classUnload(ClassUnloadEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("ClassUnloadEvent");
	}

	@Override
	public DebugStatus monitorContendedEnter(MonitorContendedEnterEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("MonitorContendedEnterEvent");
	}

	@Override
	public DebugStatus monitorContendedEntered(MonitorContendedEnteredEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("MonitorContendedEnteredEvent");
	}

	@Override
	public DebugStatus monitorWait(MonitorWaitEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("MonitorWaitEvent");
	}

	@Override
	public DebugStatus monitorWaited(MonitorWaitedEvent evt, JdiCause cause) {
		RmiTrace trace = cmds.state.trace;
		if (trace == null) {
			return DebugStatus.NO_CHANGE;
		}
		onStop(evt, trace);
		return connector.getReturnStatus("MonitorWaitedEvent");
	}

	@Override
	public DebugStatus threadStateChanged(ThreadReference thread, Integer state, JdiCause cause,
			JdiReason reason) {
		return DebugStatus.NO_CHANGE;
	}

	void onStop(Event evt, RmiTrace trace) {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		if (evt != null) {
			setCurrent(evt);
			vm = evt.virtualMachine();
		}
		VmState state = vmStates.get(vm);
		state.visited.clear();
		try (RmiBatch batch = hookState.batch();
				RmiTransaction tx = trace.openTx("Stopped")) {
			state.recordState("Stopped");
			cmds.activate(null);
		}
	}

	private void setCurrent(Event event) {
		VirtualMachine eventVM = event.virtualMachine();
		JdiManagerImpl jdi = connector.getJdi();
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
		VirtualMachine currentVM = connector.getJdi().getCurrentVM();
		VmState state = vmStates.get(currentVM);
		try (RmiBatch batch = hookState.batch();
				RmiTransaction tx = cmds.state.trace.openTx("Continue")) {
			state.recordStateContinued(currentVM);
			cmds.activate(null);
		}
	}

	public void installHooks() {
		connector.getJdi().addEventsListener(null, this);
	}

	public void removeHooks() {
		connector.getJdi().removeEventsListener(null, this);
	}

	public void enableCurrentVM() {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
		VmState state = new VmState(connector);
		vmStates.put(vm, state);
		state.recordState("VM started");
		cmds.activate(null);
	}

	public void disableCurrentVM() {
		VirtualMachine vm = connector.getJdi().getCurrentVM();
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
