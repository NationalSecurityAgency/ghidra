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

import com.sun.jdi.*;
import com.sun.jdi.event.*;

import ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointInfo;
import ghidra.dbg.jdi.manager.impl.DebugStatus;

/**
 * An adapter for {@link JdiEventsListener}
 * 
 * This provides an empty default implementation of each method.
 */
public interface JdiEventsListenerAdapter extends JdiEventsListener {

	@Override
	default DebugStatus vmSelected(VirtualMachine vm, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus threadSelected(ThreadReference thread, StackFrame frame, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus threadStateChanged(ThreadReference thread, Integer state, JdiCause cause,
			JdiReason reason) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus classLoaded(VirtualMachine vm, String name, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus classUnloaded(VirtualMachine vm, String name, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus breakpointCreated(JdiBreakpointInfo info, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus breakpointModified(JdiBreakpointInfo newInfo, JdiBreakpointInfo oldInfo,
			JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus breakpointDeleted(JdiBreakpointInfo info, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus memoryChanged(VirtualMachine vm, long addr, int len, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus vmInterrupted() {
		return DebugStatus.BREAK;
	}

	@Override
	default DebugStatus breakpointHit(BreakpointEvent evt, JdiCause cause) {
		return DebugStatus.BREAK;
	}

	@Override
	default DebugStatus exceptionHit(ExceptionEvent evt, JdiCause cause) {
		return DebugStatus.BREAK;
	}

	@Override
	default DebugStatus methodEntry(MethodEntryEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus methodExit(MethodExitEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus classPrepare(ClassPrepareEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus classUnload(ClassUnloadEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus monitorContendedEntered(MonitorContendedEnteredEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus monitorContendedEnter(MonitorContendedEnterEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus monitorWaited(MonitorWaitedEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus monitorWait(MonitorWaitEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus stepComplete(StepEvent evt, JdiCause cause) {
		return DebugStatus.STEP_INTO;
	}

	@Override
	default DebugStatus watchpointHit(WatchpointEvent evt, JdiCause cause) {
		return DebugStatus.BREAK;
	}

	@Override
	default DebugStatus accessWatchpointHit(AccessWatchpointEvent evt, JdiCause cause) {
		return DebugStatus.BREAK;
	}

	@Override
	default DebugStatus watchpointModified(ModificationWatchpointEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus threadExited(ThreadDeathEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus threadStarted(ThreadStartEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus vmDied(VMDeathEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus vmDisconnected(VMDisconnectEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus vmStarted(VMStartEvent evt, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}

	@Override
	default DebugStatus processStop(EventSet eventSet, JdiCause cause) {
		return DebugStatus.BREAK;
	}

	@Override
	default DebugStatus processShutdown(Event event, JdiCause cause) {
		return DebugStatus.NO_CHANGE;
	}
}
