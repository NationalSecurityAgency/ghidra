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

import java.util.Collection;

import com.sun.jdi.*;
import com.sun.jdi.event.*;

import ghidra.dbg.jdi.manager.breakpoint.JdiBreakpointInfo;

/**
 * An adapter for {@link JdiEventsListener}
 * 
 * This provides an empty default implementation of each method.
 */
public interface JdiEventsListenerAdapter extends JdiEventsListener {

	@Override
	default void vmSelected(VirtualMachine vm, JdiCause cause) {
	}

	@Override
	default void threadSelected(ThreadReference thread, StackFrame frame, JdiCause cause) {
	}

	@Override
	default void threadStateChanged(ThreadReference thread, Integer state, JdiCause cause,
			JdiReason reason) {
	}

	@Override
	default void libraryLoaded(VirtualMachine vm, String name, JdiCause cause) {
	}

	@Override
	default void libraryUnloaded(VirtualMachine vm, String name, JdiCause cause) {
	}

	@Override
	default void breakpointCreated(JdiBreakpointInfo info, JdiCause cause) {
	}

	@Override
	default void breakpointModified(JdiBreakpointInfo newInfo, JdiBreakpointInfo oldInfo,
			JdiCause cause) {
	}

	@Override
	default void breakpointDeleted(JdiBreakpointInfo info, JdiCause cause) {
	}

	@Override
	default void memoryChanged(VirtualMachine vm, long addr, int len, JdiCause cause) {
	}

	@Override
	default void vmInterrupted() {
	}

	@Override
	default void breakpointHit(BreakpointEvent evt, JdiCause cause) {
	}

	@Override
	default void exceptionHit(ExceptionEvent evt, JdiCause cause) {
	}

	@Override
	default void methodEntry(MethodEntryEvent evt, JdiCause cause) {
	}

	@Override
	default void methodExit(MethodExitEvent evt, JdiCause cause) {
	}

	@Override
	default void classPrepare(ClassPrepareEvent evt, JdiCause cause) {
	}

	@Override
	default void classUnload(ClassUnloadEvent evt, JdiCause cause) {
	}

	@Override
	default void monitorContendedEntered(MonitorContendedEnteredEvent evt, JdiCause cause) {
	}

	@Override
	default void monitorContendedEnter(MonitorContendedEnterEvent evt, JdiCause cause) {
	}

	@Override
	default void monitorWaited(MonitorWaitedEvent evt, JdiCause cause) {
	}

	@Override
	default void monitorWait(MonitorWaitEvent evt, JdiCause cause) {
	}

	@Override
	default void stepComplete(StepEvent evt, JdiCause cause) {
	}

	@Override
	default void watchpointHit(WatchpointEvent evt, JdiCause cause) {
	}

	@Override
	default void accessWatchpointHit(AccessWatchpointEvent evt, JdiCause cause) {
	}

	@Override
	default void watchpointModified(ModificationWatchpointEvent evt, JdiCause cause) {
	}

	@Override
	default void threadExited(ThreadDeathEvent evt, JdiCause cause) {
	}

	@Override
	default void threadStarted(ThreadStartEvent evt, JdiCause cause) {
	}

	@Override
	default void vmDied(VMDeathEvent evt, JdiCause cause) {
	}

	@Override
	default void vmDisconnected(VMDisconnectEvent evt, JdiCause cause) {
	}

	@Override
	default void vmStarted(VMStartEvent evt, JdiCause cause) {
	}

	@Override
	default void processStop(EventSet eventSet, JdiCause cause) {
	}

	@Override
	default void processShutdown(Event event, JdiCause cause) {
	}
}
