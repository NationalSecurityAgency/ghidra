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

/**
 * A listener for events related to objects known to the manager
 */
public interface JdiEventsListener {

	/**
	 * A different vm has been selected (gained focus)
	 * 
	 * @param vm a handle to the selected vm
	 * @param cause the cause of this event
	 */
	void vmSelected(VirtualMachine vm, JdiCause cause);

	/**
	 * A different thread has been selected (gained focus)
	 * 
	 * @param thread a handle to the selected thread
	 * @param frame a handle to the current frame
	 * @param cause the cause of this event
	 */
	void threadSelected(ThreadReference thread, StackFrame frame, JdiCause cause);

	/**
	 * A library has been loaded by an vm
	 * 
	 * @param vm a handle to the vm which loaded the library
	 * @param name the name of the library on the target
	 * @param cause the cause of this event
	 */
	void libraryLoaded(VirtualMachine vm, String name, JdiCause cause);

	/**
	 * A library has been unloaded from an vm
	 * 
	 * @param vm a handle to the vm which unloaded the library
	 * @param name the name of the library on the target
	 * @param cause the cause of this event
	 */
	void libraryUnloaded(VirtualMachine vm, String name, JdiCause cause);

	/**
	 * A breakpoint has been created in the session
	 * 
	 * @param info information about the new breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointCreated(JdiBreakpointInfo info, JdiCause cause);

	/**
	 * A breakpoint in the session has been modified
	 * 
	 * @param newInfo new information about the modified breakpoint
	 * @param oldInfo old information about the modified breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointModified(JdiBreakpointInfo newInfo, JdiBreakpointInfo oldInfo, JdiCause cause);

	/**
	 * A breakpoint has been deleted from the session
	 * 
	 * @param info information about the now-deleted breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointDeleted(JdiBreakpointInfo info, JdiCause cause);

	/**
	 * TODO: This is not yet implemented
	 * 
	 * It is not clear whether JDI detects when a target writes into its own memory, or if this
	 * event is emitted when JDI changes the target's memory, or both.
	 * 
	 * @param vm the vm whose memory changed
	 * @param addr the address of the change
	 * @param len the length, with the address, bounding the region of change
	 * @param cause the cause of this event
	 */
	void memoryChanged(VirtualMachine vm, long addr, int len, JdiCause cause);

	void vmInterrupted();

	/**
	 * A breakpoint has been hit
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void breakpointHit(BreakpointEvent evt, JdiCause cause);

	/**
	 * An exception has been hit
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void exceptionHit(ExceptionEvent evt, JdiCause cause);

	/**
	 * A method has been invoked
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void methodEntry(MethodEntryEvent evt, JdiCause cause);

	/**
	 * A method is about to finish
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void methodExit(MethodExitEvent evt, JdiCause cause);

	/**
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void classPrepare(ClassPrepareEvent evt, JdiCause cause);

	/**
	 * A calls is being unloaded
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void classUnload(ClassUnloadEvent evt, JdiCause cause);

	/**
	 * A thread has entered a monitor after release from another thread
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void monitorContendedEntered(MonitorContendedEnteredEvent evt, JdiCause cause);

	/**
	 * A thread is attempting to enter monitor acquired by another thread
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void monitorContendedEnter(MonitorContendedEnterEvent evt, JdiCause cause);

	/**
	 * A vm has finished waiting on a monitor object
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void monitorWaited(MonitorWaitedEvent evt, JdiCause cause);

	/**
	 * A vm is about to wait on a monitor object
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void monitorWait(MonitorWaitEvent evt, JdiCause cause);

	/**
	 * A step has completed
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void stepComplete(StepEvent evt, JdiCause cause);

	/**
	 * A watchpoint has been hit
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void watchpointHit(WatchpointEvent evt, JdiCause cause);

	/**
	 * A field has been accessed
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void accessWatchpointHit(AccessWatchpointEvent evt, JdiCause cause);

	/**
	 * A field has been modified
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void watchpointModified(ModificationWatchpointEvent evt, JdiCause cause);

	/**
	 * A thread has exited
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void threadExited(ThreadDeathEvent evt, JdiCause cause);

	/**
	 * A thread has started
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void threadStarted(ThreadStartEvent evt, JdiCause cause);

	/**
	 * A thread has changed state
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void threadStateChanged(ThreadReference thread, Integer state, JdiCause cause,
			JdiReason reason);

	/**
	 * A vm has exited
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void vmDied(VMDeathEvent evt, JdiCause cause);

	/**
	 * A vm has been disconnected
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void vmDisconnected(VMDisconnectEvent evt, JdiCause cause);

	/**
	 * A vm has started
	 * 
	 * @param evt the triggering event
	 * @param cause the cause of this event
	 */
	void vmStarted(VMStartEvent evt, JdiCause cause);

	void processStop(EventSet eventSet, JdiCause cause);

	void processShutdown(Event event, JdiCause cause);

}
