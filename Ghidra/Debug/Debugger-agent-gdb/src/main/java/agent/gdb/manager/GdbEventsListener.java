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
package agent.gdb.manager;

import java.util.Collection;

import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.manager.reason.GdbReason;

/**
 * A listener for events related to objects known to the manager
 */
public interface GdbEventsListener {

	/**
	 * An inferior has been added to the session
	 * 
	 * @param inferior a handle to the new inferior
	 * @param cause the cause of this event
	 */
	void inferiorAdded(GdbInferior inferior, GdbCause cause);

	/**
	 * An inferior has been removed from the session
	 * 
	 * @param inferiorId the ID of the now-defunct inferior
	 * @param cause the cause of this event
	 */
	void inferiorRemoved(int inferiorId, GdbCause cause);

	/**
	 * A different inferior has been selected (gained focus)
	 * 
	 * @param inferior a handle to the selected inferior
	 * @param cause the cause of this event
	 */
	void inferiorSelected(GdbInferior inferior, GdbCause cause);

	/**
	 * Execution has been started in an inferior
	 * 
	 * @param inferior a handle to the now-executing inferior
	 * @param cause the cause of this event
	 */
	void inferiorStarted(GdbInferior inferior, GdbCause cause);

	/**
	 * Execution has terminated in an inferior
	 * 
	 * @param inferior a handle to the now-stopped inferior
	 * @param cause the cause of this event
	 */
	void inferiorExited(GdbInferior inferior, GdbCause cause);

	/**
	 * An inferior's state has changed
	 * 
	 * Note this event is also parceled out to each affected thread via
	 * {@link #threadStateChanged(GdbThread, GdbState, GdbCause, GdbReason)} immediately after this
	 * callback.
	 * 
	 * @param inf the inferior which is running
	 * @param threads the threads of the inferior whose states have changed
	 * @param state the state to which the inferior changed
	 * @param thread if applicable, the thread which caused the change to {@link GdbState#STOPPED}
	 * @param cause the cause of this event
	 * @param reason the reason for the state change
	 */
	void inferiorStateChanged(GdbInferior inf, Collection<GdbThread> threads, GdbState state,
			GdbThread thread, GdbCause cause, GdbReason reason);

	/**
	 * A thread has been created
	 * 
	 * Use {@link GdbThread#getInferior()} to get a handle to the inferior in which the thread was
	 * created.
	 * 
	 * @param thread a handle to the new thread
	 * @param cause the cause of this event
	 */
	void threadCreated(GdbThread thread, GdbCause cause);

	/**
	 * A thread's state has changed, e.g., {@link GdbState#RUNNING} to {@link GdbState#STOPPED}
	 * 
	 * @param thread a handle to the thread whose state has changed
	 * @param state the state to which the thread changed
	 * @param cause the cause of this event
	 * @param reason the reason for the state change
	 */
	void threadStateChanged(GdbThread thread, GdbState state, GdbCause cause, GdbReason reason);

	/**
	 * A thread has exited
	 * 
	 * @param threadId the ID of the now-defuct thread
	 * @param inferior a handle to the inferior to which the thread belonged
	 * @param cause the cause of this event
	 */
	void threadExited(int threadId, GdbInferior inferior, GdbCause cause);

	/**
	 * A different thread has been selected (gained focus)
	 * 
	 * @param thread a handle to the selected thread
	 * @param frame a handle to the current frame
	 * @param cause the cause of this event
	 */
	void threadSelected(GdbThread thread, GdbStackFrame frame, GdbCause cause);

	/**
	 * A library has been loaded by an inferior
	 * 
	 * @param inferior a handle to the inferior which loaded the library
	 * @param name the name of the library on the target
	 * @param cause the cause of this event
	 */
	void libraryLoaded(GdbInferior inferior, String name, GdbCause cause);

	/**
	 * A library has been unloaded from an inferior
	 * 
	 * @param inferior a handle to the inferior which unloaded the library
	 * @param name the name of the library on the target
	 * @param cause the cause of this event
	 */
	void libraryUnloaded(GdbInferior inferior, String name, GdbCause cause);

	/**
	 * A breakpoint has been created in the session
	 * 
	 * @param info information about the new breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointCreated(GdbBreakpointInfo info, GdbCause cause);

	/**
	 * A breakpoint in the session has been modified
	 * 
	 * @param newInfo new information about the modified breakpoint
	 * @param oldInfo old information about the modified breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointModified(GdbBreakpointInfo newInfo, GdbBreakpointInfo oldInfo, GdbCause cause);

	/**
	 * A breakpoint has been deleted from the session
	 * 
	 * @param info information about the now-deleted breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointDeleted(GdbBreakpointInfo info, GdbCause cause);

	/**
	 * TODO: This is not yet implemented
	 * 
	 * It is not clear whether GDB detects when a target writes into its own memory, or if this
	 * event is emitted when GDB changes the target's memory, or both.
	 * 
	 * @param inferior the inferior whose memory changed
	 * @param addr the address of the change
	 * @param len the length, with the address, bounding the region of change
	 * @param cause the cause of this event
	 */
	void memoryChanged(GdbInferior inferior, long addr, int len, GdbCause cause);
}
