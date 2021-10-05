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
package agent.lldb.manager;

import SWIG.*;
import agent.lldb.lldb.DebugModuleInfo;

public interface LldbEventsListener {

	/**
	 * A session has been added
	 * 
	 * @param session a handle to the new session
	 * @param cause the cause of this event
	 */
	void sessionAdded(SBTarget session, LldbCause cause);

	/**
	 * A session has been replaced
	 * 
	 * @param session a handle to the new session
	 * @param cause the cause of this event
	 */
	void sessionReplaced(SBTarget session, LldbCause cause);

	/**
	 * A session has been removed
	 * 
	 * @param sessionId the ID of the now-defunct session
	 * @param cause the cause of this event
	 */
	void sessionRemoved(String sessionId, LldbCause cause);

	/**
	 * A different session has been selected (gained focus)
	 * 
	 * @param session a handle to the selected session
	 * @param cause the cause of this event
	 */
	void sessionSelected(SBTarget session, LldbCause cause);

	/**
	 * An Process has been added to the session
	 * 
	 * @param process a handle to the new process
	 * @param cause the cause of this event
	 */
	void processAdded(SBProcess process, LldbCause cause);

	/**
	 * An Process has been replaced in the session
	 * 
	 * @param process a handle to the new process
	 * @param cause the cause of this event
	 */
	void processReplaced(SBProcess process, LldbCause cause);

	/**
	 * An process has been removed from the session
	 * 
	 * @param processId the ID of the now-defunct process
	 * @param cause the cause of this event
	 */
	void processRemoved(String processId, LldbCause cause);

	/**
	 * A different process has been selected (gained focus)
	 * 
	 * @param process a handle to the selected process
	 * @param cause the cause of this event
	 */
	void processSelected(SBProcess process, LldbCause cause);

	/**
	 * Execution has been started in an process
	 * 
	 * @param process a handle to the now-executing process
	 * @param cause the cause of this event
	 */
	void processStarted(SBProcess process, LldbCause cause);

	/**
	 * Execution has terminated in an process
	 * 
	 * @param process a handle to the now-stopped process
	 * @param cause the cause of this event
	 */
	void processExited(SBProcess process, LldbCause cause);

	/**
	 * A thread has been created
	 * 
	 * Use {@link LldbThread#getProcess()} to get a handle to the process in which the thread was
	 * created.
	 * 
	 * @param thread a handle to the new thread
	 * @param cause the cause of this event
	 */
	void threadCreated(SBThread thread, LldbCause cause);

	/**
	 * A thread has been replaced
	 * 
	 * Use {@link LldbThread#getProcess()} to get a handle to the process in which the thread was
	 * created.
	 * 
	 * @param thread a handle to the new thread
	 * @param cause the cause of this event
	 */
	void threadReplaced(SBThread thread, LldbCause cause);

	/**
	 * A thread's state has changed, e.g., {@link LldbState#RUNNING} to
	 * {@link LldbState#STOPPED}
	 * 
	 * @param thread a handle to the thread whose state has changed
	 * @param state the state to which the thread changed
	 * @param cause the cause of this event
	 * @param reason the reason for the state change
	 */
	void threadStateChanged(SBThread thread, StateType state, LldbCause cause, LldbReason reason);

	/**
	 * A thread has exited
	 * 
	 * @param threadId the ID of the now-defuct thread
	 * @param process a handle to the process to which the thread belonged
	 * @param cause the cause of this event
	 */
	void threadExited(SBThread thread, SBProcess process, LldbCause cause);

	/**
	 * A different thread has been selected (gained focus)
	 * 
	 * @param thread a handle to the selected thread
	 * @param frame a handle to the current frame
	 * @param cause the cause of this event
	 */
	void threadSelected(SBThread thread, SBFrame frame, LldbCause cause);

	/**
	 * A module has been loaded by an process
	 * 
	 * @param process a handle to the process which loaded the module
	 * @param name the name of the module on the target
	 * @param cause the cause of this event
	 */
	void moduleLoaded(SBProcess process, DebugModuleInfo info, int index, LldbCause cause);

	/**
	 * A module has been unloaded from an process
	 * 
	 * @param process a handle to the process which unloaded the module
	 * @param name the name of the module on the target
	 * @param cause the cause of this event
	 */
	void moduleUnloaded(SBProcess process, DebugModuleInfo info, int index, LldbCause cause);

	/**
	 * A breakpoint has been created in the session
	 * 
	 * @param info information about the new breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointCreated(Object info, LldbCause cause);

	/**
	 * A breakpoint in the session has been modified
	 * 
	 * @param newInfo new information about the modified breakpoint
	 * @param oldInfo old information about the modified breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointModified(Object info, LldbCause cause);

	/**
	 * A breakpoint has been deleted from the session
	 * 
	 * @param info information about the now-deleted breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointDeleted(Object info, LldbCause cause);

	/**
	 * A breakpoint was hit in the session
	 * 
	 * @param info information about the breakpoint hit
	 * @param cause the cause of this event
	 */
	void breakpointHit(Object info, LldbCause cause);

	/**
	 * TODO: This is not yet implemented
	 * 
	 * It is not clear whether lldb detects when a target writes into its own memory, or if this
	 * event is emitted when lldb changes the target's memory, or both.
	 * 
	 * @param process the process whose memory changed
	 * @param addr the address of the change
	 * @param len the length, with the address, bounding the region of change
	 * @param cause the cause of this event
	 */
	void memoryChanged(SBProcess process, long addr, int len, LldbCause cause);

	/**
	 * @param output console output
	 * @param mask class of output
	 */
	void consoleOutput(String output, int mask);

	/**
	 * @param prompt for console output
	 */
	void promptChanged(String prompt);

}
