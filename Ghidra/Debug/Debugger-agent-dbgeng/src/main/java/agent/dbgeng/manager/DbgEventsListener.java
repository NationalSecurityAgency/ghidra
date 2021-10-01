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
package agent.dbgeng.manager;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.evt.AbstractDbgEvent;

public interface DbgEventsListener {

	/**
	 * A session has been added
	 * 
	 * @param session a handle to the new session
	 * @param cause the cause of this event
	 */
	void sessionAdded(DbgSession session, DbgCause cause);

	/**
	 * A session has been removed
	 * 
	 * @param sessionId the ID of the now-defunct session
	 * @param cause the cause of this event
	 */
	void sessionRemoved(DebugSessionId sessionId, DbgCause cause);

	/**
	 * A different session has been selected (gained focus)
	 * 
	 * @param session a handle to the selected session
	 * @param cause the cause of this event
	 */
	void sessionSelected(DbgSession session, DbgCause cause);

	/**
	 * An Process has been added to the session
	 * 
	 * @param process a handle to the new process
	 * @param cause the cause of this event
	 */
	void processAdded(DbgProcess process, DbgCause cause);

	/**
	 * An process has been removed from the session
	 * 
	 * @param processId the ID of the now-defunct process
	 * @param cause the cause of this event
	 */
	void processRemoved(DebugProcessId processId, DbgCause cause);

	/**
	 * A different process has been selected (gained focus)
	 * 
	 * @param process a handle to the selected process
	 * @param cause the cause of this event
	 */
	void processSelected(DbgProcess process, DbgCause cause);

	/**
	 * Execution has been started in an process
	 * 
	 * @param process a handle to the now-executing process
	 * @param cause the cause of this event
	 */
	void processStarted(DbgProcess process, DbgCause cause);

	/**
	 * Execution has terminated in an process
	 * 
	 * @param process a handle to the now-stopped process
	 * @param cause the cause of this event
	 */
	void processExited(DbgProcess process, DbgCause cause);

	/**
	 * A thread has been created
	 * 
	 * Use {@link DbgThread#getProcess()} to get a handle to the process in which the thread was
	 * created.
	 * 
	 * @param thread a handle to the new thread
	 * @param cause the cause of this event
	 */
	void threadCreated(DbgThread thread, DbgCause cause);

	/**
	 * A thread's state has changed, e.g., {@link DbgState#RUNNING} to {@link DbgState#STOPPED}
	 * 
	 * @param thread a handle to the thread whose state has changed
	 * @param state the state to which the thread changed
	 * @param cause the cause of this event
	 * @param reason the reason for the state change
	 */
	void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause, DbgReason reason);

	/**
	 * A thread has exited
	 * 
	 * @param threadId the ID of the now-defuct thread
	 * @param process a handle to the process to which the thread belonged
	 * @param cause the cause of this event
	 */
	void threadExited(DebugThreadId threadId, DbgProcess process, DbgCause cause);

	/**
	 * A different thread has been selected (gained focus)
	 * 
	 * @param thread a handle to the selected thread
	 * @param frame a handle to the current frame
	 * @param cause the cause of this event
	 */
	void threadSelected(DbgThread thread, DbgStackFrame frame, DbgCause cause);

	/**
	 * A system event has occurred (gained focus)
	 * 
	 * @param event a handle to the current event
	 * @param cause the cause of this event
	 */
	void eventSelected(AbstractDbgEvent<?> event, DbgCause cause);

	/**
	 * A module has been loaded by an process
	 * 
	 * @param process a handle to the process which loaded the module
	 * @param name the name of the module on the target
	 * @param cause the cause of this event
	 */
	void moduleLoaded(DbgProcess process, DebugModuleInfo info, DbgCause cause);

	/**
	 * A module has been unloaded from an process
	 * 
	 * @param process a handle to the process which unloaded the module
	 * @param name the name of the module on the target
	 * @param cause the cause of this event
	 */
	void moduleUnloaded(DbgProcess process, DebugModuleInfo info, DbgCause cause);

	/**
	 * A breakpoint has been created in the session
	 * 
	 * @param info information about the new breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointCreated(DbgBreakpointInfo info, DbgCause cause);

	/**
	 * A breakpoint in the session has been modified
	 * 
	 * @param newInfo new information about the modified breakpoint
	 * @param oldInfo old information about the modified breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointModified(DbgBreakpointInfo newInfo, DbgBreakpointInfo oldInfo, DbgCause cause);

	/**
	 * A breakpoint has been deleted from the session
	 * 
	 * @param info information about the now-deleted breakpoint
	 * @param cause the cause of this event
	 */
	void breakpointDeleted(DbgBreakpointInfo info, DbgCause cause);

	/**
	 * A breakpoint was hit in the session
	 * 
	 * @param info information about the breakpoint hit
	 * @param cause the cause of this event
	 */
	void breakpointHit(DbgBreakpointInfo info, DbgCause cause);

	/**
	 * A breakpoint has effectively been applied to an process
	 * 
	 * dbgeng has a robust (read "complicated") breakpoint model. A breakpoint may apply to multiple
	 * processes, and even within a single process, it may have multiple locations. Consider, e.g.,
	 * an inlined function or a C++ template function. If the breakpoint is specified as a line
	 * number, it may correspond to several locations in the compiled binary. Worse yet, a
	 * breakpoint may be pending, meaning its specification is ambiguous from not having a target
	 * file. Once a file is loaded, which may be an program, or a shared library loaded during the
	 * execution of a program, that matches the specification, the breakpoint is resolved to one or
	 * more locations. Even worse yet, if another library gets loaded that also matches the
	 * specification, new locations may be appended.
	 * 
	 * Thus, the dbgeng manager attempts to interpret the information about a breakpoint provided by
	 * dbgeng and builds a set of "effective breakpoints" each corresponding to a single location in
	 * a single process image, i.e., process. Consider for example: A new library is loaded and an
	 * existing dbgeng breakpoint must be applied within. dbgeng will emit a breakpoint modified
	 * event, which the manager will parse and pass to
	 * {@link #breakpointModified(DbgBreakpointInfo, DbgBreakpointInfo, DbgCause)}. The manager will
	 * also interpret that event and, seeing a new location, emit an
	 * {@link #effectiveBreakpointCreated(DbgProcess, DbgEffectiveBreakpoint, DbgCause)} event.
	 * 
	 * @param process a handle to the process to which the breakpoint has been applied
	 * @param newBkpt information about the effective breakpoint
	 * @param cause the cause of this event
	 */
	//void effectiveBreakpointCreated(DbgProcess process, DbgEffectiveBreakpoint newBkpt,
	//		DbgCause cause);

	/**
	 * An effective breakpoint has been modified within an process
	 * 
	 * @param process a handle to the process to which the modified effective breakpoint applies
	 * @param newBkpt information about the new effective breakpoint
	 * @param oldBkpt information about the old effective breakpoint
	 * @param cause the cause of this event
	 * @see #effectiveBreakpointCreated(DbgProcess, DbgEffectiveBreakpoint, DbgCause)
	 */
	//void effectiveBreakpointModified(DbgProcess process, DbgEffectiveBreakpoint newBkpt,
	//		DbgEffectiveBreakpoint oldBkpt, DbgCause cause);

	/**
	 * An effective breakpoint has been deleted from an process
	 * 
	 * @param process a handle to the process from which the effective breakpoint was deleted
	 * @param oldBkpt information about the now-deleted effective breakpoint
	 * @param cause the cause of this event
	 * @see #effectiveBreakpointCreated(DbgProcess, DbgEffectiveBreakpoint, DbgCause)
	 */
	//void effectiveBreakpointDeleted(DbgProcess process, DbgEffectiveBreakpoint oldBkpt,
	//		DbgCause cause);

	/**
	 * TODO: This is not yet implemented
	 * 
	 * It is not clear whether dbgeng detects when a target writes into its own memory, or if this
	 * event is emitted when dbgeng changes the target's memory, or both.
	 * 
	 * @param process the process whose memory changed
	 * @param addr the address of the change
	 * @param len the length, with the address, bounding the region of change
	 * @param cause the cause of this event
	 */
	void memoryChanged(DbgProcess process, long addr, int len, DbgCause cause);

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
