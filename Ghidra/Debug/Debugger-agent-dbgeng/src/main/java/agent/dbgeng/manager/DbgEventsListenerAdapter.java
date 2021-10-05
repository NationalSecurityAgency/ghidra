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

public interface DbgEventsListenerAdapter extends DbgEventsListener {

	@Override
	public default void sessionAdded(DbgSession session, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void sessionRemoved(DebugSessionId sessionId, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void sessionSelected(DbgSession session, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void processAdded(DbgProcess process, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void processRemoved(DebugProcessId processId, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void processSelected(DbgProcess process, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void processStarted(DbgProcess process, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void processExited(DbgProcess process, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void threadCreated(DbgThread thread, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void threadStateChanged(DbgThread thread, DbgState state, DbgCause cause,
			DbgReason reason) {
		// Extension point
	}

	@Override
	public default void threadExited(DebugThreadId threadId, DbgProcess process, DbgCause cause) {
		// Extension point

	}

	@Override
	public default void threadSelected(DbgThread thread, DbgStackFrame frame, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void eventSelected(AbstractDbgEvent<?> event, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void moduleLoaded(DbgProcess process, DebugModuleInfo info, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void moduleUnloaded(DbgProcess process, DebugModuleInfo info, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointCreated(DbgBreakpointInfo info, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointModified(DbgBreakpointInfo newInfo, DbgBreakpointInfo oldInfo,
			DbgCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointDeleted(DbgBreakpointInfo info, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void breakpointHit(DbgBreakpointInfo info, DbgCause cause) {
		// Extension point
	}

	/*
	@Override
	public default void effectiveBreakpointCreated(DbgProcess process,
			DbgEffectiveBreakpoint newBkpt, DbgCause cause) {
		// Extension point
	}
	
	@Override
	public default void effectiveBreakpointModified(DbgProcess process,
			DbgEffectiveBreakpoint newBkpt, DbgEffectiveBreakpoint oldBkpt, DbgCause cause) {
		// Extension point
	}
	
	@Override
	public default void effectiveBreakpointDeleted(DbgProcess process,
			DbgEffectiveBreakpoint oldBkpt, DbgCause cause) {
		// Extension point
	}
	*/

	@Override
	public default void memoryChanged(DbgProcess process, long addr, int len, DbgCause cause) {
		// Extension point
	}

	@Override
	public default void consoleOutput(String output, int mask) {
		// Extension point
	}

	@Override
	public default void promptChanged(String prompt) {
		// Extension point
	}

}
