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

import java.util.Map;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugSessionId;

public interface DbgSession {

	/**
	 * Get the dbgeng-assigned session number
	 * 
	 * @return the number
	 */
	DebugSessionId getId();

	/**
	 * If exited (implying a previous start), get the session exit code
	 * 
	 * This may be slightly system-dependent, as the exit code may specify either the status of a
	 * normal exit, or the cause of an abnormal exit.
	 * 
	 * @return the exit code
	 */
	Long getExitCode();

	/**
	 * Get a process belonging to this session
	 * 
	 * dbgeng (at least recent versions) numbers its processes using a global counter. The process
	 * ID is this number, not the OS-assigned TID.
	 * 
	 * @param id the dbgeng-assigned process ID
	 * @return a handle to the process, if it exists
	 */
	DbgProcess getProcess(DebugProcessId id);

	/**
	 * Enumerate the processes known to the manager to belong to this session
	 * 
	 * This does not send any commands to dbgeng. Rather it simply returns a read-only handle to the
	 * manager's internal map for tracking processes and sessions.
	 * 
	 * @return a map of dbgeng-assigned process IDs to process handles
	 */
	Map<DebugProcessId, DbgProcess> getKnownProcesses();

	/**
	 * List Dbg's processes in this session
	 * 
	 * This is equivalent to the CLI command: {@code info processes}.
	 * 
	 * @return a future that completes with a map of global process IDs to process handles
	 */
	CompletableFuture<Map<DebugProcessId, DbgProcess>> listProcesses();

}
