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
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import agent.dbgeng.dbgeng.DebugProcessId;
import agent.dbgeng.dbgeng.DebugThreadId;
import agent.dbgeng.manager.DbgManager.ExecSuffix;
import agent.dbgeng.manager.impl.DbgSectionImpl;
import ghidra.dbg.target.TargetAttachable;

public interface DbgProcess extends DbgMemoryOperations {

	/**
	 * Get the dbgeng-assigned process number
	 * 
	 * @return the number
	 */
	DebugProcessId getId();

	/**
	 * If started, get the OS-assigned ID of the process
	 * 
	 * @return the process ID
	 */
	Long getPid();

	/**
	 * If exited (implying a previous start), get the process exit code
	 * 
	 * This may be slightly system-dependent, as the exit code may specify either the status of a
	 * normal exit, or the cause of an abnormal exit.
	 * 
	 * @return the exit code
	 */
	Long getExitCode();

	/**
	 * Get a thread belonging to this process
	 * 
	 * dbgeng (at least recent versions) numbers its threads using a global counter. The thread ID
	 * is this number, not the OS-assigned TID.
	 * 
	 * @param id the dbgeng-assigned thread ID
	 * @return a handle to the thread, if it exists
	 */
	DbgThread getThread(DebugThreadId id);

	/**
	 * Get a module belonging to this process
	 * 
	 * dbgeng (at least recent versions) numbers its threads using a global counter. The thread ID
	 * is this number, not the OS-assigned TID.
	 * 
	 * @param id the dbgeng-assigned thread ID
	 * @return a handle to the module, if it exists
	 */
	DbgModule getModule(String id);

	/**
	 * Enumerate the threads known to the manager to belong to this process
	 * 
	 * This does not send any commands to dbgeng. Rather it simply returns a read-only handle to the
	 * manager's internal map for tracking threads and processes.
	 * 
	 * @return a map of dbgeng-assigned thread IDs to thread handles
	 */
	Map<DebugThreadId, DbgThread> getKnownThreads();

	/**
	 * List Dbg's threads in this process
	 * 
	 * This is equivalent to the CLI command: {@code info threads}.
	 * 
	 * @return a future that completes with a map of global thread IDs to thread handles
	 */
	CompletableFuture<Map<DebugThreadId, DbgThread>> listThreads();

	/**
	 * Enumerate the modules known to the manager to belong to this process
	 * 
	 * This does not send any commands to dbgeng. Rather it simply returns a read-only handle to the
	 * manager's internal map for tracking modules.
	 * 
	 * @return a map of dbgeng-assigned names to module handles
	 */
	Map<String, DbgModule> getKnownModules();

	/**
	 * List dbgeng's modules in this process
	 * 
	 * This is equivalent to the CLI command: {@code maintenance info sections ALLOBJ}. This command
	 * is more thorough than {@code info shared} as it contains the executable module, shared
	 * libraries, system-supplied objects, and enumerates all sections thereof, not just
	 * {@code .text}.
	 * 
	 * @return a future that completes with a map of module names to module handles
	 */
	CompletableFuture<Map<String, DbgModule>> listModules();

	/**
	 * Enumerate the memory mappings known to the manager to belong to this process
	 * 
	 * @return a map of start addresses to mapped memory regions
	 */
	Map<Long, DbgSectionImpl> getKnownMappings();

	/**
	 * List the memory mappings of this process
	 * 
	 * @return a future that completes with a map of start addresses to mapped memory regions
	 */
	CompletableFuture<Map<Long, DbgSectionImpl>> listMappings();

	/**
	 * Change focus to this process
	 * 
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> setActive();

	/**
	 * Specify a binary image for execution and debug symbols
	 * 
	 * @param file the path to the binary image
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> fileExecAndSymbols(String file);

	/**
	 * Begin execution
	 * 
	 * @return a future that completes with a handle to the first thread of the running process
	 */
	CompletableFuture<DbgThread> run();

	/**
	 * Attach to a running process
	 * 
	 * @param pid the OS-assigned process ID of the target process
	 * @return a future that completes with a set of handles to all threads of the attached process
	 */
	CompletableFuture<Set<DbgThread>> attach(long pid);

	/**
	 * Attach to a running process
	 * 
	 * @param ref the target process
	 * @return a future that completes with a set of handles to all threads of the attached process
	 */
	CompletableFuture<Set<DbgThread>> reattach(TargetAttachable attachable);

	/**
	 * Execute an arbitrary kd command, capturing its console output
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when Dbg has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command);

	/**
	 * Continue execution
	 * 
	 * @return a future that completes once the process is running
	 */
	CompletableFuture<Void> cont();

	/**
	 * Step the process
	 * 
	 * Note that the command can complete before the process has finished stepping. The command
	 * completes as soon as the process is running. A separate stop event is emitted when the step
	 * is completed.
	 * 
	 * @param suffix specifies how far to step, or on what conditions stepping ends.
	 * 
	 * @return a future that completes once the process is running
	 */
	CompletableFuture<Void> step(ExecSuffix suffix);

	/**
	 * Step the process
	 * 
	 * Note that the command can complete before the process has finished stepping. The command
	 * completes as soon as the process is running. A separate stop event is emitted when the step
	 * is completed.
	 * 
	 * @param args specifies how far to step, or on what conditions stepping ends.
	 * 
	 * @return a future that completes once the process is running
	 */
	CompletableFuture<Void> step(Map<String, ?> args);

	/**
	 * Evaluate an expression
	 * 
	 * @param expression the expression to evaluate
	 * @return a future that completes with the string representation of the value
	 */
	CompletableFuture<String> evaluate(String expression);

	/**
	 * Detach from the process
	 * 
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> detach();

	/**
	 * Kill the process
	 * 
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> kill();

	/**
	 * Remove this process from the session
	 * 
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> remove();

}
