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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.tuple.Pair;

import agent.dbgeng.dbgeng.*;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInfo;
import agent.dbgeng.manager.breakpoint.DbgBreakpointInsertions;
import agent.dbgeng.manager.impl.DbgManagerImpl;

public interface DbgManager extends AutoCloseable, DbgBreakpointInsertions {

	/**
	 * Possible values for {@link DbgThread#step(ExecSuffix)}
	 */
	public enum ExecSuffix {
		/** Equivalent to {@code finish} in the CLI */
		FINISH("finish"),
		/** Equivalent to {@code next} in the CLI */
		NEXT("next"),
		/** Equivalent to {@code nexti} in the CLI */
		NEXT_INSTRUCTION("next-instruction"),
		/** Equivalent to {@code return} in the CLI */
		RETURN("return"),
		/** Equivalent to {@code step} in the CLI */
		STEP("step"),
		/** Equivalent to {@code stepi} in the CLI */
		STEP_INSTRUCTION("step-instruction"),
		/** Equivalent to {@code until} in the CLI */
		UNTIL("until"),
		/** Equivalent to {@code ext} in the CLI */
		EXTENDED("ext"),;

		final String str;

		ExecSuffix(String str) {
			this.str = str;
		}

		@Override
		public String toString() {
			return str;
		}
	}

	static DbgManager newInstance() {
		//return new DbgManagerModelImpl();
		return new DbgManagerImpl();
	}

	/**
	 * Launch dbgeng
	 * 
	 * @param args cmd plus args
	 * @return a future which completes when dbgeng is ready to accept commands
	 */
	CompletableFuture<Void> start(String[] args);

	/**
	 * Terminate dbgeng
	 */
	void terminate();

	/**
	 * Check if GDB is alive
	 * 
	 * Note this is not about the state of inferiors in GDB. If the GDB controlling process is
	 * alive, GDB is alive.
	 * 
	 * @return true if GDB is alive, false otherwise
	 */
	boolean isRunning();

	/**
	 * Add a listener for dbgeng's state
	 * 
	 * @see #getState()
	 * @param listener the listener to add
	 */
	void addStateListener(DbgStateListener listener);

	/**
	 * Remove a listener for dbgeng's state
	 * 
	 * @see #getState()
	 * @param listener the listener to remove
	 */
	void removeStateListener(DbgStateListener listener);

	/**
	 * Add a listener for events on processes
	 * 
	 * @param listener the listener to add
	 */
	void addEventsListener(DbgEventsListener listener);

	/**
	 * Remove a listener for events on inferiors
	 * 
	 * @param listener the listener to remove
	 */
	void removeEventsListener(DbgEventsListener listener);

	/**
	 * Get a thread by its dbgeng-assigned ID
	 * 
	 * dbgeng numbers its threads using a global counter. These IDs are unrelated to the OS-assigned
	 * TID. This method can retrieve a thread by its ID no matter which inferior it belongs to.
	 * 
	 * @param id the dbgeng-asigned thread ID
	 * @return a handle to the thread, if it exists
	 */
	DbgThread getThread(DebugThreadId id);

	/**
	 * Get an process by its dbgeng-assigned ID
	 * 
	 * dbgeng numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addProcess()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	DbgProcess getProcess(DebugProcessId id);

	/**
	 * Get an session by its dbgeng-assigned ID
	 * 
	 * dbgeng numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	DbgSession getSession(DebugSessionId id);

	/**
	 * Get all threads known to the manager
	 * 
	 * This does not ask dbgeng to lists its known threads. Rather it returns a read-only view of
	 * the manager's understanding of the current threads based on its tracking of dbgeng events.
	 * 
	 * @return a map of dbgeng-assigned thread IDs to corresponding thread handles
	 */
	Map<DebugThreadId, DbgThread> getKnownThreads();

	/**
	 * Get all processes known to the manager
	 * 
	 * This does not ask dbgeng to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current processes based on its tracking of dbgeng events.
	 * 
	 * @return a map of process IDs to corresponding process handles
	 */
	Map<DebugProcessId, DbgProcess> getKnownProcesses();

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask dbgeng to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of dbgeng events.
	 * 
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<DebugSessionId, DbgSession> getKnownSessions();

	/**
	 * Get all breakpoints known to the manager
	 * 
	 * This does not ask dbgeng to list its breakpoints. Rather it returns a read-only view of the
	 * manager's understanding of the current breakpoints based on its tracking of dbgeng events.
	 * 
	 * @return a map of dbgeng-assigned breakpoint IDs to corresponding breakpoint information
	 */
	Map<Long, DbgBreakpointInfo> getKnownBreakpoints();

	/**
	 * Get all memory regions known to the manager
	 * 
	 * This does not ask dbgeng to list its regions. Rather it returns a read-only view of the
	 * manager's understanding of the current ememory based on its tracking of dbgeng events.
	 * 
	 * @return a map of dbgeng-assigned breakpoint IDs to corresponding breakpoint information
	 */
	Map<Long, DbgModuleMemory> getKnownMemoryRegions();

	/**
	 * Send an interrupt to dbgeng regardless of other queued commands
	 * 
	 * This may be useful if the manager's command queue is stalled because an inferior is running.
	 * 
	 */
	void sendInterruptNow();

	/**
	 * Get the state of the dbgeng session
	 * 
	 * In all-stop mode, if any thread is running, dbgeng is said to be in the running state and is
	 * unable to process commands. Otherwise, if all threads are stopped, then dbgeng is said to be
	 * in the stopped state and can accept and process commands. This manager has not been tested in
	 * non-stop mode.
	 * 
	 * @return the state
	 */
	DbgState getState();

	/**
	 * Add a process
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<DbgProcess> addProcess();

	/**
	 * Remove a process
	 * 
	 * @param process the process to remove
	 * @return a future which completes then dbgeng has executed the command
	 */
	CompletableFuture<Void> removeProcess(DbgProcess process);

	/**
	 * Add a session
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<DbgSession> addSession();

	/**
	 * Remove a session
	 * 
	 * @param process the session to remove
	 * @return a future which completes then dbgeng has executed the command
	 */
	CompletableFuture<Void> removeSession(DbgSession session);

	/**
	 * Add a memory region
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<Void> addMemory(DbgModuleMemory region);

	/**
	 * Remove a memory region
	 * 
	 * @param regionId the region to remove
	 * @return a future which completes then dbgeng has executed the command
	 */
	CompletableFuture<Void> removeMemory(Long regionId);

	/**
	 * Execute an arbitrary CLI command, printing output to the CLI console
	 * 
	 * Note: to ensure a certain thread or inferior has focus for a console command, see
	 * {@link DbgThread#console(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> console(String command);

	/**
	 * Execute an arbitrary CLI command, capturing its console output
	 * 
	 * The output will not be printed to the CLI console. To ensure a certain thread or inferior has
	 * focus for a console command, see {@link DbgThread#consoleCapture(String)} and
	 * {@link DbgProcess#consoleCapture(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when dbgeng has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command);

	/**
	 * List dbgeng's processes
	 * 
	 * @return a future that completes with a map of process IDs to process handles
	 */
	CompletableFuture<Map<DebugProcessId, DbgProcess>> listProcesses();

	/**
	 * List the available processes on target
	 * 
	 * @return a future that completes with a list of PIDs
	 */
	CompletableFuture<List<Pair<Integer, String>>> listAvailableProcesses();

	/**
	 * List dbgeng's sessions
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, DbgSession>> listSessions();

	/**
	 * List information for all breakpoints
	 * 
	 * @return a future that completes with a list of information for all breakpoints
	 */
	CompletableFuture<Map<Long, DbgBreakpointInfo>> listBreakpoints();

	/**
	 * Disable the given breakpoints
	 * 
	 * This is equivalent to the CLI command {@code disable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the dbgeng-assigned breakpoint numbers
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> disableBreakpoints(long... numbers);

	/**
	 * Enable the given breakpoints
	 * 
	 * This is equivalent to the CLI command {@code enable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the dbgeng-assigned breakpoint numbers
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> enableBreakpoints(long... numbers);

	/**
	 * Delete a breakpoint
	 * 
	 * This is equivalent to the CLI command {@code delete breakpoint [NUMBER]}.
	 * 
	 * @param numbers the dbgeng-assigned breakpoint numbers
	 * @return a future that completes when dbgeng has executed the command
	 */
	CompletableFuture<Void> deleteBreakpoints(long... numbers);

	CompletableFuture<?> launch(List<String> args);

	CompletableFuture<Void> launch(Map<String, ?> args);

	/********** NEEDED FOR TESTING ************/

	/**
	 * Returns the current process
	 * 
	 * @return the current process
	 */
	DbgProcess currentProcess();

	CompletableFuture<Void> waitForState(DbgState stopped);

	CompletableFuture<Void> waitForPrompt();

	CompletableFuture<Void> waitForEventEx();

	<T> CompletableFuture<T> execute(DbgCommand<? extends T> cmd);

	DebugEventInformation getLastEventInformation();

}
