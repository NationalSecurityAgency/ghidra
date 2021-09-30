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

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.tuple.Pair;

import SWIG.*;
import agent.lldb.lldb.DebugClient.DebugStatus;
import agent.lldb.manager.LldbManager.ExecSuffix;
import agent.lldb.manager.breakpoint.LldbBreakpointInsertions;
import agent.lldb.manager.impl.LldbManagerImpl;

public interface LldbManager extends AutoCloseable, LldbBreakpointInsertions {

	/**
	 * Possible values for {@link LldbThread#step(ExecSuffix)}
	 */
	public enum ExecSuffix {
		FINISH("finish"),
		NEXT("next"),
		NEXT_INSTRUCTION("next-instruction"),
		RETURN("return"),
		STEP("step"),
		STEP_INSTRUCTION("step-instruction"),
		UNTIL("until"),
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

	static LldbManager newInstance() {
		return new LldbManagerImpl();
	}

	/**
	 * Launch lldb
	 * 
	 * @param args cmd plus args
	 * @return a future which completes when lldb is ready to accept commands
	 */
	CompletableFuture<Void> start(String[] args);

	/**
	 * Terminate lldb
	 */
	void terminate();

	/**
	 * Check if lldb is alive
	 * 
	 * Note this is not about the state of inferiors in lldb. If the lldb controlling process is
	 * alive, lldb is alive.
	 * 
	 * @return true if lldb is alive, false otherwise
	 */
	boolean isRunning();

	/**
	 * Add a listener for lldb's state
	 * 
	 * @see #getState()
	 * @param listener the listener to add
	 */
	void addStateListener(LldbStateListener listener);

	/**
	 * Remove a listener for lldb's state
	 * 
	 * @see #getState()
	 * @param listener the listener to remove
	 */
	void removeStateListener(LldbStateListener listener);

	/**
	 * Add a listener for events on processes
	 * 
	 * @param listener the listener to add
	 */
	void addEventsListener(LldbEventsListener listener);

	/**
	 * Remove a listener for events on inferiors
	 * 
	 * @param listener the listener to remove
	 */
	void removeEventsListener(LldbEventsListener listener);

	/**
	 * Get a thread by its lldb-assigned ID
	 * 
	 * lldb numbers its threads using a global counter. These IDs are unrelated to the OS-assigned
	 * TID. This method can retrieve a thread by its ID no matter which inferior it belongs to.
	 * 
	 * @param id the lldb-asigned thread ID
	 * @return a handle to the thread, if it exists
	 */
	SBThread getThread(SBProcess process, String id);

	/**
	 * Get an process by its lldb-assigned ID
	 * 
	 * lldb numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addProcess()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	SBProcess getProcess(SBTarget session, String id);

	/**
	 * Get an session by its lldb-assigned ID
	 * 
	 * lldb numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	SBTarget getSession(String id);

	/**
	 * Get an session by its lldb-assigned ID
	 * 
	 * lldb numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	SBModule getModule(SBTarget session, String id);

	/**
	 * Get all threads known to the manager
	 * 
	 * This does not ask lldb to lists its known threads. Rather it returns a read-only view of the
	 * manager's understanding of the current threads based on its tracking of lldb events.
	 * 
	 * @return a map of lldb-assigned thread IDs to corresponding thread handles
	 */
	Map<String, SBThread> getKnownThreads(SBProcess process);

	/**
	 * Get all processes known to the manager
	 * 
	 * This does not ask lldb to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current processes based on its tracking of lldb events.
	 * 
	 * @return a map of process IDs to corresponding process handles
	 */
	Map<String, SBProcess> getKnownProcesses(SBTarget session);

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask lldb to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of lldb events.
	 * 
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<String, SBTarget> getKnownSessions();

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask lldb to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of lldb events.
	 * 
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<String, SBModule> getKnownModules(SBTarget session);

	/**
	 * Get all breakpoints known to the manager
	 * 
	 * This does not ask lldb to list its breakpoints. Rather it returns a read-only view of the
	 * manager's understanding of the current breakpoints based on its tracking of lldb events.
	 * 
	 * @return a map of lldb-assigned breakpoint IDs to corresponding breakpoint information
	 */
	Map<String, Object> getKnownBreakpoints(SBTarget session);

	/**
	 * Send an interrupt to lldb regardless of other queued commands
	 * 
	 * This may be useful if the manager's command queue is stalled because an inferior is running.
	 * 
	 */
	void sendInterruptNow();

	/**
	 * Get the state of the lldb session
	 * 
	 * In all-stop mode, if any thread is running, lldb is said to be in the running state and is
	 * unable to process commands. Otherwise, if all threads are stopped, then lldb is said to be in
	 * the stopped state and can accept and process commands. This manager has not been tested in
	 * non-stop mode.
	 * 
	 * @return the state
	 */
	StateType getState();

	/**
	 * Add a process
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<SBProcess> addProcess();

	/**
	 * Remove a process
	 * 
	 * @param process the process to remove
	 * @return a future which completes then lldb has executed the command
	 */
	CompletableFuture<Void> removeProcess(SBProcess process);

	/**
	 * Add a session
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<SBTarget> addSession();

	/**
	 * Execute an arbitrary CLI command, printing output to the CLI console
	 * 
	 * Note: to ensure a certain thread or inferior has focus for a console command, see
	 * {@link LldbThread#console(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes when lldb has executed the command
	 */
	CompletableFuture<Void> console(String command);

	/**
	 * Execute an arbitrary CLI command, capturing its console output
	 * 
	 * The output will not be printed to the CLI console. To ensure a certain thread or inferior has
	 * focus for a console command, see {@link LldbThread#consoleCapture(String)} and
	 * {@link LldbProcess#consoleCapture(String)}.
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when lldb has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command);

	/**
	 * List lldb's threads
	 * 
	 * @return a future that completes with a map of process IDs to process handles
	 */
	CompletableFuture<Map<String, SBThread>> listThreads(SBProcess process);

	/**
	 * List lldb's processes
	 * 
	 * @return a future that completes with a map of process IDs to process handles
	 */
	CompletableFuture<Map<String, SBProcess>> listProcesses(SBTarget session);

	/**
	 * List the available processes on target
	 * 
	 * @return a future that completes with a list of PIDs
	 */
	CompletableFuture<List<Pair<String, String>>> listAvailableProcesses();

	/**
	 * List lldb's sessions
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBTarget>> listSessions();

	/**
	 * List lldb's stack frames
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBFrame>> listStackFrames(SBThread thread);

	/**
	 * List lldb's stack frame register banks
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBValue>> listStackFrameRegisterBanks(SBFrame frame);

	/**
	 * List lldb's stack frame registers
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, SBValue>> listStackFrameRegisters(SBValue bank);

	/**
	 * List lldb's modules
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, SBModule>> listModules(SBTarget session);

	/**
	 * List lldb's module sections
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, SBSection>> listModuleSections(SBModule module);

	/**
	 * List lldb's module symbols
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, SBSymbol>> listModuleSymbols(SBModule module);

	/**
	 * List lldb's memory
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<List<SBMemoryRegionInfo>> listMemory(SBProcess process);

	/**
	 * List information for all breakpoints
	 * 
	 * @return a future that completes with a list of information for all breakpoints
	 */
	CompletableFuture<Map<String, Object>> listBreakpoints(SBTarget session);

	/**
	 * List information for all breakpoints
	 * 
	 * @return a future that completes with a list of information for all breakpoints
	 */
	CompletableFuture<Map<String, SBBreakpointLocation>> listBreakpointLocations(SBBreakpoint spec);

	/**
	 * List information for all env vars
	 * 
	 * @return a future that completes with a list of information for all env vars
	 */
	CompletableFuture<Map<String, String>> listEnvironment(SBTarget session);

	/**
	 * Disable the given breakpoints
	 * 
	 * This is equivalent to the CLI command {@code disable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the lldb-assigned breakpoint numbers
	 * @return a future that completes when lldb has executed the command
	 */
	CompletableFuture<Void> disableBreakpoints(String... ids);

	/**
	 * Enable the given breakpoints
	 * 
	 * This is equivalent to the CLI command {@code enable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the lldb-assigned breakpoint numbers
	 * @return a future that completes when lldb has executed the command
	 */
	CompletableFuture<Void> enableBreakpoints(String... ids);

	/**
	 * Delete a breakpoint
	 * 
	 * This is equivalent to the CLI command {@code delete breakpoint [NUMBER]}.
	 * 
	 * @param numbers the lldb-assigned breakpoint numbers
	 * @return a future that completes when lldb has executed the command
	 */
	CompletableFuture<Void> deleteBreakpoints(String... ids);

	CompletableFuture<?> attach(String pid);

	CompletableFuture<?> attach(String name, boolean wait);

	CompletableFuture<?> attach(String url, boolean wait, boolean async);

	CompletableFuture<?> launch(String fileName, List<String> args);

	CompletableFuture<?> launch(Map<String, ?> args);

	/********** NEEDED FOR TESTING ************/

	/**
	 * Returns the current process
	 * 
	 * @return the current process
	 */
	SBProcess currentProcess();

	CompletableFuture<Void> waitForPrompt();

	CompletableFuture<Void> waitForEventEx();

	<T> CompletableFuture<T> execute(LldbCommand<? extends T> cmd);

	DebugStatus processEvent(LldbEvent<?> evt);

	DebugStatus getStatus();

	void setCurrentEvent(SBEvent evt);

	void updateState(SBProcess process);

}
