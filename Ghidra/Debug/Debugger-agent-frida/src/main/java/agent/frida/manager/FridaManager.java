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
package agent.frida.manager;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.apache.commons.lang3.tuple.Pair;

import com.google.gson.JsonElement;

import agent.frida.frida.FridaClient.DebugStatus;
import agent.frida.manager.impl.FridaManagerImpl;

public interface FridaManager extends AutoCloseable {

	static FridaManager newInstance() {
		return new FridaManagerImpl();
	}

	/**
	 * Launch Frida
	 * 
	 * @param args cmd plus args
	 * @return a future which completes when Frida is ready to accept commands
	 */
	CompletableFuture<Void> start(String[] args);

	/**
	 * Terminate Frida
	 */
	void terminate();

	/**
	 * Check if Frida is alive
	 * 
	 * Note this is not about the state of inferiors in Frida. If the Frida controlling process is
	 * alive, Frida is alive.
	 * 
	 * @return true if Frida is alive, false otherwise
	 */
	boolean isRunning();

	/**
	 * Add a listener for Frida's state
	 * 
	 * @see #getState()
	 * @param listener the listener to add
	 */
	void addStateListener(FridaStateListener listener);

	/**
	 * Remove a listener for Frida's state
	 * 
	 * @see #getState()
	 * @param listener the listener to remove
	 */
	void removeStateListener(FridaStateListener listener);

	/**
	 * Add a listener for events on processes
	 * 
	 * @param listener the listener to add
	 */
	void addEventsListener(FridaEventsListener listener);

	/**
	 * Remove a listener for events on inferiors
	 * 
	 * @param listener the listener to remove
	 */
	void removeEventsListener(FridaEventsListener listener);

	/**
	 * Get a thread by its Frida-assigned ID
	 * 
	 * Frida numbers its threads using a global counter. These IDs are unrelated to the OS-assigned
	 * TID. This method can retrieve a thread by its ID no matter which inferior it belongs to.
	 * 
	 * @param process wrapper for Frida pointer
	 * @param id the Frida-asigned thread ID
	 * @return a handle to the thread, if it exists
	 */
	FridaThread getThread(FridaProcess process, String id);

	/**
	 * Get an process by its Frida-assigned ID
	 * 
	 * Frida numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addProcess()}.
	 * 
	 * @param session wrapper for Frida pointer
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	FridaProcess getProcess(FridaSession session, String id);

	/**
	 * Get an session by its Frida-assigned ID
	 * 
	 * Frida numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	FridaSession getSession(String id);

	/**
	 * Get an session by its Frida-assigned ID
	 * 
	 * Frida numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param process wrapper for Frida pointer
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	FridaModule getModule(FridaProcess process, String id);

	/**
	 * Get an memory region by its Frida-assigned ID
	 * 
	 * Frida numbers processes incrementally. All inferiors and created and destroyed by the user.
	 * See {@link #addSession()}.
	 * 
	 * @param process wrapper for Frida pointer
	 * @param id the process ID
	 * @return a handle to the process, if it exists
	 */
	FridaMemoryRegionInfo getMemoryRegion(FridaProcess process, String id);

	/**
	 * Get all threads known to the manager
	 * 
	 * This does not ask Frida to lists its known threads. Rather it returns a read-only view of the
	 * manager's understanding of the current threads based on its tracking of Frida events.
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a map of Frida-assigned thread IDs to corresponding thread handles
	 */
	Map<String, FridaThread> getKnownThreads(FridaProcess process);

	/**
	 * Get all processes known to the manager
	 * 
	 * This does not ask Frida to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current processes based on its tracking of Frida events.
	 * 
	 * @param session wrapper for Frida pointer
	 * @return a map of process IDs to corresponding process handles
	 */
	Map<String, FridaProcess> getKnownProcesses(FridaSession session);

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask Frida to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of Frida events.
	 * 
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<String, FridaSession> getKnownSessions();

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask Frida to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of Frida events.
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<String, FridaModule> getKnownModules(FridaProcess process);

	/**
	 * Get all sessions known to the manager
	 * 
	 * This does not ask Frida to list its processes. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of Frida events.
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a map of session IDs to corresponding session handles
	 */
	Map<String, FridaMemoryRegionInfo> getKnownRegions(FridaProcess process);

	/**
	 * Get the state of the Frida session
	 * 
	 * In all-stop mode, if any thread is running, Frida is said to be in the running state and is
	 * unable to process commands. Otherwise, if all threads are stopped, then Frida is said to be in
	 * the stopped state and can accept and process commands. This manager has not been tested in
	 * non-stop mode.
	 * 
	 * @return the state
	 */
	FridaState getState();

	/**
	 * Add a process
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<FridaProcess> addProcess();

	/**
	 * Remove a process
	 * 
	 * @param process the process to remove
	 * @return a future which completes then Frida has executed the command
	 */
	CompletableFuture<Void> removeProcess(FridaProcess process);

	/**
	 * Add a session
	 * 
	 * @return a future which completes with the handle to the new process
	 */
	CompletableFuture<FridaSession> addSession();

	/**
	 * Execute an arbitrary CLI command, printing output to the CLI console
	 * 
	 * @param command the command to execute
	 * @return a future that completes when Frida has executed the command
	 */
	CompletableFuture<Void> console(String command);

	/**
	 * Execute an arbitrary CLI command, capturing its console output
	 * 
	 * The output will not be printed to the CLI console. 
	 * 
	 * @param command the command to execute
	 * @return a future that completes with the captured output when Frida has executed the command
	 */
	CompletableFuture<String> consoleCapture(String command);

	/**
	 * List Frida's threads
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a future that completes with a map of process IDs to process handles
	 */
	CompletableFuture<Void> listThreads(FridaProcess process);

	/**
	 * List Frida's processes
	 * 
	 * @param session wrapper for Frida pointer
	 * @return a future that completes with a map of process IDs to process handles
	 */
	CompletableFuture<Map<String, FridaProcess>> listProcesses(FridaSession session);

	/**
	 * List the available processes on target
	 * 
	 * @return a future that completes with a list of PIDs
	 */
	CompletableFuture<List<Pair<String, String>>> listAvailableProcesses();

	/**
	 * List Frida's sessions
	 * 
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, FridaSession>> listSessions();

	/**
	 * List Frida's stack frames
	 * 
	 * @param thread wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, FridaFrame>> listStackFrames(FridaThread thread);

	/**
	 * List Frida's stack frame registers
	 * 
	 * @param thread wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	CompletableFuture<Map<String, String>> listRegisters(FridaThread thread);

	/**
	 * List Frida's modules
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Void> listModules(FridaProcess process);

	/**
	 * List Frida's module sections
	 * 
	 * @param module wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, FridaSection>> listModuleSections(FridaModule module);

	/**
	 * List Frida's module symbols
	 * 
	 * @param module wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, FridaSymbol>> listModuleSymbols(FridaModule module);

	/**
	 * List Frida's module imports
	 * 
	 * @param module wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, FridaImport>> listModuleImports(FridaModule module);

	/**
	 * List Frida's module exports
	 * 
	 * @param module wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Map<String, FridaExport>> listModuleExports(FridaModule module);

	/**
	 * List Frida's memory
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Void> listMemory(FridaProcess process);

	/**
	 * List Frida's heap memory
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Void> listHeapMemory(FridaProcess process);

	/**
	 * List Frida's heap memory
	 * 
	 * @param process wrapper for Frida pointer
	 * @return a future that completes with a map of session IDs to session handles
	 */
	public CompletableFuture<Void> setExceptionHandler(FridaProcess process);

	CompletableFuture<?> attach(String pid);

	CompletableFuture<?> launch(String fileName, List<String> args);

	CompletableFuture<?> launch(Map<String, ?> args);

	/********** NEEDED FOR TESTING ************/

	/**
	 * Returns the current process
	 * 
	 * @return the current process
	 */
	FridaProcess currentProcess();

	CompletableFuture<Void> waitForPrompt();

	<T> CompletableFuture<T> execute(FridaCommand<? extends T> cmd);

	DebugStatus processEvent(FridaEvent<?> evt);

	DebugStatus getStatus();

	void updateState(FridaSession session);

	FridaTarget getCurrentTarget();

	void setCurrentTarget(FridaTarget target);

	CompletableFuture<Void> getSessionAttributes(FridaSession session);

	void enableDebugger(FridaSession session, int port);

}
