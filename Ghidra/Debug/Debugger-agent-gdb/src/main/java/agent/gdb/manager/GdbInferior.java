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

import java.math.BigInteger;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;

import agent.gdb.manager.GdbManager.StepCmd;
import agent.gdb.manager.impl.GdbMemoryMapping;

/**
 * A handle to a GDB inferior
 * 
 * <p>
 * Each inferior controlled by GDB is numbered and usually corresponds to a target process. Methods
 * that return a {@link CompletableFuture} send a command to GDB via its GDB/MI interpreter. Each
 * method issuing a command will first change focus to this inferior. The returned future completes
 * when GDB has finished executing the command.
 */
public interface GdbInferior extends GdbConsoleOperations, GdbMemoryOperations {

	/**
	 * Get the GDB-assigned inferior number
	 * 
	 * @return the number
	 */
	int getId();

	/**
	 * If started, get the OS-assigned ID of the process
	 * 
	 * @return the process ID
	 */
	Long getPid();

	/**
	 * If exited (implying a previous start), get the process exit code
	 * 
	 * <p>
	 * This may be slightly system-dependent, as the exit code may specify either the status of a
	 * normal exit, or the cause of an abnormal exit.
	 * 
	 * @return the exit code
	 */
	Long getExitCode();

	/**
	 * Get the executable path
	 * 
	 * <p>
	 * TODO: I presume path on the target system
	 * 
	 * @return the executable
	 */
	String getExecutable();

	/**
	 * Get a thread belonging to this inferior
	 * 
	 * <p>
	 * GDB (at least recent versions) numbers its threads using a global counter. The thread ID is
	 * this number, not the OS-assigned TID.
	 * 
	 * @param tid the GDB-assigned thread ID
	 * @return a handle to the thread, if it exists
	 */
	GdbThread getThread(int tid);

	/**
	 * Enumerate the threads known to the manager to belong to this inferior
	 * 
	 * <p>
	 * This does not send any commands to GDB. Rather it simply returns a read-only handle to the
	 * manager's internal map for tracking threads and inferiors.
	 * 
	 * @return a map of GDB-assigned thread IDs to thread handles
	 */
	Map<Integer, GdbThread> getKnownThreads();

	/**
	 * List GDB's threads in this inferior (thread group)
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code info threads}.
	 * 
	 * @return a future that completes with a map of global thread IDs to thread handles
	 */
	CompletableFuture<Map<Integer, GdbThread>> listThreads();

	/**
	 * Enumerate the modules known to the manager to belong to this inferior
	 * 
	 * <p>
	 * This does not send any commands to GDB. Rather it simply returns a read-only handle to the
	 * manager's internal map for tracking modules.
	 * 
	 * @return a map of GDB-assigned names to module handles
	 */
	Map<String, GdbModule> getKnownModules();

	/**
	 * List GDB's modules in this inferior (process, thread group)
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code maintenance info sections ALLOBJ}. This command
	 * is more thorough than {@code info shared} as it contains the executable module, shared
	 * libraries, system-supplied objects, and enumerates all sections thereof, not just
	 * {@code .text}.
	 * 
	 * @return a future that completes with a map of module names to module handles
	 */
	CompletableFuture<Map<String, GdbModule>> listModules();

	/**
	 * Enumerate the memory mappings known to the manager to belong to this inferior's process
	 * 
	 * @return a map of start addresses to mapped memory regions
	 */
	Map<BigInteger, GdbMemoryMapping> getKnownMappings();

	/**
	 * List the memory mappings of this inferior's process
	 * 
	 * @return a future that completes with a map of start addresses to mapped memory regions
	 */
	CompletableFuture<Map<BigInteger, GdbMemoryMapping>> listMappings();

	/**
	 * Change CLI focus to this inferior
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code inferior [THIS_ID]}.
	 * 
	 * <p>
	 * GDB's CLI has the concept of focus. That is, commands issued must be applied to some
	 * "current" inferior. This method changes GDB's current inferior so that subsequent commands
	 * will apply to this inferior. Commands issued from this handle are always executed with this
	 * inferior in focus, so it is rare to invoke his method directly.
	 * 
	 * @param internal true to prevent announcement of the change
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> setActive(boolean internal);

	/**
	 * Specify a binary image for execution and debug symbols
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code file [FILE]}.
	 * 
	 * @param file the path to the binary image
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> fileExecAndSymbols(String file);

	/**
	 * Begin execution
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code run}. Note this will <em>not</em> stop at
	 * {@code main}. The caller should first set breakpoints if an immediate stop is desired.
	 * 
	 * <p>
	 * This command completes as soon as the inferior is running. If a stop is expected at a
	 * breakpoint, then the caller should listen for that event before issuing additional commands.
	 * Alternatively, the caller may interrupt the inferior. The manager has only been tested on GDB
	 * in all-stop mode; GDB cannot process commands while an inferior is running.
	 * 
	 * @return a future that completes with a handle to the first thread of the running inferior
	 */
	CompletableFuture<GdbThread> run();

	/**
	 * Begin execution, stopping at {@code main}
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code start}. Otherwise, it behaves the same as
	 * {@link #run()}.
	 * 
	 * @return a future that completes with a handle to the first thread of the running inferior
	 */
	CompletableFuture<GdbThread> start();

	/**
	 * Begin execution, stopping at the first instruction
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code starti}. Otherwise, it behaves the same as
	 * {@link #run()}. Note that {@code starti} is a relatively new command to GDB. Your version may
	 * not support it.
	 * 
	 * @return a future that completes with a handle to the first thread of the running inferior
	 */
	CompletableFuture<GdbThread> starti();

	/**
	 * Attach to a running process
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code attach [PID]}.
	 * 
	 * @param pid the OS-assigned process ID of the target process
	 * @return a future that completes with a set of handles to all threads of the attached inferior
	 */
	CompletableFuture<Set<GdbThread>> attach(long pid);

	/**
	 * Continue execution
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code continue}.
	 * 
	 * @return a future that completes once the inferior is running
	 */
	CompletableFuture<Void> cont();

	/**
	 * Step execution
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code step}.
	 *
	 * @param suffix specifies how far to step, or on what conditions stepping ends.
	 *
	 * @return a future that completes once the inferior has stepped
	 */
	CompletableFuture<Void> step(StepCmd suffix);

	/**
	 * Evaluate an expression
	 * 
	 * <p>
	 * This evaluates an expression in the same way that the CLI commands {@code print},
	 * {@code output}, and {@code call} would.
	 * 
	 * @param expression the expression to evaluate
	 * @return a future that completes with the string representation of the value
	 */
	CompletableFuture<String> evaluate(String expression);

	/**
	 * Set the controlling TTY for future executions
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code set inferior-tty [TTY]}. It does not affect the
	 * currently running process, if any. This is useful, e.g., to separate target output from GDB's
	 * output. If, e.g., a program outputs lines which look like GDB/MI records, the manager will
	 * interpret them possibly leading to strange behavior. Using this command can redirect the
	 * output to an alternative console to avoid any mis-interpretation.
	 * 
	 * @param tty the controlling TTY for future executions
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> setTty(String tty);

	/**
	 * Get the value of an internal GDB variable
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code show [VAR_NAME]}.
	 * 
	 * @param varName the name of the GDB variable
	 * @return a future that completes with the string representation of the value
	 */
	CompletableFuture<String> getVar(String varName);

	/**
	 * Set the value of an internal GDB variable
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code set [VAR_NAME]=[VAL]}.
	 * 
	 * @param varName the name of the GDB variable
	 * @param val the value to assign
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> setVar(String varName, String val);

	/**
	 * Detach from the process
	 * 
	 * This is equivalent to the CLI command {@code detach}.
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> detach();

	/**
	 * Kill the process
	 * 
	 * <p>
	 * This is equivalent to the CLI command {@code kill}.
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> kill();

	/**
	 * Remove this inferior from the session
	 * 
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> remove();

	/**
	 * Get the "Descriptor" column, usually a process id
	 * 
	 * @return the descriptor
	 */
	String getDescriptor();

}
