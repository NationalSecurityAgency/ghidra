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

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.manager.breakpoint.GdbBreakpointInsertions;
import agent.gdb.manager.impl.GdbManagerImpl;
import agent.gdb.pty.PtyFactory;
import agent.gdb.pty.linux.LinuxPty;
import agent.gdb.pty.linux.LinuxPtyFactory;

/**
 * The controlling side of a GDB session, using GDB/MI, usually via a pseudo-terminal
 * 
 * This facilitates the implementation of GDB front ends. This piece communicates with the GDB back
 * end, providing a more object-oriented programmatic interface. The methods returning
 * {@link CompletableFuture} all send commands to GDB, and the future completes when the command has
 * been executed.
 */
public interface GdbManager extends AutoCloseable, GdbConsoleOperations, GdbBreakpointInsertions {
	public static final String DEFAULT_GDB_CMD = "/usr/bin/gdb";

	/**
	 * Possible values for {@link GdbThread#step(StepCmd)}
	 */
	public enum StepCmd {
		FINISH("finish"),
		NEXT("next"),
		NEXTI("nexti", "next-instruction"),
		RETURN("return"),
		STEP("step"),
		STEPI("stepi", "step-instruction"),
		UNTIL("until"),
		/** User-defined */
		EXTENDED("echo extended-step?", "???"),;

		public final String mi2;
		public final String cli;

		StepCmd(String cli, String execSuffix) {
			this.cli = cli;
			this.mi2 = "-exec-" + execSuffix;
		}

		StepCmd(String cli) {
			this(cli, cli);
		}

		@Override
		public String toString() {
			return mi2;
		}
	}

	/**
	 * Just a vanilla demo of the manager
	 * 
	 * <p>
	 * This presents the usual GDB CLI, using GDB/MI on the back end. The manager is keeps track of
	 * events; however, in this vanilla front end, nothing consumes them. This also provides a quick
	 * test to ensure the console loop operates correctly, or at least closely enough to actual GDB.
	 * 
	 * @param args additional arguments to pass to GDB. Passing -i will cause problems.
	 * @throws InterruptedException
	 * @throws ExecutionException
	 * @throws IOException
	 */
	public static void main(String[] args)
			throws InterruptedException, ExecutionException, IOException {
		// TODO: Choose factory by host OS
		try (GdbManager mgr = newInstance(new LinuxPtyFactory())) {
			mgr.start(DEFAULT_GDB_CMD, args);
			mgr.runRC().get();
			mgr.consoleLoop();
		}
	}

	public enum Channel {
		STDOUT, STDERR;
	}

	/**
	 * Get a new manager instance, without starting GDB
	 * 
	 * @return the manager
	 */
	public static GdbManager newInstance(PtyFactory ptyFactory) {
		return new GdbManagerImpl(ptyFactory);
	}

	/**
	 * Set the line terminator (separator) used to serialize commands to GDB
	 * 
	 * <p>
	 * Because the manager may be communicating to GDB running remotely, possibly on another
	 * platform, it may be necessary to customize the line terminator. The manager will default to
	 * the line terminator used by the local system, i.e., {@link System#lineSeparator()}.
	 * 
	 * <p>
	 * While permitted, it is not advisable to modify this parameter while the manager is running.
	 * Chances are, if this was mis-configured, the manager and session are hopelessly out of sync.
	 * Start a new properly configured session instead.
	 * 
	 * @param newLine the line separator to use
	 */
	public void setNewLine(String newLine);

	/**
	 * Set to UNIX-style (CR) line terminator
	 */
	default void setUnixNewLine() {
		setNewLine("\n");
	}

	/**
	 * Set to DOS-style (CRLF) line terminator
	 */
	default void setDosNewLine() {
		setNewLine("\r\n");
	}

	/**
	 * Launch GDB
	 * 
	 * @return a future which completes when GDB is ready to accept commands
	 * @throws IOException if GDB cannot be started
	 */
	default void start() throws IOException {
		start(DEFAULT_GDB_CMD);
	}

	/**
	 * Launch GDB, providing a custom path to GDB
	 * 
	 * @param gdbCmd the path to the GDB executable
	 * @param args additional arguments to pass. Passing -i will cause problems.
	 * @return a future which completes when GDB is ready to accept commands
	 * @throws IOException if GDB cannot be started
	 */
	void start(String gdbCmd, String... args) throws IOException;

	/**
	 * Wait for a prompt and run any rc (initial configuration) commands
	 * 
	 * @return a future which completes when rc has finished
	 */
	CompletableFuture<Void> runRC();

	/**
	 * Terminates GDB
	 */
	@Override
	default void close() {
		terminate();
	}

	/**
	 * Execute a console loop in this thread
	 * 
	 * <p>
	 * Note this does not follow the asynchronous pattern.
	 * 
	 * @throws IOException if an I/O error occurs
	 */
	void consoleLoop() throws IOException;

	/**
	 * Terminate GDB
	 */
	void terminate();

	/**
	 * Check if GDB is alive
	 * 
	 * <p>
	 * Note this is not about the state of inferiors in GDB. If the GDB controlling process is
	 * alive, GDB is alive.
	 * 
	 * @return true if GDB is alive, false otherwise
	 */
	boolean isAlive();

	/**
	 * Add a listener for GDB's state
	 * 
	 * @see #getState()
	 * @param listener the listener to add
	 */
	void addStateListener(GdbStateListener listener);

	/**
	 * Remove a listener for GDB's state
	 * 
	 * @see #getState()
	 * @param listener the listener to remove
	 */
	void removeStateListener(GdbStateListener listener);

	/**
	 * Add a listener for events on inferiors
	 * 
	 * @param listener the listener to add
	 */
	void addEventsListener(GdbEventsListener listener);

	/**
	 * Remove a listener for events on inferiors
	 * 
	 * @param listener the listener to remove
	 */
	void removeEventsListener(GdbEventsListener listener);

	/**
	 * Add a listener for target output
	 * 
	 * <p>
	 * Note: depending on the target, its output may not be communicated via this listener. Local
	 * targets, e.g., tend to just print output to GDB's controlling TTY. See
	 * {@link GdbInferior#setTty(String)} for a means to more reliably interact with a target's
	 * input and output. See also {@link LinuxPty} for a means to easily acquire a new TTY from
	 * Java.
	 * 
	 * @param listener the listener to add
	 */
	void addTargetOutputListener(GdbTargetOutputListener listener);

	/**
	 * Remove a listener for target output
	 * 
	 * @see #addTargetOutputListener(GdbTargetOutputListener)
	 * @param listener
	 */
	void removeTargetOutputListener(GdbTargetOutputListener listener);

	/**
	 * Add a listener for console output
	 * 
	 * @param listener the listener to add
	 */
	void addConsoleOutputListener(GdbConsoleOutputListener listener);

	/**
	 * Remove a listener for console output
	 * 
	 * @param listener
	 */
	void removeConsoleOutputListener(GdbConsoleOutputListener listener);

	/**
	 * Get a thread by its GDB-assigned ID
	 * 
	 * <p>
	 * GDB numbers its threads using a global counter. These IDs are unrelated to the OS-assigned
	 * TID. This method can retrieve a thread by its ID no matter which inferior it belongs to.
	 * 
	 * @param tid the GDB-asigned thread ID
	 * @return a handle to the thread, if it exists
	 */
	GdbThread getThread(int tid);

	/**
	 * Get an inferior by its GDB-assigned ID
	 * 
	 * <p>
	 * GDB numbers inferiors incrementally. All inferiors and created and destroyed by the user. See
	 * {@link #addInferior()}.
	 * 
	 * @param iid the inferior ID
	 * @return a handle to the inferior, if it exists
	 */
	GdbInferior getInferior(int iid);

	/**
	 * Get the inferior which currently has focus
	 * 
	 * @see GdbInferior#setActive()
	 * @return a handle to the inferior with focus
	 */
	GdbInferior currentInferior();

	/**
	 * Get all inferiors known to the manager
	 * 
	 * <p>
	 * This does not ask GDB to list its inferiors. Rather it returns a read-only view of the
	 * manager's understanding of the current inferiors based on its tracking of GDB events.
	 * 
	 * @return a map of inferior IDs to corresponding inferior handles
	 */
	Map<Integer, GdbInferior> getKnownInferiors();

	/**
	 * Get all threads known to the manager
	 * 
	 * <p>
	 * This does not ask GDB to lists its known threads. Rather it returns a read-only view of the
	 * manager's understanding of the current threads based on its tracking of GDB events.
	 * 
	 * @return a map of GDB-assigned thread IDs to corresponding thread handles
	 */
	Map<Integer, GdbThread> getKnownThreads();

	/**
	 * Get all breakpoints known to the manager
	 * 
	 * <p>
	 * This does not ask GDB to list its breakpoints. Rather it returns a read-only view of the
	 * manager's understanding of the current breakpoints based on its tracking of GDB events.
	 * 
	 * @return a map of GDB-assigned breakpoint IDs to corresponding breakpoint information
	 */
	Map<Long, GdbBreakpointInfo> getKnownBreakpoints();

	/**
	 * Send an interrupt to GDB regardless of other queued commands
	 * 
	 * <p>
	 * This may be useful if the manager's command queue is stalled because an inferior is running.
	 * If this doesn't clear the stall, try {@link #cancelCurrentCommand()}.
	 * 
	 * @throws IOException if an I/O error occurs
	 * @throws InterruptedException
	 */
	void sendInterruptNow() throws IOException;

	/**
	 * Cancel the current command
	 * 
	 * <p>
	 * Occasionally, a command gets stalled up waiting for an event, which for other reasons, will
	 * no longer occur. This will free up the queue for other commands to (hopefully) be processed.
	 * If {@link #sendInterruptNow()} doesn't clear the stall, try this.
	 */
	void cancelCurrentCommand();

	/**
	 * Get the state of the GDB session
	 * 
	 * <p>
	 * In all-stop mode, if any thread is running, GDB is said to be in the running state and is
	 * unable to process commands. Otherwise, if all threads are stopped, then GDB is said to be in
	 * the stopped state and can accept and process commands. This manager has not been tested in
	 * non-stop mode.
	 * 
	 * @return the state
	 */
	GdbState getState();

	/**
	 * Wait for GDB to enter the given state
	 * 
	 * @param forState the state to wait for
	 * @return a future which completes when GDB enters the given state
	 */
	CompletableFuture<Void> waitForState(GdbState forState);

	/**
	 * Wait for GDB to present a prompt
	 * 
	 * <p>
	 * This waits for a prompt from GDB unless the last line printed is already a prompt. This is
	 * generally not necessary following normal commands. Note that depending on circumstances and
	 * GDB version, the MI console may produce a prompt before it produces all of the events
	 * associated with an interrupt. If the <em>last</em> line is not currently a prompt, then the
	 * returned future will not be complete. In other words, this is not a reliable way of verifying
	 * GDB is waiting for a command. It's primary use is confirming that GDB has started
	 * successfully and is awaiting its first command.
	 * 
	 * @return a future which completes when GDB presents a prompt
	 */
	CompletableFuture<Void> waitForPrompt();

	/**
	 * A dummy command which claims as cause a stopped event and waits for the next prompt
	 * 
	 * <p>
	 * This is used to squelch normal processing of a stopped event until the next prompt
	 * 
	 * @return a future which completes when the "command" has finished execution
	 * @deprecated I don't see this being used anywhere. Probably defunct.
	 */
	@Deprecated
	CompletableFuture<Void> claimStopped();

	/**
	 * Add an inferior
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code add-inferior}.
	 * 
	 * @return a future which completes with the handle to the new inferior
	 */
	CompletableFuture<GdbInferior> addInferior();

	/**
	 * Find an unused inferior, possibly creating a new one
	 * 
	 * @return a future which completes with the handle to the found inferior
	 */
	CompletableFuture<GdbInferior> availableInferior();

	/**
	 * Remove an inferior
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code remove-inferior}.
	 * 
	 * <p>
	 * Note that unlike the CLI, it is possible to remove the current inferior, in which case, the
	 * lowest-id inferior is selected. Like the CLI, it is not possible to remove an active inferior
	 * or the last inferior.
	 * 
	 * @param inferior the inferior to remove
	 * @return a future which completes then GDB has executed the command
	 */
	CompletableFuture<Void> removeInferior(GdbInferior inferior);

	/**
	 * Interrupt the GDB session
	 * 
	 * <p>
	 * The manager may employ a variety of mechanisms depending on the current configuration. If
	 * multiple interpreters are available, it will issue an "interrupt" command on whichever
	 * interpreter it believes is responsive -- usually the opposite of the one issuing the last
	 * run, continue, step, etc. command. Otherwise, it sends Ctrl-C to GDB's TTY, which
	 * unfortunately is notoriously unreliable. The manager will send Ctrl-C to the TTY up to three
	 * times, waiting about 10ms between each, until GDB issues a stopped event and presents a new
	 * prompt. If that fails, it is up to the user to find an alternative means to interrupt the
	 * target, e.g., issuing {@code kill [pid]} from the a terminal on the target's host.
	 * 
	 * @return a future that completes when GDB has entered the stopped state
	 */
	CompletableFuture<Void> interrupt();

	/**
	 * List GDB's inferiors
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code inferiors}.
	 * 
	 * @return a future that completes with a map of inferior IDs to inferior handles
	 */
	CompletableFuture<Map<Integer, GdbInferior>> listInferiors();

	/**
	 * List information for all breakpoints
	 * 
	 * <p>
	 * This is equivalent to the CLI command {@code info break}.
	 * 
	 * @return a future that completes with a list of information for all breakpoints
	 */
	CompletableFuture<Map<Long, GdbBreakpointInfo>> listBreakpoints();

	/**
	 * Disable the given breakpoints
	 * 
	 * <p>
	 * This is equivalent to the CLI command {@code disable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the GDB-assigned breakpoint numbers
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> disableBreakpoints(long... numbers);

	/**
	 * Enable the given breakpoints
	 * 
	 * <p>
	 * This is equivalent to the CLI command {@code enable breakpoint [NUMBER]}.
	 * 
	 * @param numbers the GDB-assigned breakpoint numbers
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> enableBreakpoints(long... numbers);

	/**
	 * Delete a breakpoint
	 * 
	 * <p>
	 * This is equivalent to the CLI command {@code delete breakpoint [NUMBER]}.
	 * 
	 * @param numbers the GDB-assigned breakpoint numbers
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> deleteBreakpoints(long... numbers);

	/**
	 * List the available processes on target
	 * 
	 * @return a future that completes with a list of PIDs
	 */
	CompletableFuture<List<GdbProcessThreadGroup>> listAvailableProcesses();

	/**
	 * Gather information about the host OS
	 * 
	 * <p>
	 * This is equivalent to the CLI command: {@code info os [TYPE]}.
	 * 
	 * @param type the type of OS information to gather
	 * @return a future which completes with a table of information
	 */
	CompletableFuture<GdbTable> infoOs(String type);

	/**
	 * Get the name of the mi2 pty for this GDB session
	 * 
	 * @return the filename
	 * @throws IOException if the filename could not be determined
	 */
	String getMi2PtyName() throws IOException;

	/**
	 * Get a description for the pty for this GDB session
	 * 
	 * @return the description
	 */
	String getPtyDescription();
}
