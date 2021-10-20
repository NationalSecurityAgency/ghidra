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
package agent.gdb.manager.impl;

import static ghidra.async.AsyncUtils.loop;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

import javax.swing.JDialog;
import javax.swing.JOptionPane;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.python.core.PyDictionary;
import org.python.icu.text.MessageFormat;
import org.python.util.InteractiveConsole;

import agent.gdb.manager.*;
import agent.gdb.manager.GdbCause.Causes;
import agent.gdb.manager.breakpoint.GdbBreakpointInfo;
import agent.gdb.manager.breakpoint.GdbBreakpointType;
import agent.gdb.manager.evt.*;
import agent.gdb.manager.impl.cmd.*;
import agent.gdb.manager.impl.cmd.GdbConsoleExecCommand.CompletesWithRunning;
import agent.gdb.manager.parsing.GdbMiParser;
import agent.gdb.manager.parsing.GdbParsingUtils.GdbParseError;
import agent.gdb.pty.*;
import ghidra.GhidraApplicationLayout;
import ghidra.async.*;
import ghidra.async.AsyncLock.Hold;
import ghidra.dbg.error.DebuggerModelTerminatingException;
import ghidra.dbg.util.HandlerMap;
import ghidra.dbg.util.PrefixMap;
import ghidra.lifecycle.Internal;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.ListenerSet;
import sun.misc.Signal;
import sun.misc.SignalHandler;

/**
 * Implementation of {@link GdbManager}
 * 
 * <p>
 * This is implemented using the asynchronous chaining library and executors. A single-threaded
 * executor handles issuing GDB command and processing events. Another thread handles reading GDB's
 * output and parsing events. Those events are then scheduled for processing on the executor. The
 * executor guarantees that commands are executed serially while reducing the risk of deadlock since
 * the asynchronous calls return futures immediately.
 * 
 * <p>
 * A {@link PrefixMap} aids in parsing GDB events. The event details are then parsed with the
 * {@link GdbMiParser} and passed around for processing. If a command is currently executed, that
 * command has the first option to claim or steal the event. If it is stolen, no further processing
 * takes place in the manager. If no command is executing, or the command does not steal it, the
 * event is processed using a {@link HandlerMap}.
 */
public class GdbManagerImpl implements GdbManager {
	private static final String GDB_IS_TERMINATING = "GDB is terminating";
	public static final int MAX_CMD_LEN = 4094; // Account for longest possible line end

	private static final String PTY_DIALOG_MESSAGE_PATTERN =
		"<html><p>Please enter:</p>" +
			"<pre>new-ui mi2 <b>{0}</b></pre>" + "" +
			"<p>into an existing gdb session.</p><br/>" +
			"<p>Alternatively, to launch a new session, cancel this dialog. " +
			"Then, retry with <b>use existing session</b> disabled.</p></html>";

	private static final String CANCEL = "Cancel";

	@Internal
	public enum Interpreter {
		CLI, MI2;
	}

	private static final boolean LOG_IO =
		Boolean.getBoolean("agent.gdb.manager.log") || SystemUtilities.isInDevelopmentMode();
	private static PrintWriter DBG_LOG = null;
	private static final String PROMPT_GDB = "(gdb)";
	public static final int INTERRUPT_MAX_RETRIES = 3;
	public static final int INTERRUPT_RETRY_PERIOD_MILLIS = 100;

	class PtyThread extends Thread {
		final Pty pty;
		final BufferedReader reader;
		final Channel channel;

		Interpreter interpreter;
		PrintWriter writer;
		CompletableFuture<Void> hasWriter;

		PtyThread(Pty pty, Channel channel, Interpreter interpreter) {
			this.pty = pty;
			this.channel = channel;
			this.reader =
				new BufferedReader(new InputStreamReader(pty.getParent().getInputStream()));
			this.interpreter = interpreter;
			hasWriter = new CompletableFuture<>();
		}

		@Override
		public void run() {
			if (LOG_IO && DBG_LOG == null) {
				initLog();
			}
			try {
				String line;
				while (isAlive() && null != (line = reader.readLine())) {
					String l = line;
					if (interpreter == null) {
						if (l.startsWith("=") || l.startsWith("~")) {
							interpreter = Interpreter.MI2;
						}
						else {
							interpreter = Interpreter.CLI;
						}
					}
					if (writer == null) {
						writer = new PrintWriter(pty.getParent().getOutputStream());
						hasWriter.complete(null);
					}
					//Msg.debug(this, channel + ": " + line);
					submit(() -> {
						if (LOG_IO) {
							DBG_LOG.println("<" + interpreter + ": " + l);
							DBG_LOG.flush();
						}
						processLine(l, channel, interpreter);
					});
				}
			}
			catch (Throwable e) {
				terminate();
				Msg.debug(this, channel + "," + interpreter + " reader exiting because " + e);
				//throw new AssertionError(e);
			}
		}
	}

	class PtyInfoDialogThread extends Thread {
		private final JOptionPane pane;
		private final JDialog dialog;
		final CompletableFuture<Integer> result = new CompletableFuture<>();

		public PtyInfoDialogThread(String ptyName) {
			String message = MessageFormat.format(PTY_DIALOG_MESSAGE_PATTERN, ptyName);
			pane = new JOptionPane(message, JOptionPane.PLAIN_MESSAGE, 0, null,
				new Object[] { CANCEL });
			dialog = pane.createDialog("Waiting for GDB/MI session");
		}

		@Override
		public void run() {
			dialog.setVisible(true);
			Object sel = pane.getValue();
			if (CANCEL.equals(sel)) {
				result.complete(JOptionPane.CANCEL_OPTION);
			}
			else {
				result.complete(JOptionPane.CLOSED_OPTION);
			}
		}
	}

	private final PtyFactory ptyFactory;

	private final AsyncReference<GdbState, GdbCause> state =
		new AsyncReference<>(GdbState.NOT_STARTED);
	// A copy of state, which is updated on the eventThread.
	private final AsyncReference<GdbState, GdbCause> asyncState = new AsyncReference<>(state.get());
	private Interpreter runningInterpreter;
	private final AsyncReference<Boolean, Void> mi2Prompt = new AsyncReference<>(false);

	private final PrefixMap<GdbEvent<?>, GdbParseError> mi2PrefixMap = new PrefixMap<>();
	private final HandlerMap<GdbEvent<?>, Void, Void> handlerMap = new HandlerMap<>();
	private final AtomicBoolean exited = new AtomicBoolean(false);

	private PtySession gdb;
	private Thread gdbWaiter;

	private PtyThread iniThread;
	private PtyThread cliThread;
	private PtyThread mi2Thread;

	private String newLine = System.lineSeparator();

	private final AsyncLock cmdLock = new AsyncLock();
	private final AtomicReference<AsyncLock.Hold> cmdLockHold = new AtomicReference<>(null);
	private ExecutorService executor;
	private final AsyncTimer timer = AsyncTimer.DEFAULT_TIMER;

	private GdbPendingCommand<?> curCmd = null;

	private final Map<Integer, GdbInferiorImpl> inferiors = new LinkedHashMap<>();
	private GdbInferiorImpl curInferior = null;
	private final Map<Integer, GdbInferior> unmodifiableInferiors =
		Collections.unmodifiableMap(inferiors);

	private final Map<Integer, GdbThreadImpl> threads = new LinkedHashMap<>();
	private final Map<Integer, GdbThread> unmodifiableThreads =
		Collections.unmodifiableMap(threads);

	private final Map<Long, GdbBreakpointInfo> breakpoints = new LinkedHashMap<>();
	private final Map<Long, GdbBreakpointInfo> unmodifiableBreakpoints =
		Collections.unmodifiableMap(breakpoints);

	protected final ListenerSet<GdbEventsListener> listenersEvent =
		new ListenerSet<>(GdbEventsListener.class);
	protected final ListenerSet<GdbTargetOutputListener> listenersTargetOutput =
		new ListenerSet<>(GdbTargetOutputListener.class);
	protected final ListenerSet<GdbConsoleOutputListener> listenersConsoleOutput =
		new ListenerSet<>(GdbConsoleOutputListener.class);
	protected final ExecutorService eventThread = Executors.newSingleThreadExecutor();

	/**
	 * Instantiate a new manager
	 * 
	 * @param ptyFactory a factory for creating Pty's for child GDBs
	 */
	public GdbManagerImpl(PtyFactory ptyFactory) {
		this.ptyFactory = ptyFactory;

		state.filter(this::stateFilter);
		state.addChangeListener(this::trackRunningInterpreter);
		state.addChangeListener((os, ns, c) -> event(() -> asyncState.set(ns, c), "managerState"));
		defaultPrefixes();
		defaultHandlers();
	}

	private void initLog() {
		try {
			GhidraApplicationLayout layout = new GhidraApplicationLayout();
			File userSettings = layout.getUserSettingsDir();
			File logFile = new File(userSettings, "GDB.log");
			try {
				logFile.createNewFile();
			}
			catch (Exception e) {
				throw new AssertionError(logFile.getPath() + " appears to be unwritable", e);
			}
			DBG_LOG = new PrintWriter(new FileOutputStream(logFile));
		}
		catch (IOException e) {
			throw new AssertionError(e);
		}
	}

	CompletableFuture<Void> event(Runnable r, String text) {
		//Msg.debug(this, "Queueing event: " + text);
		return CompletableFuture.runAsync(r, eventThread).exceptionally(ex -> {
			Msg.error(this, "Error in event callback:", ex);
			return ExceptionUtils.rethrow(ex);
		});
	}

	private GdbState stateFilter(GdbState cur, GdbState set, GdbCause cause) {
		if (set == null) {
			return cur;
		}
		return set;
	}

	private void trackRunningInterpreter(GdbState oldSt, GdbState st, GdbCause cause) {
		if (st == GdbState.RUNNING && cause instanceof GdbPendingCommand) {
			GdbPendingCommand<?> pcmd = (GdbPendingCommand<?>) cause;
			runningInterpreter = pcmd.getCommand().getInterpreter();
			//Msg.debug(this, "Entered " + st + " with interpreter: " + runningInterpreter);
		}
		else {
			runningInterpreter = null;
		}
	}

	private void defaultPrefixes() {
		mi2PrefixMap.put("-", GdbCommandEchoEvent::new);
		mi2PrefixMap.put("~", GdbConsoleOutputEvent::fromMi2);
		mi2PrefixMap.put("@", GdbTargetOutputEvent::new);
		mi2PrefixMap.put("&", GdbDebugOutputEvent::new);

		mi2PrefixMap.put("^done", GdbCommandDoneEvent::new);
		mi2PrefixMap.put("^running", GdbCommandRunningEvent::new);
		mi2PrefixMap.put("^connected", GdbCommandConnectedEvent::new);
		mi2PrefixMap.put("^exit", GdbCommandExitEvent::new);
		mi2PrefixMap.put("^error", GdbCommandErrorEvent::fromMi2);

		mi2PrefixMap.put("*running", GdbRunningEvent::new);
		mi2PrefixMap.put("*stopped", GdbStoppedEvent::new);

		mi2PrefixMap.put("=thread-group-added", GdbThreadGroupAddedEvent::new);
		mi2PrefixMap.put("=thread-group-removed", GdbThreadGroupRemovedEvent::new);
		mi2PrefixMap.put("=thread-group-started", GdbThreadGroupStartedEvent::new);
		mi2PrefixMap.put("=thread-group-exited", GdbThreadGroupExitedEvent::new);

		mi2PrefixMap.put("=thread-created", GdbThreadCreatedEvent::new);
		mi2PrefixMap.put("=thread-exited", GdbThreadExitedEvent::new);
		mi2PrefixMap.put("=thread-selected", GdbThreadSelectedEvent::new);
		mi2PrefixMap.put("=library-loaded", GdbLibraryLoadedEvent::new);
		mi2PrefixMap.put("=library-unloaded", GdbLibraryUnloadedEvent::new);
		mi2PrefixMap.put("=breakpoint-created", t -> new GdbBreakpointCreatedEvent(t, this));
		mi2PrefixMap.put("=breakpoint-modified", GdbBreakpointModifiedEvent::new);
		mi2PrefixMap.put("=breakpoint-deleted", GdbBreakpointDeletedEvent::new);

		mi2PrefixMap.put("=memory-changed", GdbMemoryChangedEvent::new);
		mi2PrefixMap.put("=cmd-param-changed", GdbParamChangedEvent::new);
	}

	private void defaultHandlers() {
		handlerMap.putVoid(GdbCommandEchoEvent.class, this::ignoreCmdEcho);
		handlerMap.putVoid(GdbConsoleOutputEvent.class, this::processStdOut);
		handlerMap.putVoid(GdbTargetOutputEvent.class, this::processTargetOut);
		handlerMap.putVoid(GdbDebugOutputEvent.class, this::processStdErr);

		handlerMap.putVoid(GdbCommandDoneEvent.class, this::processCommandDone);
		handlerMap.putVoid(GdbCommandRunningEvent.class, this::processCommandRunning);
		handlerMap.putVoid(GdbCommandConnectedEvent.class, this::processCommandConnected);
		handlerMap.putVoid(GdbCommandExitEvent.class, this::processCommandExit);
		handlerMap.putVoid(GdbCommandErrorEvent.class, this::processCommandError);

		handlerMap.putVoid(GdbRunningEvent.class, this::processRunning);
		handlerMap.putVoid(GdbStoppedEvent.class, this::processStopped);

		handlerMap.putVoid(GdbThreadGroupAddedEvent.class, this::processThreadGroupAdded);
		handlerMap.putVoid(GdbThreadGroupRemovedEvent.class, this::processThreadGroupRemoved);
		handlerMap.putVoid(GdbThreadGroupStartedEvent.class, this::processThreadGroupStarted);
		handlerMap.putVoid(GdbThreadGroupExitedEvent.class, this::processThreadGroupExited);

		handlerMap.putVoid(GdbThreadCreatedEvent.class, this::processThreadCreated);
		handlerMap.putVoid(GdbThreadExitedEvent.class, this::processThreadExited);
		handlerMap.putVoid(GdbThreadSelectedEvent.class, this::processThreadSelected);
		handlerMap.putVoid(GdbLibraryLoadedEvent.class, this::processLibraryLoaded);
		handlerMap.putVoid(GdbLibraryUnloadedEvent.class, this::processLibraryUnloaded);
		handlerMap.putVoid(GdbBreakpointCreatedEvent.class, this::processBreakpointCreated);
		handlerMap.putVoid(GdbBreakpointModifiedEvent.class, this::processBreakpointModified);
		handlerMap.putVoid(GdbBreakpointDeletedEvent.class, this::processBreakpointDeleted);

		handlerMap.putVoid(GdbMemoryChangedEvent.class, this::processMemoryChanged);
		handlerMap.putVoid(GdbParamChangedEvent.class, this::processParamChanged);
	}

	@Override
	public boolean isAlive() {
		return state.get().isAlive();
	}

	@Override
	public void addStateListener(GdbStateListener listener) {
		asyncState.addChangeListener(listener);
	}

	@Override
	public void removeStateListener(GdbStateListener listener) {
		asyncState.removeChangeListener(listener);
	}

	@Override
	public void addEventsListener(GdbEventsListener listener) {
		listenersEvent.add(listener);
	}

	@Override
	public void removeEventsListener(GdbEventsListener listener) {
		listenersEvent.remove(listener);
	}

	@Internal // for detach command
	public void fireThreadExited(int tid, GdbInferiorImpl inferior, GdbCause cause) {
		event(() -> listenersEvent.fire.threadExited(tid, inferior, cause), "threadExited");
	}

	@Override
	public void addTargetOutputListener(GdbTargetOutputListener listener) {
		listenersTargetOutput.add(listener);
	}

	@Override
	public void removeTargetOutputListener(GdbTargetOutputListener listener) {
		listenersTargetOutput.remove(listener);
	}

	@Override
	public void addConsoleOutputListener(GdbConsoleOutputListener listener) {
		listenersConsoleOutput.add(listener);
	}

	@Override
	public void removeConsoleOutputListener(GdbConsoleOutputListener listener) {
		listenersConsoleOutput.remove(listener);
	}

	/**
	 * Use {@link GdbThreadImpl#add()} instead
	 * 
	 * @param thread the thread to add
	 */
	public void addThread(GdbThreadImpl thread) {
		GdbThreadImpl exists = threads.get(thread.getId());
		if (exists != null) {
			throw new IllegalArgumentException("There is already thread " + exists);
		}
		threads.put(thread.getId(), thread);
	}

	@Override
	public GdbThreadImpl getThread(int tid) {
		GdbThreadImpl result = threads.get(tid);
		if (result == null) {
			throw new IllegalArgumentException("There is no thread with id " + tid);
		}
		return result;
	}

	public CompletableFuture<GdbThreadInfo> getThreadInfo(int threadId) {
		return execute(new GdbGetThreadInfoCommand(this, threadId));
	}

	/**
	 * Use {@link GdbThreadImpl#remove()} instead
	 * 
	 * @param tid the thread ID to remove
	 */
	public void removeThread(int tid) {
		if (threads.remove(tid) == null) {
			throw new IllegalArgumentException("There is no thread with id " + tid);
		}
	}

	/**
	 * Use {@link GdbInferiorImpl#add(GdbCause)} instead
	 * 
	 * @param inferior the inferior to add
	 * @param cause the cause of the new inferior
	 */
	@Internal
	public void addInferior(GdbInferiorImpl inferior, GdbCause cause) {
		GdbInferiorImpl exists = inferiors.get(inferior.getId());
		if (exists != null) {
			throw new IllegalArgumentException("There is already inferior " + exists);
		}
		inferiors.put(inferior.getId(), inferior);
		event(() -> listenersEvent.fire.inferiorAdded(inferior, cause), "addInferior");
	}

	/**
	 * Use {@link GdbInferiorImpl#remove(GdbCause)} instead
	 * 
	 * @param iid the inferior ID to remove
	 * @param cause the cause of removal
	 */
	@Internal
	public void removeInferior(int iid, GdbCause cause) {
		if (inferiors.remove(iid) == null) {
			throw new IllegalArgumentException("There is no inferior with id " + iid);
		}
		event(() -> listenersEvent.fire.inferiorRemoved(iid, cause), "removeInferior");
	}

	/**
	 * Update the selected inferior
	 * 
	 * @param inferior the inferior that now has focus
	 * @param cause the cause of the focus change
	 */
	protected boolean updateCurrentInferior(GdbInferiorImpl inferior, GdbCause cause,
			boolean fire) {
		// GDB will not permit removing all inferiors, so one is guaranteed to exist
		// GDB may actually have already selected it, but without generating events
		GdbInferiorImpl inf = inferior != null ? inferior : inferiors.values().iterator().next();
		if (curInferior != inf) {
			curInferior = inf;
			if (fire) {
				event(() -> listenersEvent.fire.inferiorSelected(inf, cause),
					"updateCurrentInferior");
			}
			return true;
		}
		return false;
	}

	@Override
	public GdbInferiorImpl getInferior(int iid) {
		GdbInferiorImpl result = inferiors.get(iid);
		if (result == null) {
			throw new IllegalArgumentException("There is no inferior with id " + iid);
		}
		return result;
	}

	private void checkStarted() {
		if (state.get() == GdbState.NOT_STARTED) {
			throw new IllegalStateException(
				"GDB has not been started or has not finished starting");
		}
	}

	private void checkStartedNotExit() {
		checkStarted();
		if (state.get() == GdbState.EXIT) {
			throw new DebuggerModelTerminatingException(GDB_IS_TERMINATING);
		}
	}

	@Override
	public GdbInferior currentInferior() {
		checkStartedNotExit();
		return curInferior;
	}

	@Override
	public Map<Integer, GdbInferior> getKnownInferiors() {
		return unmodifiableInferiors;
	}

	@Internal
	public Map<Integer, GdbInferiorImpl> getKnownInferiorsInternal() {
		return inferiors;
	}

	@Override
	public Map<Integer, GdbThread> getKnownThreads() {
		return unmodifiableThreads;
	}

	@Override
	public Map<Long, GdbBreakpointInfo> getKnownBreakpoints() {
		return unmodifiableBreakpoints;
	}

	@Internal
	public Map<Long, GdbBreakpointInfo> getKnownBreakpointsInternal() {
		return breakpoints;
	}

	public GdbBreakpointInfo addKnownBreakpoint(GdbBreakpointInfo bkpt, boolean expectExisting) {
		GdbBreakpointInfo old = breakpoints.put(bkpt.getNumber(), bkpt);
		if (expectExisting && old == null) {
			Msg.warn(this, "Was missing breakpoint " + bkpt.getNumber());
		}
		else if (!expectExisting && old != null) {
			Msg.warn(this, "Already had breakpoint " + bkpt.getNumber());
		}
		return old;
	}

	private GdbBreakpointInfo getKnownBreakpoint(long number) {
		GdbBreakpointInfo info = breakpoints.get(number);
		if (info == null) {
			Msg.warn(this, "Breakpoint " + number + " is not known");
		}
		return info;
	}

	public GdbBreakpointInfo removeKnownBreakpoint(long number) {
		GdbBreakpointInfo del = breakpoints.remove(number);
		if (del == null) {
			Msg.warn(this, "Deleted missing breakpoint " + number);
		}
		return del;
	}

	@Override
	public CompletableFuture<GdbBreakpointInfo> insertBreakpoint(String loc,
			GdbBreakpointType type) {
		return execute(new GdbInsertBreakpointCommand(this, null, loc, type));
	}

	@Override
	public CompletableFuture<Void> disableBreakpoints(long... numbers) {
		return execute(new GdbDisableBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Void> enableBreakpoints(long... numbers) {
		return execute(new GdbEnableBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Void> deleteBreakpoints(long... numbers) {
		return execute(new GdbDeleteBreakpointsCommand(this, numbers));
	}

	@Override
	public CompletableFuture<Map<Long, GdbBreakpointInfo>> listBreakpoints() {
		return execute(new GdbListBreakpointsCommand(this, null));
	}

	private void submit(Runnable runnable) {
		checkStartedNotExit();
		executor.submit(() -> {
			try {
				runnable.run();
			}
			catch (Throwable e) {
				e.printStackTrace();
			}
		});
	}

	@Override
	public void setNewLine(String newLine) {
		this.newLine = newLine;
	}

	@Override
	public void start(String gdbCmd, String... args) throws IOException {
		List<String> fullargs = new ArrayList<>();
		fullargs.addAll(Arrays.asList(gdbCmd));
		fullargs.addAll(Arrays.asList(args));

		state.set(GdbState.STARTING, Causes.UNCLAIMED);
		executor = Executors.newSingleThreadExecutor();

		if (gdbCmd != null) {
			iniThread = new PtyThread(ptyFactory.openpty(), Channel.STDOUT, null);

			gdb = iniThread.pty.getChild().session(fullargs.toArray(new String[] {}), null);
			gdbWaiter = new Thread(this::waitGdbExit, "GDB WaitExit");
			gdbWaiter.start();

			iniThread.start();
			try {
				CompletableFuture.anyOf(iniThread.hasWriter, state.waitValue(GdbState.EXIT))
						.get(10, TimeUnit.SECONDS);
			}
			catch (InterruptedException | ExecutionException | TimeoutException e) {
				throw new IOException("Could not detect GDB's interpreter mode");
			}
			if (state.get() == GdbState.EXIT) {
				throw new IOException("GDB terminated before first prompt");
			}
			switch (iniThread.interpreter) {
				case CLI:
					Pty mi2Pty = ptyFactory.openpty();

					cliThread = iniThread;
					cliThread.setName("GDB Read CLI");
					// Looks terrible, but we're already in this world
					cliThread.writer.print("set confirm off" + newLine);
					cliThread.writer.print("set pagination off" + newLine);
					cliThread.writer
							.print("new-ui mi2 " + mi2Pty.getChild().nullSession() + newLine);
					cliThread.writer.flush();

					mi2Thread = new PtyThread(mi2Pty, Channel.STDOUT, Interpreter.MI2);
					mi2Thread.setName("GDB Read MI2");
					mi2Thread.start();
					try {
						mi2Thread.hasWriter.get(2, TimeUnit.SECONDS);
					}
					catch (InterruptedException | ExecutionException | TimeoutException e) {
						throw new IOException(
							"Could not obtain GDB/MI2 interpreter. Try " + gdbCmd + " -i mi2");
					}
					break;
				case MI2:
					mi2Thread = iniThread;
					mi2Thread.setName("GDB Read MI2");
					break;
			}
		}
		else {
			Pty mi2Pty = ptyFactory.openpty();
			String mi2PtyName = mi2Pty.getChild().nullSession();
			Msg.info(this, "Agent is waiting for GDB/MI v2 interpreter at " + mi2PtyName);
			mi2Thread = new PtyThread(mi2Pty, Channel.STDOUT, Interpreter.MI2);
			mi2Thread.setName("GDB Read MI2");

			mi2Thread.start();

			PtyInfoDialogThread dialog = new PtyInfoDialogThread(mi2PtyName);
			dialog.start();
			dialog.result.thenAccept(choice -> {
				if (choice == JOptionPane.CANCEL_OPTION) {
					mi2Thread.hasWriter.cancel(false);
					// This will cause 
				}
			});

			// Yes, wait on the user indefinitely.
			try {
				mi2Thread.hasWriter.get();
			}
			catch (InterruptedException | ExecutionException e) {
				Msg.info(this, "The user cancelled, or something else: " + e);
				terminate();
			}
			dialog.dialog.setVisible(false);
		}

		// Do this whether or not joining existing. It's possible .gdbinit did stuff.
		resync();
	}

	@Override
	public CompletableFuture<Void> runRC() {
		return waitForPrompt().thenCompose(__ -> rc());
	}

	/**
	 * Execute commands upon GDB startup
	 * 
	 * @return a future which completes when the rc commands are complete
	 */
	protected CompletableFuture<Void> rc() {
		if (cliThread != null) {
			// NB. confirm and pagination are already disabled here
			return AsyncUtils.NIL;
		}
		else {
			// NB. Don't disable pagination here. MI2 is not paginated.
			return console("set confirm off", CompletesWithRunning.CANNOT);
		}
	}

	protected void resync() {
		AsyncFence fence = new AsyncFence();
		fence.include(listInferiors().thenCompose(infs -> {
			AsyncFence inner = new AsyncFence();
			for (GdbInferior inf : infs.values()) {
				// NOTE: Mappings need not be constantly synced
				// NOTE: Modules need not be constantly synced
				inner.include(inf.listThreads());
			}
			return inner.ready();
		}));
		fence.include(listBreakpoints());
		// NOTE: Available processes need not be constantly synced
		fence.ready().exceptionally(ex -> {
			Msg.error(this, "Could not resync the GDB session: " + ex);
			return null;
		});
	}

	private void waitGdbExit() {
		try {
			int exitcode = gdb.waitExited();
			state.set(GdbState.EXIT, Causes.UNCLAIMED);
			exited.set(true);
			if (!executor.isShutdown()) {
				processGdbExited(exitcode);
				terminate();
			}
		}
		catch (InterruptedException e) {
			terminate();
		}
	}

	@Override
	public synchronized void terminate() {
		Msg.debug(this, "Terminating " + this);
		checkStarted();
		exited.set(true);
		executor.shutdownNow();
		if (gdbWaiter != null) {
			gdbWaiter.interrupt();
		}
		if (gdb != null) {
			gdb.destroyForcibly();
		}
		try {
			if (cliThread != null) {
				cliThread.interrupt();
				cliThread.pty.close();
			}
			if (mi2Thread != null) {
				mi2Thread.interrupt();
				mi2Thread.pty.close();
			}
		}
		catch (IOException e) {
			Msg.error(this, "Problem closing PTYs to GDB.");
		}
		DebuggerModelTerminatingException reason =
			new DebuggerModelTerminatingException(GDB_IS_TERMINATING);
		cmdLock.dispose(reason);
		state.dispose(reason);
		mi2Prompt.dispose(reason);
		for (GdbThreadImpl thread : threads.values()) {
			thread.dispose(reason);
		}
		GdbPendingCommand<?> cc = this.curCmd; // read volatile
		if (cc != null && !cc.isDone()) {
			cc.completeExceptionally(reason);
		}
	}

	protected <T> CompletableFuture<T> execute(GdbCommand<? extends T> cmd) {
		// NB. curCmd::finish is passed to eventThread already 
		return doExecute(cmd);//.thenApplyAsync(t -> t, eventThread);
	}

	/**
	 * Schedule a command for execution
	 * 
	 * @param cmd the command to execute
	 * @return the pending command, which acts as a future for later completion
	 */
	protected <T> GdbPendingCommand<T> doExecute(GdbCommand<? extends T> cmd) {
		assert cmd != null;
		checkStartedNotExit();
		GdbPendingCommand<T> pcmd = new GdbPendingCommand<>(cmd);

		//Msg.debug(this, "WAITING cmdLock: " + pcmd);
		cmdLock.acquire(null).thenAccept(hold -> {
			cmdLockHold.set(hold);
			//Msg.debug(this, "ACQUIRED cmdLock: " + pcmd);
			synchronized (this) {
				if (curCmd != null) {
					throw new AssertionError("Cannot execute more than one command at a time");
				}
				if (gdb != null && !cmd.validInState(state.get())) {
					throw new GdbCommandError(
						"Command " + cmd + " is not valid while " + state.get());
				}
				cmd.preCheck(pcmd);
				if (pcmd.isDone()) {
					cmdLockHold.getAndSet(null).release();
					return;
				}
				curCmd = pcmd;
				//Msg.debug(this, "CURCMD = " + curCmd);
				if (LOG_IO) {
					DBG_LOG.println("*CMD: " + cmd.getClass());
					DBG_LOG.flush();
				}
				String text = cmd.encode();
				if (text != null) {
					Interpreter interpreter = cmd.getInterpreter();
					PrintWriter wr = getWriter(interpreter);
					//Msg.debug(this, "STDIN: " + text);
					wr.print(text + newLine);
					wr.flush();
					if (LOG_IO) {
						DBG_LOG.println(">" + interpreter + ": " + text);
						DBG_LOG.flush();
					}
				}
			}
		}).exceptionally((exc) -> {
			pcmd.completeExceptionally(exc);
			//Msg.debug(this, "ON_EXCEPTION: CURCMD = " + curCmd);
			synchronized (this) {
				curCmd = null;
			}
			//Msg.debug(this, "SET CURCMD = null");
			//Msg.debug(this, "RELEASING cmdLock");
			Hold hold = cmdLockHold.getAndSet(null);
			if (hold != null) {
				hold.release();
			}
			return null;
		});
		return pcmd;
	}

	@Override
	public void cancelCurrentCommand() {
		GdbPendingCommand<?> curCmd;
		synchronized (this) {
			curCmd = this.curCmd;
			this.curCmd = null;
		}
		if (curCmd != null) {
			Msg.info(this, "Cancelling current command: " + curCmd);
			curCmd.cancel(false);
		}
		Hold hold = cmdLockHold.getAndSet(null);
		if (hold != null) {
			hold.release();
		}
	}

	protected PrintWriter getWriter(Interpreter interpreter) {
		switch (interpreter) {
			case CLI:
				return cliThread == null ? null : cliThread.writer;
			case MI2:
				return mi2Thread == null ? null : mi2Thread.writer;
			default:
				throw new AssertionError();
		}
	}

	protected void checkImpliedFocusChange() {
		Integer tid = curCmd.impliesCurrentThreadId();
		GdbThreadImpl thread = null;
		if (tid != null) {
			thread = threads.get(tid);
			if (thread == null) {
				Msg.info(this, "Thread " + tid + " no longer exists");
				return;
				// Presumably, some event will have announced the new current thread
			}
		}
		Integer level = curCmd.impliesCurrentFrameId();
		GdbStackFrameImpl frame = null;
		if (level != null) {
			frame = new GdbStackFrameImpl(thread, level, null, null);
		}
		if (thread != null) {
			doThreadSelected(thread, frame, curCmd);
		}
	}

	protected synchronized void processEvent(GdbEvent<?> evt) {
		/**
		 * NOTE: I've forgotten why, but the the state update needs to happen between handle and
		 * finish.
		 */
		boolean cmdFinished = false;
		if (curCmd != null) {
			cmdFinished = curCmd.handle(evt);
			if (cmdFinished) {
				checkImpliedFocusChange();
			}
		}

		GdbState newState = evt.newState();
		//Msg.debug(this, evt + " transitions state to " + newState);
		state.set(newState, evt.getCause());

		// NOTE: Do not check if claimed here.
		// Downstream processing should check for cause
		handlerMap.handle(evt, null);

		if (cmdFinished) {
			event(curCmd::finish, "curCmd::finish");
			curCmd = null;
			cmdLockHold.getAndSet(null).release();
		}
	}

	/**
	 * Schedule a line of GDB output for processing
	 * 
	 * <p>
	 * Before the implementation started using a PTY, the channel was used to distinguish whether
	 * the line was read from stdout or stderr. Now, all output is assumed to be from stdout.
	 * 
	 * @param line the line
	 * @param channel the channel producing the line (stdout)
	 */
	protected synchronized void processLine(String line, Channel channel, Interpreter interpreter) {
		if (interpreter == Interpreter.CLI) {
			processEvent(GdbConsoleOutputEvent.fromCli(line));
			return;
		}
		if ("".equals(line.trim())) {
			return;
		}
		//Msg.debug(this, "processing: " + channel + ": " + line);
		mi2Prompt.set(false, null); // Go ahead and fire on a second consecutive prompt
		if (PROMPT_GDB.equals(line.trim())) {
			if (state.get() == GdbState.STARTING) {
				state.set(GdbState.STOPPED, Causes.UNCLAIMED);
			}
			//Msg.debug(this, "AT_PROMPT: CURCMD = " + curCmd);
			/*if (curCmd != null) {
				curCmd.finish();
				curCmd = null;
				//Msg.debug(this, "SET CURCMD = null");
				//Msg.debug(this, "RELEASING cmdLock");
				cmdLockHold.getAndSet(null).release();
			}*/
			mi2Prompt.set(true, null);
		}
		else {
			GdbEvent<?> evt = null;
			try {
				while (line.startsWith("^C")) {
					Msg.info(this, "Got ^C");
					line = line.substring(2);
				}
				evt = mi2PrefixMap.construct(line);
				if (evt == null) {
					Msg.warn(this, "Unknown event: " + line);
					return;
				}
				processEvent(evt);
			}
			catch (GdbParseError e) {
				throw new RuntimeException("GDB gave an unrecognized response", e);
			}
			catch (IllegalArgumentException e) {
				Msg.warn(this, "Error processing GDB output", e);
			}
		}
	}

	protected void processGdbExited(int exitcode) {
		Msg.info(this, "GDB exited with code " + exitcode);
	}

	/**
	 * Called for lines starting with "-", which are just commands echoed back by the PTY
	 * 
	 * @param evt the "event"
	 * @param v nothing
	 */
	protected void ignoreCmdEcho(GdbCommandEchoEvent evt, Void v) {
		// Do nothing
	}

	/**
	 * Called for lines starting with "~", which are lines GDB would like printed to stdout
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processStdOut(GdbConsoleOutputEvent evt, Void v) {
		String out = evt.getOutput();
		//System.out.print(out);
		if (!evt.isStolen()) {
			listenersConsoleOutput.fire.output(Channel.STDOUT, out);
		}
		if (evt.getInterpreter() == Interpreter.MI2 &&
			out.toLowerCase().contains("switching to inferior")) {
			String[] parts = out.trim().split("\\s+");
			int iid = Integer.parseInt(parts[3]);
			updateCurrentInferior(getInferior(iid), evt.getCause(), true);
		}
	}

	/**
	 * Called for lines starting with "@", which are lines printed by the target (limited support)
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processTargetOut(GdbTargetOutputEvent evt, Void v) {
		listenersTargetOutput.fire.output(evt.getOutput());
	}

	/**
	 * Called for lines starting with "&", which are lines GDB would like printed to stderr
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processStdErr(GdbDebugOutputEvent evt, Void v) {
		String out = evt.getOutput();
		//System.err.print(out);
		if (!evt.isStolen()) {
			listenersConsoleOutput.fire.output(Channel.STDERR, out);
		}
	}

	/**
	 * Handler for "=thread-group-added" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processThreadGroupAdded(GdbThreadGroupAddedEvent evt, Void v) {
		int iid = evt.getInferiorId();
		GdbInferiorImpl inferior = new GdbInferiorImpl(this, iid);
		/**
		 * Update currentInferior, but delay event. inferiorAdded callbacks may ask for
		 * currentInferior, so it must be up-to-date. However, inferiorSelected callbacks should not
		 * refer to an inferior that has not appeared in an inferiorAdded event.
		 */
		boolean fireSelected = false;
		if (inferiors.isEmpty()) {
			fireSelected = updateCurrentInferior(inferior, evt.getCause(), false);
		}
		inferior.add(evt.getCause());
		if (fireSelected) {
			event(() -> listenersEvent.fire.inferiorSelected(inferior, evt.getCause()),
				"groupAdded-sel");
		}
	}

	/**
	 * Handler for "=thread-group-removed" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processThreadGroupRemoved(GdbThreadGroupRemovedEvent evt, Void v) {
		int iid = evt.getInferiorId();
		GdbInferiorImpl inferior = getInferior(iid);
		GdbInferiorImpl cur;
		boolean fireSelected = false;
		if (curInferior == inferior) {
			// Select a new current before removing, so no event is generated yet
			cur = inferiors.values().stream().filter(i -> i != inferior).findFirst().get();
			// Can't remove all, so this should always come out true
			fireSelected = updateCurrentInferior(cur, evt.getCause(), false);
		}
		else {
			cur = null;
		}
		inferior.remove(evt.getCause());
		if (fireSelected) {
			event(() -> listenersEvent.fire.inferiorSelected(cur, evt.getCause()),
				"groupRemoved-sel");
			// Also cause GDB to generate thread selection events, if applicable
			setActiveInferior(cur, false);
		}
	}

	/**
	 * Handler for "=thread-group-started" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processThreadGroupStarted(GdbThreadGroupStartedEvent evt, Void v) {
		int iid = evt.getInferiorId();
		GdbInferiorImpl inf = getInferior(iid);
		inf.setPid(evt.getPid());
		fireInferiorStarted(inf, evt.getCause(), "inferiorStarted");
	}

	public void fireInferiorStarted(GdbInferiorImpl inf, GdbCause cause, String text) {
		event(() -> listenersEvent.fire.inferiorStarted(inf, cause), text);
	}

	/**
	 * Handler for "=thread-group-exited" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processThreadGroupExited(GdbThreadGroupExitedEvent evt, Void v) {
		int iid = evt.getInferiorId();
		GdbInferiorImpl inf = getInferior(iid);
		inf.setExitCode(evt.getExitCode());
		event(() -> listenersEvent.fire.inferiorExited(inf, evt.getCause()), "inferiorExited");
	}

	/**
	 * Handler for "=thread-created" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processThreadCreated(GdbThreadCreatedEvent evt, Void v) {
		int tid = evt.getThreadId();
		int iid = evt.getInferiorId();
		GdbInferiorImpl inf = getInferior(iid);
		GdbThreadImpl thread = new GdbThreadImpl(this, inf, tid);
		thread.add();
		event(() -> listenersEvent.fire.threadCreated(thread, evt.getCause()), "threadCreated");
	}

	/**
	 * Handler for "=thread-exited" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processThreadExited(GdbThreadExitedEvent evt, Void v) {
		int tid = evt.getThreadId();
		int iid = evt.getInferiorId();
		GdbInferiorImpl inf = getInferior(iid);
		GdbThreadImpl thread = inf.getThread(tid);
		thread.remove();
		event(() -> listenersEvent.fire.threadExited(tid, inf, evt.getCause()), "threadExited");
	}

	/**
	 * Handler for "=thread-selected" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processThreadSelected(GdbThreadSelectedEvent evt, Void v) {
		int tid = evt.getThreadId();
		GdbThreadImpl thread = getThread(tid);
		GdbStackFrameImpl frame = evt.getFrame(thread);
		doThreadSelected(thread, frame, evt.getCause());
	}

	/**
	 * Fire thread (and frame) selection event
	 * 
	 * @param thread the new thread
	 * @param frame the new frame
	 * @param cause the cause of the selection change
	 */
	public void doThreadSelected(GdbThreadImpl thread, GdbStackFrame frame, GdbCause cause) {
		updateCurrentInferior(thread.getInferior(), cause, true);
		event(() -> listenersEvent.fire.threadSelected(thread, frame, cause), "threadSelected");
	}

	/**
	 * Handler for "=library-loaded" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processLibraryLoaded(GdbLibraryLoadedEvent evt, Void v) {
		Integer iid = evt.getInferiorId();
		String name = evt.getTargetName();
		if (iid == null) { // Context of all inferiors
			for (GdbInferiorImpl inf : inferiors.values()) {
				inf.libraryLoaded(name);
				event(() -> listenersEvent.fire.libraryLoaded(inf, name, evt.getCause()),
					"libraryLoaded");
			}
		}
		else {
			GdbInferiorImpl inf = getInferior(iid);
			inf.libraryLoaded(name);
			event(() -> listenersEvent.fire.libraryLoaded(inf, name, evt.getCause()),
				"libraryLoaded");
		}
	}

	/**
	 * Handler for "=library-unloaded" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processLibraryUnloaded(GdbLibraryUnloadedEvent evt, Void v) {
		Integer iid = evt.getInferiorId();
		String name = evt.getTargetName();
		if (iid == null) { // Context of all inferiors
			for (GdbInferiorImpl inf : inferiors.values()) {
				inf.libraryUnloaded(name);
				event(() -> listenersEvent.fire.libraryUnloaded(inf, name, evt.getCause()),
					"libraryUnloaded");
			}
		}
		else {
			GdbInferiorImpl inf = getInferior(iid);
			inf.libraryUnloaded(name);
			event(() -> listenersEvent.fire.libraryUnloaded(inf, name, evt.getCause()),
				"libraryUnloaded");
		}
	}

	/**
	 * Fire breakpoint created event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the creation
	 */
	@Internal
	public void doBreakpointCreated(GdbBreakpointInfo newInfo, GdbCause cause) {
		addKnownBreakpoint(newInfo, false);
		event(() -> listenersEvent.fire.breakpointCreated(newInfo, cause), "breakpointCreated");
	}

	/**
	 * Handler for "=breakpoint-created" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointCreated(GdbBreakpointCreatedEvent evt, Void v) {
		doBreakpointCreated(evt.getBreakpointInfo(), evt.getCause());
	}

	/**
	 * Fire breakpoint modified event
	 * 
	 * @param newInfo the new information
	 * @param cause the cause of the modification
	 */
	@Internal
	public void doBreakpointModified(GdbBreakpointInfo newInfo, GdbCause cause) {
		GdbBreakpointInfo oldInfo = addKnownBreakpoint(newInfo, true);
		event(() -> listenersEvent.fire.breakpointModified(newInfo, oldInfo, cause),
			"breakpointModified");
	}

	/**
	 * Handler for "=breakpoint-modified" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointModified(GdbBreakpointModifiedEvent evt, Void v) {
		doBreakpointModified(evt.getBreakpointInfo(), evt.getCause());
	}

	/**
	 * Fire breakpoint deleted event
	 * 
	 * @param number the deleted breakpoint number
	 * @param cause the cause of the deletion
	 */
	@Internal
	public void doBreakpointDeleted(long number, GdbCause cause) {
		GdbBreakpointInfo oldInfo = removeKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		event(() -> listenersEvent.fire.breakpointDeleted(oldInfo, cause), "breakpointDeleted");
	}

	protected void doBreakpointModifiedSameLocations(GdbBreakpointInfo newInfo,
			GdbBreakpointInfo oldInfo, GdbCause cause) {
		if (Objects.equals(newInfo, oldInfo)) {
			return;
		}
		addKnownBreakpoint(newInfo, true);
		event(() -> listenersEvent.fire.breakpointModified(newInfo, oldInfo, cause),
			"breakpointModified");
	}

	@Internal
	public void doBreakpointDisabled(long number, GdbCause cause) {
		GdbBreakpointInfo oldInfo = getKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		GdbBreakpointInfo newInfo = oldInfo.withEnabled(false);
		//oldInfo = oldInfo.withEnabled(true);
		doBreakpointModifiedSameLocations(newInfo, oldInfo, cause);
	}

	@Internal
	public void doBreakpointEnabled(long number, GdbCause cause) {
		GdbBreakpointInfo oldInfo = getKnownBreakpoint(number);
		if (oldInfo == null) {
			return;
		}
		GdbBreakpointInfo newInfo = oldInfo.withEnabled(true);
		//oldInfo = oldInfo.withEnabled(false);
		doBreakpointModifiedSameLocations(newInfo, oldInfo, cause);
	}

	/**
	 * Handler for "=breakpoint-deleted" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processBreakpointDeleted(GdbBreakpointDeletedEvent evt, Void v) {
		doBreakpointDeleted(evt.getNumber(), evt.getCause());
	}

	/**
	 * Handler for "=memory-changed" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processMemoryChanged(GdbMemoryChangedEvent evt, Void v) {
		int iid = evt.getInferiorId();
		GdbInferior inf = getInferior(iid);
		event(() -> listenersEvent.fire.memoryChanged(inf, evt.getAddress(), evt.getLength(),
			evt.getCause()), "memoryChanged");
	}

	/**
	 * Handler for "=cmd-param-changed" events
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processParamChanged(GdbParamChangedEvent evt, Void v) {
		event(() -> listenersEvent.fire.paramChanged(evt.getParam(), evt.getValue(),
			evt.getCause()), "paramChanged");
	}

	/**
	 * Check that a command completion event was claimed
	 * 
	 * Except under certain error conditions, GDB should never issue a command completed event that
	 * is not associated with a command. A command implementation in the manager must claim the
	 * completion event. This is an assertion to ensure no implementation forgets to do that.
	 * 
	 * @param evt the event
	 */
	protected void checkClaimed(GdbEvent<?> evt) {
		if (evt.getCause() == Causes.UNCLAIMED) {
			if (evt instanceof AbstractGdbCompletedCommandEvent) {
				AbstractGdbCompletedCommandEvent completed = (AbstractGdbCompletedCommandEvent) evt;
				String msg = completed.assumeMsg();
				if (msg != null) {
					if (evt instanceof GdbCommandErrorEvent) {
						Msg.error(this, msg);
					}
					else {
						Msg.info(this, msg);
						throw new AssertionError("Command completion left unclaimed!");
					}
				}
			}
		}
	}

	/**
	 * Handler for "^done"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processCommandDone(GdbCommandDoneEvent evt, Void v) {
		checkClaimed(evt);
	}

	/**
	 * Handler for "^running"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processCommandRunning(GdbCommandRunningEvent evt, Void v) {
		checkClaimed(evt);
		Msg.debug(this, "Target is running");
	}

	/**
	 * Handler for "^connected"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processCommandConnected(GdbCommandConnectedEvent evt, Void v) {
		checkClaimed(evt);
		Msg.debug(this, "Connected to target");
	}

	/**
	 * Handler for "^exit"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processCommandExit(GdbCommandExitEvent evt, Void v) {
		checkClaimed(evt);
		Msg.debug(this, "GDB is exiting....");
	}

	/**
	 * Handler for "^error"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processCommandError(GdbCommandErrorEvent evt, Void v) {
		checkClaimed(evt);
	}

	/**
	 * Handler for "*running"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processRunning(GdbRunningEvent evt, Void v) {
		String threadId = evt.assumeThreadId();
		if (threadId == null) {
			threadId = "all";
		}
		if ("all".equals(threadId)) {
			GdbInferiorImpl cur = curInferior;
			event(() -> {
				listenersEvent.fire.inferiorStateChanged(cur, cur.getKnownThreads().values(),
					evt.newState(), null, evt.getCause(), evt.getReason());
			}, "inferiorState-running");
			for (GdbThreadImpl thread : curInferior.getKnownThreadsImpl().values()) {
				thread.setState(evt.newState(), evt.getCause(), evt.getReason());
			}
		}
		else {
			int id = Integer.parseUnsignedInt(threadId);
			GdbThreadImpl thread = threads.get(id);
			event(() -> {
				listenersEvent.fire.inferiorStateChanged(thread.getInferior(),
					List.of(thread), evt.newState(), null, evt.getCause(), evt.getReason());
			}, "inferiorState-running");
			thread.setState(evt.newState(), evt.getCause(), evt.getReason());
		}
	}

	/**
	 * Handler for "*stopped"
	 * 
	 * @param evt the event
	 * @param v nothing
	 */
	protected void processStopped(GdbStoppedEvent evt, Void v) {
		String stoppedThreadsStr = evt.assumeStoppedThreads();
		Collection<GdbThreadImpl> stoppedThreads;
		if (null == stoppedThreadsStr || "all".equals(stoppedThreadsStr)) {
			stoppedThreads = threads.values();
		}
		else {
			stoppedThreads = new LinkedHashSet<>();
			for (String stopped : stoppedThreadsStr.split(",")) {
				stoppedThreads.add(threads.get(Integer.parseInt(stopped)));
			}
		}

		Integer tid = evt.getThreadId();
		GdbThreadImpl evtThread = tid == null ? null : threads.get(tid);
		Map<GdbInferior, Set<GdbThread>> byInf = new LinkedHashMap<>();
		for (GdbThreadImpl thread : stoppedThreads) {
			thread.setState(evt.newState(), evt.getCause(), evt.getReason());
			byInf.computeIfAbsent(thread.getInferior(), i -> new LinkedHashSet<>()).add(thread);
		}
		for (Map.Entry<GdbInferior, Set<GdbThread>> ent : byInf.entrySet()) {
			event(() -> {
				listenersEvent.fire.inferiorStateChanged(ent.getKey(), ent.getValue(),
					evt.newState(), evtThread, evt.getCause(), evt.getReason());
			}, "inferiorState-stopped");
		}
		if (evtThread != null) {
			GdbStackFrameImpl frame = evt.getFrame(evtThread);
			event(() -> listenersEvent.fire.threadSelected(evtThread, frame, evt),
				"inferiorState-stopped");
		}
	}

	// Link lazily to Jython
	private static class JythonConsole {
		/**
		 * Launch a Jython interpreter
		 * 
		 * The interpreter the variable "{@code mgr}" bound to the manager. This method does not
		 * return until the user exits the interpreter.
		 * 
		 * @param manager the manager
		 */
		static void interact(GdbManagerImpl manager) {
			PyDictionary dict = new PyDictionary();
			dict.put("mgr", manager);
			try (InteractiveConsole jyConsole = new InteractiveConsole(dict);) {
				jyConsole.interact();
			}
			catch (Throwable e) {
				e.printStackTrace();
			}
		}
	}

	/**
	 * An interface for taking lines of input
	 */
	public interface LineReader {
		String readLine(String prompt) throws IOException;
	}

	/**
	 * An implementation of {@link LineReader} that does not use GPL code
	 */
	public static class BufferedReaderLineReader implements LineReader {
		private BufferedReader reader;

		BufferedReaderLineReader() {
			this.reader = new BufferedReader(new InputStreamReader(System.in));
		}

		@Override
		public String readLine(String prompt) throws IOException {
			System.out.print(prompt);
			return reader.readLine();
		}
	}

	@Override
	public void consoleLoop() throws IOException {
		checkStarted();
		Signal sigInterrupt = new Signal("INT");
		SignalHandler oldHandler = Signal.handle(sigInterrupt, (sig) -> {
			try {
				sendInterruptNow();
			}
			catch (IOException e) {
				e.printStackTrace();
			}
		});
		try {
			/*
			 * prompt.addChangeListener((p, v) -> { if (p) { System.out.print(PROMPT_GDB + " "); }
			 * });
			 */
			LineReader reader = new BufferedReaderLineReader();
			//LineReader reader = new GnuReadlineLineReader();
			// System.out.print(PROMPT_GDB + " ");
			while (isAlive()) {
				String cmd = reader.readLine(PROMPT_GDB + " ");
				if (cmd == null) {
					System.out.println("quit");
					return;
				}
				if (">>>".equals(cmd.trim())) {
					try {
						JythonConsole.interact(this);
					}
					catch (NoClassDefFoundError e) {
						Msg.error(this, "Jython is not in the classpath");
					}
					catch (Throwable e) {
						e.printStackTrace();
					}
				}
				else {
					console(cmd).exceptionally((e) -> {
						Throwable realExc = AsyncUtils.unwrapThrowable(e);
						if (realExc instanceof GdbCommandError) {
							return null; // Gdb will have already printed it
						}
						e.printStackTrace();
						//System.out.print(PROMPT_GDB + " ");
						return null;
					});
				}
			}
		}
		finally {
			Signal.handle(sigInterrupt, oldHandler);
		}
	}

	public void sendInterruptNow(PtyThread thread, byte[] bytes) throws IOException {
		Msg.info(this, "Interrupting by Ctrl-C on " + thread + "'s pty");
		OutputStream os = thread.pty.getParent().getOutputStream();
		os.write(bytes);
		os.flush();
	}

	@Override
	public void sendInterruptNow() throws IOException {
		checkStarted();
		/*Msg.info(this, "Interrupting while runningInterpreter = " + runningInterpreter);
		if (runningInterpreter == Interpreter.MI2) {
			if (cliThread != null) {
				Msg.info(this, "Interrupting by 'interrupt' on CLI");
				OutputStream os = cliThread.pty.getParent().getOutputStream();
				os.write(("interrupt" + newLine).getBytes());
				os.flush();
			}
			else {
				sendInterruptNow(mi2Thread);
			}
		}
		else*/
		if (cliThread != null) {
			sendInterruptNow(cliThread, (((char) 3) + "interrupt" + newLine).getBytes());
		}
		else if (mi2Thread != null) {
			sendInterruptNow(mi2Thread, (((char) 3) + "-exec-interrupt" + newLine).getBytes());
		}
	}

	@Internal
	public void injectInput(Interpreter interpreter, String input) {
		PrintWriter writer = getWriter(interpreter);
		writer.print(input);
		writer.flush();
	}

	@Internal
	public void synthesizeConsoleOut(Channel channel, String line) {
		listenersConsoleOutput.fire.output(channel, line);
	}

	@Override
	public synchronized GdbState getState() {
		return state.get();
	}

	@Override
	public synchronized CompletableFuture<Void> waitForState(GdbState forState) {
		checkStarted();
		return state.waitValue(forState);
	}

	@Override
	public CompletableFuture<Void> waitForPrompt() {
		return mi2Prompt.waitValue(true);
	}

	@Override
	@Deprecated
	public CompletableFuture<Void> claimStopped() {
		return execute(new GdbClaimStopped(this));
	}

	@Override
	public CompletableFuture<GdbInferior> addInferior() {
		return execute(new GdbAddInferiorCommand(this));
	}

	@Override
	public CompletableFuture<GdbInferior> availableInferior() {
		return listInferiors().thenCompose(map -> {
			for (GdbInferior inf : map.values()) {
				if (inf.getPid() == null) {
					return CompletableFuture.completedFuture(inf);
				}
			}
			return addInferior();
		});
	}

	@Override
	public CompletableFuture<Void> removeInferior(GdbInferior inferior) {
		return execute(new GdbRemoveInferiorCommand(this, inferior.getId()));
	}

	/**
	 * Select the given inferior
	 * 
	 * <p>
	 * This issues a command to GDB to change its focus. It is not just a manager concept.
	 * 
	 * @param inferior the inferior to select
	 * @param internal true to prevent announcement of the change
	 * @return a future that completes when GDB has executed the command
	 */
	CompletableFuture<Void> setActiveInferior(GdbInferior inferior, boolean internal) {
		return execute(new GdbInferiorSelectCommand(this, inferior.getId(), internal));
	}

	@Override
	public CompletableFuture<Void> console(String command, CompletesWithRunning cwr) {
		return execute(new GdbConsoleExecCommand(this, null, null, command,
			GdbConsoleExecCommand.Output.CONSOLE, cwr)).thenApply(e -> null);
	}

	@Override
	public CompletableFuture<String> consoleCapture(String command, CompletesWithRunning cwr) {
		return execute(new GdbConsoleExecCommand(this, null, null, command,
			GdbConsoleExecCommand.Output.CAPTURE, cwr));
	}

	@Override
	public CompletableFuture<Void> interrupt() {
		AtomicInteger retryCount = new AtomicInteger();
		return loop(TypeSpec.VOID, loop -> {
			GdbCommand<Void> interrupt = new GdbInterruptCommand(this);
			execute(interrupt).thenApply(e -> (Throwable) null)
					.exceptionally(e -> e)
					.handle(loop::consume);
		}, TypeSpec.cls(Throwable.class), (exc, loop) -> {
			Msg.debug(this, "Executed an interrupt");
			if (exc == null) {
				loop.exit();
			}
			else if (state.get() == GdbState.STOPPED) {
				// Not the cleanest, but as long as we're stopped, why not call it good?
				loop.exit();
			}
			else if (retryCount.getAndAdd(1) >= INTERRUPT_MAX_RETRIES) {
				loop.exit(exc);
			}
			else {
				Msg.error(this, "Error executing interrupt: " + exc);
				timer.mark().after(INTERRUPT_RETRY_PERIOD_MILLIS).handle(loop::repeat);
			}
		});
	}

	@Override
	public CompletableFuture<Map<Integer, GdbInferior>> listInferiors() {
		return execute(new GdbListInferiorsCommand(this));
	}

	@Override
	public CompletableFuture<List<GdbProcessThreadGroup>> listAvailableProcesses() {
		return execute(new GdbListAvailableProcessesCommand(this));
	}

	@Override
	public CompletableFuture<GdbTable> infoOs(String type) {
		return execute(new GdbInfoOsCommand(this, type));
	}

	@Override
	public String getMi2PtyName() throws IOException {
		return mi2Thread.pty.getChild().nullSession();
	}

	@Override
	public String getPtyDescription() {
		return ptyFactory.getDescription();
	}

	public boolean hasCli() {
		return cliThread != null && cliThread.pty != null;
	}

	public Interpreter getRunningInterpreter() {
		return runningInterpreter;
	}
}
