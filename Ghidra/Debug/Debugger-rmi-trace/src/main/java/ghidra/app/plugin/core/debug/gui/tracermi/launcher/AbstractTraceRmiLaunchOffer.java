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
package ghidra.app.plugin.core.debug.gui.tracermi.launcher;

import java.io.File;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.charset.Charset;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.*;

import javax.swing.Icon;

import org.jdom.Element;
import org.jdom.JDOMException;

import db.Transaction;
import docking.widgets.OptionDialog;
import ghidra.app.plugin.core.debug.gui.DebuggerResources;
import ghidra.app.plugin.core.debug.gui.objects.components.DebuggerMethodInvocationDialog;
import ghidra.app.plugin.core.debug.service.tracermi.DefaultTraceRmiAcceptor;
import ghidra.app.plugin.core.debug.service.tracermi.TraceRmiHandler;
import ghidra.app.plugin.core.terminal.TerminalListener;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.async.AsyncUtils;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.util.ShellUtils;
import ghidra.debug.api.modules.*;
import ghidra.debug.api.modules.ModuleMapProposal.ModuleMapEntry;
import ghidra.debug.api.tracermi.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.pty.*;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public abstract class AbstractTraceRmiLaunchOffer implements TraceRmiLaunchOffer {

	public static final String PREFIX_DBGLAUNCH = "DBGLAUNCH_";
	public static final String PARAM_DISPLAY_IMAGE = "Image";

	protected record PtyTerminalSession(Terminal terminal, Pty pty, PtySession session,
			Thread waiter) implements TerminalSession {
		@Override
		public void close() throws IOException {
			terminate();
			terminal.close();
		}

		@Override
		public void terminate() throws IOException {
			terminal.terminated();
			session.destroyForcibly();
			pty.close();
			waiter.interrupt();
		}

		@Override
		public boolean isTerminated() {
			return terminal.isTerminated();
		}

		@Override
		public String description() {
			return session.description();
		}
	}

	protected record NullPtyTerminalSession(Terminal terminal, Pty pty, String name)
			implements TerminalSession {
		@Override
		public void close() throws IOException {
			terminate();
			terminal.close();
		}

		@Override
		public void terminate() throws IOException {
			terminal.terminated();
			pty.close();
		}

		@Override
		public boolean isTerminated() {
			return terminal.isTerminated();
		}

		@Override
		public String description() {
			return name;
		}
	}

	static class TerminateSessionTask extends Task {
		private final TerminalSession session;

		public TerminateSessionTask(TerminalSession session) {
			super("Terminate Session", false, false, false);
			this.session = session;
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			try {
				session.close();
			}
			catch (IOException e) {
				Msg.error(this, "Could not terminate: " + e, e);
			}
		}
	}

	protected final TraceRmiLauncherServicePlugin plugin;
	protected final Program program;
	protected final PluginTool tool;
	protected final TerminalService terminalService;

	public AbstractTraceRmiLaunchOffer(TraceRmiLauncherServicePlugin plugin, Program program) {
		this.plugin = Objects.requireNonNull(plugin);
		this.program = Objects.requireNonNull(program);
		this.tool = plugin.getTool();
		this.terminalService = Objects.requireNonNull(tool.getService(TerminalService.class));
	}

	protected int getTimeoutMillis() {
		return 10000;
	}

	@Override
	public Icon getIcon() {
		return DebuggerResources.ICON_DEBUGGER;
	}

	protected Address getMappingProbeAddress() {
		AddressIterator eepi = program.getSymbolTable().getExternalEntryPointIterator();
		if (eepi.hasNext()) {
			return eepi.next();
		}
		InstructionIterator ii = program.getListing().getInstructions(true);
		if (ii.hasNext()) {
			return ii.next().getAddress();
		}
		AddressSetView es = program.getMemory().getExecuteSet();
		if (!es.isEmpty()) {
			return es.getMinAddress();
		}
		if (!program.getMemory().isEmpty()) {
			return program.getMinAddress();
		}
		return null; // I guess we won't wait for a mapping, then
	}

	protected CompletableFuture<Void> listenForMapping(DebuggerStaticMappingService mappingService,
			TraceRmiConnection connection, Trace trace) {
		Address probeAddress = getMappingProbeAddress();
		if (probeAddress == null) {
			return AsyncUtils.nil(); // No need to wait on mapping of nothing
		}
		ProgramLocation probe = new ProgramLocation(program, probeAddress);
		var result = new CompletableFuture<Void>() {
			DebuggerStaticMappingChangeListener listener = (affectedTraces, affectedPrograms) -> {
				if (!affectedPrograms.contains(program) &&
					!affectedTraces.contains(trace)) {
					return;
				}
				check();
			};

			protected void check() {
				long snap = connection.getLastSnapshot(trace);
				TraceLocation result = mappingService.getOpenMappedLocation(trace, probe, snap);
				if (result == null) {
					return;
				}
				complete(null);
				mappingService.removeChangeListener(listener);
			}
		};
		mappingService.addChangeListener(result.listener);
		result.check();
		result.exceptionally(ex -> {
			mappingService.removeChangeListener(result.listener);
			return null;
		});
		return result;
	}

	protected Collection<ModuleMapEntry> invokeMapper(TaskMonitor monitor,
			DebuggerStaticMappingService mappingService, Trace trace) throws CancelledException {
		Map<TraceModule, ModuleMapProposal> map = mappingService
				.proposeModuleMaps(trace.getModuleManager().getAllModules(), List.of(program));
		Collection<ModuleMapEntry> proposal = MapProposal.flatten(map.values());
		mappingService.addModuleMappings(proposal, monitor, true);
		return proposal;
	}

	private void saveLauncherArgs(Map<String, ?> args,
			Map<String, ParameterDescription<?>> params) {
		SaveState state = new SaveState();
		for (ParameterDescription<?> param : params.values()) {
			Object val = args.get(param.name);
			if (val != null) {
				ConfigStateField.putState(state, param.type.asSubclass(Object.class),
					"param_" + param.name, val);
				state.putLong("last", System.currentTimeMillis());
			}
		}
		if (program != null) {
			ProgramUserData userData = program.getProgramUserData();
			try (Transaction tx = userData.openTransaction()) {
				Element element = state.saveToXml();
				userData.setStringProperty(PREFIX_DBGLAUNCH + getConfigName(),
					XmlUtilities.toString(element));
			}
		}
	}

	/**
	 * Generate the default launcher arguments
	 * 
	 * <p>
	 * It is not sufficient to simply take the defaults specified in the parameters. This must
	 * populate the arguments necessary to launch the requested program.
	 * 
	 * @param params the parameters
	 * @return the default arguments
	 */
	@SuppressWarnings("unchecked")
	protected Map<String, ?> generateDefaultLauncherArgs(
			Map<String, ParameterDescription<?>> params) {
		if (program == null) {
			return Map.of();
		}
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		ParameterDescription<String> paramImage = null;
		for (Entry<String, ParameterDescription<?>> entry : params.entrySet()) {
			ParameterDescription<?> param = entry.getValue();
			map.put(entry.getKey(), param.defaultValue);
			if (PARAM_DISPLAY_IMAGE.equals(param.display)) {
				if (param.type != String.class) {
					Msg.warn(this, "'Image' parameter has unexpected type: " + paramImage.type);
				}
				paramImage = (ParameterDescription<String>) param;
			}
		}
		if (paramImage != null) {
			File imageFile = TraceRmiLauncherServicePlugin.getProgramPath(program);
			if (imageFile != null) {
				paramImage.set(map, imageFile.getAbsolutePath());
			}
		}
		return map;
	}

	/**
	 * Prompt the user for arguments, showing those last used or defaults
	 * 
	 * @param lastExc
	 * 
	 * @param params the parameters of the model's launcher
	 * @param lastExc if re-prompting, an error to display
	 * @return the arguments given by the user, or null if cancelled
	 */
	protected Map<String, ?> promptLauncherArgs(LaunchConfigurator configurator,
			Throwable lastExc) {
		Map<String, ParameterDescription<?>> params = getParameters();
		DebuggerMethodInvocationDialog dialog =
			new DebuggerMethodInvocationDialog(tool, getTitle(), "Launch", getIcon());
		dialog.setDescription(getDescription());
		// NB. Do not invoke read/writeConfigState
		Map<String, ?> args;
		boolean reset = false;
		do {
			args =
				configurator.configureLauncher(this, loadLastLauncherArgs(true), RelPrompt.BEFORE);
			for (ParameterDescription<?> param : params.values()) {
				Object val = args.get(param.name);
				if (val != null) {
					dialog.setMemorizedArgument(param.name, param.type.asSubclass(Object.class),
						val);
				}
			}
			if (lastExc != null) {
				dialog.setStatusText(lastExc.toString(), MessageType.ERROR);
			}
			else {
				dialog.setStatusText("");
			}
			args = dialog.promptArguments(params);
			if (args == null) {
				// Cancelled
				return null;
			}
			reset = dialog.isResetRequested();
			if (reset) {
				args = generateDefaultLauncherArgs(params);
			}
			saveLauncherArgs(args, params);
		}
		while (reset);
		return args;
	}

	/**
	 * Load the arguments last used for this offer, or give the defaults
	 * 
	 * <p>
	 * If there are no saved "last used" arguments, then this will return the defaults. If there are
	 * saved arguments, but they cannot be loaded, then this will behave differently depending on
	 * whether the user will be confirming the arguments. If there will be no prompt/confirmation,
	 * then this method must throw an exception in order to avoid launching with defaults, when the
	 * user may be expecting a customized launch. If there will be a prompt, then this may safely
	 * return the defaults, since the user will be given a chance to correct them.
	 * 
	 * @param params the parameters of the model's launcher
	 * @param forPrompt true if the user will be confirming the arguments
	 * @return the loaded arguments, or defaults
	 */
	protected Map<String, ?> loadLastLauncherArgs(boolean forPrompt) {
		/**
		 * TODO: Supposedly, per-program, per-user config stuff is being generalized for analyzers.
		 * Re-examine this if/when that gets merged
		 */
		if (program != null) {
			Map<String, ParameterDescription<?>> params = getParameters();
			ProgramUserData userData = program.getProgramUserData();
			String property =
				userData.getStringProperty(PREFIX_DBGLAUNCH + getConfigName(), null);
			if (property != null) {
				try {
					Element element = XmlUtilities.fromString(property);
					SaveState state = new SaveState(element);
					List<String> names = List.of(state.getNames());
					Map<String, Object> args = new LinkedHashMap<>();
					for (ParameterDescription<?> param : params.values()) {
						String key = "param_" + param.name;
						if (names.contains(key)) {
							Object configState = ConfigStateField.getState(state, param.type, key);
							if (configState != null) {
								args.put(param.name, configState);
							}
						}
					}
					if (!args.isEmpty()) {
						return args;
					}
				}
				catch (JDOMException | IOException e) {
					if (!forPrompt) {
						throw new RuntimeException(
							"Saved launcher args are corrupt, or launcher parameters changed. Not launching.",
							e);
					}
					Msg.error(this,
						"Saved launcher args are corrupt, or launcher parameters changed. Defaulting.",
						e);
				}
			}
			Map<String, ?> args = generateDefaultLauncherArgs(params);
			saveLauncherArgs(args, params);
			return args;
		}

		return new LinkedHashMap<>();
	}

	/**
	 * Obtain the launcher args
	 * 
	 * <p>
	 * This should either call {@link #promptLauncherArgs(Map))} or
	 * {@link #loadLastLauncherArgs(Map, boolean))}. Note if choosing the latter, the user will not
	 * be prompted to confirm.
	 * 
	 * @param params the parameters of the model's launcher
	 * @param configurator the rules for configuring the launcher
	 * @param lastExc if retrying, the last exception to display as an error message
	 * @return the chosen arguments, or null if the user cancels at the prompt
	 */
	public Map<String, ?> getLauncherArgs(boolean prompt, LaunchConfigurator configurator,
			Throwable lastExc) {
		return prompt
				? configurator.configureLauncher(this, promptLauncherArgs(configurator, lastExc),
					RelPrompt.AFTER)
				: configurator.configureLauncher(this, loadLastLauncherArgs(false), RelPrompt.NONE);
	}

	public Map<String, ?> getLauncherArgs(boolean prompt) {
		return getLauncherArgs(prompt, LaunchConfigurator.NOP, null);
	}

	protected PtyFactory getPtyFactory() {
		return PtyFactory.local();
	}

	protected PtyTerminalSession runInTerminal(List<String> commandLine, Map<String, String> env,
			File workingDirectory, Collection<TerminalSession> subordinates) throws IOException {
		PtyFactory factory = getPtyFactory();
		Pty pty = factory.openpty();

		PtyParent parent = pty.getParent();
		Terminal terminal = terminalService.createWithStreams(Charset.forName("UTF-8"),
			parent.getInputStream(), parent.getOutputStream());
		terminal.setSubTitle(ShellUtils.generateLine(commandLine));
		TerminalListener resizeListener = new TerminalListener() {
			@Override
			public void resized(short cols, short rows) {
				try {
					parent.setWindowSize(cols, rows);
				}
				catch (Exception e) {
					Msg.error(this, "Could not resize pty: " + e);
				}
			}
		};
		terminal.addTerminalListener(resizeListener);

		env.put("TERM", "xterm-256color");
		PtySession session =
			pty.getChild().session(commandLine.toArray(String[]::new), env, workingDirectory);

		Thread waiter = new Thread(() -> {
			try {
				session.waitExited();
				terminal.terminated();
				pty.close();

				for (TerminalSession ss : subordinates) {
					ss.terminate();
				}
			}
			catch (InterruptedException | IOException e) {
				Msg.error(this, e);
			}
		}, "Waiter: " + getConfigName());
		waiter.start();

		PtyTerminalSession terminalSession =
			new PtyTerminalSession(terminal, pty, session, waiter);
		terminal.setTerminateAction(() -> {
			tool.execute(new TerminateSessionTask(terminalSession));
		});
		return terminalSession;
	}

	protected NullPtyTerminalSession nullPtyTerminal() throws IOException {
		PtyFactory factory = getPtyFactory();
		Pty pty = factory.openpty();

		PtyParent parent = pty.getParent();
		Terminal terminal = terminalService.createWithStreams(Charset.forName("UTF-8"),
			parent.getInputStream(), parent.getOutputStream());
		TerminalListener resizeListener = new TerminalListener() {
			@Override
			public void resized(short cols, short rows) {
				parent.setWindowSize(cols, rows);
			}
		};
		terminal.addTerminalListener(resizeListener);

		String name = pty.getChild().nullSession();
		terminal.setSubTitle(name);

		NullPtyTerminalSession terminalSession = new NullPtyTerminalSession(terminal, pty, name);
		terminal.setTerminateAction(() -> {
			tool.execute(new TerminateSessionTask(terminalSession));
		});
		return terminalSession;
	}

	protected abstract void launchBackEnd(TaskMonitor monitor,
			Map<String, TerminalSession> sessions, Map<String, ?> args, SocketAddress address)
			throws Exception;

	static class NoStaticMappingException extends Exception {
		public NoStaticMappingException(String message) {
			super(message);
		}

		@Override
		public String toString() {
			return getMessage();
		}
	}

	@Override
	public LaunchResult launchProgram(TaskMonitor monitor, LaunchConfigurator configurator) {
		InternalTraceRmiService service = tool.getService(InternalTraceRmiService.class);
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		final PromptMode mode = configurator.getPromptMode();
		boolean prompt = mode == PromptMode.ALWAYS;

		DefaultTraceRmiAcceptor acceptor = null;
		Map<String, TerminalSession> sessions = new LinkedHashMap<>();
		TraceRmiHandler connection = null;
		Trace trace = null;
		Throwable lastExc = null;

		monitor.setMaximum(5);
		while (true) {
			monitor.setMessage("Gathering arguments");
			Map<String, ?> args = getLauncherArgs(prompt, configurator, lastExc);
			if (args == null) {
				if (lastExc == null) {
					lastExc = new CancelledException();
				}
				return new LaunchResult(program, sessions, connection, trace, lastExc);
			}
			acceptor = null;
			sessions.clear();
			connection = null;
			trace = null;
			lastExc = null;

			try {
				monitor.setMessage("Listening for connection");
				acceptor = service.acceptOne(new InetSocketAddress("127.0.0.1", 0));
				monitor.setMessage("Launching back-end");
				launchBackEnd(monitor, sessions, args, acceptor.getAddress());
				monitor.setMessage("Waiting for connection");
				acceptor.setTimeout(getTimeoutMillis());
				connection = acceptor.accept();
				connection.registerTerminals(sessions.values());
				monitor.setMessage("Waiting for trace");
				trace = connection.waitForTrace(getTimeoutMillis());
				traceManager.openTrace(trace);
				traceManager.activate(traceManager.resolveTrace(trace),
					ActivationCause.START_RECORDING);
				monitor.setMessage("Waiting for module mapping");
				try {
					listenForMapping(mappingService, connection, trace).get(getTimeoutMillis(),
						TimeUnit.MILLISECONDS);
				}
				catch (TimeoutException e) {
					monitor.setMessage(
						"Timed out waiting for module mapping. Invoking the mapper.");
					Collection<ModuleMapEntry> mapped;
					try {
						mapped = invokeMapper(monitor, mappingService, trace);
					}
					catch (CancelledException ce) {
						throw new CancellationException(e.getMessage());
					}
					if (mapped.isEmpty()) {
						throw new NoStaticMappingException(
							"The resulting target process has no mapping to the static image.");
					}
				}
			}
			catch (Exception e) {
				lastExc = e;
				prompt = mode != PromptMode.NEVER;
				LaunchResult result =
					new LaunchResult(program, sessions, connection, trace, lastExc);
				if (prompt) {
					switch (promptError(result)) {
						case KEEP:
							return result;
						case RETRY:
							try {
								result.close();
							}
							catch (Exception e1) {
								Msg.error(this, "Could not close", e1);
							}
							continue;
						case TERMINATE:
							try {
								result.close();
							}
							catch (Exception e1) {
								Msg.error(this, "Could not close", e1);
							}
							return new LaunchResult(program, Map.of(), null, null, lastExc);
					}
					continue;
				}
				return result;
			}
			return new LaunchResult(program, sessions, connection, trace, null);
		}
	}

	enum ErrPromptResponse {
		KEEP, RETRY, TERMINATE;
	}

	protected ErrPromptResponse promptError(LaunchResult result) {
		String message = """
				<html><body width="400px">
				<h3>Failed to launch %s due to an exception:</h3>

				<tt>%s</tt>

				<h3>Troubleshooting</h3>
				<p>
				<b>Check the Terminal!</b>
				If no terminal is visible, check the menus: <b>Window &rarr; Terminals &rarr;
				...</b>.
				A path or other configuration parameter may be incorrect.
				The back-end debugger may have paused for user input.
				There may be a missing dependency.
				There may be an incorrect version, etc.</p>

				<h3>These resources remain after the failed launch:</h3>
				<ul>
				%s
				</ul>

				<h3>Do you want to keep these resources?</h3>
				<ul>
				<li>Choose <b>Yes</b> to stop here and diagnose or complete the launch manually.
				</li>
				<li>Choose <b>No</b> to clean up and retry at the launch dialog.</li>
				<li>Choose <b>Cancel</b> to clean up without retrying.</li>
				""".formatted(
			htmlProgramName(result), htmlExceptionMessage(result), htmlResources(result));
		return LaunchFailureDialog.show(message);
	}

	static class LaunchFailureDialog extends OptionDialog {
		public LaunchFailureDialog(String message) {
			super("Launch Failed", message, "&Yes", "&No", OptionDialog.ERROR_MESSAGE, null,
				true, "No");
		}

		static ErrPromptResponse show(String message) {
			return switch (new LaunchFailureDialog(message).show()) {
				case OptionDialog.YES_OPTION -> ErrPromptResponse.KEEP;
				case OptionDialog.NO_OPTION -> ErrPromptResponse.RETRY;
				case OptionDialog.CANCEL_OPTION -> ErrPromptResponse.TERMINATE;
				default -> throw new AssertionError();
			};
		}
	}

	protected String htmlProgramName(LaunchResult result) {
		if (result.program() == null) {
			return "";
		}
		return "<tt>" + HTMLUtilities.escapeHTML(result.program().getName()) + "</tt>";
	}

	protected String htmlExceptionMessage(LaunchResult result) {
		if (result.exception() == null) {
			return "(No exception)";
		}
		return HTMLUtilities.escapeHTML(result.exception().toString());
	}

	protected String htmlResources(LaunchResult result) {
		StringBuilder sb = new StringBuilder();
		for (Entry<String, TerminalSession> ent : result.sessions().entrySet()) {
			TerminalSession session = ent.getValue();
			sb.append("<li>Terminal: " + HTMLUtilities.escapeHTML(ent.getKey()) + " &rarr; <tt>" +
				HTMLUtilities.escapeHTML(session.description()) + "</tt>");
			if (session.isTerminated()) {
				sb.append(" (Terminated)");
			}
			sb.append("</li>\n");
		}
		if (result.connection() != null) {
			sb.append("<li>Connection: <tt>" +
				HTMLUtilities.escapeHTML(result.connection().getRemoteAddress().toString()) +
				"</tt></li>\n");
		}
		if (result.trace() != null) {
			sb.append(
				"<li>Trace: " + HTMLUtilities.escapeHTML(result.trace().getName()) + "</li>\n");
		}
		return sb.toString();
	}
}
