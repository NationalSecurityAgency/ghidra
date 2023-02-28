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
package ghidra.app.plugin.core.debug.service.model.launch;

import static ghidra.async.AsyncUtils.*;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import javax.swing.JOptionPane;

import org.jdom.Element;
import org.jdom.JDOMException;

import db.Transaction;
import ghidra.app.plugin.core.debug.gui.objects.components.DebuggerMethodInvocationDialog;
import ghidra.app.services.*;
import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.app.services.ModuleMapProposal.ModuleMapEntry;
import ghidra.async.*;
import ghidra.dbg.*;
import ghidra.dbg.target.*;
import ghidra.dbg.target.TargetLauncher.TargetCmdLineLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetMethod.TargetParameterMap;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;
import ghidra.trace.model.Trace;
import ghidra.trace.model.TraceLocation;
import ghidra.trace.model.modules.TraceModule;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.datastruct.CollectionChangeListener;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public abstract class AbstractDebuggerProgramLaunchOffer implements DebuggerProgramLaunchOffer {
	private static final String HTML = "<html><p style='width:300px;'>";
	private static final String NO_PAUSE_DIAGNOSTIC_MESSAGE = "" +
		"It's possible the target launched but never paused, and so Ghidra has not been " +
		"able to inspect it. Try interrupting the target, then inspect the process list. " +
		"Further intervention may be required to establish the module/address mappings.";

	protected final Program program;
	protected final PluginTool tool;
	protected final DebuggerModelFactory factory;

	public AbstractDebuggerProgramLaunchOffer(Program program, PluginTool tool,
			DebuggerModelFactory factory) {
		this.program = program;
		this.tool = tool;
		this.factory = factory;
	}

	@Override
	public String getMenuParentTitle() {
		String name = program.getName();
		DomainFile df = program.getDomainFile();
		if (df != null) {
			name = df.getName();
		}
		return "Debug " + name;
	}

	protected List<String> getLauncherPath() {
		return PathUtils.parse("");
	}

	protected long getTimeoutMillis() {
		return 10000;
	}

	/**
	 * Listen for the launched target in the model
	 * 
	 * <p>
	 * The abstract offer will invoke this before invoking the launch command, so there should be no
	 * need to replay. Once the target has been found, the listener must remove itself. The default
	 * is to just listen for the first live {@link TargetProcess} that appears. See
	 * {@link DebugModelConventions#isProcessAlive(TargetProcess)}.
	 * 
	 * @param model the model
	 * @return a future that completes with the target object
	 */
	protected CompletableFuture<TargetObject> listenForTarget(DebuggerObjectModel model) {
		var result = new CompletableFuture<TargetObject>() {
			DebuggerModelListener listener = new DebuggerModelListener() {
				protected void checkObject(TargetObject object) {
					if (DebugModelConventions.liveProcessOrNull(object) == null) {
						return;
					}
					complete(object);
					model.removeModelListener(this);
				}

				@Override
				public void created(TargetObject object) {
					checkObject(object);
				}

				@Override
				public void attributesChanged(TargetObject object, Collection<String> removed,
						Map<String, ?> added) {
					if (!added.containsKey(TargetExecutionStateful.STATE_ATTRIBUTE_NAME)) {
						return;
					}
					checkObject(object);
				}
			};
		};
		model.addModelListener(result.listener);
		result.exceptionally(ex -> {
			model.removeModelListener(result.listener);
			return null;
		});
		return result;
	}

	/**
	 * Listen for the recording of a given target
	 * 
	 * @param service the model service
	 * @param target the expected target
	 * @return a future that completes with the recorder
	 */
	protected CompletableFuture<TraceRecorder> listenForRecorder(DebuggerModelService service,
			TargetObject target) {
		var result = new CompletableFuture<TraceRecorder>() {
			CollectionChangeListener<TraceRecorder> listener = new CollectionChangeListener<>() {
				@Override
				public void elementAdded(TraceRecorder element) {
					if (element.getTarget() == target) {
						complete(element);
						service.removeTraceRecordersChangedListener(this);
					}
				}
			};
		};
		service.addTraceRecordersChangedListener(result.listener);
		result.exceptionally(ex -> {
			service.removeTraceRecordersChangedListener(result.listener);
			return null;
		});
		return result;
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
		return null; // There's no hope
	}

	protected CompletableFuture<Void> listenForMapping(
			DebuggerStaticMappingService mappingService, TraceRecorder recorder) {
		ProgramLocation probe = new ProgramLocation(program, getMappingProbeAddress());
		Trace trace = recorder.getTrace();
		var result = new CompletableFuture<Void>() {
			DebuggerStaticMappingChangeListener listener = (affectedTraces, affectedPrograms) -> {
				if (!affectedPrograms.contains(program) &&
					!affectedTraces.contains(trace)) {
					return;
				}
				check();
			};

			protected void check() {
				TraceLocation result =
					mappingService.getOpenMappedLocation(trace, probe, recorder.getSnap());
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
			DebuggerStaticMappingService mappingService, TraceRecorder recorder)
			throws CancelledException {
		Map<TraceModule, ModuleMapProposal> map =
			mappingService.proposeModuleMaps(recorder.getTrace().getModuleManager().getAllModules(),
				List.of(program));
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
				ConfigStateField.putState(state, param.type.asSubclass(Object.class), param.name,
					val);
			}
		}
		if (program != null) {
			ProgramUserData userData = program.getProgramUserData();
			try (Transaction tx = userData.openTransaction()) {
				Element element = state.saveToXml();
				userData.setStringProperty(TargetCmdLineLauncher.CMDLINE_ARGS_NAME,
					XmlUtilities.toString(element));
			}
		}
	}

	protected Map<String, ?> takeDefaultsForParameters(
			Map<String, ParameterDescription<?>> params) {
		return params.values().stream().collect(Collectors.toMap(p -> p.name, p -> p.defaultValue));
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
	protected Map<String, ?> generateDefaultLauncherArgs(
			Map<String, ParameterDescription<?>> params) {
		if (program == null) {
			return Map.of();
		}
		Map<String, Object> map = new LinkedHashMap<String, Object>();
		for (Entry<String, ParameterDescription<?>> entry : params.entrySet()) {
			map.put(entry.getKey(), entry.getValue().defaultValue);
		}
		map.put(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, program.getExecutablePath());
		return map;
	}

	/**
	 * Prompt the user for arguments, showing those last used or defaults
	 * 
	 * @param params the parameters of the model's launcher
	 * @return the arguments given by the user, or null if cancelled
	 */
	protected Map<String, ?> promptLauncherArgs(TargetLauncher launcher,
			LaunchConfigurator configurator) {
		TargetParameterMap params = launcher.getParameters();
		DebuggerMethodInvocationDialog dialog =
			new DebuggerMethodInvocationDialog(tool, getButtonTitle(), "Launch", getIcon());
		// NB. Do not invoke read/writeConfigState
		Map<String, ?> args;
		boolean reset = false;
		do {
			args = configurator.configureLauncher(launcher,
				loadLastLauncherArgs(launcher, true), RelPrompt.BEFORE);
			for (ParameterDescription<?> param : params.values()) {
				Object val = args.get(param.name);
				if (val != null) {
					dialog.setMemorizedArgument(param.name, param.type.asSubclass(Object.class),
						val);
				}
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
	protected Map<String, ?> loadLastLauncherArgs(TargetLauncher launcher, boolean forPrompt) {
		/**
		 * TODO: Supposedly, per-program, per-user config stuff is being generalized for analyzers.
		 * Re-examine this if/when that gets merged
		 */
		if (program != null) {
			TargetParameterMap params = launcher.getParameters();
			ProgramUserData userData = program.getProgramUserData();
			String property =
				userData.getStringProperty(TargetCmdLineLauncher.CMDLINE_ARGS_NAME, null);
			if (property != null) {
				try {
					Element element = XmlUtilities.fromString(property);
					SaveState state = new SaveState(element);
					List<String> names = List.of(state.getNames());
					Map<String, Object> args = new LinkedHashMap<>();
					for (ParameterDescription<?> param : params.values()) {
						if (names.contains(param.name)) {
							Object configState =
								ConfigStateField.getState(state, param.type, param.name);
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
	 * @return the chosen arguments, or null if the user cancels at the prompt
	 */
	public Map<String, ?> getLauncherArgs(TargetLauncher launcher,
			boolean prompt, LaunchConfigurator configurator) {
		return prompt
				? configurator.configureLauncher(launcher,
					promptLauncherArgs(launcher, configurator), RelPrompt.AFTER)
				: configurator.configureLauncher(launcher, loadLastLauncherArgs(launcher, false),
					RelPrompt.NONE);
	}

	public Map<String, ?> getLauncherArgs(TargetLauncher launcher, boolean prompt) {
		return getLauncherArgs(launcher, prompt, LaunchConfigurator.NOP);
	}

	/**
	 * Get the model factory, as last configured by the user, for this launcher
	 * 
	 * @return the factory
	 */
	protected DebuggerModelFactory getModelFactory() {
		return factory;
	}

	/**
	 * TODO: This could be more surgical, and perhaps ought to be part of
	 * {@link DebugModelConventions}.
	 */
	static class ValueExpecter extends CompletableFuture<Object> implements DebuggerModelListener {
		private final DebuggerObjectModel model;
		private final List<String> path;

		public ValueExpecter(DebuggerObjectModel model, List<String> path) {
			this.model = model;
			this.path = path;
			model.addModelListener(this);
			retryFetch();
		}

		protected void retryFetch() {
			model.fetchModelValue(path).thenAccept(v -> {
				if (v != null) {
					model.removeModelListener(this);
					complete(v);
				}
			}).exceptionally(ex -> {
				model.removeModelListener(this);
				completeExceptionally(ex);
				return null;
			});
		}

		@Override
		public void rootAdded(TargetObject root) {
			retryFetch();
		}

		@Override
		public void attributesChanged(TargetObject object, Collection<String> removed,
				Map<String, ?> added) {
			retryFetch();
		}

		@Override
		public void elementsChanged(TargetObject object, Collection<String> removed,
				Map<String, ? extends TargetObject> added) {
			retryFetch();
		}
	}

	protected CompletableFuture<DebuggerObjectModel> connect(DebuggerModelService service,
			boolean prompt, LaunchConfigurator configurator) {
		DebuggerModelFactory factory = getModelFactory();
		configurator.configureConnector(factory);
		if (prompt) {
			return service.showConnectDialog(factory);
		}
		return factory.build().thenApplyAsync(m -> {
			service.addModel(m);
			return m;
		}, SwingExecutorService.LATER);
	}

	protected CompletableFuture<TargetLauncher> findLauncher(DebuggerObjectModel m) {
		List<String> launcherPath = getLauncherPath();
		TargetObjectSchema schema = m.getRootSchema().getSuccessorSchema(launcherPath);
		if (!schema.getInterfaces().contains(TargetLauncher.class)) {
			throw new AssertionError("LaunchOffer / model implementation error: " +
				"The given launcher path is not a TargetLauncher, according to its schema");
		}
		return new ValueExpecter(m, launcherPath).thenApply(o -> (TargetLauncher) o);
	}

	// Eww.
	protected CompletableFuture<Void> launch(TargetLauncher launcher,
			boolean prompt, LaunchConfigurator configurator, TaskMonitor monitor) {
		Map<String, ?> args = getLauncherArgs(launcher, prompt, configurator);
		if (args == null) {
			throw new CancellationException();
		}
		return AsyncTimer.DEFAULT_TIMER.mark()
				.timeOut(
					launcher.launch(args), getTimeoutMillis(), () -> onTimedOutLaunch(monitor));
	}

	protected void checkCancelled(TaskMonitor monitor) {
		if (monitor.isCancelled()) {
			throw new CancellationException("User cancelled");
		}
	}

	protected TargetLauncher onTimedOutFindLauncher(TaskMonitor monitor) {
		checkCancelled(monitor);
		monitor.setMessage("Timed out finding the launcher. Aborting.");
		JOptionPane.showMessageDialog(null, HTML + "Timed out finding the launcher. " +
			"This indicates an error in the implementation of the connector and/or the launcher " +
			"opinion. Try again, and/or report the bug.",
			getMenuParentTitle(), JOptionPane.ERROR_MESSAGE);
		throw new CancellationException("Timed out");
	}

	protected Void onTimedOutLaunch(TaskMonitor monitor) {
		checkCancelled(monitor);
		monitor.setMessage("Timed out waiting for launch. Aborting.");
		JOptionPane.showMessageDialog(null, HTML +
			"Timed out waiting for launch. " + NO_PAUSE_DIAGNOSTIC_MESSAGE,
			getMenuParentTitle(), JOptionPane.ERROR_MESSAGE);
		throw new CancellationException("Timed out");
	}

	protected TargetObject onTimedOutTarget(TaskMonitor monitor) {
		checkCancelled(monitor);
		monitor.setMessage("Timed out waiting for target. Aborting.");
		JOptionPane.showMessageDialog(null, HTML +
			"Timed out waiting for target. " + NO_PAUSE_DIAGNOSTIC_MESSAGE,
			getMenuParentTitle(), JOptionPane.ERROR_MESSAGE);
		throw new CancellationException("Timed out");
	}

	protected CompletableFuture<TraceRecorder> waitRecorder(DebuggerModelService service,
			TargetObject target) {
		CompletableFuture<TraceRecorder> futureRecorder = listenForRecorder(service, target);
		TraceRecorder recorder = service.getRecorder(target);
		if (recorder != null) {
			futureRecorder.cancel(true);
			return CompletableFuture.completedFuture(recorder);
		}
		return futureRecorder;
	}

	protected TraceRecorder onTimedOutRecorder(TaskMonitor monitor, DebuggerModelService service,
			TargetObject target) {
		checkCancelled(monitor);
		monitor.setMessage("Timed out waiting for recording. Invoking the recorder.");
		TraceRecorder recorder = service.recordTargetPromptOffers(target);
		if (recorder == null) {
			throw new CancellationException("User cancelled at record dialog");
		}
		DebuggerTraceManagerService traceManager =
			tool.getService(DebuggerTraceManagerService.class);
		if (traceManager != null) {
			Trace trace = recorder.getTrace();
			Swing.runLater(() -> {
				traceManager.openTrace(trace);
				traceManager.activate(traceManager.resolveTrace(trace),
					ActivationCause.START_RECORDING);
			});
		}
		return recorder;
	}

	protected Void onTimedOutMapping(TaskMonitor monitor,
			DebuggerStaticMappingService mappingService, TraceRecorder recorder) {
		checkCancelled(monitor);
		monitor.setMessage("Timed out waiting for module map. Invoking the mapper.");
		Collection<ModuleMapEntry> mapped;
		try {
			mapped = invokeMapper(monitor, mappingService, recorder);
		}
		catch (CancelledException e) {
			throw new CancellationException(e.getMessage());
		}
		if (mapped.isEmpty()) {
			monitor.setMessage(
				"Could not formulate a mapping with the target program. " +
					"Continuing without one.");
			Msg.showWarn(this, null, "Launch " + program,
				"The resulting target process has no mapping to the static image " +
					program + ". Intervention is required before static and dynamic " +
					"addresses can be translated. Check the target's module list.");
		}
		return null;
	}

	@Override
	public CompletableFuture<LaunchResult> launchProgram(TaskMonitor monitor, PromptMode mode,
			LaunchConfigurator configurator) {
		DebuggerModelService service = tool.getService(DebuggerModelService.class);
		DebuggerStaticMappingService mappingService =
			tool.getService(DebuggerStaticMappingService.class);
		monitor.initialize(6);
		monitor.setMessage("Connecting");
		var locals = new Object() {
			DebuggerObjectModel model;
			CompletableFuture<TargetObject> futureTarget;
			TargetObject target;
			TraceRecorder recorder;
			Throwable exception;
			boolean prompt = mode == PromptMode.ALWAYS;

			LaunchResult getResult() {
				return new LaunchResult(model, target, recorder, exception);
			}
		};
		return connect(service, locals.prompt, configurator).thenCompose(m -> {
			checkCancelled(monitor);
			locals.model = m;
			monitor.incrementProgress(1);
			monitor.setMessage("Finding Launcher");
			return AsyncTimer.DEFAULT_TIMER.mark()
					.timeOut(findLauncher(m), getTimeoutMillis(),
						() -> onTimedOutFindLauncher(monitor));
		}).thenCompose(l -> {
			checkCancelled(monitor);
			monitor.incrementProgress(1);
			monitor.setMessage("Launching");
			locals.futureTarget = listenForTarget(l.getModel());
			return loop(TypeSpec.VOID, (loop) -> {
				launch(l, locals.prompt, configurator, monitor).thenAccept(loop::exit)
						.exceptionally(ex -> {
							loop.repeat();
							return null;
						});
				locals.prompt = mode != PromptMode.NEVER;
			});
		}).thenCompose(__ -> {
			checkCancelled(monitor);
			monitor.incrementProgress(1);
			monitor.setMessage("Waiting for target");
			return AsyncTimer.DEFAULT_TIMER.mark()
					.timeOut(locals.futureTarget, getTimeoutMillis(),
						() -> onTimedOutTarget(monitor));
		}).thenCompose(t -> {
			checkCancelled(monitor);
			locals.target = t;
			monitor.incrementProgress(1);
			monitor.setMessage("Waiting for recorder");
			return AsyncTimer.DEFAULT_TIMER.mark()
					.timeOut(waitRecorder(service, t), getTimeoutMillis(),
						() -> onTimedOutRecorder(monitor, service, t));
		}).thenCompose(r -> {
			checkCancelled(monitor);
			locals.recorder = r;
			monitor.incrementProgress(1);
			if (r == null) {
				throw new CancellationException();
			}
			monitor.setMessage("Confirming program is mapped to target");
			return AsyncTimer.DEFAULT_TIMER.mark()
					.timeOut(listenForMapping(mappingService, r), getTimeoutMillis(),
						() -> onTimedOutMapping(monitor, mappingService, r));
		}).exceptionally(ex -> {
			locals.exception = AsyncUtils.unwrapThrowable(ex);
			return null;
		}).thenApply(__ -> {
			if (locals.exception != null) {
				monitor.setMessage("Launch error: " + locals.exception);
				return locals.getResult();
			}
			monitor.setMessage("Launch successful");
			monitor.incrementProgress(1);
			return locals.getResult();
		});
	}

}
