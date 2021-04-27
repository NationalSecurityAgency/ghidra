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

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

import org.jdom.Element;
import org.jdom.JDOMException;

import ghidra.app.plugin.core.debug.gui.objects.components.DebuggerMethodInvocationDialog;
import ghidra.app.plugin.core.debug.service.model.DebuggerModelServicePlugin;
import ghidra.app.services.DebuggerModelService;
import ghidra.async.SwingExecutorService;
import ghidra.dbg.*;
import ghidra.dbg.target.TargetLauncher;
import ghidra.dbg.target.TargetMethod.ParameterDescription;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.PathUtils;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.AutoConfigState.ConfigStateField;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.program.model.util.StringPropertyMap;
import ghidra.util.Msg;
import ghidra.util.database.UndoableTransaction;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

public abstract class AbstractDebuggerProgramLaunchOffer implements DebuggerProgramLaunchOffer {
	protected final Program program;
	protected final PluginTool tool;
	protected final DebuggerModelFactory factory;

	public AbstractDebuggerProgramLaunchOffer(Program program, PluginTool tool,
			DebuggerModelFactory factory) {
		this.program = program;
		this.tool = tool;
		this.factory = factory;
	}

	protected List<String> getLauncherPath() {
		return PathUtils.parse("");
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
		String owner = PluginUtils.getPluginNameFromClass(DebuggerModelServicePlugin.class);
		ProgramUserData userData = program.getProgramUserData();
		try (UndoableTransaction tid = UndoableTransaction.start(userData)) {
			StringPropertyMap stringProperty =
				userData.getStringProperty(owner, getConfigName(), true);
			Element element = state.saveToXml();
			stringProperty.add(Address.NO_ADDRESS, XmlUtilities.toString(element));
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
	protected abstract Map<String, ?> generateDefaultLauncherArgs(
			Map<String, ParameterDescription<?>> params);

	/**
	 * Prompt the user for arguments, showing those last used or defaults
	 * 
	 * @param params the parameters of the model's launcher
	 * @return the arguments given by the user
	 */
	protected Map<String, ?> promptLauncherArgs(Map<String, ParameterDescription<?>> params) {
		DebuggerMethodInvocationDialog dialog =
			new DebuggerMethodInvocationDialog(tool, getButtonTitle(), "Launch", getIcon());
		// NB. Do not invoke read/writeConfigState
		Map<String, ?> args = loadLastLauncherArgs(params, true);
		for (ParameterDescription<?> param : params.values()) {
			Object val = args.get(param.name);
			if (val != null) {
				dialog.setMemorizedArgument(param.name, param.type.asSubclass(Object.class), val);
			}
		}
		args = dialog.promptArguments(params);
		saveLauncherArgs(args, params);
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
	protected Map<String, ?> loadLastLauncherArgs(
			Map<String, ParameterDescription<?>> params, boolean forPrompt) {
		/**
		 * TODO: Supposedly, per-program, per-user config stuff is being generalized for analyzers.
		 * Re-examine this if/when that gets merged
		 */
		String owner = PluginUtils.getPluginNameFromClass(DebuggerModelServicePlugin.class);
		ProgramUserData userData = program.getProgramUserData();
		StringPropertyMap property =
			userData.getStringProperty(owner, getConfigName(), false);
		if (property != null) {
			String xml = property.getString(Address.NO_ADDRESS);
			if (xml != null) {
				try {
					Element element = XmlUtilities.fromString(xml);
					SaveState state = new SaveState(element);
					Map<String, Object> args = new LinkedHashMap<>();
					for (ParameterDescription<?> param : params.values()) {
						args.put(param.name,
							ConfigStateField.getState(state, param.type, param.name));
					}
					return args;
				}
				catch (JDOMException | IOException e) {
					if (!forPrompt) {
						throw new RuntimeException(
							"Saved launcher args are corrupt, or launcher parameters changed. Not launching.",
							e);
					}
					Msg.error(this,
						"Saved launcher args are corrup, or launcher parameters changed. Defaulting.",
						e);
				}
			}
		}

		Map<String, ?> args = generateDefaultLauncherArgs(params);
		saveLauncherArgs(args, params);
		return args;
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
	 * @return the chosen arguments
	 */
	protected Map<String, ?> getLauncherArgs(Map<String, ParameterDescription<?>> params,
			boolean prompt) {
		return prompt
				? promptLauncherArgs(params)
				: loadLastLauncherArgs(params, false);
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

	protected CompletableFuture<DebuggerObjectModel> connect(boolean prompt) {
		DebuggerModelService service = tool.getService(DebuggerModelService.class);
		DebuggerModelFactory factory = getModelFactory();
		if (prompt) {
			return service.showConnectDialog(factory);
		}
		return factory.build().thenApplyAsync(m -> {
			service.addModel(m);
			return m;
		});
	}

	@Override
	public CompletableFuture<Void> launchProgram(TaskMonitor monitor, boolean prompt) {
		monitor.initialize(2);
		monitor.setMessage("Connecting");
		return connect(prompt).thenComposeAsync(m -> {
			List<String> launcherPath = getLauncherPath();
			TargetObjectSchema schema = m.getRootSchema().getSuccessorSchema(launcherPath);
			if (!schema.getInterfaces().contains(TargetLauncher.class)) {
				throw new AssertionError("LaunchOffer / model implementation error: " +
					"The given launcher path is not a TargetLauncher, according to its schema");
			}
			return new ValueExpecter(m, launcherPath);
		}, SwingExecutorService.INSTANCE).thenCompose(l -> {
			monitor.incrementProgress(1);
			monitor.setMessage("Launching");
			TargetLauncher launcher = (TargetLauncher) l;
			return launcher.launch(getLauncherArgs(launcher.getParameters(), prompt));
		}).thenRun(() -> {
			monitor.incrementProgress(1);
		});
	}
}
