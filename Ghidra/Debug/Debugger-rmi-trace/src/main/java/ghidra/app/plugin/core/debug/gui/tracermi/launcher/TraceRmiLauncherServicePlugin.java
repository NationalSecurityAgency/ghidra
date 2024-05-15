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
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jdom.Element;
import org.jdom.JDOMException;

import db.Transaction;
import docking.action.DockingActionIf;
import docking.action.builder.ActionBuilder;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.core.debug.DebuggerPluginPackage;
import ghidra.app.plugin.core.debug.gui.DebuggerResources.DebugProgramAction;
import ghidra.app.services.*;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.LaunchConfigurator;
import ghidra.debug.api.tracermi.TraceRmiLaunchOffer.PromptMode;
import ghidra.debug.spi.tracermi.TraceRmiLaunchOpinion;
import ghidra.formats.gfilesystem.FSRL;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramUserData;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.util.xml.XmlUtilities;

@PluginInfo(
	shortDescription = "GUI elements to launch targets using Trace RMI",
	description = """
			Provides menus and toolbar actions to launch Trace RMI targets.
			""",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.RELEASED,
	eventsConsumed = {
		ProgramActivatedPluginEvent.class,
		ProgramClosedPluginEvent.class,
	},
	servicesRequired = {
		TraceRmiService.class,
		TerminalService.class,
	},
	servicesProvided = {
		TraceRmiLauncherService.class,
	})
public class TraceRmiLauncherServicePlugin extends Plugin
		implements TraceRmiLauncherService, OptionsChangeListener {
	protected static final String KEY_DBGLAUNCH = "DBGLAUNCH";
	protected static final String PREFIX_DBGLAUNCH = "DBGLAUNCH_";
	protected static final String KEY_LAST = "last";

	protected static final String OPTION_NAME_SCRIPT_PATHS = "Script Paths";

	private final static LaunchConfigurator RELAUNCH = new LaunchConfigurator() {
		@Override
		public PromptMode getPromptMode() {
			return PromptMode.ON_ERROR;
		}
	};

	private final static LaunchConfigurator PROMPT = new LaunchConfigurator() {
		@Override
		public PromptMode getPromptMode() {
			return PromptMode.ALWAYS;
		}
	};

	private static abstract class AbstractLaunchTask extends Task {
		final TraceRmiLaunchOffer offer;

		public AbstractLaunchTask(TraceRmiLaunchOffer offer) {
			super(offer.getTitle(), true, true, true);
			this.offer = offer;
		}
	}

	private static class ReLaunchTask extends AbstractLaunchTask {
		public ReLaunchTask(TraceRmiLaunchOffer offer) {
			super(offer);
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			offer.launchProgram(monitor, RELAUNCH);
		}
	}

	private static class ConfigureAndLaunchTask extends AbstractLaunchTask {
		public ConfigureAndLaunchTask(TraceRmiLaunchOffer offer) {
			super(offer);
		}

		@Override
		public void run(TaskMonitor monitor) throws CancelledException {
			offer.launchProgram(monitor, PROMPT);
		}
	}

	public static File tryProgramPath(String path) {
		if (path == null) {
			return null;
		}
		File file = new File(path);
		try {
			if (!file.canExecute()) {
				return null;
			}
			return file.getCanonicalFile();
		}
		catch (SecurityException | IOException e) {
			Msg.error(TraceRmiLauncherServicePlugin.class, "Cannot examine file " + path, e);
			return null;
		}
	}

	public static String extractFirstFsrl(Program program) {
		FSRL fsrl = FSRL.fromProgram(program);
		if (fsrl == null) {
			return null;
		}
		FSRL first = fsrl.split().get(0);
		return first.getPath();
	}

	public static File getProgramPath(Program program) {
		if (program == null) {
			return null;
		}
		File exec = tryProgramPath(program.getExecutablePath());
		if (exec != null) {
			return exec;
		}
		return tryProgramPath(extractFirstFsrl(program));
	}

	protected final ToolOptions options;

	protected Program currentProgram;
	protected LaunchAction launchAction;
	protected List<DockingActionIf> currentLaunchers = new ArrayList<>();

	protected SaveState toolLaunchConfigs = new SaveState();

	public TraceRmiLauncherServicePlugin(PluginTool tool) {
		super(tool);
		this.options = tool.getOptions(DebuggerPluginPackage.NAME);
		this.options.addOptionsChangeListener(this);
		createActions();
	}

	@Override
	protected void init() {
		super.init();
		for (TraceRmiLaunchOpinion opinion : ClassSearcher
				.getInstances(TraceRmiLaunchOpinion.class)) {
			opinion.registerOptions(options);
		}
	}

	protected void createActions() {
		launchAction = new LaunchAction(this);
		tool.addAction(launchAction);
	}

	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) throws OptionsVetoException {
		for (TraceRmiLaunchOpinion opinion : ClassSearcher
				.getInstances(TraceRmiLaunchOpinion.class)) {
			if (opinion.requiresRefresh(optionName)) {
				updateLauncherMenu();
				return;
			}
		}
	}

	@Override
	public Collection<TraceRmiLaunchOffer> getOffers(Program program) {
		return ClassSearcher.getInstances(TraceRmiLaunchOpinion.class)
				.stream()
				.flatMap(op -> op.getOffers(this, program).stream())
				.toList();
	}

	@Override
	public List<TraceRmiLaunchOffer> getSavedOffers(Program program) {
		Map<String, Long> savedConfigs = loadSavedConfigs(program);
		return getOffers(program).stream()
				.filter(o -> savedConfigs.containsKey(o.getConfigName()))
				.sorted(Comparator.comparing(o -> -savedConfigs.get(o.getConfigName())))
				.toList();
	}

	protected void executeTask(Task task) {
		ProgressService progressService = tool.getService(ProgressService.class);
		if (progressService != null) {
			progressService.execute(task);
		}
		else {
			tool.execute(task);
		}
	}

	protected void relaunch(TraceRmiLaunchOffer offer) {
		executeTask(new ReLaunchTask(offer));
	}

	protected void configureAndLaunch(TraceRmiLaunchOffer offer) {
		executeTask(new ConfigureAndLaunchTask(offer));
	}

	protected static String getProgramName(Program program) {
		DomainFile df = program.getDomainFile();
		if (df != null) {
			return df.getName();
		}
		return program.getName();
	}

	protected String[] constructLaunchMenuPrefix() {
		return new String[] {
			DebuggerPluginPackage.NAME,
			"Configure and Launch " + getProgramName(currentProgram) + " using..." };
	}

	protected String[] prependConfigAndLaunch(List<String> menuPath) {
		return Stream.concat(
			Stream.of(constructLaunchMenuPrefix()),
			menuPath.stream()).toArray(String[]::new);
	}

	private void updateLauncherMenu() {
		Collection<TraceRmiLaunchOffer> offers = currentProgram == null
				? List.of()
				: getOffers(currentProgram);
		synchronized (currentLaunchers) {
			for (DockingActionIf launcher : currentLaunchers) {
				tool.removeAction(launcher);
			}
			currentLaunchers.clear();

			if (!offers.isEmpty()) {
				tool.setMenuGroup(constructLaunchMenuPrefix(), DebugProgramAction.GROUP, "zz");
			}
			for (TraceRmiLaunchOffer offer : offers) {
				currentLaunchers.add(new ActionBuilder(offer.getConfigName(), getName())
						.menuPath(prependConfigAndLaunch(offer.getMenuPath()))
						.menuGroup(offer.getMenuGroup(), offer.getMenuOrder())
						.menuIcon(offer.getIcon())
						.helpLocation(offer.getHelpLocation())
						.enabledWhen(ctx -> true)
						.onAction(ctx -> configureAndLaunch(offer))
						.buildAndInstall(tool));
			}
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		super.processEvent(event);
		if (event instanceof ProgramActivatedPluginEvent evt) {
			currentProgram = evt.getActiveProgram();
			updateLauncherMenu();
		}
		if (event instanceof ProgramClosedPluginEvent evt) {
			if (currentProgram == evt.getProgram()) {
				currentProgram = null;
				updateLauncherMenu();
			}
		}
	}

	@Override
	public void readConfigState(SaveState saveState) {
		super.readConfigState(saveState);
		SaveState read = saveState.getSaveState(KEY_DBGLAUNCH);
		if (read != null) {
			toolLaunchConfigs = read;
		}
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		super.writeConfigState(saveState);
		if (toolLaunchConfigs != null) {
			saveState.putSaveState(KEY_DBGLAUNCH, toolLaunchConfigs);
		}
	}

	protected SaveState readProgramLaunchConfig(Program program, String name, boolean forPrompt) {
		/**
		 * TODO: Supposedly, per-program, per-user config stuff is being generalized for analyzers.
		 * Re-examine this if/when that gets merged
		 */
		ProgramUserData userData = program.getProgramUserData();
		String property = userData.getStringProperty(PREFIX_DBGLAUNCH + name, null);
		if (property == null) {
			return new SaveState();
		}
		try {
			Element element = XmlUtilities.fromString(property);
			return new SaveState(element);
		}
		catch (JDOMException | IOException e) {
			if (forPrompt) {
				Msg.error(this,
					"Saved launcher args are corrupt, or launcher parameters changed. Defaulting.",
					e);
				return new SaveState();
			}
			throw new RuntimeException(
				"Saved launcher args are corrupt, or launcher parameters changed. Not launching.",
				e);
		}
	}

	protected SaveState readToolLaunchConfig(String name) {
		if (!toolLaunchConfigs.hasValue(name)) {
			return new SaveState();
		}
		return toolLaunchConfigs.getSaveState(name);
	}

	protected void writeProgramLaunchConfig(Program program, String name, SaveState state) {
		ProgramUserData userData = program.getProgramUserData();
		state.putLong(KEY_LAST, System.currentTimeMillis());
		try (Transaction tx = userData.openTransaction()) {
			Element element = state.saveToXml();
			userData.setStringProperty(PREFIX_DBGLAUNCH + name, XmlUtilities.toString(element));
		}
	}

	protected void writeToolLaunchConfig(String name, SaveState state) {
		state.putLong(KEY_LAST, System.currentTimeMillis());
		toolLaunchConfigs.putSaveState(name, state);
	}

	protected record ConfigLast(String configName, long last, Program program) {
	}

	protected ConfigLast checkSavedConfig(Program program, ProgramUserData userData,
			String propName) {
		if (!propName.startsWith(PREFIX_DBGLAUNCH)) {
			return null;
		}
		String configName = propName.substring(PREFIX_DBGLAUNCH.length());
		String propVal = Objects.requireNonNull(
			userData.getStringProperty(propName, null));
		Element element;
		try {
			element = XmlUtilities.fromString(propVal);
		}
		catch (JDOMException | IOException e) {
			Msg.error(this, "Could not load launcher config for " + configName + ": " + e, e);
			return null;
		}
		return checkSavedConfig(program, configName, new SaveState(element));
	}

	protected ConfigLast checkSavedConfig(Program program, String name, SaveState state) {
		if (!state.hasValue(KEY_LAST)) {
			return null;
		}
		return new ConfigLast(name, state.getLong(KEY_LAST, 0), program);
	}

	protected Stream<ConfigLast> streamSavedConfigs(Program program) {
		if (program == null) {
			return Stream.of(toolLaunchConfigs.getNames())
					.map(n -> checkSavedConfig(null, n, toolLaunchConfigs.getSaveState(n)))
					.filter(c -> c != null);
		}
		ProgramUserData userData = program.getProgramUserData();
		return userData.getStringPropertyNames()
				.stream()
				.map(n -> checkSavedConfig(program, userData, n))
				.filter(c -> c != null);
	}

	protected ConfigLast findMostRecentConfig(Program program) {
		return streamSavedConfigs(program).max(Comparator.comparing(c -> c.last)).orElse(null);
	}

	protected TraceRmiLaunchOffer findOffer(ConfigLast last) {
		if (last == null) {
			return null;
		}
		for (TraceRmiLaunchOffer offer : getOffers(last.program)) {
			if (offer.getConfigName().equals(last.configName)) {
				return offer;
			}
		}
		return null;
	}

	protected Map<String, Long> loadSavedConfigs(Program program) {
		return streamSavedConfigs(program)
				.collect(Collectors.toMap(c -> c.configName(), c -> c.last()));
	}
}
