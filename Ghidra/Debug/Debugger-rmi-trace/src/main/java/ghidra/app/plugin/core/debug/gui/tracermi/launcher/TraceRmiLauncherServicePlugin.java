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
import java.util.stream.Stream;

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
import ghidra.debug.api.tracermi.TraceRmiLaunchOpinion;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.bean.opteditor.OptionsVetoException;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

@PluginInfo(
	shortDescription = "GUI elements to launch targets using Trace RMI",
	description = """
			Provides menus and toolbar actions to launch Trace RMI targets.
			""",
	category = PluginCategoryNames.DEBUGGER,
	packageName = DebuggerPluginPackage.NAME,
	status = PluginStatus.UNSTABLE,
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
	protected static final String OPTION_NAME_SCRIPT_PATHS = "Script Paths";

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
			offer.launchProgram(monitor);
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

	public static File getProgramPath(Program program) {
		if (program == null) {
			return null;
		}
		String path = program.getExecutablePath();
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

	protected final ToolOptions options;

	protected Program currentProgram;
	protected LaunchAction launchAction;
	protected List<DockingActionIf> currentLaunchers = new ArrayList<>();

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
	public Collection<TraceRmiLaunchOpinion> getOpinions() {
		return ClassSearcher.getInstances(TraceRmiLaunchOpinion.class);
	}

	@Override
	public Collection<TraceRmiLaunchOffer> getOffers(Program program) {
		if (program == null) {
			return List.of();
		}
		return ClassSearcher.getInstances(TraceRmiLaunchOpinion.class)
				.stream()
				.flatMap(op -> op.getOffers(program, getTool()).stream())
				.toList();
	}

	protected void relaunch(TraceRmiLaunchOffer offer) {
		tool.execute(new ReLaunchTask(offer));
	}

	protected void configureAndLaunch(TraceRmiLaunchOffer offer) {
		tool.execute(new ConfigureAndLaunchTask(offer));
	}

	protected String[] constructLaunchMenuPrefix() {
		return new String[] {
			DebuggerPluginPackage.NAME,
			"Configure and Launch " + currentProgram.getName() + " using..." };
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
}
