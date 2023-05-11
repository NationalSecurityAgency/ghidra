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
package ghidra.app.plugin.core.analysis;

import java.util.*;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.action.builder.ActionBuilder;
import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.GhidraOptions;
import ghidra.app.CorePluginPackage;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.events.*;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.Analyzer;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.program.util.ProgramSelection;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskLauncher;

/**
 * AutoAnalysisPlugin
 * 
 * Provides support for auto analysis tasks. Manages a pipeline or priority of
 * tasks to run given some event has occurred.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Manages auto-analysis",
	description = "Provides coordination and a service for All Auto Analysis tasks.",
	eventsConsumed = { ProgramOpenedPluginEvent.class, ProgramClosedPluginEvent.class, ProgramActivatedPluginEvent.class, ProgramPostActivatedPluginEvent.class }
)
//@formatter:on
public class AutoAnalysisPlugin extends Plugin implements AutoAnalysisManagerListener {

	private static final String SHOW_ANALYSIS_OPTIONS = "Show Analysis Options";
	private static final String ANALYZE_GROUP_NAME = "Analyze";

	private DockingAction autoAnalyzeAction;

	private HelpLocation helpLocation;

	private List<Analyzer> analyzers = new ArrayList<>();
	private List<OneShotAnalyzerAction> oneShotActions = new ArrayList<>();

	public AutoAnalysisPlugin(PluginTool tool) {
		super(tool);

		findAnalyzers();
		createActions();

		// get the option so that an owner is associated with it, otherwise
		// it will not show up in the Options dialog for the tool.
		Options options = tool.getOptions(GhidraOptions.CATEGORY_AUTO_ANALYSIS);
		String description = "This option forces the analysis options" +
			" dialog to appear whenever auto-analysis action is invoked.";

		helpLocation = new HelpLocation("AutoAnalysisPlugin", "AnalysisOptions");
		options.setOptionsHelpLocation(helpLocation);
		options.registerOption(SHOW_ANALYSIS_OPTIONS, true, helpLocation, description);
	}

	private void findAnalyzers() {
		analyzers.addAll(ClassSearcher.getInstances(Analyzer.class));

		// sort so that the menu items are always in the same order
		Collections.sort(analyzers, (o1, o2) -> o1.getName().compareTo(o2.getName()));
	}

	/**
	 * Creates actions for the plugin.
	 */
	private void createActions() {

		// use this index to make sure that the following actions are ordered in the way that 
		// they are inserted
		int subGroupIndex = 0;

		autoAnalyzeAction = new ActionBuilder("Auto Analyze", getName())
			.menuPath("&Analysis", "&Auto Analyze...")
			.menuGroup(ANALYZE_GROUP_NAME, "" + subGroupIndex++)
			.keyBinding("A")
			.withContext(ListingActionContext.class, true)
			.onAction(this::analyzeCallback)
			.buildAndInstall(tool);

		// we need to specially override the validContextWhen so that as a side effect, we
		// can change the action name to not include a program name when the action is
		// actually invalid. 
		autoAnalyzeAction.validContextWhen(ac -> {
			updateActionName(ac);
			return ac instanceof ListingActionContext;
		});

		new ActionBuilder("Analyze All Open", getName())
			.menuPath("&Analysis", "Analyze All &Open...")
			.menuGroup(ANALYZE_GROUP_NAME, "" + subGroupIndex++)
			.withContext(ListingActionContext.class, true)
			.onAction(c -> analyzeAllCallback())
			.buildAndInstall(tool);

		tool.setMenuGroup(new String[] { "Analysis", "One Shot" }, ANALYZE_GROUP_NAME);

	}

	private void updateActionName(ActionContext context) {
		String programName = "";
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			programName = listingContext.getProgram().getDomainFile().getName();
		}
		MenuData menuBarData = autoAnalyzeAction.getMenuBarData();
		menuBarData.setMenuItemName("&Auto Analyze '" + programName + "'...");
	}

	private void analyzeCallback(ActionContext context) {
		if (context instanceof ListingActionContext) {
			ListingActionContext listingContext = (ListingActionContext) context;
			analyzeCallback(listingContext.getProgram(), listingContext.getSelection());
		}
	}

	private void addOneShotActions(Program program) {
		removeOneShotActions();
		for (Analyzer analyzer : analyzers) {
			if (analyzer.supportsOneTimeAnalysis()) {
				if (!analyzer.canAnalyze(program)) {
					continue;
				}
				OneShotAnalyzerAction action = new OneShotAnalyzerAction(analyzer);
				oneShotActions.add(action);
				tool.addAction(action);
			}
		}
	}

	private void removeOneShotActions() {
		for (OneShotAnalyzerAction action : oneShotActions) {
			tool.removeAction(action);
		}
		oneShotActions.clear();
	}

	private void analyzeAllCallback() {
		AnalyzeAllOpenProgramsTask task = new AnalyzeAllOpenProgramsTask(this);
		new TaskLauncher(task, tool.getToolFrame());
	}

	private void analyzeCallback(Program program, ProgramSelection selection) {
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);

		analysisMgr.initializeOptions(); // this allows analyzers to register options with defaults

		if (!showOptionsDialog(program)) {
			return;
		}

		analysisMgr.initializeOptions(); // reloads the options in case the user changed them

		// check if this is the first time this program is being analyzed. If so,
		// schedule a callback when it is completed to send a FirstTimeAnalyzedPluginEvent
		boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
		if (!isAnalyzed) {
			analysisMgr.addListener(new FirstTimeAnalyzedCallback());
		}

		// start analysis to set the flag, but it probably won't do more.  A bit goofy but better
		// than the way it was
		//TODO simplify all this after creating a taskManager per program instead of per tool.
		tool.executeBackgroundCommand(new AnalysisBackgroundCommand(analysisMgr, true), program);

		// if has a selection use it
		// if no selection, use all of memory
		analysisMgr.reAnalyzeAll(selection);
	}

	public static String getDescription() {
		return "Provides coordination and a service for All Auto Analysis tasks";
	}

	public static String getDescriptiveName() {
		return "AutoAnalysisManager";
	}

	public static String getCategory() {
		return "Analysis";
	}

	protected void programClosed(Program program) {

		if (AutoAnalysisManager.hasAutoAnalysisManager(program)) {
			AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
			analysisMgr.removeTool(tool);
			analysisMgr.removeListener(this);
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramClosedPluginEvent ev) {
			programClosed(ev.getProgram());
		}
		else if (event instanceof ProgramOpenedPluginEvent ev) {
			programOpened(ev.getProgram());
		}
		else if (event instanceof ProgramActivatedPluginEvent ev) {
			Program program = ev.getActiveProgram();
			if (program == null) {
				removeOneShotActions();
			}
			else {
				programActivated(program);
				addOneShotActions(program);
			}
		}
		else if (event instanceof ProgramPostActivatedPluginEvent ev) {
			Program program = ev.getActiveProgram();
			if (program != null) {
				postProgramActivated(program);
			}
		}
	}

	protected void programOpened(final Program program) {
		final AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		analysisMgr.addTool(tool);
		analysisMgr.addListener(this);

		Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
		options.registerOptionsEditor(new AnalysisOptionsEditor(program));
		options.setOptionsHelpLocation(
			new HelpLocation("AutoAnalysisPlugin", "Auto_Analysis_Option"));
	}

	private void programActivated(Program program) {
		program.getOptions(StoredAnalyzerTimes.OPTIONS_LIST)
			.registerOption(StoredAnalyzerTimes.OPTION_NAME, OptionType.CUSTOM_TYPE, null, null,
				"Cumulative analysis task times", new StoredAnalyzerTimesPropertyEditor());

	}

	private void postProgramActivated(Program program) {
		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		if (analysisMgr.askToAnalyze(tool)) {
			analyzeCallback(program, null);
		}
	}

	/**
	 * Show the options panel for the auto analysis options. 
	 */
	private boolean showOptionsDialog(Program program) {
		tool.clearStatusInfo();
		Options options = tool.getOptions(GhidraOptions.CATEGORY_AUTO_ANALYSIS);
		boolean showDialog = options.getBoolean(SHOW_ANALYSIS_OPTIONS, true);

		if (!showDialog) {
			return true;
		}
		int id = program.startTransaction("Analysis Options");
		try {
			AnalysisOptionsDialog dialog = new AnalysisOptionsDialog(program);
			tool.showDialog(dialog);
			return dialog.wasAnalyzeButtonSelected();
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	@Override
	public void analysisEnded(AutoAnalysisManager manager) {
		MessageLog log = manager.getMessageLog();
		if (log.hasMessages()) {

			log.write(AutoAnalysisManager.class, "Analysis Log Messages");

			String shortMessage = "There were warnings/errors issued during analysis.";
			String detailedMessage =
				"(These messages are also written to the application log file)\n\n" +
					log.toString();
			MultiLineMessageDialog dialog = new MultiLineMessageDialog("Auto Analysis Summary",
				shortMessage, detailedMessage, MultiLineMessageDialog.WARNING_MESSAGE, false);//modal?
			DockingWindowManager.showDialog(null, dialog);
		}
	}

	class OneShotAnalyzerAction extends ListingContextAction {
		private Analyzer analyzer;
		private Program canAnalyzeProgram;
		private boolean canAnalyze;

		public OneShotAnalyzerAction(Analyzer analyzer) {
			super(analyzer.getName(), AutoAnalysisPlugin.this.getName());
			this.analyzer = analyzer;
			setMenuBarData(new MenuData(new String[] { "Analysis", "One Shot", analyzer.getName() },
				null, ANALYZE_GROUP_NAME));
			setHelpLocation(new HelpLocation("AutoAnalysisPlugin", "Auto_Analyzers"));

			setContextClass(ListingActionContext.class, true);
		}

		@Override
		public void actionPerformed(ListingActionContext context) {
			AddressSetView set;
			if (context.hasSelection()) {
				set = context.getSelection();
			}
			else {
				Memory memory = context.getProgram().getMemory();
				AddressSet external = new AddressSet(AddressSpace.EXTERNAL_SPACE.getMinAddress(),
					AddressSpace.EXTERNAL_SPACE.getMaxAddress());
				set = memory.union(external);
			}

			AutoAnalysisManager analysisMgr =
				AutoAnalysisManager.getAnalysisManager(context.getProgram());

			Program program = context.getProgram();
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			options = options.getOptions(analyzer.getName());
			analyzer.optionsChanged(options, program);

			analysisMgr.schedule(
				new OneShotAnalysisCommand(analyzer, set, analysisMgr.getMessageLog()),
				analyzer.getPriority().priority());

			tool.setStatusInfo("Analysis scheduled: " + analyzer.getName());
		}

		@Override
		public boolean isEnabledForContext(ListingActionContext context) {
			Program p = context.getProgram();
			if (p != canAnalyzeProgram) {
				canAnalyzeProgram = p;
				canAnalyze = analyzer.canAnalyze(p);
			}
			return canAnalyze;
		}
	}

	private class FirstTimeAnalyzedCallback implements AutoAnalysisManagerListener {
		@Override
		public void analysisEnded(AutoAnalysisManager manager) {
			manager.removeListener(this);
			tool.firePluginEvent(new FirstTimeAnalyzedPluginEvent(AutoAnalysisPlugin.this.getName(),
				manager.getProgram()));
		}
	}
}
