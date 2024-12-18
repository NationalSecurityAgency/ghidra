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
package ghidra.feature.vt.gui.plugin;

import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import javax.swing.Icon;
import javax.swing.JFrame;

import docking.action.DockingActionIf;
import docking.tool.ToolConstants;
import docking.wizard.WizardManager;
import generic.theme.GIcon;
import ghidra.GhidraOptions;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.util.viewer.options.ListingDisplayOptionsEditor;
import ghidra.feature.vt.api.db.VTSessionDB;
import ghidra.feature.vt.api.main.VTSession;
import ghidra.feature.vt.gui.actions.*;
import ghidra.feature.vt.gui.provider.functionassociation.VTFunctionAssociationProvider;
import ghidra.feature.vt.gui.provider.impliedmatches.*;
import ghidra.feature.vt.gui.provider.markuptable.VTMarkupItemsTableProvider;
import ghidra.feature.vt.gui.provider.matchtable.VTMatchTableProvider;
import ghidra.feature.vt.gui.wizard.VTNewSessionWizardManager;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.*;
import help.Help;
import help.HelpService;
import resources.ResourceManager;

//@formatter:off
@PluginInfo(
	status = PluginStatus.HIDDEN,
	packageName = VersionTrackingPluginPackage.NAME,
	category = "Version Tracking",
	shortDescription = "Version Tracking",
	description = "This plugin provides the Version Tracking Feature.",
	servicesProvided = { VTController.class }
)
//@formatter:on
public class VTPlugin extends Plugin {
	public static final String WINDOW_GROUP = "VTResults";
	public static final String HELP_TOPIC_NAME = "VersionTrackingPlugin";
	private static final String SHOW_HELP_PREFERENCE = "VersionTrackingShowHelp";

	public static String OWNER;

	// menu stuffs
	public static final String MATCH_POPUP_MENU_NAME = "Version Tracking Match";
	public static final String MARKUP_POPUP_MENU_NAME = "Version Tracking Markup";
	public static final String VT_MAIN_MENU_GROUP = "AAA_VT_Main";
	public static final String ADDRESS_EDIT_MENU_GROUP = "A_VT_X_AddressEdit";
	public static final String APPLY_EDIT_MENU_GROUP = "A_VT_Apply_Edit";
	public static final String EDIT_MENU_GROUP = "A_VT_Edit_1";
	public static final String TAG_MENU_GROUP = "A_VT_Edit_2";
	public static final String UNEDIT_MENU_GROUP = "A_VT_UnEdit";
	public static final String VT_SETTINGS_MENU_GROUP = "ZZ_VT_SETTINGS";

	public static final Icon UNFILTERED_ICON = new GIcon("icon.version.tracking.unfiltered");
	public static final Icon FILTERED_ICON = new GIcon("icon.version.tracking.filtered");
	public static final Icon REPLACED_ICON = new GIcon("icon.version.tracking.replaced");

	private VTController controller;

	// common resources

	// destination-side resources

	private VTMatchTableProvider matchesProvider;
	private VTMarkupItemsTableProvider markupProvider;
	private VTSubToolManager toolManager;
	private VTImpliedMatchesTableProvider impliedMatchesTable;
	private VTFunctionAssociationProvider functionAssociationProvider;

	public VTPlugin(PluginTool tool) {
		super(tool);
		OWNER = getName();
		controller = new VTControllerImpl(this);
		matchesProvider = new VTMatchTableProvider(controller);
		markupProvider = new VTMarkupItemsTableProvider(controller);
		impliedMatchesTable = new VTImpliedMatchesTableProvider(controller);
		functionAssociationProvider = new VTFunctionAssociationProvider(controller);
		toolManager = new VTSubToolManager(this);
		createActions();
		registerServiceProvided(VTController.class, controller);
		tool.setUnconfigurable();

		DockingActionIf saveAs = getToolAction("Save Tool As");
		tool.removeAction(saveAs);

		DockingActionIf export = getToolAction("Export Tool");
		tool.removeAction(export);

		new MatchStatusUpdaterAssociationHook(controller);
		new ImpliedMatchAssociationHook(controller);

		initializeOptions();

	}

	private DockingActionIf getToolAction(String actionName) {
		Set<DockingActionIf> actions = tool.getDockingActionsByOwnerName(ToolConstants.TOOL_OWNER);
		for (DockingActionIf action : actions) {
			if (action.getName().equals(actionName)) {
				return action;
			}
		}
		throw new IllegalArgumentException("Unable to find Tool action '" + actionName + "'");
	}

	private void initializeOptions() {
		Options options = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_DISPLAY);
		options.registerOptionsEditor(() -> new ListingDisplayOptionsEditor(options));
		options.setOptionsHelpLocation(new HelpLocation(CodeBrowserPlugin.class.getSimpleName(),
			GhidraOptions.CATEGORY_BROWSER_DISPLAY));

	}

	@Override
	protected void init() {
		addCustomPlugins();

		maybeShowHelp();
	}

	private void addCustomPlugins() {

		List<String> names =
			new ArrayList<>(List.of("ghidra.features.codecompare.plugin.FunctionComparisonPlugin"));
		List<Plugin> plugins = tool.getManagedPlugins();
		Set<String> existingNames =
			plugins.stream().map(c -> c.getName()).collect(Collectors.toSet());

		// Note: we check to see if the plugins we want to add have already been added to the tool.
		// We should not need to do this, but once the tool has been saved with the plugins added,
		// they will get added again the next time the tool is loaded.  Adding this check here seems
		// easier than modifying the default to file to load the plugins, since the amount of xml
		// required for that is non-trivial.
		try {
			for (String className : names) {
				if (!existingNames.contains(className)) {
					tool.addPlugin(className);
				}
			}

		}
		catch (PluginException e) {
			Msg.error(this, "Unable to load plugin", e);
		}
	}

	private void maybeShowHelp() {
		if (SystemUtilities.isInDevelopmentMode() || SystemUtilities.isInTestingMode()) {
			return; // don't show help for dev mode
		}

		HelpService help = Help.getHelpService();

		// if this is the first time Ghidra is being run, pop up
		// the What's New help page
		String preference = Preferences.getProperty(SHOW_HELP_PREFERENCE);
		if (preference != null) {
			return;
		}

		Preferences.setProperty(SHOW_HELP_PREFERENCE, "No");
		Preferences.store();

		URL url = ResourceManager.getResource("help/topics/VersionTrackingPlugin/VT_Workflow.html");
		if (url == null) {
			Msg.showError(this, null, "Help Not Found",
				"Unable to find the Version Tracking workflow help");
			return;
		}

		help.showHelp(url);
	}

	private void createActions() {
		tool.addAction(new CreateVersionTrackingSessionAction(controller));
		tool.addAction(new OpenVersionTrackingSessionAction(controller));
		tool.addAction(new AddToVersionTrackingSessionAction(controller));
		tool.addAction(new CloseVersionTrackingSessionAction(controller));
		tool.addAction(new SaveVersionTrackingSessionAction(controller));
		tool.addAction(new UndoAction(controller));
		tool.addAction(new RedoAction(controller));
		tool.addAction(new ResetToolAction(controller, toolManager));
		tool.addAction(new HelpAction());
		tool.addAction(new AutoVersionTrackingAction(controller));
	}

	@Override
	protected void close() {
		controller.closeCurrentSessionIgnoringChanges();

		matchesProvider.setVisible(false);
		markupProvider.setVisible(false);
		impliedMatchesTable.setVisible(false);
		functionAssociationProvider.setVisible(false);

		super.close();
	}

	@Override
	protected void dispose() {
		controller.dispose();

		super.dispose();
	}

	@Override
	public Class<?>[] getSupportedDataTypes() {
		return new Class[] { VTSession.class, Program.class };
	}

	@Override
	public boolean acceptData(DomainFile[] data) {
		if (data == null || data.length == 0) {
			return false;
		}
		for (DomainFile domainFile : data) {
			if (domainFile != null &&
				VTSession.class.isAssignableFrom(domainFile.getDomainObjectClass())) {
				return controller.openVersionTrackingSession(domainFile);
			}
		}

		DomainFile programFile1 = null;
		DomainFile programFile2 = null;
		for (DomainFile domainFile : data) {
			if (domainFile != null &&
				Program.class.isAssignableFrom(domainFile.getDomainObjectClass())) {

				if (programFile1 == null) {
					programFile1 = domainFile;
				}
				else if (programFile2 == null) {
					programFile2 = domainFile;
				}
			}
		}
		if (programFile1 != null) {
			if (!controller.closeVersionTrackingSession()) {
				return false; // user cancelled  during save dialog
			}
			VTNewSessionWizardManager vtWizardManager =
				new VTNewSessionWizardManager(controller, programFile1, programFile2);
			WizardManager wizardManager =
				new WizardManager("Version Tracking Wizard", true, vtWizardManager);
			wizardManager.showWizard(tool.getToolFrame());
			return true;
		}

		return false;
	}

	@Override
	public void readConfigState(SaveState saveState) {
		controller.readConfigState(saveState);
		matchesProvider.readConfigState(saveState);
		markupProvider.readConfigState(saveState);
		impliedMatchesTable.readConfigState(saveState);
		functionAssociationProvider.readConfigState(saveState);
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		controller.writeConfigState(saveState);
		matchesProvider.writeConfigState(saveState);
		markupProvider.writeConfigState(saveState);
		impliedMatchesTable.writeConfigState(saveState);
		functionAssociationProvider.writeConfigState(saveState);
	}

	@Override
	public void readDataState(SaveState saveState) {
		String pathname = saveState.getString("PATHNAME", null);
		if (pathname == null) {
			return;
		}
		Project project = tool.getProject();
		if (project == null) {
			return;
		}
		ProjectData projectData = project.getProjectData();
		DomainFile domainFile = projectData.getFile(pathname);
		if (domainFile == null) {
			return;
		}
		controller.openVersionTrackingSession(domainFile);
	}

	@Override
	public void writeDataState(SaveState saveState) {
		VTSessionDB session = (VTSessionDB) controller.getSession();
		if (session == null) {
			return;
		}
		DomainFile domainFile = session.getDomainFile();
		saveState.putString("PATHNAME", domainFile.getPathname());
	}

	@Override
	protected boolean saveData() {
		return controller.checkForUnSavedChanges();
	}

	@Override
	protected boolean canClose() {
		PluginTool sourceTool = toolManager.getSourceTool();
		PluginTool destinationTool = toolManager.getDestinationTool();
		if (toolManager.isToolExecutingCommand(sourceTool)) {
			showBusyToolMessage(sourceTool);
			return false;
		}
		else if (toolManager.isToolExecutingCommand(destinationTool)) {
			showBusyToolMessage(destinationTool);
			return false;
		}
		return true;
	}

	public AddressSetView getSelectionInSourceTool() {
		return toolManager.getSelectionInSourceTool();
	}

	public AddressSetView getSelectionInDestinationTool() {
		return toolManager.getSelectionInDestinationTool();
	}

	public void setSelectionInDestinationTool(AddressSetView destinationSet) {
		toolManager.setSelectionInDestinationTool(destinationSet);
	}

	public void setSelectionInSourceTool(AddressSetView sourceSet) {
		toolManager.setSelectionInSourceTool(sourceSet);
	}

	public List<DomainFile> getChangedProgramsInSourceTool() {
		return toolManager.getChangedProgramsInSourceTool();
	}

	public List<DomainFile> getChangedProgramsInDestinationTool() {
		return toolManager.getChangedProgramsInDestinationTool();
	}

	public void gotoSourceLocation(ProgramLocation location) {
		toolManager.gotoSourceLocation(location);
	}

	public void gotoDestinationLocation(ProgramLocation location) {
		toolManager.gotoDestinationLocation(location);
	}

	public void updateUndoActions() {
		tool.contextChanged(null);
	}

	public VTController getController() {
		return controller;
	}

	public VTSubToolManager getToolManager() {
		return toolManager;
	}

	public VTMatchTableProvider getMatchesProvider() {
		return matchesProvider;
	}

	public ColorizingService getSourceColorizingService() {
		return toolManager.getSourceColorizingService();
	}

	public ColorizingService getDestinationColorizingService() {
		return toolManager.getDestinationColorizingService();
	}

	/**
	 * Displays a dialog stating that a tool is busy.
	 * @param tool the tool to display that's busy.
	 */
	static void showBusyToolMessage(PluginTool tool) {
		JFrame toolFrame = tool.getToolFrame();
		tool.beep();
		Msg.showInfo(VTPlugin.class, toolFrame, "Tool \"" + tool.getName() + "\" Busy",
			"You must stop all background tasks before exiting.");
	}
}
