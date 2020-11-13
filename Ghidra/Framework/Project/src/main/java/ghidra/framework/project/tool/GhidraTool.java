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
package ghidra.framework.project.tool;

import java.util.*;
import java.util.stream.Collectors;

import org.apache.commons.lang3.ArrayUtils;
import org.jdom.Element;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.app.util.FileOpenDropHandler;
import ghidra.framework.main.FrontEndOnly;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.options.PreferenceState;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.dialog.*;
import ghidra.framework.plugintool.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Tool created by the workspace when the user chooses to create a new
 * tool. Its ToolConfigProvider shows all Plugins with the exception of
 * those plugins that can be added to the Front End tool only.
 */
public class GhidraTool extends PluginTool {

	private static final String NON_AUTOSAVE_SAVE_TOOL_TITLE = "Save Tool?";

	// Preference category stored in the tools' xml file, indicating which extensions
	// this tool is aware of. This is used to recognize when new extensions have been
	// installed that the user should be made aware of.
	public static final String EXTENSIONS_PREFERENCE_NAME = "KNOWN_EXTENSIONS";

	public static boolean autoSave = true;

	private FileOpenDropHandler fileOpenDropHandler;

	private PluginClassManager pluginClassManager;

	private DockingAction configureToolAction;

	/**
	 * Construct a new Ghidra Tool.
	 *
	 * @param project the project associated with the tool
	 * @param name the name of the tool
	 */
	public GhidraTool(Project project, String name) {
		super(project, name, true, true, false);
	}

	/**
	 * Construct a new GhidraTool using an existing template.
	 *
	 * @param project project that is the associated with the tool.
	 * @param template the template to use when creating the tool
	 */
	public GhidraTool(Project project, GhidraToolTemplate template) {
		super(project, template);
	}

	@Override
	protected DockingWindowManager createDockingWindowManager(boolean isDockable, boolean hasStatus,
			boolean isModal) {
		return new DockingWindowManager(this, null, isModal, isDockable, hasStatus,
			new OpenFileDropHandlerFactory(this));
	}

	@Override
	protected void initActions() {
		addSaveToolAction();
		addExportToolAction();
		addCloseAction();
		addExitAction();
		addManagePluginsAction();
		addOptionsAction();
		addHelpActions();
	}

	@Override
	public PluginClassManager getPluginClassManager() {
		if (pluginClassManager == null) {
			pluginClassManager = new PluginClassManager(Plugin.class, FrontEndOnly.class);
		}
		return pluginClassManager;
	}

	@Override
	public void setToolName(String name) {
		super.setToolName(name);
		setConfigChanged(true);
	}

	@Override
	public ToolTemplate getToolTemplate(boolean includeConfigState) {
		return new GhidraToolTemplate(iconURL, saveToXml(includeConfigState),
			getSupportedDataTypes());
	}

	@Override
	public Element saveWindowingDataToXml() {
		return winMgr.saveWindowingDataToXml();
	}

	@Override
	public void restoreWindowingDataFromXml(Element rootElement) {
		winMgr.restoreWindowDataFromXml(rootElement);
	}

	@Override
	public boolean shouldSave() {
		if (autoSave) {
			return true; // we are dirty and we can simply save without user input (autosave)
		}

		// otherwise, we've changed and we must ask the user if we should save
		if (hasConfigChanged()) {
			return promptUserToSave();
		}
		return false;
	}

	@Override
	protected boolean doSaveTool() {
		if (autoSave) {
			return super.doSaveTool(); // default handling
		}

		// old style of exiting - prompt to save if we are dirty
		if (hasConfigChanged()) {
			if (promptUserToSave()) {
				saveTool();
			}
		}
		return true;
	}

	private boolean promptUserToSave() {
		int result =
			OptionDialog.showOptionNoCancelDialog(getToolFrame(), NON_AUTOSAVE_SAVE_TOOL_TITLE,
				"The tool configuration has changed for " + getName() +
					".\nDo you want to save it to your " + "tool chest?",
				"&Save", "Do&n't Save", OptionDialog.QUESTION_MESSAGE);
		return (result == OptionDialog.OPTION_ONE);
	}

	@Override
	public void exit() {
		if (fileOpenDropHandler != null) {
			fileOpenDropHandler.dispose();
			fileOpenDropHandler = null;
		}
		super.exit();
	}

	private void addCloseAction() {
		DockingAction closeAction = new DockingAction("Close Tool", ToolConstants.TOOL_OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				close();
			}
		};
		closeAction.setHelpLocation(
			new HelpLocation(ToolConstants.TOOL_HELP_TOPIC, closeAction.getName()));
		closeAction.setEnabled(true);

		closeAction.setMenuBarData(
			new MenuData(new String[] { ToolConstants.MENU_FILE, "Close Tool" }, null, "Window_A"));

		addAction(closeAction);
	}

	protected void addManagePluginsAction() {

		configureToolAction = new DockingAction("Configure Tool", ToolConstants.TOOL_OWNER) {
			@Override
			public void actionPerformed(ActionContext context) {
				showConfig();
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return isConfigurable();
			}
		};

		configureToolAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_FILE, "Configure..." }, null, "PrintPost_PreTool"));

		configureToolAction.setEnabled(true);
		addAction(configureToolAction);
	}

	protected void showConfig() {
//		if (hasUnsavedData()) {
//			OptionDialog.showWarningDialog( getToolFrame(),"Configure Not Allowed!",
//					"The tool has unsaved data. Configuring the tool can potentially lose\n"+
//					"data. Therefore, this operation is not allowed with unsaved data.\n\n"+
//					"Please save your data before configuring the tool.");
//			return;
//		}
		showConfig(true, false);
	}

	/**
	 * Looks for extensions that have been installed since the last time this tool
	 * was launched. If any are found, and if those extensions contain plugins, the user is
	 * notified and given the chance to install them.
	 *
	 */
	public void checkForNewExtensions() {

		// 1. First remove any extensions that are in the tool preferences that are no longer
		//    installed. This will happen if the user installs an extension, launches
		//    a tool, then uninstalls the extension.
		removeUninstalledExtensions();

		// 2. Now figure out which extensions have been added.
		Set<ExtensionDetails> newExtensions =
			ExtensionUtils.getExtensionsInstalledSinceLastToolLaunch(this);

		// 3. Get a list of all plugins contained in those extensions. If there are none, then
		//    either none of the extensions has any plugins, or Ghidra hasn't been restarted since
		//    installing the extension(s), so none of the plugin classes have been loaded. In
		//    either case, there is nothing more to do.
		List<Class<?>> newPlugins = PluginUtils.findLoadedPlugins(newExtensions);
		if (newPlugins.isEmpty()) {
			return;
		}

		// 4. Notify the user there are new plugins.
		int option = OptionDialog.showYesNoDialog(getActiveWindow(), "New Plugins Found!",
			"New extension plugins detected. Would you like to configure them?");
		if (option == OptionDialog.YES_OPTION) {
			List<PluginDescription> pluginDescriptions =
				PluginUtils.getPluginDescriptions(this, newPlugins);
			PluginInstallerDialog pluginInstaller =
				new PluginInstallerDialog("New Plugins Found!", this, pluginDescriptions);
			showDialog(pluginInstaller);
		}

		// 5. Update the preference file to reflect the new extensions now known to this tool.
		addInstalledExtensions(newExtensions);
	}

	/**
	 * Removes any extensions in the tool preferences that are no longer installed.
	 */
	private void removeUninstalledExtensions() {

		try {
			// Get all installed extensions
			Set<ExtensionDetails> installedExtensions =
				ExtensionUtils.getInstalledExtensions(false);
			List<String> installedExtensionNames =
				installedExtensions.stream().map(ext -> ext.getName()).collect(Collectors.toList());

			// Get the list of extensions in the tool preference state
			DockingWindowManager dockingWindowManager =
				DockingWindowManager.getInstance(getToolFrame());

			PreferenceState state = getExtensionPreferences(dockingWindowManager);

			String[] extNames = state.getStrings(EXTENSIONS_PREFERENCE_NAME, new String[0]);
			List<String> preferenceExtensionNames = new ArrayList<>(Arrays.asList(extNames));

			// Now see if any extensions are in the current preferences that are NOT in the installed extensions
			// list. Those are the ones we need to remove.
			for (Iterator<String> i = preferenceExtensionNames.iterator(); i.hasNext();) {
				String extName = i.next();
				if (!installedExtensionNames.contains(extName)) {
					i.remove();
				}
			}

			// Finally, put the new extension list in the preferences object
			state.putStrings(EXTENSIONS_PREFERENCE_NAME,
				preferenceExtensionNames.toArray(new String[preferenceExtensionNames.size()]));
			dockingWindowManager.putPreferenceState(EXTENSIONS_PREFERENCE_NAME, state);
		}
		catch (ExtensionException e) {
			// This is a problem but isn't catastrophic. Just warn the user and continue.
			Msg.warn(this, "Couldn't retrieve installed extensions!", e);
		}
	}

	/**
	 * Updates the preferences for this tool with a set of new extensions.
	 *
	 * @param newExtensions the extensions to add
	 */
	private void addInstalledExtensions(Set<ExtensionDetails> newExtensions) {

		DockingWindowManager dockingWindowManager =
			DockingWindowManager.getInstance(getToolFrame());

		// Get the current preference object. We need to get the existing prefs so we can add our
		// new extensions to them. If the extensions category doesn't exist yet, just create one.
		PreferenceState state = getExtensionPreferences(dockingWindowManager);

		// Now get the list of extensions already in the prefs...
		String[] extNames = state.getStrings(EXTENSIONS_PREFERENCE_NAME, new String[0]);

		// ...and parse the passed-in extension list to get just the names of the extensions to add.
		List<String> extensionNamesToAdd =
			newExtensions.stream().map(ext -> ext.getName()).collect(Collectors.toList());

		// Finally add them together and update the preference state.
		String[] allPreferences = ArrayUtils.addAll(extNames,
			extensionNamesToAdd.toArray(new String[extensionNamesToAdd.size()]));
		state.putStrings(EXTENSIONS_PREFERENCE_NAME, allPreferences);
		dockingWindowManager.putPreferenceState(EXTENSIONS_PREFERENCE_NAME, state);
	}

	/**
	 * Return the extensions portion of the preferences object.
	 *
	 * @param dockingWindowManager the docking window manager
	 * @return the extensions portion of the preference state, or a new preference state object if no extension section exists
	 */
	private PreferenceState getExtensionPreferences(DockingWindowManager dockingWindowManager) {

		PreferenceState state = dockingWindowManager.getPreferenceState(EXTENSIONS_PREFERENCE_NAME);
		if (state == null) {
			state = new PreferenceState();
		}

		return state;
	}
}
