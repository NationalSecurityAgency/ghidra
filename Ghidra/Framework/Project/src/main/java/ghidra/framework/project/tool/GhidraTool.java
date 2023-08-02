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

import org.jdom.Element;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import ghidra.app.util.FileOpenDropHandler;
import ghidra.framework.model.Project;
import ghidra.framework.model.ToolTemplate;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.PluginsConfiguration;
import ghidra.util.HelpLocation;

/**
 * Tool created by the workspace when the user chooses to create a new
 * tool. Its ToolConfigProvider shows all Plugins with the exception of
 * those plugins that can be added to the Front End tool only.
 */
public class GhidraTool extends PluginTool {

	private static final String NON_AUTOSAVE_SAVE_TOOL_TITLE = "Save Tool?";

	public static boolean autoSave = true;

	private FileOpenDropHandler fileOpenDropHandler;
	private DockingAction configureToolAction;

	private ExtensionManager extensionManager;
	private boolean hasBeenShown;

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

	/**
	 * We need to do this here, since our parent constructor calls methods on us that need the 
	 * extension manager.
	 * @return the extension manager
	 */
	private ExtensionManager getExtensionManager() {
		if (extensionManager == null) {
			extensionManager = new ExtensionManager(this);
		}
		return extensionManager;
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
	protected PluginsConfiguration createPluginsConfigurations() {
		return new GhidraPluginsConfiguration();
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
	public Element saveToXml(boolean includeConfigState) {
		Element xml = super.saveToXml(includeConfigState);
		getExtensionManager().saveToXml(xml);
		return xml;
	}

	@Override
	protected boolean restoreFromXml(Element root) {
		boolean success = super.restoreFromXml(root);
		getExtensionManager().restoreFromXml(root);
		return success;
	}

	@Override
	public void setVisible(boolean visible) {
		if (visible) {
			if (!hasBeenShown) { // first time being shown
				getExtensionManager().checkForNewExtensions();
			}
			hasBeenShown = true;
		}
		super.setVisible(visible);
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
	public void dispose() {
		if (fileOpenDropHandler != null) {
			fileOpenDropHandler.dispose();
			fileOpenDropHandler = null;
		}
		super.dispose();
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
			new String[] { ToolConstants.MENU_FILE, "Configure" }, null, "PrintPost_PreTool"));

		configureToolAction.setEnabled(true);
		addAction(configureToolAction);
	}

	protected void showConfig() {
		showConfig(true, false);
	}
}
