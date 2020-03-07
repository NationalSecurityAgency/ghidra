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
package ghidra.framework.main;

import java.io.File;
import java.io.IOException;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import ghidra.net.ApplicationKeyManagerFactory;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;

/**
 * Helper class to manage the actions on the Edit menu.
 */
class EditActionManager {

	private FrontEndPlugin plugin;
	private FrontEndTool tool;
	private DockingAction editPluginPathAction;
	private DockingAction editCertPathAction;
	private DockingAction clearCertPathAction;
	private EditPluginPathDialog pluginPathDialog;
	private GhidraFileChooser certFileChooser;

	EditActionManager(FrontEndPlugin plugin) {
		this.plugin = plugin;
		tool = (FrontEndTool) plugin.getTool();
		createActions();
	}

	/**
	 * Create the menu items.
	 */
	private void createActions() {

		// window.addSeparator(Ghidra.MENU_FILE);

		editPluginPathAction = new DockingAction("Edit Plugin Path", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				editPluginPath();
			}
		};
// ACTIONS - auto generated
		editPluginPathAction.setEnabled(true);

		editPluginPathAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_EDIT,
			"Plugin Path..." }, "GEdit"));

		editCertPathAction = new DockingAction("Set PKI Certificate", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				editCertPath();
			}
		};
// ACTIONS - auto generated
		editCertPathAction.setEnabled(true);

		editCertPathAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_EDIT,
			"Set PKI Certificate..." }, "PKI"));

		clearCertPathAction = new DockingAction("Clear PKI Certificate", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				clearCertPath();
			}
		};
// ACTIONS - auto generated
		clearCertPathAction.setEnabled(ApplicationKeyManagerFactory.getKeyStore() != null);

		clearCertPathAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_EDIT,
			"Clear PKI Certificate..." }, "PKI"));

		clearCertPathAction.setHelpLocation(new HelpLocation("FrontEndPlugin",
			"Set_PKI_Certificate"));
		tool.addAction(editCertPathAction);
		tool.addAction(clearCertPathAction);
		tool.addAction(editPluginPathAction);
	}

	/**
	 * Pop up the edit plugin path dialog.
	 */
	private void editPluginPath() {
		if (pluginPathDialog == null) {
			pluginPathDialog = new EditPluginPathDialog();
		}
		pluginPathDialog.show(tool);
	}

	private void clearCertPath() {

		String path = ApplicationKeyManagerFactory.getKeyStore();
		if (path == null) {
			// unexpected
			clearCertPathAction.setEnabled(false);
			return;
		}

		if (OptionDialog.YES_OPTION != OptionDialog.showYesNoDialog(tool.getToolFrame(),
			"Clear PKI Certificate", "Clear PKI certificate setting?\n(" + path + ")")) {
			return;
		}

		try {
			ApplicationKeyManagerFactory.setKeyStore(null, true);
			clearCertPathAction.setEnabled(false);
		}
		catch (IOException e) {
			Msg.error(this,
				"Error occurred while clearing PKI certificate setting: " + e.getMessage());
		}
	}

	private void editCertPath() {
		if (certFileChooser == null) {
			certFileChooser = createCertFileChooser();
		}

		File dir = null;
		File oldFile = null;
		String path = ApplicationKeyManagerFactory.getKeyStore();
		if (path != null) {
			oldFile = new File(path);
			dir = oldFile.getParentFile();
			if (!oldFile.isFile()) {
				oldFile = null;
				if (!dir.isDirectory()) {
					dir = null;
				}
			}
		}
		if (dir == null) {
			dir = new File(System.getProperty("user.home"));
		}

		if (oldFile != null) {
			certFileChooser.setSelectedFile(oldFile);
		}
		else {
			certFileChooser.setCurrentDirectory(dir);
		}

		boolean validInput = false;
		while (!validInput) {
			// display the file chooser and handle the action, Select or Create
			File file = certFileChooser.getSelectedFile();
			if (file == null) {
				return; // cancelled
			}
			try {
				ApplicationKeyManagerFactory.setKeyStore(file.getAbsolutePath(), true);
				clearCertPathAction.setEnabled(true);
				validInput = true;
			}
			catch (IOException e) {
				Msg.showError(this, tool.getToolFrame(), "Certificate Failure",
					"Failed to initialize key manager.\n" + e.getMessage(), e);
				file = null;
			}
		}
	}

	private GhidraFileChooser createCertFileChooser() {

		GhidraFileChooser fileChooser = new GhidraFileChooser(tool.getToolFrame());
		fileChooser.setTitle("Select Certificate (req'd for PKI authentication only)");
		fileChooser.setApproveButtonText("Set Certificate");
		fileChooser.setFileFilter(ApplicationKeyManagerFactory.CERTIFICATE_FILE_FILTER);
		fileChooser.setFileSelectionMode(GhidraFileChooser.FILES_ONLY);
		fileChooser.setHelpLocation(new HelpLocation(plugin.getName(), "Set_PKI_Certificate"));
		return fileChooser;
	}
}
