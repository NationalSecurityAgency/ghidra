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

import javax.swing.event.ChangeListener;

import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.tool.ToolConstants;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.framework.OperatingSystem;
import ghidra.framework.client.UrlAllowListManager;
import ghidra.framework.main.certs.CertificateManagerLauncher;
import ghidra.net.DefaultKeyManagerFactory;
import ghidra.net.PKIUtils;
import ghidra.util.HelpLocation;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;

/**
 * Helper class to manage the actions on the Edit menu.
 */
class EditActionManager {
	/**
	 * PKCS Private Key/Certificate File Filter
	 */
	public static final GhidraFileFilter CERTIFICATE_FILE_FILTER =
		new ExtensionFileFilter(PKIUtils.PKCS_FILE_EXTENSIONS, "PKCS Key File");

	private FrontEndPlugin plugin;
	private FrontEndTool tool;

	private ChangeListener serverAllowListListener = e -> serverAllowListChanged();

	private DockingAction clearServerAllowList;
	private DockingAction clearCertPathAction;

	EditActionManager(FrontEndPlugin plugin) {
		this.plugin = plugin;
		tool = (FrontEndTool) plugin.getTool();
		createActions();

		UrlAllowListManager.addChangeListener(serverAllowListListener);
	}

	void dispose() {
		UrlAllowListManager.removeChangeListener(serverAllowListListener);
	}

	private void serverAllowListChanged() {
		clearServerAllowList.setEnabled(!UrlAllowListManager.getAccessMap().isEmpty());
	}

	/**
	 * Create the menu items.
	 */
	@SuppressWarnings("unused")
	private void createActions() {

		DockingAction editPluginPathAction =
			new ActionBuilder("Edit Plugin Path", plugin.getName()).menuGroup("GEdit")
					.menuPath(ToolConstants.MENU_EDIT, "Plugin Path...")
					.onAction(c -> editPluginPath())
					.enabled(true)
					.build();
		tool.addAction(editPluginPathAction);

		OperatingSystem currentOS = OperatingSystem.CURRENT_OPERATING_SYSTEM;
		if (currentOS == OperatingSystem.WINDOWS || currentOS == OperatingSystem.MAC_OS_X) {
			DockingAction manageCaCertsAction =
				new ActionBuilder("Manage Certificates", plugin.getName()).menuGroup("PKI", "A")
						.menuPath(ToolConstants.MENU_EDIT, "Manage Certificates...")
						.helpLocation(new HelpLocation("FrontEndPlugin", "Manage_Certificates"))
						.onAction(c -> CertificateManagerLauncher.launchOrFocus())
						.enabled(true)
						.build();
			tool.addAction(manageCaCertsAction);
		}

		DockingAction editCertPathAction =
			new ActionBuilder("Set PKI Certificate", plugin.getName()).menuGroup("PKI", "B")
					.menuPath(ToolConstants.MENU_EDIT, "Set PKI Certificate...")
					.helpLocation(new HelpLocation("FrontEndPlugin", "Set_PKI_Certificate"))
					.onAction(c -> editCertPath())
					.enabled(true)
					.build();
		tool.addAction(editCertPathAction);

		clearCertPathAction =
			new ActionBuilder("Clear PKI Certificate", plugin.getName()).menuGroup("PKI", "C")
					.menuPath(ToolConstants.MENU_EDIT, "Clear PKI Certificate...")
					.onAction(c -> clearCertPath())
					.enabledWhen(c -> DefaultKeyManagerFactory.getKeyStore() != null)
					.enabled(true)
					.build();
		tool.addAction(clearCertPathAction);

		clearServerAllowList =
			new ActionBuilder("Clear Server Allow List", plugin.getName()).menuGroup("SvrAllowList")
					.menuPath(ToolConstants.MENU_EDIT, "Clear Server Allow List...")
					.helpLocation(new HelpLocation("FrontEndPlugin", "Clear_Server_Allow_List"))
					.onAction(c -> clearServerAllowList())
					.enabledWhen(c -> !UrlAllowListManager.getAccessMap().isEmpty())
					.enabled(true)
					.build();
		tool.addAction(clearServerAllowList);
	}

	private void clearServerAllowList() {
		if (OptionDialog.YES_OPTION == OptionDialog.showYesNoDialog(tool.getToolFrame(),
			"Clear Server Allow List", "Clear all Server Allow List entries?\n")) {
			UrlAllowListManager.clearAll();
		}
	}

	/**
	 * Pop up the edit plugin path dialog.
	 */
	private void editPluginPath() {
		EditPluginPathDialog pluginPathDialog = new EditPluginPathDialog();
		pluginPathDialog.show(tool);
	}

	private void clearCertPath() {

		String path = DefaultKeyManagerFactory.getKeyStore();
		if (path == null) {
			// unexpected
			clearCertPathAction.setEnabled(false);
			return;
		}

		OperatingSystem os = OperatingSystem.CURRENT_OPERATING_SYSTEM;
		String revertMsg =
			(os == OperatingSystem.WINDOWS || os == OperatingSystem.MAC_OS_X)
					? "The OS-managed certificate store, or an auto-generated certificate\n" +
						"if no suitable OS certificate is found, will be used instead."
					: "An auto-generated certificate will be used instead.";

		if (OptionDialog.YES_OPTION != OptionDialog.showYesNoDialog(tool.getToolFrame(),
			"Clear PKI Certificate",
			"Clear PKI certificate setting?\n(" + path + ")\n\n" + revertMsg)) {
			return;
		}

		DefaultKeyManagerFactory.setDefaultKeyStore(null, true);
		clearCertPathAction.setEnabled(false);
	}

	private void editCertPath() {

		GhidraFileChooser certFileChooser = createCertFileChooser();

		File dir = null;
		File oldFile = null;
		String path = DefaultKeyManagerFactory.getKeyStore();
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
			DefaultKeyManagerFactory.setDefaultKeyStore(file.getAbsolutePath(), true);
			clearCertPathAction.setEnabled(true);
			validInput = true;
		}

		certFileChooser.dispose();
	}

	private GhidraFileChooser createCertFileChooser() {

		GhidraFileChooser fileChooser = new GhidraFileChooser(tool.getToolFrame());
		String title = "Select Certificate (req'd for PKI authentication only)";
		if (DefaultKeyManagerFactory.usingOSManagedKeyStore()) {
			title = "Select Certificate (currently using OS certificate store)";
		}
		else {
			title = "Select Certificate";
		}
		fileChooser.setTitle(title);
		fileChooser.setApproveButtonText("Set Certificate");
		fileChooser.setFileFilter(CERTIFICATE_FILE_FILTER);
		fileChooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
		fileChooser.setHelpLocation(new HelpLocation(plugin.getName(), "Set_PKI_Certificate"));
		return fileChooser;
	}

}
