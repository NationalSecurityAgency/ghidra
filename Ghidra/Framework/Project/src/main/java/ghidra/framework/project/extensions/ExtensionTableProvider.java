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
package ghidra.framework.project.extensions;

import java.awt.BorderLayout;
import java.io.File;
import java.util.List;

import javax.swing.*;

import docking.ActionContext;
import docking.DialogComponentProvider;
import docking.action.*;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GTable;
import generic.jar.ResourceFile;
import ghidra.app.util.GenericHelpTopics;
import ghidra.framework.Application;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.Icons;

/**
 * Component Provider that shows the known extensions in Ghidra in a {@link GTable}. Users may
 * install/uninstall extensions, or add new ones.
 */
public class ExtensionTableProvider extends DialogComponentProvider {

	private static final String LAST_IMPORT_DIRECTORY_KEY = "LastExtensionImportDirectory";

	private ExtensionTablePanel extensionTablePanel;

	private boolean requireRestart = false;

	/**
	 * Constructor.
	 * 
	 * @param tool the plugin tool
	 */
	public ExtensionTableProvider(PluginTool tool) {
		super("Install Extensions");
		addWorkPanel(createMainPanel(tool));
		setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END, "Extensions"));
	}

	/**
	 * Creates the main panel for the extension dialog.
	 * 
	 * @param tool the current tool
	 * @return the new panel
	 */
	private JComponent createMainPanel(PluginTool tool) {

		JPanel panel = new JPanel(new BorderLayout());

		extensionTablePanel = new ExtensionTablePanel(tool);
		ExtensionDetailsPanel extensionDetailsPanel =
			new ExtensionDetailsPanel(extensionTablePanel);

		final JSplitPane splitPane =
			new JSplitPane(JSplitPane.VERTICAL_SPLIT, extensionTablePanel, extensionDetailsPanel);
		splitPane.setResizeWeight(.75);
		panel.add(splitPane, BorderLayout.CENTER);

		splitPane.setDividerLocation(.75);

		createAddAction(extensionTablePanel);
		createRefreshAction(extensionTablePanel, extensionDetailsPanel);

		addOKButton();

		return panel;
	}

	@Override
	protected void okCallback() {
		close();
	}

	@Override
	public void close() {
		super.close();
		extensionTablePanel.dispose();
	}

	@Override
	protected void dialogClosed() {
		super.dialogClosed();

		if (extensionTablePanel.getTableModel().hasModelChanged() || requireRestart) {
			Msg.showInfo(this, getComponent(), "Extensions Changed!",
				"Please restart Ghidra for extension changes to take effect.");
		}
	}

	/**
	 * Creates an action to allow users to manually add new extensions.
	 * 
	 * @param panel The extensions table panel.
	 */
	private void createAddAction(ExtensionTablePanel panel) {
		Icon addIcon = Icons.ADD_ICON;
		DockingAction addAction = new DockingAction("ExtensionTools", "AddExtension") {

			@Override
			public void actionPerformed(ActionContext context) {

				// Don't let the user attempt to install anything if they don't have write
				// permissions on the installation dir.
				ResourceFile installDir =
					Application.getApplicationLayout().getExtensionInstallationDirs().get(0);
				if (!installDir.exists() && !installDir.mkdir()) {
					Msg.showError(this, null, "Directory Error",
						"Cannot install/uninstall extensions: Failed to create extension " +
							"installation directory: " + installDir);
				}
				if (!installDir.canWrite()) {
					Msg.showError(this, null, "Permissions Error",
						"Cannot install/uninstall extensions: Invalid write permissions on " +
							"installation directory: " + installDir);
					return;
				}

				GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
				chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
				chooser.setLastDirectoryPreference(LAST_IMPORT_DIRECTORY_KEY);
				chooser.setTitle("Select Extension");
				chooser.addFileFilter(new ExtensionFileFilter());

				List<File> files = chooser.getSelectedFiles();
				chooser.dispose();

				if (installExtensions(files)) {
					panel.refreshTable();
					requireRestart = true;
				}
			}
		};

		String group = "extensionTools";
		addAction.setMenuBarData(new MenuData(new String[] { "Add Extension" }, addIcon, group));
		addAction.setToolBarData(new ToolBarData(addIcon, group));
		addAction.setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END, "ExtensionTools"));
		addAction.setDescription("Add extension");
		addAction.setEnabled(!Application.inSingleJarMode());
		addAction(addAction);
	}

	private boolean installExtensions(List<File> files) {
		boolean didInstall = false;
		for (File file : files) {

			// A sanity check for users that try to install an extension from a source folder
			// instead of a fully built extension.
			if (new File(file, "build.gradle").isFile()) {
				Msg.showWarn(this, null, "Invalid Extension", "The selected extension " +
					"contains a 'build.gradle' file.\nGhidra does not support installing " +
					"extensions in source form.\nPlease build the extension and try again.");
				continue;
			}

			boolean success = ExtensionUtils.install(file);
			didInstall |= success;
		}
		return didInstall;
	}

	/**
	 * Creates an action to refresh the extensions list.
	 * 
	 * @param tablePanel the table to be refreshed
	 * @param detailsPanel the details to be refreshed
	 */
	private void createRefreshAction(ExtensionTablePanel tablePanel,
			ExtensionDetailsPanel detailsPanel) {
		String group;
		Icon refreshIcon = Icons.REFRESH_ICON;
		DockingAction refreshAction = new DockingAction("ExtensionTools", "RefreshExtensions") {

			@Override
			public void actionPerformed(ActionContext context) {
				tablePanel.refreshTable();
			}
		};

		group = "extensionTools";
		refreshAction.setMenuBarData(new MenuData(new String[] { "Refresh" }, refreshIcon, group));
		refreshAction.setToolBarData(new ToolBarData(refreshIcon, group));
		refreshAction.setHelpLocation(
			new HelpLocation(GenericHelpTopics.FRONT_END, "ExtensionTools"));
		refreshAction.setDescription("Refresh extension list");
		addAction(refreshAction);
	}

	/**
	 * Filter for a {@link GhidraFileChooser} that restricts selection to those files that are
	 * Ghidra Extensions (zip files with an extension.properties file) or folders.
	 */
	private class ExtensionFileFilter implements GhidraFileFilter {
		@Override
		public String getDescription() {
			return "Ghidra Extension";
		}

		@Override
		public boolean accept(File f, GhidraFileChooserModel model) {
			return f.isDirectory() || ExtensionUtils.isExtension(f);
		}
	}
}
