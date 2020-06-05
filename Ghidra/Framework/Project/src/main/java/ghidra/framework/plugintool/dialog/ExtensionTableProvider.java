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
package ghidra.framework.plugintool.dialog;

import java.awt.BorderLayout;
import java.io.File;
import java.util.List;
import java.util.Properties;

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
import ghidra.util.*;
import ghidra.util.filechooser.GhidraFileChooserModel;
import ghidra.util.filechooser.GhidraFileFilter;
import resources.Icons;
import resources.ResourceManager;

/**
 * Component Provider that shows the known extensions in Ghidra in a {@link GTable}. Users may
 * install/uninstall extensions, or add new ones.
 */
public class ExtensionTableProvider extends DialogComponentProvider {

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
		Icon addIcon = ResourceManager.loadImage("images/Plus.png");
		DockingAction addAction = new DockingAction("ExtensionTools", "AddExtension") {

			@Override
			public void actionPerformed(ActionContext context) {

				// Don't let the user attempt to install anything if they don't have write
				// permissions on the installation dir.
				ResourceFile installDir =
					Application.getApplicationLayout().getExtensionInstallationDirs().get(0);
				if (!installDir.exists() && !installDir.mkdir()) {
					Msg.showError(this, null, "Directory Error",
						"Cannot install/uninstall extensions: Failed to create extension installation directory.\n" +
							"See the \"Ghidra Extension Notes\" section of the Ghidra Installation Guide for more information.");
				}
				if (!installDir.canWrite()) {
					Msg.showError(this, null, "Permissions Error",
						"Cannot install/uninstall extensions: Invalid write permissions on installation directory.\n" +
							"See the \"Ghidra Extension Notes\" section of the Ghidra Installation Guide for more information.");
					return;
				}

				GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
				chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_AND_DIRECTORIES);
				chooser.setTitle("Select extension");
				chooser.addFileFilter(new ExtensionFileFilter());

				List<File> files = chooser.getSelectedFiles();
				for (File file : files) {
					try {
						if (!ExtensionUtils.isExtension(new ResourceFile(file))) {
							Msg.showError(this, null, "Installation Error", "Selected file: [" +
								file.getName() + "] is not a valid Ghidra Extension");
							continue;
						}
					}
					catch (ExtensionException e1) {
						Msg.showError(this, null, "Installation Error", "Error determining if [" +
							file.getName() + "] is a valid Ghidra Extension", e1);
						continue;
					}

					if (!hasCorrectVersion(file)) {
						Msg.showError(this, null, "Installation Error", "Extension version for [" +
							file.getName() + "] is incompatible with Ghidra.");
						continue;
					}

					try {
						if (ExtensionUtils.install(new ResourceFile(file))) {
							panel.refreshTable();
							requireRestart = true;
						}
					}
					catch (Exception e) {
						Msg.error(null, "Problem installing extension [" + file.getName() + "]", e);
					}
				}
			}
		};

		String group = "extensionTools";
		addAction.setMenuBarData(new MenuData(new String[] { "Add Extension" }, addIcon, group));
		addAction.setToolBarData(new ToolBarData(addIcon, group));
		addAction.setHelpLocation(new HelpLocation(GenericHelpTopics.FRONT_END, "ExtensionTools"));
		addAction.setDescription(
			SystemUtilities.isInDevelopmentMode() ? "Add Extension (disabled in development mode)"
					: "Add extension");
		addAction.setEnabled(
			!SystemUtilities.isInDevelopmentMode() && !Application.inSingleJarMode());
		addAction(addAction);
	}

	/**
	 * Verifies that the extension(s) represented by the given file (or directory) have
	 * a version that is compatible with the current version of Ghidra.
	 * 
	 * @param file the file or directory to inspect
	 * @return true if the extension(s) has the correct version
	 */
	private boolean hasCorrectVersion(File file) {

		String ghidraVersion = Application.getApplicationVersion();

		// If the given file is a zip...
		if (file.isFile()) {
			try {
				if (ExtensionUtils.isZip(file)) {
					Properties props = ExtensionUtils.getPropertiesFromArchive(file);
					if (props == null) {
						return false;  // no prop file exists
					}
					ExtensionDetails extension =
						ExtensionUtils.createExtensionDetailsFromProperties(props);
					String extVersion = extension.getVersion();
					if (extVersion != null && extVersion.equals(ghidraVersion)) {
						return true;
					}
				}
			}
			catch (ExtensionException e) {
				// just fall through
			}

			return false;
		}

		// If the given file is a directory...
		List<ResourceFile> propFiles =
			ExtensionUtils.findExtensionPropertyFiles(new ResourceFile(file), true);
		for (ResourceFile propFile : propFiles) {
			ExtensionDetails extension =
				ExtensionUtils.createExtensionDetailsFromPropertyFile(propFile);
			String extVersion = extension.getVersion();
			if (extVersion != null && extVersion.equals(ghidraVersion)) {
				return true;
			}
		}

		return false;
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
	 * Filter for a {@link GhidraFileChooser} that restricts selection to those 
	 * files that are Ghidra Extensions (zip files with an extension.properties
	 * file) or folders.
	 */
	private class ExtensionFileFilter implements GhidraFileFilter {
		@Override
		public String getDescription() {
			return "Ghidra Extension";
		}

		@Override
		public boolean accept(File f, GhidraFileChooserModel l_model) {

			try {
				return ExtensionUtils.isExtension(new ResourceFile(f)) || f.isDirectory();
			}
			catch (ExtensionException e) {
				// if something fails to be recognized as an extension, just move on.
			}

			return false;
		}
	}
}
