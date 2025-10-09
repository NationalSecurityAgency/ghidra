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
package ghidra.app.util.bin.format.dwarf.external.gui;

import java.awt.*;
import java.io.File;
import java.net.URI;
import java.util.*;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.button.BrowseButton;
import docking.widgets.button.GButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import docking.widgets.textfield.HintTextField;
import generic.theme.GIcon;
import ghidra.app.util.bin.format.dwarf.external.*;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.ThreeColumnLayout;
import ghidra.util.task.*;
import resources.Icons;

public class ExternalDebugFilesConfigDialog extends DialogComponentProvider {

	public static boolean show() {
		ExternalDebugFilesConfigDialog dlg = new ExternalDebugFilesConfigDialog();
		DockingWindowManager.showDialog(dlg);
		return dlg.wasSuccess;
	}

	private static final Dimension BUTTON_SIZE = new Dimension(32, 32);

	private List<WellKnownDebugProvider> knownProviders =
		WellKnownDebugProvider.loadAll(".debuginfod_urls");

	private DebugInfoProviderCreatorContext creatorContext =
		DebugInfoProviderRegistry.getInstance().newContext(null);
	private DebugFileStorage storage;

	private ExternalDebugInfoProviderTableModel tableModel;

	private ExternalDebugFileProvidersPanel configPanel;
	private boolean wasSuccess;
	private boolean configChanged;

	public ExternalDebugFilesConfigDialog() {
		super("DWARF External Debug Files Configuration", true, false, true, true);

		build();

		tableModel.addTableModelListener(e -> updateButtonEnablement());
		setupInitialConfig();
	}

	private void setupInitialConfig() {
		ExternalDebugFilesService tmpService = ExternalDebugFilesService.fromPrefs(creatorContext);
		DebugFileStorage newStorage = tmpService.getStorage();
		setStorageLocation(newStorage);
		tableModel.addItems(tmpService.getProviders());
		setConfigChanged(false);
	}

	@Override
	protected void cancelCallback() {
		close();
	}

	@Override
	protected void okCallback() {
		if (isConfigChanged()) {
			saveConfig();
		}
		wasSuccess = true;
		close();
	}

	@Override
	protected void dialogShown() {
		TableColumnInitializer.initializeTableColumns(configPanel.table, tableModel);
		configPanel.refreshStatus();
	}

	private void build() {
		tableModel = new ExternalDebugInfoProviderTableModel();

		configPanel = new ExternalDebugFileProvidersPanel();

		addButtons();
		addWorkPanel(configPanel);

		setHelpLocation(
			new HelpLocation(DWARFExternalDebugFilesPlugin.HELP_TOPIC, "Configuration"));

		setRememberSize(false);
		okButton.setEnabled(true);
	}

	private void updateButtonEnablement() {
		okButton.setEnabled(true);
		configPanel.updatePanelButtonEnablement();
	}

	private void addButtons() {
		addOKButton();
		addCancelButton();
		setDefaultButton(cancelButton);
	}

	/**
	 * Screen shot usage only
	 */
	public void pushAddLocationButton() {
		configPanel.addLocation();
	}

	/**
	 * Screen shot usage only
	 * 
	 * @param list fake well known debug provider servers
	 */
	public void setWellknownProviders(List<WellKnownDebugProvider> list) {
		knownProviders = list;
	}

	/**
	 * Screen shot only
	 */
	public void setService(ExternalDebugFilesService edfs) {
		setProviders(edfs.getProviders());
		setStorageLocation(edfs.getStorage());
	}

	private void setStorageLocationPath(String path) {
		configPanel.storageLocationTextField.setText(path);
	}

	/**
	 * Returns a new {@link ExternalDebugFilesService} instance representing the currently
	 * displayed configuration, or null if the displayed configuration is not valid.
	 *
	 * @return new {@link ExternalDebugFilesService} or null
	 */
	ExternalDebugFilesService getService() {
		return new ExternalDebugFilesService(storage, tableModel.getItems());
	}

	void setProviders(List<DebugInfoProvider> providers) {
		tableModel.setItems(providers);
	}

	private void setStorageLocation(DebugFileStorage newStorage) {
		storage = newStorage;
		setStorageLocationPath(newStorage.getDescriptiveName());
		updateButtonEnablement();
	}

	void executeMonitoredRunnable(String taskTitle, boolean canCancel, boolean hasProgress,
			int delay, MonitoredRunnable runnable) {
		Task task = new Task(taskTitle, canCancel, hasProgress, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				runnable.monitoredRun(monitor);
			}
		};
		executeProgressTask(task, delay);
	}

	/**
	 * The union of the changed status of the local storage path and the additional
	 * search paths table model changed status.
	 *
	 * @return boolean true if the config has changed
	 */
	boolean isConfigChanged() {
		return configChanged || tableModel.isDataChanged();
	}

	void setConfigChanged(boolean configChanged) {
		this.configChanged = configChanged;
		tableModel.setDataChanged(configChanged);
	}

	/* package */ void saveConfig() {
		ExternalDebugFilesService tmpService = getService();
		ExternalDebugFilesService.saveToPrefs(tmpService);
		Preferences.store();
		setConfigChanged(false);
		updateButtonEnablement();
	}

	private void registerHelp(Component comp, String anchorName) {
		DockingWindowManager.getHelpService()
				.registerHelp(comp,
					new HelpLocation(DWARFExternalDebugFilesPlugin.HELP_TOPIC, anchorName));
	}

	//---------------------------------------------------------------------------------------------

	class ExternalDebugFileProvidersPanel extends JPanel {

		private GTable table;
		private JPanel additionalSearchLocationsPanel;

		private JButton refreshSearchLocationsStatusButton;
		private JButton moveLocationUpButton;
		private JButton moveLocationDownButton;
		private JButton deleteLocationButton;
		private JButton addLocationButton;
		private JPanel storageLocationPanel;
		private HintTextField storageLocationTextField;
		private JButton saveSearchLocationsButton;

		ExternalDebugFileProvidersPanel() {
			super(new BorderLayout());
			build();
			registerHelp(this, "Summary");
		}

		private void build() {
			setBorder(BorderFactory.createTitledBorder("External Debug Files Config"));

			buildLocationPanel();
			JPanel tableButtonPanel = buildButtonPanel();
			JScrollPane tableScrollPane = buildTable();

			additionalSearchLocationsPanel = new JPanel();
			additionalSearchLocationsPanel
					.setLayout(new BoxLayout(additionalSearchLocationsPanel, BoxLayout.Y_AXIS));
			additionalSearchLocationsPanel.add(tableButtonPanel);
			additionalSearchLocationsPanel.add(tableScrollPane);

			add(storageLocationPanel, BorderLayout.NORTH);
			add(additionalSearchLocationsPanel, BorderLayout.CENTER);
		}

		void refreshStatus() {
			executeMonitoredRunnable("Refresh Provider Status", true, true, 0, monitor -> {
				List<ExternalDebugInfoProviderTableRow> rowsCopy =
					new ArrayList<>(tableModel.getModelData());
				monitor.initialize(rowsCopy.size(), "Refreshing provider status");
				try {
					for (ExternalDebugInfoProviderTableRow row : rowsCopy) {
						if (monitor.isCancelled()) {
							break;
						}
						monitor.setMessage("Checking " + row.getItem().getName());
						monitor.incrementProgress();

						DebugInfoProvider provider = row.getItem();
						row.setStatus(provider.getStatus(monitor));
					}
				}
				finally {
					Swing.runLater(() -> tableModel.fireTableDataChanged());
				}
			});
		}

		private JScrollPane buildTable() {
			table = new GTable(tableModel);
			table.setVisibleRowCount(4);
			table.setUserSortingEnabled(false);
			table.getSelectionManager()
					.addListSelectionListener(e -> updatePanelButtonEnablement());

			table.setPreferredScrollableViewportSize(new Dimension(500, 100));

			return new JScrollPane(table);
		}

		private JPanel buildButtonPanel() {
			refreshSearchLocationsStatusButton =
				createImageButton(Icons.REFRESH_ICON, "Refresh Status", "ButtonActions");
			refreshSearchLocationsStatusButton.addActionListener(e -> refreshStatus());

			moveLocationUpButton = createImageButton(Icons.UP_ICON, "Up", "ButtonActions");
			moveLocationUpButton.addActionListener(e -> moveLocation(-1));
			moveLocationUpButton.setToolTipText("Move location up");

			moveLocationDownButton = createImageButton(Icons.DOWN_ICON, "Down", "ButtonActions");
			moveLocationDownButton.addActionListener(e -> moveLocation(1));
			moveLocationDownButton.setToolTipText("Move location down");

			deleteLocationButton = createImageButton(Icons.DELETE_ICON, "Delete", "ButtonActions");
			deleteLocationButton.addActionListener(e -> deleteLocation());

			addLocationButton = createImageButton(Icons.ADD_ICON, "Add", "ButtonActions");
			addLocationButton.addActionListener(e -> addLocation());

			saveSearchLocationsButton =
				createImageButton(Icons.SAVE_ICON, "Save Configuration", "ButtonActions");
			saveSearchLocationsButton.addActionListener(e -> saveConfig());

			JPanel tableButtonPanel = new JPanel();
			tableButtonPanel.setLayout(new BoxLayout(tableButtonPanel, BoxLayout.X_AXIS));
			tableButtonPanel.add(new GLabel("Additional Locations:"));
			tableButtonPanel.add(Box.createHorizontalGlue());
			tableButtonPanel.add(addLocationButton);
			tableButtonPanel.add(deleteLocationButton);
			tableButtonPanel.add(moveLocationUpButton);
			tableButtonPanel.add(moveLocationDownButton);
			tableButtonPanel.add(refreshSearchLocationsStatusButton);
			tableButtonPanel.add(saveSearchLocationsButton);

			return tableButtonPanel;
		}

		private JPanel buildLocationPanel() {
			storageLocationTextField = new HintTextField(" Required ");
			storageLocationTextField.setEditable(false);
			storageLocationTextField.setFocusable(false);
			storageLocationTextField.setToolTipText(
				"User-specified directory where debug files are stored.  Required.");

			JButton chooseStorageLocationButton = new BrowseButton();
			chooseStorageLocationButton.addActionListener(e -> chooseStorageLocation());
			registerHelp(chooseStorageLocationButton, "LocalStorage");

			File ghidraCacheDir =
				LocalDirDebugInfoDProvider.getGhidraCacheInstance().getDirectory();

			JButton chooseGhidraCacheLocationButton =
				createImageButton(new GIcon("icon.base.application.home"),
					"Use private Ghidra cache location\n" + ghidraCacheDir, "LocalStorage");
			chooseGhidraCacheLocationButton.addActionListener(e -> chooseGhidraCacheLocation());

			JPanel storageButtonPanel = new JPanel();
			storageButtonPanel.setLayout(new BoxLayout(storageButtonPanel, BoxLayout.X_AXIS));
			storageButtonPanel.add(chooseStorageLocationButton, BorderLayout.CENTER);
			storageButtonPanel.add(chooseGhidraCacheLocationButton);

			GLabel storageLocLabel = new GLabel("Local Storage:", SwingConstants.RIGHT);
			storageLocLabel.setToolTipText(storageLocationTextField.getToolTipText());

			storageLocationPanel = new JPanel(new ThreeColumnLayout(5, 5, 5));
			storageLocationPanel.add(storageLocLabel);
			storageLocationPanel.add(storageLocationTextField);
			storageLocationPanel.add(storageButtonPanel);
			return storageLocationPanel;
		}

		private void updatePanelButtonEnablement() {
			boolean singleRow = table.getSelectedRowCount() == 1;
			boolean moreThanOneRow = table.getRowCount() > 1;

			refreshSearchLocationsStatusButton.setEnabled(!tableModel.isEmpty());
			moveLocationUpButton.setEnabled(singleRow && moreThanOneRow);
			moveLocationDownButton.setEnabled(singleRow && moreThanOneRow);
			addLocationButton.setEnabled(true);
			deleteLocationButton.setEnabled(table.getSelectedRowCount() > 0);
			saveSearchLocationsButton.setEnabled(isConfigChanged());
		}

		private void chooseStorageLocation() {
			GhidraFileChooser chooser = getChooser("Choose Debug File Storage Directory");
			File f = chooser.getSelectedFile();
			chooser.dispose();

			if (f != null) {
				configChanged = true;
				setStorageLocation(new LocalDirDebugInfoDProvider(f));
				updateButtonEnablement();
			}
		}

		private void chooseGhidraCacheLocation() {
			configChanged = true;
			setStorageLocation(LocalDirDebugInfoDProvider.getGhidraCacheInstance());
			updateButtonEnablement();
		}

		private void importLocations() {
			String envVar = (String) JOptionPane.showInputDialog(this, """
					<html>Enter value:<br>
					<br>
					Example: https://debuginfod.domain1.org https://debuginfod.domain2.org<br>
					<br>""", "Enter DEBUGINFOD_URLS Value", JOptionPane.QUESTION_MESSAGE, null,
				null, Objects.requireNonNullElse(System.getenv("DEBUGINFOD_URLS"), ""));
			if (envVar == null) {
				return;
			}

			List<String> urls = getURLsFromEnvStr(envVar);
			urls.forEach(
				s -> tableModel.addItem(creatorContext.registry().create(s, creatorContext)));
			updateButtonEnablement();
		}

		private void addLocation() {
			JPopupMenu menu = createAddLocationPopupMenu();
			menu.show(addLocationButton, 0, 0);
		}

		private JPopupMenu createAddLocationPopupMenu() {
			JPopupMenu menu = new JPopupMenu();
			registerHelp(menu, "LocationTypes");

			JMenuItem addProgLocMenuItem = new JMenuItem(SameDirDebugInfoProvider.DESC);
			addProgLocMenuItem.addActionListener(e -> addSameDirLocation());
			addProgLocMenuItem
					.setToolTipText("Directory that the program was originally imported from.");
			menu.add(addProgLocMenuItem);

			JMenuItem addBuildIdDirMenuItem = new JMenuItem("Build-id Directory");
			addBuildIdDirMenuItem.addActionListener(e -> addBuildIdDirLocation());
			addBuildIdDirMenuItem.setToolTipText(
				"Directory where debug files that are identified by a build-id hash are stored.\n" +
					"Debug files are named AA/BBCCDD...ZZ.debug under the base directory\n" +
					"This storage scheme for build-id debug files is distinct from debuginfod's scheme.\n\n" +
					"e.g. /usr/lib/debug/.build-id");
			menu.add(addBuildIdDirMenuItem);

			JMenuItem addDebugLinkDirMenuItem = new JMenuItem("Debug Link Directory");
			addDebugLinkDirMenuItem.addActionListener(e -> addDebugLinkDirLocation());
			addDebugLinkDirMenuItem
					.setToolTipText("Directory where debug files that are identified\n" +
						"by a debug filename and crc hash\n" +
						"(found in the binary's .gnu_debuglink section).\n\n" +
						"NOTE: This directory is searched recursively for a matching file.");
			menu.add(addDebugLinkDirMenuItem);

			JMenuItem addDebugInfoDDirMenuItem = new JMenuItem("Debuginfod Directory");
			addDebugInfoDDirMenuItem.addActionListener(e -> addDebugInfoDDirLocation());
			addDebugInfoDDirMenuItem.setToolTipText("Directory where debuginfod has stored files.");
			menu.add(addDebugInfoDDirMenuItem);

			JMenuItem addURLMenuItem = new JMenuItem("Debuginfod URL");
			addURLMenuItem.addActionListener(e -> addUrlLocation());
			addURLMenuItem.setToolTipText("HTTP(s) URL that points to a debuginfod server.");
			menu.add(addURLMenuItem);

			JMenuItem importEnvMenuItem = new JMenuItem("Import DEBUGINFOD_URLS Env Var");
			importEnvMenuItem.addActionListener(e -> importLocations());
			importEnvMenuItem.setToolTipText(
				"Adds debuginfod URLs found in the system environment variable.");
			menu.add(importEnvMenuItem);

			if (!knownProviders.isEmpty()) {
				menu.add(new JSeparator());
				for (WellKnownDebugProvider provider : knownProviders) {
					JMenuItem mi = new JMenuItem(provider.location());
					mi.addActionListener(e -> addKnownLocation(provider));
					mi.setToolTipText("Debuginfod URL [from " + provider.fileOrigin() + "]");
					menu.add(mi);
				}
			}
			return menu;
		}

		private void addSameDirLocation() {
			SameDirDebugInfoProvider provider = new SameDirDebugInfoProvider(null);
			tableModel.addItem(provider);
		}

		private void addKnownLocation(WellKnownDebugProvider providerInfo) {
			DebugInfoProvider newProvider =
				creatorContext.registry().create(providerInfo.location(), creatorContext);
			if (newProvider != null) {
				tableModel.addItem(newProvider);
			}
		}

		private void addUrlLocation() {
			String urlStr = OptionDialog.showInputSingleLineDialog(this, "Enter URL",
				"Enter the URL of a Debuginfod Server: ", "https://");
			if (urlStr == null || urlStr.isBlank() || urlStr.equals("https://")) {
				return;
			}
			try {
				urlStr = urlStr.toLowerCase();
				if (urlStr.startsWith("http://") || urlStr.startsWith("https://")) {
					HttpDebugInfoDProvider newProvider =
						new HttpDebugInfoDProvider(URI.create(urlStr));
					tableModel.addItem(newProvider);
					return; // success
				}
			}
			catch (IllegalArgumentException e) {
				// fall thru
			}
			Msg.showWarn(this, this, "Bad URL", "Invalid URL: " + urlStr);
		}

		private void addBuildIdDirLocation() {
			File dir =
				FilePromptDialog.chooseDirectory("Enter Path", "Build-Id Root Directory: ", null);
			if (dir == null) {
				return;
			}
			if (!dir.exists() || !dir.isDirectory()) {
				Msg.showError(this, this, "Bad path", "Invalid path: " + dir);
				return;
			}
			BuildIdDebugFileProvider provider = new BuildIdDebugFileProvider(dir);
			tableModel.addItem(provider);
		}

		private void addDebugLinkDirLocation() {
			File dir =
				FilePromptDialog.chooseDirectory("Enter Path", "Debug-Link Root Directory: ", null);
			if (dir == null) {
				return;
			}
			if (!dir.exists() || !dir.isDirectory()) {
				Msg.showError(this, this, "Bad path", "Invalid path: " + dir);
				return;
			}
			LocalDirDebugLinkProvider provider = new LocalDirDebugLinkProvider(dir);
			tableModel.addItem(provider);
		}

		private void addDebugInfoDDirLocation() {
			File dir = FilePromptDialog.chooseDirectory("Enter Path",
				"Debuginfod Cache Directory: ", null);
			if (dir == null) {
				return;
			}
			if (!dir.exists() || !dir.isDirectory()) {
				Msg.showError(this, this, "Bad path", "Invalid path: " + dir);
				return;
			}
			LocalDirDebugInfoDProvider provider = new LocalDirDebugInfoDProvider(dir);
			tableModel.addItem(provider);
		}

		private void deleteLocation() {
			int selectedRow = table.getSelectedRow();
			tableModel.deleteRows(table.getSelectedRows());
			if (selectedRow >= 0 && selectedRow < table.getRowCount()) {
				table.selectRow(selectedRow);
			}
		}

		private void moveLocation(int delta) {
			if (table.getSelectedRowCount() == 1) {
				tableModel.moveRow(table.getSelectedRow(), delta);
			}
		}

		private GhidraFileChooser getChooser(String title) {

			GhidraFileChooser chooser = new GhidraFileChooser(this);
			chooser.setMultiSelectionEnabled(false);
			chooser.setApproveButtonText("Choose");
			chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			chooser.setTitle(title);

			return chooser;
		}

	}

	//---------------------------------------------------------------------------------------------

	private JButton createImageButton(Icon buttonIcon, String alternateText, String helpLoc) {

		JButton button = new GButton(buttonIcon);
		button.setToolTipText(alternateText);
		button.setPreferredSize(BUTTON_SIZE);
		registerHelp(button, helpLoc);

		return button;
	}

	private static List<String> getURLsFromEnvStr(String envString) {
		String[] envParts = envString.split("[ ;]");
		List<String> results = new ArrayList<>();
		Set<String> dedup = new HashSet<>();
		for (String envPart : envParts) {
			String s = envPart.trim();
			if (!s.isBlank() && dedup.add(s)) {
				results.add(s);
			}
		}

		return results;
	}

}
