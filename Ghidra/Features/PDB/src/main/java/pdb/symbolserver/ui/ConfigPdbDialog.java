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
package pdb.symbolserver.ui;

import static pdb.symbolserver.ui.SymbolServerRow.LocationStatus.*;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.OptionDialog;
import docking.widgets.button.BrowseButton;
import docking.widgets.button.GButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import docking.widgets.textfield.HintTextField;
import generic.theme.GThemeDefaults.Colors.Messages;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.*;
import pdb.PdbPlugin;
import pdb.symbolserver.*;
import resources.Icons;
import utilities.util.FileUtilities;

/**
 * Dialog that allows the user to configure the Pdb search locations and symbol directory
 */
public class ConfigPdbDialog extends DialogComponentProvider {

	public static boolean showSymbolServerConfig() {
		ConfigPdbDialog choosePdbDialog = new ConfigPdbDialog();
		DockingWindowManager.showDialog(choosePdbDialog);
		return choosePdbDialog.wasSuccess;
	}

	private static final String MS_SYMBOLSERVER_ENVVAR = "_NT_SYMBOL_PATH";

	private static final Dimension BUTTON_SIZE = new Dimension(32, 32);

	private List<WellKnownSymbolServerLocation> knownSymbolServers =
		WellKnownSymbolServerLocation.loadAll();

	private SymbolStore localSymbolStore;
	private SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext =
		SymbolServerInstanceCreatorRegistry.getInstance().getContext();
	private SymbolServerTableModel tableModel;

	private SymbolServerPanel symbolServerConfigPanel;
	private boolean wasSuccess;
	private boolean configChanged;

	public ConfigPdbDialog() {
		super("Configure Symbol Server Search", true, false, true, true);

		build();

		tableModel.addTableModelListener(e -> updateButtonEnablement());
		setupInitialSymbolServer();
	}

	private void setupInitialSymbolServer() {
		SymbolServerService temporarySymbolServerService =
			PdbPlugin.getSymbolServerService(symbolServerInstanceCreatorContext);
		if (temporarySymbolServerService
				.getSymbolStore() instanceof LocalSymbolStore tempLocalSymbolStore) {
			setSymbolStorageLocation(tempLocalSymbolStore.getRootDir(), false);
			tableModel.addSymbolServers(temporarySymbolServerService.getSymbolServers());
			setConfigChanged(false);
		}
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
		TableColumnInitializer.initializeTableColumns(symbolServerConfigPanel.table, tableModel);
		symbolServerConfigPanel.refreshSymbolServerLocationStatus(true /* only query trusted */);
	}

	private void build() {
		tableModel = new SymbolServerTableModel();

		symbolServerConfigPanel = new SymbolServerPanel();

		addButtons();
		addWorkPanel(symbolServerConfigPanel);
		setRememberSize(false);
		okButton.setEnabled(hasSymbolServer());
	}

	private void updateButtonEnablement() {
		okButton.setEnabled(hasSymbolServer());
		symbolServerConfigPanel.updatePanelButtonEnablement();
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
		symbolServerConfigPanel.addLocation();
	}

	/**
	 * Screen shot usage only
	 * 
	 * @param list fake well known symbol servers
	 */
	public void setWellknownSymbolServers(List<WellKnownSymbolServerLocation> list) {
		knownSymbolServers = list;
	}

	/**
	 * Screen shot only
	 *  
	 * @param fakeDirectoryText fake text to display in the storage directory text field
	 * @param symbolServers list of symbol servers to force set
	 */
	public void setSymbolServerService(String fakeDirectoryText, List<SymbolServer> symbolServers) {
		setSymbolServers(symbolServers);
		setSymbolStorageLocationPath(fakeDirectoryText);
	}

	private void setSymbolStorageLocationPath(String path) {
		symbolServerConfigPanel.symbolStorageLocationTextField.setText(path);
	}

	/**
	 * Returns a new {@link SymbolServerService} instance representing the currently
	 * displayed configuration, or null if the displayed configuration is not valid.
	 *
	 * @return new {@link SymbolServerService} or null
	 */
	SymbolServerService getSymbolServerService() {
		return (localSymbolStore != null)
				? new SymbolServerService(localSymbolStore, tableModel.getSymbolServers())
				: null;
	}

	boolean hasSymbolServer() {
		return localSymbolStore != null;
	}

	void setSymbolServers(List<SymbolServer> symbolServers) {
		tableModel.setSymbolServers(symbolServers);
	}

	private void setSymbolStorageLocation(File symbolStorageDir, boolean allowGUIPrompt) {
		if (symbolStorageDir == null) {
			return;
		}
		if (!symbolStorageDir.exists()) {
			if (!allowGUIPrompt) {
				return;
			}

			int opt =
				OptionDialog.showOptionDialog(rootPanel, "Create Local Symbol Storage Directory?",
					"<html>Symbol storage directory<br>" +
						HTMLUtilities.escapeHTML(symbolStorageDir.getPath()) +
						"<br>does not exist.  Create?",
					"Yes", OptionDialog.QUESTION_MESSAGE);
			if (opt == OptionDialog.CANCEL_OPTION) {
				return;
			}
			try {
				FileUtilities.checkedMkdirs(symbolStorageDir);
			}
			catch (IOException e) {
				Msg.showError(this, rootPanel, "Failure",
					"Failed to create symbol storage directory %s: %s".formatted(symbolStorageDir,
						e.getMessage()));
				return;
			}
		}

		if (allowGUIPrompt && isEmptyDirectory(symbolStorageDir)) {
			if (OptionDialog.showYesNoDialog(rootPanel, "Initialize Symbol Storage Directory?",
				"<html>Initialize new directory as Microsoft symbol storage directory?<br>" +
					"(Answer <b>No</b> to leave as unorganized storage directory)") == OptionDialog.YES_OPTION) {
				try {
					LocalSymbolStore.create(symbolStorageDir,
						1 /* level1 MS symbol storage directory */);
				}
				catch (IOException e) {
					Msg.showError(this, rootPanel, "Initialize Failure",
						"Failed to initialize symbol storage directory " + symbolStorageDir, e);
				}
			}
		}

		localSymbolStore =
			symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
					.newSymbolServer(symbolStorageDir.getPath(), symbolServerInstanceCreatorContext,
						SymbolStore.class);
		setSymbolStorageLocationPath(symbolStorageDir.getPath());
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
		SymbolServerService temporarySymbolServerService = getSymbolServerService();
		if (temporarySymbolServerService != null) {
			PdbPlugin.saveSymbolServerServiceConfig(temporarySymbolServerService);
			Preferences.store();
			setConfigChanged(false);
			updateButtonEnablement();
		}
	}

	//---------------------------------------------------------------------------------------------

	class SymbolServerPanel extends JPanel {

		private GTable table;
		private JPanel additionalSearchLocationsPanel;
		private JPanel defaultConfigNotice;

		private JButton refreshSearchLocationsStatusButton;
		private JButton moveLocationUpButton;
		private JButton moveLocationDownButton;
		private JButton deleteLocationButton;
		private JButton addLocationButton;
		private JPanel symbolStorageLocationPanel;
		private HintTextField symbolStorageLocationTextField;
		private JButton chooseSymbolStorageLocationButton;
		private JButton saveSearchLocationsButton;

		SymbolServerPanel() {
			build();

			DockingWindowManager.getHelpService()
					.registerHelp(this,
						new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC, "Symbol Server Config"));
		}

		private void build() {
			setLayout(new BorderLayout());
			setBorder(BorderFactory.createTitledBorder("Symbol Server Search Config"));

			buildSymbolStorageLocationPanel();
			JPanel tableButtonPanel = buildButtonPanel();
			JScrollPane tableScrollPane = buildTable();
			defaultConfigNotice = new JPanel();
			GHtmlLabel label = new GHtmlLabel("<html><center><font color=\"" +
				Messages.ERROR.toHexString() + "\"><br>Missing / invalid configuration.<br><br>" +
				"Using default search location:<br>Program's Import Location<br>");
			label.setHorizontalAlignment(SwingConstants.CENTER);
			defaultConfigNotice.add(label);
			defaultConfigNotice.setPreferredSize(tableScrollPane.getPreferredSize());

			additionalSearchLocationsPanel = new JPanel();
			additionalSearchLocationsPanel
					.setLayout(new BoxLayout(additionalSearchLocationsPanel, BoxLayout.Y_AXIS));
			additionalSearchLocationsPanel.add(tableButtonPanel);
			additionalSearchLocationsPanel.add(tableScrollPane);

			add(symbolStorageLocationPanel, BorderLayout.NORTH);
			add(additionalSearchLocationsPanel, BorderLayout.CENTER);
		}

		private void updateLayout(boolean showTable) {
			if (showTable == (additionalSearchLocationsPanel.getParent() != null)) {
				return;
			}

			remove(additionalSearchLocationsPanel);
			remove(defaultConfigNotice);
			add(showTable ? additionalSearchLocationsPanel : defaultConfigNotice,
				BorderLayout.CENTER);
			invalidate();
			repaint();
		}

		void refreshSymbolServerLocationStatus(boolean trustedOnly) {
			executeMonitoredRunnable("Refresh Symbol Server Location Status", true, true, 0,
				monitor -> {
					List<SymbolServerRow> rowsCopy = new ArrayList<>(tableModel.getModelData());
					monitor.initialize(rowsCopy.size(), "Refreshing symbol server status");
					try {
						for (SymbolServerRow row : rowsCopy) {
							if (monitor.isCancelled()) {
								break;
							}
							monitor.setMessage("Checking " + row.getSymbolServer().getName());
							monitor.incrementProgress();

							SymbolServer symbolServer = row.getSymbolServer();
							if (symbolServer instanceof SymbolServer.StatusRequiresContext || // we don't have program context here in the config dialog
								(trustedOnly && !symbolServer.isTrusted())) {
								continue;
							}
							row.setStatus(symbolServer.isValid(monitor) ? VALID : INVALID);
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

			refreshSearchLocationsStatusButton = createImageButton(Icons.REFRESH_ICON,
				"Refresh Status", "SymbolServerConfig Refresh Status");
			refreshSearchLocationsStatusButton.addActionListener(
				e -> refreshSymbolServerLocationStatus(false /* query all */));

			moveLocationUpButton =
				createImageButton(Icons.UP_ICON, "Up", "SymbolServerConfig MoveUpDown");
			moveLocationUpButton.addActionListener(e -> moveLocation(-1));
			moveLocationUpButton.setToolTipText("Move location up");

			moveLocationDownButton =
				createImageButton(Icons.DOWN_ICON, "Down", "SymbolServerConfig MoveUpDown");
			moveLocationDownButton.addActionListener(e -> moveLocation(1));
			moveLocationDownButton.setToolTipText("Move location down");

			deleteLocationButton =
				createImageButton(Icons.DELETE_ICON, "Delete", "SymbolServerConfig Delete");
			deleteLocationButton.addActionListener(e -> deleteLocation());

			addLocationButton = createImageButton(Icons.ADD_ICON, "Add", "SymbolServerConfig Add");
			addLocationButton.addActionListener(e -> addLocation());

			saveSearchLocationsButton =
				createImageButton(Icons.SAVE_ICON, "Save Configuration", "SymbolServerConfig Save");
			saveSearchLocationsButton.addActionListener(e -> saveConfig());

			JPanel tableButtonPanel = new JPanel();
			tableButtonPanel.setLayout(new BoxLayout(tableButtonPanel, BoxLayout.X_AXIS));
			tableButtonPanel.add(new GLabel("Additional Search Paths:"));
			tableButtonPanel.add(Box.createHorizontalGlue());
			tableButtonPanel.add(addLocationButton);
			tableButtonPanel.add(deleteLocationButton);
			tableButtonPanel.add(moveLocationUpButton);
			tableButtonPanel.add(moveLocationDownButton);
			tableButtonPanel.add(refreshSearchLocationsStatusButton);
			tableButtonPanel.add(saveSearchLocationsButton);

			return tableButtonPanel;
		}

		private JPanel buildSymbolStorageLocationPanel() {
			symbolStorageLocationTextField = new HintTextField(" Required ");
			symbolStorageLocationTextField.setEditable(false);
			symbolStorageLocationTextField.setToolTipText(
				"User-specified directory where PDB files are stored.  Required.");

			chooseSymbolStorageLocationButton = new BrowseButton();
			chooseSymbolStorageLocationButton.addActionListener(e -> chooseSymbolStorageLocation());

			symbolStorageLocationPanel = new JPanel(new PairLayout(5, 5));
			GLabel symbolStorageLocLabel =
				new GLabel("Local Symbol Storage:", SwingConstants.RIGHT);
			symbolStorageLocLabel.setToolTipText(symbolStorageLocationTextField.getToolTipText());

			symbolStorageLocationPanel.add(symbolStorageLocLabel);
			symbolStorageLocationPanel.add(LoadPdbDialog.join(null, symbolStorageLocationTextField,
				chooseSymbolStorageLocationButton));
			return symbolStorageLocationPanel;
		}

		private void updatePanelButtonEnablement() {
			boolean hasLocalSymbolStore = localSymbolStore != null;
			boolean singleRow = table.getSelectedRowCount() == 1;
			boolean moreThanOneRow = table.getRowCount() > 1;

			refreshSearchLocationsStatusButton
					.setEnabled(hasLocalSymbolStore && !tableModel.isEmpty());
			moveLocationUpButton.setEnabled(hasLocalSymbolStore && singleRow && moreThanOneRow);
			moveLocationDownButton.setEnabled(hasLocalSymbolStore && singleRow && moreThanOneRow);
			addLocationButton.setEnabled(hasLocalSymbolStore);
			deleteLocationButton.setEnabled(hasLocalSymbolStore && table.getSelectedRowCount() > 0);
			saveSearchLocationsButton.setEnabled(hasLocalSymbolStore && isConfigChanged());
			updateLayout(hasLocalSymbolStore);
		}

		private void chooseSymbolStorageLocation() {
			GhidraFileChooser chooser = getChooser();
			File f = chooser.getSelectedFile();
			chooser.dispose();

			if (f != null) {
				configChanged = true;
				setSymbolStorageLocation(f, true);
				updateButtonEnablement();
			}
		}

		private void importLocations() {
			String envVar = (String) JOptionPane.showInputDialog(this,
				"<html>Enter value:<br><br>Example: SVR*c:\\symbols*https://msdl.microsoft.com/download/symbols/<br><br>",
				"Enter Symbol Server Search Path Value", JOptionPane.QUESTION_MESSAGE, null, null,
				Objects.requireNonNullElse(System.getenv(MS_SYMBOLSERVER_ENVVAR), ""));
			if (envVar == null) {
				return;
			}

			List<String> symbolServerPaths = getSymbolPathsFromEnvStr(envVar);
			if (!symbolServerPaths.isEmpty()) {
				// if the first item in the path list looks like a local symbol storage path,
				// allow the user to set it as the storage dir (and remove it from the elements
				// that will be added to the search list)
				String firstSearchPath = symbolServerPaths.get(0);
				SymbolServer symbolServer =
					symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
							.newSymbolServer(firstSearchPath, symbolServerInstanceCreatorContext);
				if (symbolServer instanceof LocalSymbolStore localSymbolStore &&
					localSymbolStore.isValid()) {
					int choice =
						OptionDialog.showYesNoCancelDialog(this, "Set Symbol Storage Location",
							"Set symbol storage location to " + firstSearchPath + "?");
					if (choice == OptionDialog.CANCEL_OPTION) {
						return;
					}
					if (choice == OptionDialog.YES_OPTION) {
						symbolServerPaths.remove(0);
						configChanged = true;
						setSymbolStorageLocation(localSymbolStore.getRootDir(), true);
					}
				}
			}

			tableModel.addSymbolServers(
				symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
						.createSymbolServersFromPathList(symbolServerPaths,
							symbolServerInstanceCreatorContext));
			updateButtonEnablement();
		}

		private void addLocation() {
			JPopupMenu menu = createAddLocationPopupMenu();
			menu.show(addLocationButton, 0, 0);
		}

		private JPopupMenu createAddLocationPopupMenu() {
			JPopupMenu menu = new JPopupMenu();
			JMenuItem addDirMenuItem = new JMenuItem("Directory");
			addDirMenuItem.addActionListener(e -> addDirectoryLocation());
			menu.add(addDirMenuItem);

			JMenuItem addURLMenuItem = new JMenuItem("URL");
			addURLMenuItem.addActionListener(e -> addUrlLocation());
			menu.add(addURLMenuItem);

			JMenuItem addProgLocMenuItem =
				new JMenuItem(SameDirSymbolStore.PROGRAMS_IMPORT_LOCATION_DESCRIPTION_STR);
			addProgLocMenuItem.addActionListener(e -> addSameDirLocation());
			menu.add(addProgLocMenuItem);

			JMenuItem importEnvMenuItem = new JMenuItem("Import _NT_SYMBOL_PATH");
			importEnvMenuItem.addActionListener(e -> importLocations());
			menu.add(importEnvMenuItem);

			if (!knownSymbolServers.isEmpty()) {
				menu.add(new JSeparator());
				for (WellKnownSymbolServerLocation ssloc : knownSymbolServers) {
					JMenuItem mi = new JMenuItem(ssloc.location());
					mi.addActionListener(e -> addKnownLocation(ssloc));
					mi.setToolTipText(" [from " + ssloc.fileOrigin() + "]");
					menu.add(mi);
				}
			}
			DockingWindowManager.getHelpService()
					.registerHelp(menu, new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"SymbolServerConfig_Add"));
			return menu;
		}

		private void addSameDirLocation() {
			SameDirSymbolStore sameDirSymbolStore =
				new SameDirSymbolStore(symbolServerInstanceCreatorContext.getRootDir());
			tableModel.addSymbolServer(sameDirSymbolStore);
		}

		private void addKnownLocation(WellKnownSymbolServerLocation ssloc) {
			SymbolServer symbolServer =
				symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
						.newSymbolServer(ssloc.location(), symbolServerInstanceCreatorContext);
			if (symbolServer != null) {
				tableModel.addSymbolServer(symbolServer);
			}
		}

		private void addUrlLocation() {
			String urlLocationString = OptionDialog.showInputSingleLineDialog(this, "Enter URL",
				"Enter the URL of a Symbol Server: ", "https://");
			if (urlLocationString == null || urlLocationString.isBlank()) {
				return;
			}
			urlLocationString = urlLocationString.toLowerCase();
			if (!(urlLocationString.startsWith("http://") ||
				urlLocationString.startsWith("https://"))) {
				Msg.showWarn(this, this, "Bad URL", "Invalid URL: " + urlLocationString);
				return;
			}
			try {
				HttpSymbolServer httpSymbolServer =
					HttpSymbolServer.createUntrusted(urlLocationString);
				tableModel.addSymbolServer(httpSymbolServer);
			}
			catch (IllegalArgumentException e) {
				Msg.showWarn(this, this, "Bad URL", "Invalid URL: " + urlLocationString);
			}
		}

		private void addDirectoryLocation() {
			File dir =
				FilePromptDialog.chooseDirectory("Enter Path", "Symbol Storage Location: ", null);
			if (dir == null) {
				return;
			}
			if (!dir.exists() || !dir.isDirectory()) {
				Msg.showError(this, this, "Bad path", "Invalid path: " + dir);
				return;
			}
			LocalSymbolStore symbolStore = new LocalSymbolStore(dir);
			tableModel.addSymbolServer(symbolStore);
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

		private GhidraFileChooser getChooser() {

			GhidraFileChooser chooser = new GhidraFileChooser(this);
			chooser.setMultiSelectionEnabled(false);
			chooser.setApproveButtonText("Choose");
			chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			chooser.setTitle("Select Symbol Storage Dir");

			return chooser;
		}

	}

	//---------------------------------------------------------------------------------------------

	private static JButton createImageButton(Icon buttonIcon, String alternateText,
			String helpLoc) {

		JButton button = new GButton(buttonIcon);
		button.setToolTipText(alternateText);
		button.setPreferredSize(BUTTON_SIZE);

		DockingWindowManager.getHelpService()
				.registerHelp(button, new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC, helpLoc));

		return button;
	}

	/**
	 * Returns true if the given file path is a directory that contains no files.
	 *
	 * @param directory path to a location on the file system
	 * @return true if is a directory and it contains no files
	 */
	private static boolean isEmptyDirectory(File directory) {
		if (directory.isDirectory()) {
			File[] dirContents = directory.listFiles();
			return dirContents != null && dirContents.length == 0;
		}
		return false;
	}

	private static List<String> getSymbolPathsFromEnvStr(String envString) {
		// Expect the environment string to be in the MS symbol server search path form:
		//    srv*[local cache]*[private symbol server]*https://msdl.microsoft.com/download/symbols
		//    srv*c:\symbols*https://msdl.microsoft.com/download/symbols;srv*c:\additional*https://symbol.server.tld/
		String[] envParts = envString.split("[*;]");
		List<String> results = new ArrayList<>();
		Set<String> locationStringDeduplicationSet = new HashSet<>();
		for (String envPart : envParts) {
			String locationString = envPart.trim();
			if (!locationString.isBlank() && !locationString.equalsIgnoreCase("srv") &&
				!locationStringDeduplicationSet.contains(locationString)) {
				results.add(locationString);
				locationStringDeduplicationSet.add(locationString);
			}
		}

		return results;
	}

}
