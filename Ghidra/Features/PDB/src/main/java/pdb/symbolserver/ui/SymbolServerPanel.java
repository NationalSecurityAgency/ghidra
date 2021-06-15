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

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import javax.swing.*;
import javax.swing.table.TableColumn;

import docking.DockingWindowManager;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.OptionDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GHtmlLabel;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import docking.widgets.textfield.HintTextField;
import ghidra.framework.preferences.Preferences;
import ghidra.util.*;
import ghidra.util.layout.PairLayout;
import pdb.PdbPlugin;
import pdb.symbolserver.*;
import pdb.symbolserver.ui.LoadPdbDialog.StatusText;
import resources.Icons;
import utilities.util.FileUtilities;

/**
 * Panel that allows the user to configure a SymbolServerService: a local 
 * symbol storage directory and a list of search locations.
 */
class SymbolServerPanel extends JPanel {
	private static final String MS_SYMBOLSERVER_ENVVAR = "_NT_SYMBOL_PATH";

	private static List<WellKnownSymbolServerLocation> knownSymbolServers =
		WellKnownSymbolServerLocation.loadAll();

	private SymbolStore localSymbolStore;
	private SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext;

	private SymbolServerTableModel tableModel;
	private GTable table;
	private JPanel additionalSearchLocationsPanel;
	private JPanel defaultConfigNotice;
	private GhidraFileChooser chooser;
	private Consumer<SymbolServerService> changeCallback;

	private JButton refreshSearchLocationsStatusButton;
	private JButton moveLocationUpButton;
	private JButton moveLocationDownButton;
	private JButton deleteLocationButton;
	private JButton addLocationButton;
	private JPanel symbolStorageLocationPanel;
	private HintTextField symbolStorageLocationTextField;
	private JButton chooseSymbolStorageLocationButton;
	private JButton saveSearchLocationsButton;
	private boolean configChanged;

	SymbolServerPanel(Consumer<SymbolServerService> changeCallback,
			SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext) {
		this.symbolServerInstanceCreatorContext = symbolServerInstanceCreatorContext;

		build();

		DockingWindowManager.getHelpService()
				.registerHelp(this,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC, "Symbol Server Config"));

		SymbolServerService temporarySymbolServerService =
			PdbPlugin.getSymbolServerService(symbolServerInstanceCreatorContext);
		if (temporarySymbolServerService.getSymbolStore() instanceof LocalSymbolStore) {
			setSymbolStorageLocation(
				((LocalSymbolStore) temporarySymbolServerService.getSymbolStore()).getRootDir(),
				false);
		}
		tableModel.addSymbolServers(temporarySymbolServerService.getSymbolServers());
		setConfigChanged(false);

		this.changeCallback = changeCallback;
	}

	private void build() {
		setLayout(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder("Symbol Server Search Config"));

		buildSymbolStorageLocationPanel();
		JPanel buttonPanel = buildButtonPanel();
		JScrollPane tableScrollPane = buildTable();
		defaultConfigNotice = new JPanel();
		defaultConfigNotice.add(
			new GHtmlLabel(
				"<html><center><font color=red><br>" +
					"Missing / invalid configuration.<br><br>" +
					"Using default search location:<br>" +
					"Program's Import Location<br>",
				SwingConstants.CENTER));
		defaultConfigNotice.setPreferredSize(tableScrollPane.getPreferredSize());

		additionalSearchLocationsPanel = new JPanel();
		additionalSearchLocationsPanel
				.setLayout(new BoxLayout(additionalSearchLocationsPanel, BoxLayout.Y_AXIS));
		additionalSearchLocationsPanel.add(buttonPanel);
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
		add(showTable ? additionalSearchLocationsPanel : defaultConfigNotice, BorderLayout.CENTER);
		invalidate();
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

	void setSymbolServers(List<SymbolServer> symbolServers) {
		tableModel.setSymbolServers(symbolServers);
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

	private JScrollPane buildTable() {
		tableModel = new SymbolServerTableModel();
		table = new GTable(tableModel);
		table.setVisibleRowCount(4);
		table.setUserSortingEnabled(false);
		table.getSelectionManager().addListSelectionListener(e -> {
			updateButtonEnablement();
		});
		tableModel.addTableModelListener(e -> {
			updateButtonEnablement();
			fireChanged();
		});

		TableColumn enabledColumn = table.getColumnModel().getColumn(0);
		enabledColumn.setResizable(false);
		enabledColumn.setPreferredWidth(32);
		enabledColumn.setMaxWidth(32);
		enabledColumn.setMinWidth(32);

		TableColumn statusColumn = table.getColumnModel().getColumn(1);
		statusColumn.setResizable(false);
		statusColumn.setPreferredWidth(32);
		statusColumn.setMaxWidth(32);
		statusColumn.setMinWidth(32);

		table.setPreferredScrollableViewportSize(new Dimension(100, 100));

		return new JScrollPane(table);
	}

	private JPanel buildButtonPanel() {
		refreshSearchLocationsStatusButton = createImageButton(Icons.REFRESH_ICON, "Refresh Status",
				ButtonPanelFactory.ARROW_SIZE);
		refreshSearchLocationsStatusButton.addActionListener(e -> refreshSearchLocationStatus());
		DockingWindowManager.getHelpService()
				.registerHelp(refreshSearchLocationsStatusButton,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"SymbolServerConfig Refresh Status"));

		moveLocationUpButton = ButtonPanelFactory.createButton(ButtonPanelFactory.ARROW_UP_TYPE);
		moveLocationUpButton.addActionListener(e -> moveLocation(-1));
		moveLocationUpButton.setToolTipText("Move location up");
		DockingWindowManager.getHelpService()
				.registerHelp(moveLocationUpButton,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"SymbolServerConfig MoveUpDown"));

		moveLocationDownButton =
			ButtonPanelFactory.createButton(ButtonPanelFactory.ARROW_DOWN_TYPE);
		moveLocationDownButton.addActionListener(e -> moveLocation(1));
		moveLocationDownButton.setToolTipText("Move location down");
		DockingWindowManager.getHelpService()
				.registerHelp(moveLocationDownButton,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"SymbolServerConfig MoveUpDown"));

		deleteLocationButton = createImageButton(Icons.DELETE_ICON, "Delete",
			ButtonPanelFactory.ARROW_SIZE);
		deleteLocationButton.addActionListener(e -> deleteLocation());
		DockingWindowManager.getHelpService()
				.registerHelp(deleteLocationButton,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"SymbolServerConfig Delete"));

		addLocationButton = createImageButton(Icons.ADD_ICON, "Add",
			ButtonPanelFactory.ARROW_SIZE);
		addLocationButton.addActionListener(e -> addLocation());
		DockingWindowManager.getHelpService()
				.registerHelp(addLocationButton,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"SymbolServerConfig Add"));

		saveSearchLocationsButton =
			ButtonPanelFactory.createImageButton(Icons.get("images/disk.png"),
				"Save Configuration", ButtonPanelFactory.ARROW_SIZE);
		saveSearchLocationsButton.addActionListener(e -> saveConfig());
		DockingWindowManager.getHelpService()
				.registerHelp(saveSearchLocationsButton,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"SymbolServerConfig Save"));

		JPanel buttonPanel = new JPanel();
		buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.X_AXIS));
		buttonPanel.add(new GLabel("Additional Search Paths:"));
		buttonPanel.add(Box.createHorizontalGlue());
		buttonPanel.add(addLocationButton);
		buttonPanel.add(deleteLocationButton);
		buttonPanel.add(moveLocationUpButton);
		buttonPanel.add(moveLocationDownButton);
		buttonPanel.add(refreshSearchLocationsStatusButton);
		buttonPanel.add(saveSearchLocationsButton);

		return buttonPanel;
	}

	private JPanel buildSymbolStorageLocationPanel() {
		symbolStorageLocationTextField = new HintTextField(" Required ");
		symbolStorageLocationTextField.setEditable(false);
		symbolStorageLocationTextField
				.setToolTipText("User-specified directory where PDB files are stored.  Required.");

		chooseSymbolStorageLocationButton =
			ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		chooseSymbolStorageLocationButton.addActionListener(e -> chooseSymbolStorageLocation());

		symbolStorageLocationPanel = new JPanel(new PairLayout(5, 5));
		GLabel symbolStorageLocLabel = new GLabel("Local Symbol Storage:", SwingConstants.RIGHT);
		symbolStorageLocLabel.setToolTipText(symbolStorageLocationTextField.getToolTipText());

		symbolStorageLocationPanel.add(symbolStorageLocLabel);
		symbolStorageLocationPanel.add(LoadPdbDialog.join(null, symbolStorageLocationTextField,
			chooseSymbolStorageLocationButton));
		return symbolStorageLocationPanel;
	}

	private void updateButtonEnablement() {
		boolean hasLocalSymbolStore = localSymbolStore != null;
		boolean singleRow = table.getSelectedRowCount() == 1;
		boolean moreThanOneRow = table.getRowCount() > 1;

		refreshSearchLocationsStatusButton.setEnabled(hasLocalSymbolStore && !tableModel.isEmpty());
		moveLocationUpButton.setEnabled(hasLocalSymbolStore && singleRow && moreThanOneRow);
		moveLocationDownButton.setEnabled(hasLocalSymbolStore && singleRow && moreThanOneRow);
		addLocationButton.setEnabled(hasLocalSymbolStore);
		deleteLocationButton.setEnabled(hasLocalSymbolStore && table.getSelectedRowCount() > 0);
		saveSearchLocationsButton.setEnabled(hasLocalSymbolStore && isConfigChanged());
		updateLayout(hasLocalSymbolStore);
	}

	private void setSymbolStorageLocation(File symbolStorageDir, boolean allowGUIPrompt) {
		if (symbolStorageDir == null) {
			return;
		}
		if (!symbolStorageDir.exists()) {
			if (!allowGUIPrompt) {
				return;
			}

			int opt = OptionDialog.showOptionDialog(this, "Create Local Symbol Storage Directory?",
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
				Msg.showError(this, this, "Failure", "Failed to create symbol storage directory " +
					symbolStorageDir + ": " + e.getMessage());
				return;
			}
		}

		if (allowGUIPrompt && isEmptyDirectory(symbolStorageDir)) {
			if (OptionDialog.showYesNoDialog(this,
				"Initialize Symbol Storage Directory?",
				"<html>Initialize new directory as Microsoft symbol storage directory?") == OptionDialog.YES_OPTION) {
				try {
					LocalSymbolStore.create(symbolStorageDir,
						1 /* level1 MS symbol storage directory */);
				}
				catch (IOException e) {
					Msg.showError(this, this, "Initialize Failure",
						"Failed to initialize symbol storage directory " + symbolStorageDir, e);
				}
			}
		}

		localSymbolStore =
			symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
					.newSymbolServer(symbolStorageDir.getPath(), symbolServerInstanceCreatorContext,
						SymbolStore.class);
		symbolStorageLocationTextField.setText(symbolStorageDir.getPath());
		fireChanged();
	}

	private void fireChanged() {
		if (changeCallback != null) {
			changeCallback.accept(getSymbolServerService());
		}
	}

	private void chooseSymbolStorageLocation() {
		configChanged = true;
		setSymbolStorageLocation(getChooser().getSelectedFile(), true);
		updateButtonEnablement();
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
			if (symbolServer instanceof LocalSymbolStore &&
				((LocalSymbolStore) symbolServer).isValid()) {
				int choice = OptionDialog.showYesNoCancelDialog(this, "Set Symbol Storage Location",
					"Set symbol storage location to " + firstSearchPath + "?");
				if (choice == OptionDialog.CANCEL_OPTION) {
					return;
				}
				if (choice == OptionDialog.YES_OPTION) {
					symbolServerPaths.remove(0);
					configChanged = true;
					setSymbolStorageLocation(((LocalSymbolStore) symbolServer).getRootDir(), true);
					symbolStorageLocationTextField.setText(symbolServer.getName());
				}
			}
		}

		tableModel.addSymbolServers(
			symbolServerInstanceCreatorContext.getSymbolServerInstanceCreatorRegistry()
					.createSymbolServersFromPathList(symbolServerPaths,
						symbolServerInstanceCreatorContext));
		fireChanged();
	}

	private List<String> getSymbolPathsFromEnvStr(String envString) {
		// Expect the environment string to be in the MS symbol server search path form:
		//    srv*[local cache]*[private symbol server]*https://msdl.microsoft.com/download/symbols
		//    srv*c:\symbols*https://msdl.microsoft.com/download/symbols;srv*c:\additional*https://symbol.server.tld/
		String[] envParts = envString.split("[*;]");
		List<String> results = new ArrayList<>();
		Set<String> locationStringDeduplicationSet = new HashSet<>();
		for (int i = 0; i < envParts.length; i++) {
			String locationString = envParts[i].trim();
			if (!locationString.isBlank() && !locationString.equalsIgnoreCase("srv") &&
				!locationStringDeduplicationSet.contains(locationString)) {
				results.add(locationString);
				locationStringDeduplicationSet.add(locationString);
			}
		}

		return results;
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
				JMenuItem mi = new JMenuItem(ssloc.getLocation());
				mi.addActionListener(e -> addKnownLocation(ssloc));
				mi.setToolTipText(" [from " + ssloc.getFileOrigin() + "]");
				menu.add(mi);
			}
		}
		DockingWindowManager.getHelpService()
				.registerHelp(menu,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC, "SymbolServerConfig_Add"));
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
					.newSymbolServer(ssloc.getLocation(), symbolServerInstanceCreatorContext);
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
			HttpSymbolServer httpSymbolServer = new HttpSymbolServer(URI.create(urlLocationString));
			tableModel.addSymbolServer(httpSymbolServer);
		}
		catch (IllegalArgumentException e) {
			Msg.showWarn(this, this, "Bad URL", "Invalid URL: " + urlLocationString);
		}
	}

	private void addDirectoryLocation() {
		File dir = FilePromptDialog.chooseDirectory("Enter Path", "Symbol Storage Location: ",
			null);
		if (dir == null) {
			return;
		}
		if (!dir.exists() || !dir.isDirectory()) {
			Msg.showError(this, this, "Bad path", "Invalid path: " + dir);
			return;
		}
		LocalSymbolStore localSymbolStore = new LocalSymbolStore(dir);
		tableModel.addSymbolServer(localSymbolStore);
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

	private void refreshSearchLocationStatus() {
		tableModel.refreshSymbolServerLocationStatus();
		updateButtonEnablement();
	}

	/* package */ void saveConfig() {
		SymbolServerService temporarySymbolServerService = getSymbolServerService();
		if (temporarySymbolServerService != null) {
			PdbPlugin.saveSymbolServerServiceConfig(temporarySymbolServerService);
			Preferences.store();
			setConfigChanged(false);
			fireChanged();
			updateButtonEnablement();
		}
	}

	private GhidraFileChooser getChooser() {

		if (chooser == null) {
			chooser = new GhidraFileChooser(this);
			chooser.setMultiSelectionEnabled(false);
			chooser.setApproveButtonText("Choose");
			chooser.setFileSelectionMode(GhidraFileChooserMode.DIRECTORIES_ONLY);
			chooser.setTitle("Select Symbol Storage Dir");
		}

		return chooser;
	}

	/* screen shot usage */ void pushAddLocationButton() {
		addLocation();
	}

	/* screen shot usage */ void setSymbolStorageDirectoryTextOnly(String pathStr) {
		symbolStorageLocationTextField.setText(pathStr);
	}

	/**
	 * Returns true if the given file path is a directory that contains no files.
	 * <p>
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

	private static JButton createImageButton(ImageIcon buttonIcon, String alternateText,
			Dimension preferredSize) {

		JButton button = ButtonPanelFactory.createButton("");
		button.setIcon(buttonIcon);
		button.setToolTipText(alternateText);
		button.setPreferredSize(preferredSize);

		return button;
	}
	
	static StatusText getSymbolServerWarnings(List<SymbolServer> symbolServers) {
		Map<String, String> warningsByLocation = new HashMap<>();
		for (WellKnownSymbolServerLocation ssloc : knownSymbolServers) {
			if (ssloc.getWarning() != null && !ssloc.getWarning().isBlank()) {
				warningsByLocation.put(ssloc.getLocation(), ssloc.getWarning());
			}
		}
		String warning = symbolServers
				.stream()
				.map(symbolServer -> warningsByLocation.get(symbolServer.getName()))
				.filter(Objects::nonNull)
				.distinct()
				.collect(Collectors.joining("<br>\n"));

		return !warning.isEmpty() ? new StatusText(warning, MessageType.WARNING, false) : null;
	}

}
