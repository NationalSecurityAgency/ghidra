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

import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Supplier;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.event.mouse.GMouseListenerAdapter;
import docking.options.editor.ButtonPanelFactory;
import docking.widgets.OptionDialog;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.combobox.GComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.HexOrDecimalInput;
import docking.widgets.textfield.HintTextField;
import ghidra.app.util.bin.format.pdb.PdbParser;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorControl;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.IOCancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.filechooser.GhidraFileFilter;
import ghidra.util.layout.PairLayout;
import ghidra.util.task.*;
import pdb.PdbPlugin;
import pdb.symbolserver.*;
import resources.Icons;
import resources.ResourceManager;

/**
 * A dialog that allows the user to pick or search for a Pdb file for a program.
 */
public class LoadPdbDialog extends DialogComponentProvider {

	private static final String LAST_PDBFILE_PREFERENCE_KEY = "Pdb.LastFile";
	static final Icon MATCH_OK_ICON =
		ResourceManager.loadImage("images/checkmark_green.gif", 16, 16);
	static final Icon MATCH_BAD_ICON =
		ResourceManager.loadImage("images/emblem-important.png", 16, 16);
	public static final GhidraFileFilter PDB_FILES_FILTER =
		ExtensionFileFilter.forExtensions("Microsoft Program Databases", "pdb", "pd_", "pdb.xml");

	public static class LoadPdbResults {
		public File pdbFile;
		public PdbApplicatorControl control;
		public boolean useMsDiaParser;
	}

	/**
	 * Shows a modal dialog to the user, allowing them to pick or search for a Pdb
	 * file.<p>
	 * The selected file and parser options are returned in a LoadPdbResults instance.
	 * 
	 * @param program the Ghidra {@link Program} that has Pdb info
	 * @return LoadPdbResults instance with the selected file and options, or null if canceled
	 */
	public static LoadPdbResults choosePdbForProgram(Program program) {
		LoadPdbDialog choosePdbDlg = new LoadPdbDialog(program);
		DockingWindowManager.showDialog(choosePdbDlg);
		File pdbFile = choosePdbDlg.getLocalSymbolFile(choosePdbDlg.selectedSymbolFile);
		if (pdbFile == null) {
			return null;
		}
		LoadPdbResults results = new LoadPdbResults();
		results.pdbFile = pdbFile;
		results.control =
			(PdbApplicatorControl) choosePdbDlg.applicatorControlCombo.getSelectedItem();
		results.useMsDiaParser = choosePdbDlg.msdiaParserButton.isSelected();
		return results;
	}

	private SymbolFileLocation selectedSymbolFile;

	private SymbolServerService symbolServerService;
	private SymbolServerInstanceCreatorContext symbolServerInstanceCreatorContext;

	private SymbolFileInfo programSymbolFileInfo;

	private List<Supplier<StatusText>> statusTextSuppliers = new ArrayList<>();
	private Set<FindOption> lastSearchOptions;
	private boolean searchCanceled;
	private boolean hasShownAdvanced;

	private Program program;

	private SymbolFilePanel symbolFilePanel;

	private JTextField programNameTextField;
	private JTextField pdbPathTextField;
	private GCheckBox overridePdbPathCheckBox;
	private JTextField pdbUniqueIdTextField;
	private GCheckBox overridePdbUniqueIdCheckBox;
	private HexOrDecimalInput pdbAgeTextField;
	private GCheckBox overridePdbAgeCheckBox;
	private HintTextField pdbLocationTextField;
	private GIconLabel exactMatchIconLabel;

	private JButton configButton;
	private JToggleButton advancedToggleButton;

	private GhidraFileChooser chooser;

	private JButton choosePdbLocationButton;
	private JButton loadPdbButton;

	private JPanel pdbLocationPanel;
	private JPanel programPdbPanel;
	private JComponent workComp;

	private JPanel parserOptionsPanel;
	private JRadioButton universalParserButton;
	private JRadioButton msdiaParserButton;
	private GComboBox<PdbApplicatorControl> applicatorControlCombo;

	/**
	 * Creates a new instance of the LoadPdbDialog class.
	 * 
	 * @param program the ghidra {@link Program} that is loading the Pdb
	 */
	public LoadPdbDialog(Program program) {
		super("Load PDB for " + program.getName(), true, true, true, true);
		setRememberSize(false);

		this.program = program;
		this.programSymbolFileInfo = SymbolFileInfo.fromMetadata(program.getMetadata());
		if (programSymbolFileInfo == null) {
			programSymbolFileInfo = SymbolFileInfo.unknown("missing");
		}
		updateSymbolServerServiceInstanceFromPreferences();
		build();
	}

	private void updateSymbolServerServiceInstanceFromPreferences() {
		symbolServerInstanceCreatorContext =
			SymbolServerInstanceCreatorRegistry.getInstance().getContext(program);
		symbolServerService =
			PdbPlugin.getSymbolServerService(symbolServerInstanceCreatorContext);
	}

	@Override
	protected void dialogShown() {
		pdbPathTextField.setText(programSymbolFileInfo.getPath());
		pdbUniqueIdTextField.setText(programSymbolFileInfo.getUniqueName());
		pdbAgeTextField.setValue(programSymbolFileInfo.getIdentifiers().getAge());
		programNameTextField.setText(program.getName());
		cancelButton.requestFocusInWindow();

		searchForPdbs(false);
	}

	@Override
	protected void cancelCallback() {
		selectedSymbolFile = null;
		close();
	}

	/**
	 * For screenshot use only
	 * 
	 * @param options set of {@link FindOption} enum
	 */
	public void setSearchOptions(Set<FindOption> options) {
		symbolFilePanel.setFindOptions(options);
	}

	private void setSelectedPdbFile(SymbolFileLocation symbolFileLocation) {
		this.selectedSymbolFile = symbolFileLocation;
		setPdbLocationValue(symbolFileLocation, getLocalSymbolFile(symbolFileLocation));
	}

	/**
	 * Sets the contents of the search results table.
	 * <p>
	 * Public only for screenshot usage, treat as private otherwise.
	 * 
	 * @param results list of {@link SymbolFileLocation}s to add to results
	 * @param findOptions the options used to search
	 */
	public void setSearchResults(List<SymbolFileLocation> results, Set<FindOption> findOptions) {
		lastSearchOptions = findOptions;
		symbolFilePanel.getTableModel().setSearchResults(programSymbolFileInfo, results);
	}

	/**
	 * Selects a row in the results table.
	 * <p>
	 * Public only for screenshot usage.  Treat as private.
	 * 
	 * @param symbolFileLocation {@link SymbolFileLocation} to select in results table
	 */
	public void selectRowByLocation(SymbolFileLocation symbolFileLocation) {
		for (int i = 0; i < symbolFilePanel.getTableModel().getModelData().size(); i++) {
			SymbolFileRow symbolFileRow = symbolFilePanel.getTableModel().getModelData().get(i);
			if (symbolFileRow.getLocation().equals(symbolFileLocation)) {
				symbolFilePanel.getTable().selectRow(i);
				return;
			}
		}
		symbolFilePanel.getTable().clearSelection();
	}

	private StatusText getSelectedPdbNoticeText() {
		if (selectedSymbolFile == null) {
			return null;
		}
		if (selectedSymbolFile.getFileInfo() == null) {
			return new StatusText("Unable to read Pdb information", MessageType.ERROR, false);
		}
		return !selectedSymbolFile.isExactMatch(programSymbolFileInfo)
				? new StatusText("WARNING: Selected PDB is not an exact match!",
					MessageType.WARNING, false)
				: null;
	}

	private String getSymbolFileToolText(SymbolFileLocation symbolFileLocation) {
		return symbolFileLocation != null
				? String.format(
					"<html><table>" +
						"<tr><td>PDB Name:</td><td><b>%s</b></td></tr>" +
						"<tr><td>Path:</td><td><b>%s</b></td></tr>" +
						"<tr><td>GUID/ID:</td><td><b>%s</b></td></tr>" +
						"<tr><td>Age:</td><td><b>%x</b></td></tr>" +
						"<tr><td>Is Exact Match:</td><td><b>%b</b></td</tr>" +
						"</table>",
					HTMLUtilities.escapeHTML(symbolFileLocation.getFileInfo().getName()),
					HTMLUtilities.escapeHTML(symbolFileLocation.getLocationStr()),
					symbolFileLocation.getFileInfo().getUniqueName(),
					symbolFileLocation.getFileInfo().getIdentifiers().getAge(),
					symbolFileLocation.getFileInfo().isExactMatch(programSymbolFileInfo))
				: null;
	}

	private void updateButtonEnablement() {
		boolean hasLocation = selectedSymbolFile != null;
		boolean hasGoodService = symbolServerService.isValid();
		loadPdbButton.setEnabled(hasLocation);
		configButton.setIcon(hasGoodService ? null : MATCH_BAD_ICON);
		configButton.setToolTipText(hasGoodService ? null : "Missing configuration");
		symbolFilePanel.setEnablement(hasGoodService);
	}

	private SymbolFileInfo getCurrentSymbolFileInfo() {
		String pdbPath = pdbPathTextField.getText();
		String uid = pdbUniqueIdTextField.getText();
		int age = pdbAgeTextField.getIntValue();

		return SymbolFileInfo.fromValues(pdbPath, uid, age);
	}

	private void searchForPdbs(boolean allowRemote) {
		if (pdbAgeTextField.getText().isBlank() ||
			pdbAgeTextField.getValue() > NumericUtilities.MAX_UNSIGNED_INT32_AS_LONG) {
			Msg.showWarn(this, null, "Bad PDB Age", "Invalid PDB Age value");
			return;
		}
		SymbolFileInfo symbolFileInfo = getCurrentSymbolFileInfo();
		if (symbolFileInfo == null) {
			Msg.showWarn(this, null, "Bad PDB GUID/ID",
				"Invalid PDB GUID / UID value: " + pdbUniqueIdTextField.getText());
			return;
		}
		Set<FindOption> findOptions = symbolFilePanel.getFindOptions();
		if (allowRemote) {
			findOptions.add(FindOption.ALLOW_REMOTE);
		}
		executeMonitoredRunnable("Search for PDBs", true, true, 0, monitor -> {
			try {
				searchCanceled = false;
				List<SymbolFileLocation> results =
					symbolServerService.find(symbolFileInfo, findOptions, monitor);
				Swing.runLater(() -> {
					setSearchResults(results, findOptions);
					if (!results.isEmpty()) {
						selectRowByLocation(results.get(0));
					}
					updateStatusText();
					updateButtonEnablement();
					updateParserOptionEnablement(true);
				});
			}
			catch (CancelledException e1) {
				searchCanceled = true;
				Swing.runLater(() -> updateStatusText());
			}
		});

	}

	private void build() {
		buildSymbolFilePanel();
		buildPdbLocationPanel();
		buildProgramPdbPanel();
		buildParserOptionsPanel();
		setHelpLocation(new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC, "Load PDB File"));

		addStatusTextSupplier(() -> lastSearchOptions != null && advancedToggleButton.isSelected()
				? SymbolServerPanel.getSymbolServerWarnings(symbolServerService.getSymbolServers())
				: null);
		addStatusTextSupplier(this::getSelectedPdbNoticeText);
		addStatusTextSupplier(this::getAllowRemoteWarning);
		addStatusTextSupplier(this::getFoundCountInfo);

		addButtons();
		layoutSimple();

		updateStatusText();
		updateButtonEnablement();
		// later dialogShow() will be called 
	}

	private void buildSymbolFilePanel() {
		// panel will be added in layoutAdvanced()
		symbolFilePanel = new SymbolFilePanel(this::searchForPdbs);

		symbolFilePanel.getTable()
				.getSelectionModel()
				.addListSelectionListener(e -> updateSelectedRow());
		symbolFilePanel.getTable().addMouseListener(new GMouseListenerAdapter() {
			@Override
			public void doubleClickTriggered(MouseEvent e) {
				if (loadPdbButton.isEnabled()) {
					e.consume();
					loadPdbButton.doClick();
				}
			}
		});
	}

	private void updateSelectedRow() {
		SymbolFileRow row = symbolFilePanel.getSelectedRow();
		setSelectedPdbFile(row != null ? row.getLocation() : null);
		updateStatusText();
		updateButtonEnablement();
		updateParserOptionEnablement(true);
	}

	private JPanel buildProgramPdbPanel() {

		programNameTextField = new BetterNonEditableTextField(20);
		programNameTextField.setEditable(false);

		pdbPathTextField = new BetterNonEditableTextField(20);
		pdbPathTextField.setEditable(false);

		overridePdbPathCheckBox = new GCheckBox();
		overridePdbPathCheckBox.setVisible(false);
		overridePdbPathCheckBox.setToolTipText("Override PDB name (when searching).");
		overridePdbPathCheckBox.addItemListener(e -> {
			pdbPathTextField.setEditable(overridePdbPathCheckBox.isSelected());
			if (overridePdbPathCheckBox.isSelected()) {
				pdbPathTextField.requestFocusInWindow();
			}
			else {
				pdbPathTextField.setText(programSymbolFileInfo.getPath());
			}
		});
		DockingWindowManager.getHelpService()
				.registerHelp(overridePdbPathCheckBox,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						SymbolFilePanel.SEARCH_OPTIONS_HELP_ANCHOR));

		pdbUniqueIdTextField = new BetterNonEditableTextField(36);
		pdbUniqueIdTextField.setEditable(false);
		pdbUniqueIdTextField.setToolTipText(
			"<html>PDB GUID - 32 hexadecimal characters:<br>" +
				"&nbsp;&nbsp;<b>'012345678-0123-0123-0123-0123456789ABC'</b> (with or without dashes) or<br>" +
				"PDB Signature ID - 8 hexadecimal characters:<br>" +
				"&nbsp;&nbsp;<b>'11223344'</b>");

		overridePdbUniqueIdCheckBox = new GCheckBox();
		overridePdbUniqueIdCheckBox.setVisible(false);
		overridePdbUniqueIdCheckBox.setToolTipText("Override PDB Unique ID (when searching).");
		overridePdbUniqueIdCheckBox.addItemListener(e -> {
			pdbUniqueIdTextField.setEditable(overridePdbUniqueIdCheckBox.isSelected());
			if (overridePdbUniqueIdCheckBox.isSelected()) {
				pdbUniqueIdTextField.requestFocusInWindow();
			}
			else {
				pdbUniqueIdTextField.setText(programSymbolFileInfo.getUniqueName());
			}
		});
		DockingWindowManager.getHelpService()
				.registerHelp(overridePdbUniqueIdCheckBox,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						SymbolFilePanel.SEARCH_OPTIONS_HELP_ANCHOR));

		pdbAgeTextField = new BetterNonEditableHexTextField(8);
		pdbAgeTextField.setAllowNegative(false);
		pdbAgeTextField.setHexMode();
		pdbAgeTextField.setEditable(false);

		overridePdbAgeCheckBox = new GCheckBox();
		overridePdbAgeCheckBox.setVisible(false);
		overridePdbAgeCheckBox.setToolTipText("Override PDB age (when searching).");
		overridePdbAgeCheckBox.addItemListener(e -> {
			pdbAgeTextField.setEditable(overridePdbAgeCheckBox.isSelected());
			if (overridePdbAgeCheckBox.isSelected()) {
				pdbAgeTextField.requestFocus();
			}
			else {
				pdbAgeTextField.setValue(programSymbolFileInfo.getIdentifiers().getAge());
			}
		});
		DockingWindowManager.getHelpService()
				.registerHelp(overridePdbAgeCheckBox,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						SymbolFilePanel.SEARCH_OPTIONS_HELP_ANCHOR));

		programPdbPanel = new JPanel(new PairLayout(5, 5));
		programPdbPanel.setBorder(BorderFactory.createTitledBorder("Program PDB Information"));
		programPdbPanel.add(new GLabel("Program:", SwingConstants.RIGHT));
		programPdbPanel.add(programNameTextField);

		programPdbPanel.add(
			join(null, new GLabel("PDB Name:", SwingConstants.RIGHT), overridePdbPathCheckBox));
		programPdbPanel.add(pdbPathTextField);

		programPdbPanel.add(join(null, new GLabel("PDB Unique ID:", SwingConstants.RIGHT),
			overridePdbUniqueIdCheckBox));
		programPdbPanel.add(pdbUniqueIdTextField);

		programPdbPanel.add(
			join(null, new GLabel("PDB Age:", SwingConstants.RIGHT), overridePdbAgeCheckBox));
		programPdbPanel.add(join(pdbAgeTextField, new JPanel(), null));

		return programPdbPanel;
	}

	private JPanel buildPdbLocationPanel() {
		pdbLocationTextField = new HintTextField("Browse [...] for PDB file or use 'Advanced'");
		pdbLocationTextField.setEditable(false);

		choosePdbLocationButton = ButtonPanelFactory.createButton(ButtonPanelFactory.BROWSE_TYPE);
		choosePdbLocationButton.addActionListener(e -> choosePdbFile());

		exactMatchIconLabel = new GIconLabel(Icons.EMPTY_ICON);

		pdbLocationPanel = new JPanel(new PairLayout(5, 5));
		pdbLocationPanel.setBorder(BorderFactory.createTitledBorder("PDB Location"));
		pdbLocationPanel.add(new GLabel("PDB Location:", SwingConstants.RIGHT));
		pdbLocationPanel
				.add(join(exactMatchIconLabel, pdbLocationTextField, choosePdbLocationButton));
		return pdbLocationPanel;
	}

	private void updateParserOptionEnablement(boolean trySetUniversal) {
		if (trySetUniversal) {
			universalParserButton.setSelected(true);
			msdiaParserButton.setSelected(false);
		}

		boolean isXML = (selectedSymbolFile != null &&
			selectedSymbolFile.getPath().toLowerCase().endsWith(".pdb.xml"));
		boolean isWindows = PdbParser.onWindows;
		msdiaParserButton.setEnabled(isXML || isWindows);
		if (isXML) {
			msdiaParserButton.setSelected(true);
		}
		if (msdiaParserButton.isSelected() && !msdiaParserButton.isEnabled()) {
			msdiaParserButton.setSelected(false);
		}
		if (!isWindows && !isXML) {
			universalParserButton.setSelected(true);
		}
		universalParserButton.setEnabled(!isXML);
		if (universalParserButton.isSelected() && !universalParserButton.isEnabled()) {
			universalParserButton.setSelected(false);
		}
		applicatorControlCombo.setEnabled(universalParserButton.isSelected());
		if (!applicatorControlCombo.isEnabled()) {
			applicatorControlCombo.setSelectedItem(PdbApplicatorControl.ALL);
		}
	}

	private JPanel buildParserOptionsPanel() {

		ActionListener l = (e) -> updateParserOptionEnablement(false);
		universalParserButton = new JRadioButton("Universal");
		universalParserButton
				.setToolTipText("Platform-independent PDB analyzer (No PDB.XML support).");
		msdiaParserButton = new JRadioButton("MSDIA");
		msdiaParserButton.setToolTipText(
			"<html>Legacy PDB Analyzer.<br>" +
				"Requires MS DIA-SDK for raw PDB processing (Windows only), or preprocessed PDB.XML file.");
		universalParserButton.setSelected(true);
		universalParserButton.addActionListener(l);
		msdiaParserButton.addActionListener(l);

		ButtonGroup buttonGroup = new ButtonGroup();
		buttonGroup.add(msdiaParserButton);
		buttonGroup.add(universalParserButton);

		JPanel radioButtons = new JPanel(new FlowLayout(FlowLayout.LEFT));
		radioButtons.add(universalParserButton);
		radioButtons.add(msdiaParserButton);

		applicatorControlCombo = new GComboBox<>(PdbApplicatorControl.values());
		applicatorControlCombo.setToolTipText("Selects which subsets of information to parse.");
		applicatorControlCombo.setSelectedItem(PdbApplicatorControl.ALL);

		parserOptionsPanel = new JPanel(new PairLayout(5, 5));
		parserOptionsPanel.setBorder(BorderFactory.createTitledBorder("PDB Parser"));
		DockingWindowManager.getHelpService()
				.registerHelp(parserOptionsPanel,
					new HelpLocation(PdbPlugin.PDB_PLUGIN_HELP_TOPIC,
						"PDB Parser Panel"));

		parserOptionsPanel.add(new GLabel("Parser:"));
		parserOptionsPanel.add(radioButtons);

		parserOptionsPanel.add(new GLabel("Control:"));
		parserOptionsPanel.add(applicatorControlCombo);

		return parserOptionsPanel;
	}

	private void addButtons() {

		loadPdbButton = new JButton("Load");
		loadPdbButton.setName("Load");

		loadPdbButton.addActionListener(e -> {
			if (selectedSymbolFile == null ||
				(!selectedSymbolFile.isExactMatch(programSymbolFileInfo) &&
					OptionDialog.showYesNoDialog(loadPdbButton, "Mismatched Pdb File Warning",
						"<html>The selected file is not an exact match for the current program.<br>" +
							"Note: <b>Invalid disassembly may be produced!</b><br>" +
							"Continue anyway?") != OptionDialog.YES_OPTION)) {
				return;
			}
			executeMonitoredRunnable("Prepare Selected Symbol File",
				true, true, 0, this::prepareSelectedSymbolFileAndClose);
		});
		addButton(loadPdbButton);

		addCancelButton();
		setDefaultButton(cancelButton);

		configButton = new JButton("Config...");
		configButton.addActionListener(e -> {
			if (ConfigPdbDialog.showSymbolServerConfig()) {
				updateSymbolServerServiceInstanceFromPreferences();
				updateButtonEnablement();
				updateStatusText();
				searchForPdbs(false);
			}
		});
		addButton(configButton);

		advancedToggleButton = new JToggleButton("Advanced >>");
		advancedToggleButton.addActionListener(e -> toggleAdvancedSearch());
		buttonPanel.add(advancedToggleButton);
	}

	private void prepareSelectedSymbolFileAndClose(TaskMonitor monitor) {
		try {
			if (selectedSymbolFile != null) {
				selectedSymbolFile =
					symbolServerService.getLocalSymbolFileLocation(selectedSymbolFile, monitor);
			}
			Swing.runLater(() -> close());
			return;
		}
		catch (CancelledException | IOCancelledException ce) {
			setStatusText("Operation cancelled");
			monitor.clearCanceled();
		}
		catch (IOException ioe) {
			Msg.showError(this, getComponent(), "Error Getting Symbol File", ioe);
		}
	}

	private StatusText getAllowRemoteWarning() {
		int remoteSymbolServerCount = symbolServerService.getRemoteSymbolServerCount();
		return lastSearchOptions != null && advancedToggleButton.isSelected() &&
			remoteSymbolServerCount != 0 && !lastSearchOptions.contains(FindOption.ALLOW_REMOTE)
					? new StatusText(
						"Remote servers were excluded.  Use \"Search All\" button to also search remote servers.",
						MessageType.INFO, false)
					: null;
	}

	private StatusText getFoundCountInfo() {
		if (advancedToggleButton.isSelected()) {
			if (searchCanceled) {
				return new StatusText("Search canceled", MessageType.INFO, false);
			}
			if (lastSearchOptions != null) {
				int foundCount = symbolFilePanel.getTableModel().getModelData().size();
				return new StatusText(
					"Found " + foundCount + " file" + (foundCount != 1 ? "s" : ""),
					MessageType.INFO, false);
			}
		}
		return null;
	}

	private void toggleAdvancedSearch() {
		boolean isAdvanced = advancedToggleButton.isSelected();
		advancedToggleButton.setText("Advanced " + (isAdvanced ? "<<" : ">>"));

		overridePdbAgeCheckBox.setVisible(isAdvanced);
		overridePdbPathCheckBox.setVisible(isAdvanced);
		overridePdbUniqueIdCheckBox.setVisible(isAdvanced);

		if (isAdvanced) {
			layoutAdvanced();
		}
		else {
			layoutSimple();
		}

		updateStatusText();
		updateButtonEnablement();
		updateParserOptionEnablement(false);
		if (isAdvanced && !hasShownAdvanced) {
			hasShownAdvanced = true;
			repack();
		}
	}

	private void layoutSimple() {
		Box box = Box.createVerticalBox();
		box.add(programPdbPanel);
		box.add(pdbLocationPanel);
		box.add(parserOptionsPanel);

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(box, BorderLayout.NORTH);

		overrideWorkPanel(panel);
	}

	private void overrideWorkPanel(JComponent newWorkComp) {
		if (this.workComp != null && this.workComp.getParent() != null) {
			this.workComp.getParent().remove(this.workComp);
		}
		this.workComp = newWorkComp;
		addWorkPanel(newWorkComp);
	}

	private void layoutAdvanced() {
		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(programPdbPanel, BorderLayout.NORTH);
		mainPanel.add(symbolFilePanel, BorderLayout.CENTER);
		mainPanel.add(parserOptionsPanel, BorderLayout.SOUTH);

		overrideWorkPanel(mainPanel);
	}

	private void choosePdbFile() {
		File file = getChooser().getSelectedFile();
		if (file != null && file.isFile()) {
			Preferences.setProperty(LAST_PDBFILE_PREFERENCE_KEY, file.getPath());
			executeMonitoredRunnable("Get PDB Info", true, true, 0, monitor -> {
				SymbolFileInfo pdbSymbolFileInfo = SymbolFileInfo.fromFile(file, monitor);
				if (pdbSymbolFileInfo == null) {
					pdbSymbolFileInfo = SymbolFileInfo.unknown(file.getName());
				}
				SymbolFileLocation symbolFileLocation =
					SameDirSymbolStore.createManuallySelectedSymbolFileLocation(file,
						pdbSymbolFileInfo);
				Swing.runLater(() -> {
					setSearchResults(List.of(symbolFileLocation), null);
					setSelectedPdbFile(symbolFileLocation);
					setPdbLocationValue(symbolFileLocation, file);
					selectRowByLocation(symbolFileLocation);
					updateStatusText();
					updateButtonEnablement();
					updateParserOptionEnablement(true);
				});
			});

		}
	}

	private void setPdbLocationValue(SymbolFileLocation symbolFileLocation, File file) {
		boolean isExactMatch = symbolFileLocation != null
				? symbolFileLocation.isExactMatch(programSymbolFileInfo)
				: false;
		pdbLocationTextField.setText(file != null ? file.getPath() : "");
		pdbLocationTextField.setToolTipText(getSymbolFileToolText(symbolFileLocation));
		exactMatchIconLabel
				.setIcon(file == null ? null : isExactMatch ? MATCH_OK_ICON : MATCH_BAD_ICON);
		exactMatchIconLabel.setToolTipText(
			file == null ? null : isExactMatch ? "Exact match" : "Not exact match");

	}

	private GhidraFileChooser getChooser() {

		if (chooser == null) {
			chooser = new GhidraFileChooser(getComponent());
			chooser.addFileFilter(PDB_FILES_FILTER);
			chooser.setMultiSelectionEnabled(false);
			chooser.setApproveButtonText("Choose");
			chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			chooser.setTitle("Select PDB");

			String lastFile = Preferences.getProperty(LAST_PDBFILE_PREFERENCE_KEY);
			if (lastFile != null) {
				chooser.setSelectedFile(new File(lastFile));
			}
		}

		return chooser;
	}

	/**
	 * Adds a supplier of status text messages.  The supplier will be polled
	 * whenever the updateStatusText() method is called.
	 * <p>
	 * Use this status text scheme instead of {@link #setStatusText(String)} if
	 * there are multiple locations that need to provide a status message at the
	 * bottom of the dialog.
	 * 
	 * @param supplier StatusText supplier
	 */
	private void addStatusTextSupplier(Supplier<StatusText> supplier) {
		statusTextSuppliers.remove(supplier);
		statusTextSuppliers.add(supplier);
	}

	/**
	 * Polls all {@link #addStatusTextSupplier(Supplier) registered} StatusText suppliers and
	 * sets the status message at the bottom of the dialog to the resulting message.
	 * <p>
	 * Not compatible with {@link #setStatusText(String)}.  Either use it, or this. 
	 */
	private void updateStatusText() {
		StringBuilder sb = new StringBuilder();
		boolean alert = false;
		MessageType mt = MessageType.INFO;
		for (Supplier<StatusText> supplier : statusTextSuppliers) {
			StatusText statusText = supplier.get();
			if (statusText != null && statusText.message != null && !statusText.message.isEmpty()) {
				if (sb.length() != 0) {
					sb.append("<br>");
				}
				sb.append(HTMLUtilities.colorString(getStatusColor(statusText.messageType),
					statusText.message));
				alert |= statusText.alert;
				if (mt.ordinal() < statusText.messageType.ordinal()) {
					mt = statusText.messageType;
				}
			}
		}
		if (sb.length() != 0) {
			setStatusText("<html>" + sb.toString(), mt, alert);
		}
		else {
			clearStatusText();
		}

	}

	private File getLocalSymbolFile(SymbolFileLocation symbolFileLocation) {
		if (symbolFileLocation == null) {
			return null;
		}
		SymbolServer symbolServer = symbolFileLocation.getSymbolServer();
		if (!(symbolServer instanceof SymbolStore)) {
			return null;
		}
		SymbolStore symbolStore = (SymbolStore) symbolServer;
		File file = symbolStore.getFile(symbolFileLocation.getPath());
		return SymbolStore.isCompressedFilename(file.getName()) ? null : file;
	}

	/**
	 * Execute a non-modal task that has progress and can be cancelled.
	 * <p>
	 * See {@link #executeProgressTask(Task, int)}.
	 * 
	 * @param taskTitle String title of task
	 * @param canCancel boolean flag, if true task can be canceled by the user
	 * @param hasProgress boolean flag, if true the task has a progress meter
	 * @param delay int number of milliseconds to delay before showing the task's
	 * progress
	 * @param runnable {@link MonitoredRunnable} to run
	 */
	private void executeMonitoredRunnable(String taskTitle, boolean canCancel,
			boolean hasProgress, int delay, MonitoredRunnable runnable) {
		Task task = new Task(taskTitle, canCancel, hasProgress, false) {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				runnable.monitoredRun(monitor);
			}
		};
		executeProgressTask(task, delay);
	}

	//-----------------------------------------------------------------------------------

	static class StatusText {

		public StatusText(String message, MessageType messageType, boolean alert) {
			this.message = message;
			this.messageType = messageType;
			this.alert = alert;
		}

		public String message;
		public MessageType messageType;
		public boolean alert;
	}

	static JPanel join(JComponent left, JComponent main, JComponent right) {
		JPanel panel = new JPanel(new BorderLayout());
		if (left != null) {
			panel.add(left, BorderLayout.WEST);
		}
		panel.add(main, BorderLayout.CENTER);
		if (right != null) {
			panel.add(right, BorderLayout.EAST);
		}

		return panel;
	}

	/**
	 * A customized JTextField that changes the background of non-editable
	 * text fields to be the same color as the parent container's background.
	 */
	static class BetterNonEditableTextField extends JTextField {

		BetterNonEditableTextField(int columns) {
			super(columns);
		}

		@Override
		public Color getBackground() {
			Container parent = getParent();
			if (parent != null && !isEditable()) {
				Color bg = parent.getBackground();
				// mint a new Color object to avoid it being
				// ignored because the parent handed us a DerivedColor
				// instance
				return new Color(bg.getRGB());
			}
			return super.getBackground();
		}
	}

	static class BetterNonEditableHexTextField extends HexOrDecimalInput {

		BetterNonEditableHexTextField(int columns) {
			super(columns);
		}

		@Override
		public Color getBackground() {
			Container parent = getParent();
			if (parent != null && !isEditable()) {
				Color bg = parent.getBackground();
				// mint a new Color object to avoid it being
				// ignored because the parent handed us a DerivedColor
				// instance
				return new Color(bg.getRGB());
			}
			return super.getBackground();
		}
	}
}
