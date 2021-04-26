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
package ghidra.app.plugin.core.analysis;

import java.awt.*;
import java.awt.event.ItemEvent;
import java.beans.*;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.ListSelectionEvent;
import javax.swing.table.TableColumn;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.io.FilenameUtils;

import docking.help.Help;
import docking.help.HelpService;
import docking.options.editor.GenericOptionsComponent;
import docking.widgets.OptionDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GLabel;
import docking.widgets.table.GTable;
import ghidra.GhidraOptions;
import ghidra.app.services.Analyzer;
import ghidra.framework.Application;
import ghidra.framework.GenericRunInfo;
import ghidra.framework.options.*;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.layout.VerticalLayout;
import utilities.util.FileUtilities;

class AnalysisPanel extends JPanel implements PropertyChangeListener {
	// create an empty options to represent the defaults of the analyzers
	private static final Options STANDARD_DEFAULT_OPTIONS =
		new FileOptions("Standard Defaults");

	private static final int CURRENT_PROGRAM_OPTIONS_CHOICE_INDEX = 0;
	private static final int STANDARD_OPTIONS_CHOICE_INDEX = 1;

	private static final String OPTIONS_FILE_EXTENSION = "options";

	public static final String PROTOTYPE = " (Prototype)";
	public final static int COLUMN_ANALYZER_IS_ENABLED = 0;

	static final String ANALYZER_OPTIONS_SAVE_DIR = "analyzer_options";

	// preference which retains last used analyzer_options file name 
	public static final String LAST_USED_OPTIONS_CONFIG = "LAST_USED_OPTIONS_CONFIG";

	private List<Program> programs;
	private PropertyChangeListener propertyChangeListener;
	private Options analysisOptions;
	private Options currentProgramOptions; // this will have all the non-default options from the program
	private Options selectedOptions = STANDARD_DEFAULT_OPTIONS;

	private JTable table;
	private AnalysisEnablementTableModel model;
	private JTextArea descriptionComponent;
	private JPanel analyzerOptionsPanel;

	private List<EditorState> editorList = new ArrayList<>();
	private Map<String, Component> analyzerToOptionsPanelMap = new HashMap<>();
	private Map<String, List<Component>> analyzerManagedComponentsMap = new HashMap<>();
	private EditorStateFactory editorStateFactory;

	private JPanel noOptionsPanel;
	private GhidraComboBox<Options> defaultOptionsCombo;
	private JButton deleteButton;

	/**
	 * Constructor
	 *
	 * @param program the programs to be analyzed
	 * @param editorStateFactory the editor factory
	 * @param propertyChangeListener subscriber for property change notifications
	 */
	AnalysisPanel(Program program, EditorStateFactory editorStateFactory,
			PropertyChangeListener propertyChangeListener) {
		this(List.of(program), editorStateFactory, propertyChangeListener);
	}

	/**
	 * Constructor
	 *
	 * @param programs list of programs that will be analyzed
	 * @param editorStateFactory the editor factory
	 * @param propertyChangeListener subscriber for property change notifications
	 */
	AnalysisPanel(List<Program> programs, EditorStateFactory editorStateFactory) {
		this(programs, editorStateFactory, e -> {});
	}
	

	/**
	 * Constructor
	 *
	 * @param programs list of programs that will be analyzed
	 * @param editorStateFactory the editor factory
	 * @param propertyChangeListener subscriber for property change notifications
	 */
	AnalysisPanel(List<Program> programs, EditorStateFactory editorStateFactory,
			PropertyChangeListener propertyChangeListener) {

		// Do a quick check to make sure we have at least one program. If not, we
		// shouldn't even be here (the menus should be disabled).
		if (CollectionUtils.isEmpty(programs)) {
			throw new AssertException("Must provide a program to run analysis");
		}
		this.programs = programs;
		this.propertyChangeListener = propertyChangeListener;
		this.editorStateFactory = editorStateFactory;
		analysisOptions = programs.get(0).getOptions(Program.ANALYSIS_PROPERTIES);
		currentProgramOptions = getNonDefaultProgramOptions();
		setName("Analysis Panel");
		build();
		load();
		loadCurrentOptionsIntoEditors();
	}

	/**
	 * Copies the the non-default options from the program analysis options into a new options object
	 * @return the the non-default options from the program analysis options into a new options object
	 */
	private Options getNonDefaultProgramOptions() {
		FileOptions options = new FileOptions("Current Program Options");
		List<String> optionNames = analysisOptions.getOptionNames();
		for (String optionName : optionNames) {
			if (!analysisOptions.isDefaultValue(optionName)) {
				options.putObject(optionName, analysisOptions.getObject(optionName, null));
			}
		}
		return options;
	}

	private void load() {
		editorList.clear();
		analyzerToOptionsPanelMap.clear();
		analyzerManagedComponentsMap.clear();

		int selectedAnalyzerRow = table.getSelectedRow();

		loadAnalyzers();
		loadAnalyzerOptionsPanels();

		if (selectedAnalyzerRow >= 0) {
			table.setRowSelectionInterval(selectedAnalyzerRow, selectedAnalyzerRow);
		}
	}

	private void loadAnalyzers() {
		List<AnalyzerEnablementState> states = new ArrayList<>();
		Program program = programs.get(0);
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);

		List<String> propertyNames = analysisOptions.getOptionNames();
		Collections.sort(propertyNames, (o1, o2) -> o1.compareToIgnoreCase(o2));
		for (String analyzerName : propertyNames) {
			if (analyzerName.indexOf('.') == -1) {
				if (analysisOptions.getType(analyzerName) != OptionType.BOOLEAN_TYPE) {
					throw new AssertException(
						"Analyzer enable property that is not boolean - " + analyzerName);
				}

				Analyzer analyzer = manager.getAnalyzer(analyzerName);
				if (analyzer != null) {
					boolean enabled = analysisOptions.getBoolean(analyzerName, false);
					boolean defaultEnabled = analyzer.getDefaultEnablement(program);
					states.add(new AnalyzerEnablementState(analyzer, enabled, defaultEnabled));
				}
			}
		}
		model.setData(states);
	}

	private void build() {
		setLayout(new BorderLayout());
		setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		add(buildMainPanel(), BorderLayout.CENTER);
	}

	private JComponent buildMainPanel() {
		buildTable();
		buildAnalyzerOptionsPanel();

		JSplitPane splitpane =
			new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildLeftPanel(), buildRightPanel());
		splitpane.setBorder(null);

		return splitpane;
	}

	private void buildAnalyzerOptionsPanel() {
		analyzerOptionsPanel = new JPanel(new BorderLayout());
		configureBorder(analyzerOptionsPanel, "Options");
	}

	private Component buildOptionsComboBoxPanel() {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER));

		Options[] defaultOptionsArray = getDefaultOptionsArray();
		defaultOptionsCombo = new GhidraComboBox<>(defaultOptionsArray);
		selectedOptions = findOptions(defaultOptionsArray, getLastUsedDefaultOptionsName());
		defaultOptionsCombo.setSelectedItem(selectedOptions);
		defaultOptionsCombo.addItemListener(this::analysisComboChanged);
		Dimension preferredSize = defaultOptionsCombo.getPreferredSize();
		defaultOptionsCombo.setPreferredSize(new Dimension(200, preferredSize.height));
		panel.add(defaultOptionsCombo);

		deleteButton = new JButton("Delete");
		deleteButton.addActionListener(e -> deleteSelectedOptionsConfiguration());
		deleteButton.setToolTipText("Deletes the currently selected user configuration");
		panel.add(deleteButton);

		panel.setBorder(BorderFactory.createEmptyBorder(0, 5, 0, 5));
		return panel;
	}

	private Component buildRightPanel() {
		JSplitPane splitpane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, buildDescriptionPanel(),
			analyzerOptionsPanel);
		splitpane.setBorder(null);
		splitpane.setDividerLocation(0.50);
		return splitpane;
	}

	private JPanel buildDescriptionPanel() {
		descriptionComponent = buildTextArea();
		JScrollPane descriptionScrollPane = new JScrollPane(descriptionComponent);
		JPanel descriptionPanel = new JPanel(new BorderLayout());
		configureBorder(descriptionScrollPane, "Description");
		descriptionPanel.add(descriptionScrollPane, BorderLayout.CENTER);
		return descriptionPanel;
	}

	private JTextArea buildTextArea() {
		JTextArea textarea = new JTextArea(3, 20);
		textarea.setEditable(false);
		textarea.setOpaque(false);
		textarea.setWrapStyleWord(true);
		textarea.setLineWrap(true);
		return textarea;
	}

	private JPanel buildLeftPanel() {
		JPanel buttonPanel = buildControlPanel();

		JScrollPane scrollPane = new JScrollPane(table);
		scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		scrollPane.setPreferredSize(new Dimension(350, 300));

		JPanel panel = new JPanel(new BorderLayout(5, 5));
		configureBorder(panel, "Analyzers");

		panel.add(scrollPane, BorderLayout.CENTER);
		panel.add(buttonPanel, BorderLayout.SOUTH);
		return panel;
	}

	private JPanel buildControlPanel() {
		JPanel panel = new JPanel(new BorderLayout());

		panel.add(buildButtonPanel(), BorderLayout.NORTH);
		panel.add(buildOptionsComboBoxPanel(), BorderLayout.SOUTH);

		return panel;
	}

	private JPanel buildButtonPanel() {
		JButton selectAllButton = new JButton("Select All");
		selectAllButton.addActionListener(e -> selectAll());
		JButton deselectAllButton = new JButton("Deselect All");
		deselectAllButton.addActionListener(e -> deselectAll());
		JButton resetButton = new JButton("Reset");
		resetButton.setToolTipText("Resets the editors to the selected options configuration");
		resetButton.addActionListener(e -> loadCurrentOptionsIntoEditors());
		JButton saveButton = new JButton("Save...");
		saveButton.setToolTipText("Saves the current editor settings to a named configuration");
		saveButton.addActionListener(e -> saveCurrentOptionsConfiguration());
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		buttonPanel.add(selectAllButton);
		buttonPanel.add(deselectAllButton);
		buttonPanel.add(resetButton);
		buttonPanel.add(saveButton);
		return buttonPanel;
	}

	private void deleteSelectedOptionsConfiguration() {
		if (!isUserConfiguration(selectedOptions)) {
			// can only delete user configurations
			return;
		}
		String configurationName = selectedOptions.getName();
		int result = OptionDialog.showYesNoDialog(this, "Delete Configuration?",
			"Are you sure you want to delete options configuration \"" + configurationName + "\"?");
		if (result != OptionDialog.YES_OPTION) {
			return;
		}

		File configurationFile = getOptionsSaveFile(configurationName);
		configurationFile.delete();
		selectedOptions = currentProgramOptions;
		reloadOptionsCombo(currentProgramOptions);
		loadCurrentOptionsIntoEditors();
	}

	private void selectAll() {
		int rowCount = model.getRowCount();
		for (int i = 0; i < rowCount; ++i) {
			model.setValueAt(true, i, COLUMN_ANALYZER_IS_ENABLED);
		}
	}

	private void deselectAll() {
		int rowCount = model.getRowCount();
		for (int i = 0; i < rowCount; ++i) {
			model.setValueAt(false, i, COLUMN_ANALYZER_IS_ENABLED);
		}
	}

	private void saveCurrentOptionsConfiguration() {
		String defaultSaveName = "";
		if (selectedOptions != STANDARD_DEFAULT_OPTIONS &&
			selectedOptions != currentProgramOptions) {
			defaultSaveName = selectedOptions.getName();
		}

		String saveName = OptionDialog.showEditableInputChoiceDialog(this, "Save Configuration",
			"Options Configuration Name", getSavedChoices(), defaultSaveName,
			OptionDialog.QUESTION_MESSAGE);
		if (saveName == null) {
			return;
		}
		saveName = saveName.trim();
		if (saveName.length() == 0) {
			return;
		}
		File saveFile = getOptionsSaveFile(saveName);
		if (saveFile.exists() && OptionDialog.CANCEL_OPTION ==
			OptionDialog.showOptionDialogWithCancelAsDefaultButton(this, "Overwrite Configuration",
					"Overwrite existing configuration file: " + saveName + " ?", "Overwrite")) {
			return;
		}
		FileOptions saved = saveCurrentOptions();
		try {
			saved.save(saveFile);
			reloadOptionsCombo(saved);
		}
		catch (IOException e) {
			Msg.error(this, "Error saving default options", e);
		}
	}

	private FileOptions saveCurrentOptions() {
		FileOptions saveTo = new FileOptions("");
		List<AnalyzerEnablementState> analyzerStates = model.getModelData();
		for (AnalyzerEnablementState analyzerState : analyzerStates) {
			String analyzerName = analyzerState.getName();
			boolean enabled = analyzerState.isEnabled();
			if (!Objects.equals(Boolean.valueOf(enabled),
				analysisOptions.getDefaultValue(analyzerName))) {
				saveTo.setBoolean(analyzerName, enabled);
			}
		}

		for (EditorState editorState : editorList) {
			editorState.applyNonDefaults(saveTo);
		}
		return saveTo;
	}

	private void loadCurrentOptionsIntoEditors() {
		List<AnalyzerEnablementState> analyzerStates = model.getModelData();
		for (AnalyzerEnablementState analyzerState : analyzerStates) {
			String analyzerName = analyzerState.getName();
			Object defaultObject = analysisOptions.getDefaultValue(analyzerName);
			boolean defaultValue =
				(defaultObject instanceof Boolean) ? (Boolean) defaultObject : false;
			boolean newValue = selectedOptions.getBoolean(analyzerName, defaultValue);
			analyzerState.setEnabled(newValue);
			setAnalyzerEnabled(analyzerName, newValue, false);
			model.fireTableRowsUpdated(0, model.getRowCount() - 1);
		}

		for (EditorState editorState : editorList) {
			editorState.loadFrom(selectedOptions);
		}
		updateDeleteButton();
	}

	private void reloadOptionsCombo(Options newDefaultOptions) {
		Options[] defaultOptionsArray = getDefaultOptionsArray();
		defaultOptionsCombo.setModel(new DefaultComboBoxModel<Options>(defaultOptionsArray));
		Options selected = findOptions(defaultOptionsArray, newDefaultOptions.getName());
		defaultOptionsCombo.setSelectedItem(selected);
	}

	private Options findOptions(Options[] defaultOptionsArray, String name) {
		for (Options fileOptions : defaultOptionsArray) {
			if (fileOptions.getName().equals(name)) {
				return fileOptions;
			}
		}
		return STANDARD_DEFAULT_OPTIONS;
	}

	private void configureEnabledColumnWidth(int width) {
		TableColumn column = table.getColumnModel().getColumn(COLUMN_ANALYZER_IS_ENABLED);
		column.setWidth(width);
		column.setMinWidth(width);
		column.setMaxWidth(width);
		column.setResizable(false);
	}

	private void buildTable() {
		model = new AnalysisEnablementTableModel(this, Collections.emptyList());
		table = new GTable(model);
		configureEnabledColumnWidth(60);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.getSelectionModel().addListSelectionListener(this::selectedAnalyzerChanged);
	}

	private void selectedAnalyzerChanged(ListSelectionEvent event) {
		if (event.getValueIsAdjusting()) {
			return;
		}
		analyzerOptionsPanel.removeAll();
		descriptionComponent.setText("");

		int selectedRow = table.getSelectedRow();
		if (selectedRow >= 0) {
			String analyzerName = model.getModelData().get(selectedRow).getName();
			Component component = analyzerToOptionsPanelMap.get(analyzerName);
			if (component == null) {
				component = noOptionsPanel;
			}
			analyzerOptionsPanel.add(component, BorderLayout.CENTER);
			descriptionComponent.setText(analysisOptions.getDescription(analyzerName));
		}

		analyzerOptionsPanel.validate();
		analyzerOptionsPanel.repaint();
		analyzerOptionsPanel.getParent().validate();
		descriptionComponent.setCaretPosition(0);
	}

	/**
	 * Sets a compound border around the component consisting
	 * of a titled border and a 10 pixel wide empty border.
	 */
	private void configureBorder(JComponent component, String title) {
		Border emptyBorder = BorderFactory.createEmptyBorder(10, 10, 10, 10);
		Border titleBorder =
			BorderFactory.createTitledBorder(BorderFactory.createEtchedBorder(), title);
		Border compoundBorder = BorderFactory.createCompoundBorder(titleBorder, emptyBorder);
		component.setBorder(compoundBorder);
	}

	void setAnalyzerEnabled(String analyzerName, boolean enabled, boolean fireEvent) {
		List<Component> list = analyzerManagedComponentsMap.get(analyzerName);
		if (list != null) {
			Iterator<Component> iterator = list.iterator();
			while (iterator.hasNext()) {
				Component next = iterator.next();
				next.setEnabled(enabled);
			}
		}
		if (fireEvent) {
			propertyChange(null);
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		if (checkForDifferencesWithProgram()) {
			propertyChangeListener.propertyChange(
				new PropertyChangeEvent(this, GhidraOptions.APPLY_ENABLED, null, Boolean.TRUE));
		}
	}

	private boolean checkForDifferencesWithProgram() {
		List<AnalyzerEnablementState> analyzerStates = model.getModelData();
		boolean changes = false;
		for (AnalyzerEnablementState analyzerState : analyzerStates) {
			String analyzerName = analyzerState.getName();
			boolean currEnabled = analyzerState.isEnabled();
			boolean origEnabled = analysisOptions.getBoolean(analyzerName, false);
			if (currEnabled != origEnabled) {
				changes = true;
				propertyChangeListener.propertyChange(
					new PropertyChangeEvent(this, analyzerName, origEnabled, currEnabled));
			}
		}
		if (changes) {
			return true;
		}
		for (EditorState info : editorList) {
			if (info.isValueChanged()) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Updates programs with the latest option settings.
	 * <p>
	 * Details: This loops over every analyzer name in this panel and for
	 * each, updates the associated enablement for all programs being
	 * analyzed.
	 */
	void applyChanges() {
		int id = programs.get(0).startTransaction("Setting Analysis Options");
		boolean commit = false;
		try {
			List<AnalyzerEnablementState> analyzerStates = model.getModelData();
			for (AnalyzerEnablementState analyzerState : analyzerStates) {
				String analyzerName = analyzerState.getName();
				boolean enabled = analyzerState.isEnabled();
				analysisOptions.setBoolean(analyzerName, enabled);
				commit = true;
			}
			for (EditorState info : editorList) {
				info.applyValue();
			}
		}
		finally {
			programs.get(0).endTransaction(id, commit);
		}

		copyOptionsToAllPrograms();
		currentProgramOptions = getNonDefaultProgramOptions();
		reloadOptionsCombo(currentProgramOptions);
	}

	private void copyOptionsToAllPrograms() {
		for (int i = 1; i < programs.size(); i++) {
			Program program = programs.get(i);

			int id = program.startTransaction("Setting Analysis Options");
			boolean commit = false;
			try {
				copyOptionsTo(program);
				commit = true;
			}
			finally {
				program.endTransaction(id, commit);
			}
		}
	}

	private void copyOptionsTo(Program program) {
		Options destinationOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);

		// first remove all options in destination
		for (String optionName : destinationOptions.getOptionNames()) {
			destinationOptions.removeOption(optionName);
		}

		// now copy all the options in the source
		for (String optionName : analysisOptions.getOptionNames()) {
			destinationOptions.putObject(optionName, analysisOptions.getObject(optionName, null));
		}
	}

	private void loadAnalyzerOptionsPanels() {
		List<Options> optionGroups = analysisOptions.getChildOptions();
		noOptionsPanel = new JPanel(new VerticalLayout(5));
		noOptionsPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));
		noOptionsPanel.add(new GLabel("No options available."));

		HelpService help = Help.getHelpService();

		for (Options optionsGroup : optionGroups) {
			String analyzerName = optionsGroup.getName();

			JPanel optionsContainer = new JPanel(new VerticalLayout(5));
			optionsContainer.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 5));

			JScrollPane scrollPane = new JScrollPane(optionsContainer);
			scrollPane.setBorder(null);

			analyzerToOptionsPanelMap.put(analyzerName, scrollPane);
			analyzerManagedComponentsMap.put(analyzerName, new ArrayList<Component>());

			List<String> optionNames = getOptionNames(optionsGroup);
			Collections.sort(optionNames);

			List<GenericOptionsComponent> optionComponents = new ArrayList<>();

			for (String childOptionName : optionNames) {

				EditorState childState =
					editorStateFactory.getEditorState(optionsGroup, childOptionName, this);
				GenericOptionsComponent comp =
					GenericOptionsComponent.createOptionComponent(childState);

				HelpLocation helpLoc = analysisOptions
						.getHelpLocation(analyzerName + Options.DELIMITER_STRING + childOptionName);
				if (helpLoc != null) {
					help.registerHelp(comp, helpLoc);
				}

				optionsContainer.add(comp);
				optionComponents.add(comp);
				analyzerManagedComponentsMap.get(analyzerName).add(comp);
				editorList.add(childState);
			}

			GenericOptionsComponent.alignLabels(optionComponents);
			Object value = analysisOptions.getObject(analyzerName, null);
			boolean enabled = true;
			if (value instanceof Boolean) {
				enabled = (Boolean) value;
			}
			setAnalyzerEnabled(analyzerName, enabled, false);
		}
	}

	private List<String> getOptionNames(Options optionsGroup) {
		List<String> subOptions = optionsGroup.getLeafOptionNames();
		Iterator<String> it = subOptions.iterator();
		while (it.hasNext()) {
			String next = it.next();
			if (!isEditable(optionsGroup, next)) {
				it.remove();
			}
		}
		return subOptions;
	}

	private boolean isEditable(Options options, String optionName) {
		PropertyEditor editor = options.getPropertyEditor(optionName);
		return options.getObject(optionName, null) != null || editor != null;
	}

	/**
	 * Updates the enablement of the given analyzer for all programs being analyzed.
	 * <p>
	 * A couple notes about this:
	 * 	<OL>
	 * 		<LI>
	 *	   	When a user toggles the status of an analyzer we need to update that status for
	 *	    EVERY open program. We don't want a situation where a user turns a particular
	 *		analyzer off, but it's only turned off for the selected program.
	 *		</LI>
	 *		<LI>
	 *		Programs with different architectures may have different available analyzers, but we
	 *		don't worry about that here because this class is only handed programs with
	 *		similar architectures. If this were to ever change we would need to revisit this.
	 *		</LI>
	 * </OL>
	 *
	 * @param analyzerName the name of the analyzer to update
	 * @param enabled if true, enable the analyzer; otherwise disable it
	 */
	public void updateOptionForAllPrograms(String analyzerName, boolean enabled) {
		for (Program program : programs) {

			// Check to make sure we're only handling events that relate to analyzers. If we
			// receive something else (eg: "analyze.apply") ignore it.
			Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
			if (!options.getOptionNames().contains(analyzerName)) {
				continue;
			}

			boolean commit = false;
			int id = program.startTransaction("Setting analysis property " + analyzerName);
			try {
				options.setBoolean(analyzerName, enabled);
				commit = true;
			}
			finally {
				program.endTransaction(id, commit);
			}
		}
	}

	private String getLastUsedDefaultOptionsName() {
		// if the program has non-default options or has been analyzed use its 
		// current settings initially
		if (isAnalyzed() || !currentProgramOptions.getOptionNames().isEmpty()) {
			return currentProgramOptions.getName();
		}
		// Otherwise, use the last used analysis options configuration
		return Preferences.getProperty(LAST_USED_OPTIONS_CONFIG,
			STANDARD_DEFAULT_OPTIONS.getName());
	}

	private boolean isAnalyzed() {
		Options options = programs.get(0).getOptions(Program.PROGRAM_INFO);
		return options.getBoolean(Program.ANALYZED, false);
	}

	private Options[] getDefaultOptionsArray() {
		List<Options> savedDefaultsList = getSavedOptionsObjects();
		Options[] optionsArray = new FileOptions[savedDefaultsList.size() + 2]; // 2 standard configurations always present
		optionsArray[CURRENT_PROGRAM_OPTIONS_CHOICE_INDEX] = currentProgramOptions;
		optionsArray[STANDARD_OPTIONS_CHOICE_INDEX] = STANDARD_DEFAULT_OPTIONS;
		for (int i = 0; i < savedDefaultsList.size(); i++) {
			optionsArray[i + 2] = savedDefaultsList.get(i);
		}
		return optionsArray;
	}

	private String[] getSavedChoices() {
		Options[] defaultOptionsArray = getDefaultOptionsArray();
		List<String> list = new ArrayList<>();
		for (int i = 2; i < defaultOptionsArray.length; i++) {
			list.add(defaultOptionsArray[i].getName());
		}
		String[] a = new String[list.size()];
		list.toArray(a);
		return a;
	}

	private File getOptionsSaveFile(String saveName) {
		File userSettingsDirectory = Application.getUserSettingsDirectory();
		File optionsDir = new File(userSettingsDirectory, ANALYZER_OPTIONS_SAVE_DIR);
		FileUtilities.mkdirs(optionsDir);
		return new File(optionsDir, saveName + "." + OPTIONS_FILE_EXTENSION);
	}

	private List<Options> getSavedOptionsObjects() {
		File userSettingsDirectory = Application.getUserSettingsDirectory();
		File optionsDir = new File(userSettingsDirectory, ANALYZER_OPTIONS_SAVE_DIR);
		if (!optionsDir.isDirectory()) {
			// new installation, copy any old saved analysis options files to current
			migrateOptionsFromPreviousRevision(optionsDir);
		}
		return readSavedOptions(optionsDir);
	}

	private List<Options> readSavedOptions(File optionsDir) {
		List<Options> list = new ArrayList<>();
		File[] listFiles = optionsDir.listFiles();
		Arrays.sort(listFiles);
		for (File file : listFiles) {
			if (OPTIONS_FILE_EXTENSION.equals(FilenameUtils.getExtension(file.getName()))) {
				FileOptions fileOptions;
				try {
					fileOptions = new FileOptions(file);
					list.add(fileOptions);
				}
				catch (IOException e) {
					Msg.error(this, "Error reading saved analysis options", e);
				}
			}
		}

		return list;
	}

	private void migrateOptionsFromPreviousRevision(File optionsDir) {
		FileUtilities.mkdirs(optionsDir);
		File previous = getMostRecentApplicationSettingsDirWithSavedOptions();
		if (previous == null) {
			return;
		}
		List<Options> readSavedOptions = readSavedOptions(previous);
		for (Options options : readSavedOptions) {
			FileOptions fileOptions = (FileOptions) options;
			String name = fileOptions.getName();
			try {
				fileOptions.save(getOptionsSaveFile(name));
			} catch (IOException e) {
				Msg.error(this, "Error copying analysis options from previous Ghidra install", e);
			}
		}
	}
	private File getMostRecentApplicationSettingsDirWithSavedOptions() {
		List<File> ghidraUserDirsByTime = GenericRunInfo.getPreviousApplicationSettingsDirsByTime();
		if (ghidraUserDirsByTime.size() == 0) {
			return null;
		}

		// get the tools from the most recent projects first
		for (File ghidraUserDir : ghidraUserDirsByTime) {
			File possible = new File(ghidraUserDir, ANALYZER_OPTIONS_SAVE_DIR);
			if (possible.exists()) {
				return possible;
			}
		}
		return null;
	}


	private boolean isUserConfiguration(Options options) {
		if (options == STANDARD_DEFAULT_OPTIONS ||
			options == currentProgramOptions) {
			// these two are not user configurations.
			return false;
		}
		return true;

	}

	private void analysisComboChanged(ItemEvent e) {
		if (e.getStateChange() == ItemEvent.SELECTED) {
			selectedOptions = (FileOptions) defaultOptionsCombo.getSelectedItem();
			updateDeleteButton();
			loadCurrentOptionsIntoEditors();
			// save off preference (unless it is the current program options, then don't save it)
			if (selectedOptions != currentProgramOptions) {
				Preferences.setProperty(LAST_USED_OPTIONS_CONFIG,
					selectedOptions.getName());
			}
		}
	}

	private void updateDeleteButton() {
		deleteButton.setEnabled(isUserConfiguration(selectedOptions));
	}
}

