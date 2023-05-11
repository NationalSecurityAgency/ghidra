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
package ghidra.machinelearning.functionfinding;

import java.awt.BorderLayout;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.LongStream;

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.ReusableDialogComponentProvider;
import docking.action.DockingAction;
import docking.action.builder.ActionBuilder;
import docking.widgets.combobox.GComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.GThreadedTablePanel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.DataTreeDialog;
import ghidra.framework.model.DomainFile;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.*;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.*;

/**
 * This class creates a dialog window for the user to enter data mining parameters
 * for learning function starts, train models, see performance statistics, and
 * apply the models.
 */
public class FunctionStartRFParamsDialog extends ReusableDialogComponentProvider {

	private static final String INITIAL_BYTES_TEXT = "Number of Initial Bytes (CSV)";
	private static final String INITIAL_BYTES_TIP =
		"Number of initial bytes of a function to record";

	private static final String PRE_BYTES_TEXT = "Number of Pre-bytes (CSV)";
	private static final String PRE_BYTES_TIP =
		"Number of bytes immediately before a function start to record";

	private static final String MIN_FUNC_SIZE_TEXT = "Minimum Function Size";
	private static final String MIN_FUNC_SIZE_TIP =
		"Functions whose size in bytes are below this number are skipped";

	private static final String CONTEXT_REGISTER_TEXT = "Context Registers and Values (CSV)";
	private static final String CONTEXT_REGISTER_TIP =
		"Restrict gathering to functions where context registers have been set." +
			" Form: cReg1=x,cReg2=y,...";

	private static final String FACTOR_TEXT = "Start to Non-start Sampling Factors (CSV)";
	private static final String FACTOR_TIP =
		"Number of non-starts to gather for each function start";

	private static final String MAX_STARTS_TEXT = "Maximum Number of Starts";
	private static final String MAX_STARTS_TIP = "Maximum number of function starts to gather";

	private static final String INCLUDE_PRECEDING_FOLLOWING_TEXT =
		"Include Preceding and Following";
	private static final String INCLUDE_PRECEDING_FOLLOWING_TIP =
		"Include code units immediately before and after a function start when testing and training";

	private static final String INCLUDE_BIT_FEATURES_TEXT = "Include Bit Features";
	private static final String INCLUDE_BIT_FEATURES_TIP =
		"Include bit-level features.  May improve models; will increase computation time.";

	private static final String FUNCTIONS_MEETING_SIZE_TEXT = "Functions Meeting Size Bound";
	private static final String FUNCTIONS_MEETING_SIZE_TIP =
		"Number of functions meeting the size " + "bound";

	private static final String RESTRICT_SEARCH_TEXT = "Restrict Search To Aligned Addresses ";
	private static final String RESTRICT_SEARCH_TIP =
		"Only apply model to aligned addresses.  NOTE:" + "Does not affect training or test sets!";

	private static final String ALIGNMENT_MODULUS_TEXT = "Alignment Modulus";
	private static final String ALIGNMENT_MODULUS_TIP =
		"Use to define the alignment for restricted search";

	private static final String DEFAULT_INITIAL_BYTES = "8,16";
	private static final String INITIAL_BYTES_PROPERTY = "functionStartRFParams_initialBytes";
	private static final String DEFAULT_PRE_BYTES = "2,8";
	private static final String PRE_BYTES_PROPERTY = "functionStartRFParams_preBytes";
	private static final String DEFAULT_MINIMUM_FUNCTION_SIZE = "16";
	private static final String MIN_FUNC_SIZE_PROPERTY = "functionStartRFParams_minFuncSize";
	private static final String DEFAULT_CONTEXT_REGISTERS = "";
	private static final String CONTEXT_REGISTER_PROPERTY = "functionStartRFParams_cRegs";
	private static final String DEFAULT_FACTOR = "10,50";
	private static final String FACTOR_PROPERTY = "functionStartRFParams_factor";
	private static final String DEFAULT_MAX_STARTS = "1000";
	private static final String MAX_STARTS_PROPERTY = "functionStartRFParams_maxStarts";
	private static final String INCLUDE_PRECEDING_AND_FOLLOWING_PROPERTY =
		"functionStartRFParams_use_pf";
	private static final String DEFAULT_INCLUDE_PF = "True";
	private static final String INCLUDE_BIT_FEATURES_PROPERTY =
		"funcstionStartRFParams_includeBitFeatures";
	private static final String DEFAULT_INCLUDE_BIT_FEATURES = "False";

	private static final String DATA_GATHERING_PARAMETERS = "Data Gathering Parameters";
	private static final String MODEL_STATISTICS = "Model Statistics";
	private static final String TITLE = "Random Forest Function Finder";
	private static final String FUNCTION_INFO = "Function Information";

	private static final String APPLY_MODEL_ACTION_NAME = "ApplyModel";
	private static final String APPLY_MODEL_MENU_TEXT = "Apply Model";
	private static final String APPLY_MODEL_TO_ACTION_NAME = "ApplyModelTo";
	private static final String APPLY_MODEL_TO_MENU_TEXT = "Apply Model To...";
	private static final String DEBUG_MODEL_ACTION_NAME = "DebugModel";
	private static final String DEBUG_MODEL_MENU_TEXT = "DEBUG - Show test set errors";

	private JTextField initialBytesField;
	private JTextField preBytesField;
	private JTextField factorField;
	private IntegerTextField minimumSizeField;
	private IntegerTextField maxStartsField;
	private JTextField contextRegistersField;
	private JLabel numFuncsField;
	private JScrollPane tableScrollPane;
	private JPanel funcInfoPanel;

	private RandomForestFunctionFinderPlugin plugin;
	private List<RandomForestRowObject> rowObjects;
	private RandomForestTableModel tableModel;
	private Program trainingSource;
	private FunctionStartRFParams params;
	private Vector<Long> moduli = new Vector<>(Arrays.asList(new Long[] { 4l, 8l, 16l, 32l }));
	private GComboBox<Long> modBox;
	private JButton trainButton;
	private JCheckBox includeBeforeAndAfterBox;
	private JCheckBox includeBitFeaturesBox;
	private JCheckBox restrictBox;
	private JButton restoreDefaultsButton;

	/**
	 * Creates a dialog for training models to find function starts using the
	 * current program of {@code plugin}.
	 * @param plugin plugin owning this dialog
	 */
	public FunctionStartRFParamsDialog(RandomForestFunctionFinderPlugin plugin) {
		super(TITLE + ": " + plugin.getCurrentProgram().getDomainFile().getPathname(), false, true,
			true, true);
		this.plugin = plugin;
		rowObjects = new ArrayList<>();
		trainingSource = plugin.getCurrentProgram();
		JPanel panel = createWorkPanel();
		addWorkPanel(panel);
		trainButton = addTrainModelsButton();
		addHideDialogButton();
		addRestoreDefaultsButton();
		setHelpLocation(new HelpLocation(plugin.getName(), plugin.getName()));
	}

	@Override
	public void taskCompleted(Task task) {
		super.taskCompleted(task);
		setStatusText("Training Completed");
		setEnabled(true);
	}

	@Override
	public void taskCancelled(Task task) {
		super.taskCancelled(task);
		setStatusText("Training Canceled");
		setEnabled(true);
	}

	/**
	 * Returns the program used to train the models
	 * @return source program
	 */
	Program getTrainingSource() {
		return trainingSource;
	}

	@Override
	protected void dismissCallback() {
		TaskMonitorComponent monitorComp = getTaskMonitorComponent();
		if (monitorComp != null) {
			monitorComp.cancel();
		}
		setStatusText("");
		//rows in the table can have large objects as fields
		//make sure that memory is reclaimed
		tableModel.dispose();
		rowObjects.clear();
		plugin.resetDialog();
		dispose();
	}

	private FunctionStartRFParams getMachineLearningParams() {
		FunctionStartRFParams rfParams = new FunctionStartRFParams(trainingSource);
		List<Integer> preBytes = FunctionStartRFParams.parseIntegerCSV(preBytesField.getText());
		rfParams.setPreBytes(preBytes);
		List<Integer> initialBytes =
			FunctionStartRFParams.parseIntegerCSV(initialBytesField.getText());
		rfParams.setInitialBytes(initialBytes);
		List<Integer> factors = FunctionStartRFParams.parseIntegerCSV(factorField.getText());
		rfParams.setFactors(factors);
		int minSize = minimumSizeField.getIntValue();
		if (minSize <= 0) {
			Msg.showWarn(this, null, "Invalid Minimum Size", "Minimum size must be positive!");
			return null;
		}
		rfParams.setMinFuncSize(minSize);

		int maxStarts = maxStartsField.getIntValue();
		if (maxStarts <= 0) {
			Msg.showWarn(this, null, "Invalid Max Starts", "Max Starts must be positive!");
			return null;
		}
		rfParams.setMaxStarts(maxStarts);

		String csv = contextRegistersField.getText();
		if (!StringUtils.isBlank(csv)) {
			try {
				rfParams.setRegistersAndValues(csv);
			}
			catch (IllegalArgumentException e) {
				Msg.showError(factors, null, "Context Register/Value Error", e);
				return null;
			}
		}
		rfParams.setIncludePrecedingAndFollowing(includeBeforeAndAfterBox.isSelected());
		rfParams.setIncludeBitFeatures(includeBitFeaturesBox.isSelected());
		setProperties();
		return rfParams;
	}

	private void trainModelsCallback() {
		rowObjects.clear();
		tableModel.reload();
		params = getMachineLearningParams();
		if (params == null) {
			return;
		}
		RandomForestTrainingTask trainingTask = new RandomForestTrainingTask(trainingSource, params,
			r -> tableModel.addObject(r), plugin.getTestMaxSize());
		trainingTask.addTaskListener(this);
		setEnabled(false);
		executeProgressTask(trainingTask, 500);
	}

	private JButton addTrainModelsButton() {
		JButton trainModelsButton = new JButton("Train");
		trainModelsButton.setToolTipText("Train models using the specified parameters");
		trainModelsButton.addActionListener(e -> trainModelsCallback());
		addButton(trainModelsButton);
		return trainModelsButton;
	}

	private JPanel createWorkPanel() {
		JPanel mainPanel = new JPanel(new BorderLayout());

		tableModel = new RandomForestTableModel(plugin.getTool(), rowObjects);
		GThreadedTablePanel<RandomForestRowObject> evalPanel =
			new GThreadedTablePanel<>(tableModel);
		GTable modelStatsTable = evalPanel.getTable();
		modelStatsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		evalPanel.setBorder(BorderFactory.createTitledBorder(MODEL_STATISTICS));
		mainPanel.add(evalPanel, BorderLayout.CENTER);

		DockingAction applyAction = new ActionBuilder(APPLY_MODEL_ACTION_NAME, plugin.getName())
				.description("Apply Model to Source Program")
				.popupWhen(c -> trainingSource != null)
				.enabledWhen(c -> tableModel.getLastSelectedObjects().size() == 1)
				.popupMenuPath(APPLY_MODEL_MENU_TEXT)
				.inWindow(ActionBuilder.When.ALWAYS)
				.onAction(c -> {
					searchTrainingProgram(tableModel.getLastSelectedObjects().get(0));
				})
				.build();
		addAction(applyAction);

		DockingAction applyToAction =
			new ActionBuilder(APPLY_MODEL_TO_ACTION_NAME, plugin.getName())
					.description("Choose Program and Apply Model to it")
					.popupWhen(c -> trainingSource != null)
					.enabledWhen(c -> tableModel.getLastSelectedObjects().size() == 1)
					.popupMenuPath(APPLY_MODEL_TO_MENU_TEXT)
					.inWindow(ActionBuilder.When.ALWAYS)
					.onAction(c -> {
						searchOtherProgram(tableModel.getLastSelectedObjects().get(0));
					})
					.build();
		addAction(applyToAction);

		DockingAction checkAction = new ActionBuilder(DEBUG_MODEL_ACTION_NAME, plugin.getName())
				.description("Show Test Set Errors")
				.popupWhen(c -> trainingSource != null)
				.enabledWhen(c -> tableModel.getLastSelectedObjects().size() == 1)
				.popupMenuPath(DEBUG_MODEL_MENU_TEXT)
				.inWindow(ActionBuilder.When.ALWAYS)
				.onAction(c -> {
					showTestErrors(tableModel.getLastSelectedObjects().get(0));
				})
				.build();
		addAction(checkAction);

		JPanel paramsPanel = new JPanel();
		paramsPanel.setBorder(BorderFactory.createTitledBorder(DATA_GATHERING_PARAMETERS));
		PairLayout pairLayout = new PairLayout();
		paramsPanel.setLayout(pairLayout);

		JLabel preLabel = new GDLabel(PRE_BYTES_TEXT);
		preLabel.setToolTipText(PRE_BYTES_TIP);
		paramsPanel.add(preLabel);
		preBytesField = new JTextField();
		String preBytes = Preferences.getProperty(PRE_BYTES_PROPERTY, DEFAULT_PRE_BYTES);
		preBytesField.setText(preBytes);
		paramsPanel.add(preBytesField);

		JLabel initialLabel = new GDLabel(INITIAL_BYTES_TEXT);
		initialLabel.setToolTipText(INITIAL_BYTES_TIP);
		paramsPanel.add(initialLabel);
		initialBytesField = new JTextField();
		String initialBytes =
			Preferences.getProperty(INITIAL_BYTES_PROPERTY, DEFAULT_INITIAL_BYTES);
		initialBytesField.setText(initialBytes);
		paramsPanel.add(initialBytesField);

		JLabel factorLabel = new GDLabel(FACTOR_TEXT);
		factorLabel.setToolTipText(FACTOR_TIP);
		paramsPanel.add(factorLabel);
		factorField = new JTextField();
		String factor = Preferences.getProperty(FACTOR_PROPERTY, DEFAULT_FACTOR);
		factorField.setText(factor);
		paramsPanel.add(factorField);

		JLabel maxStartsLabel = new GDLabel(MAX_STARTS_TEXT);
		maxStartsLabel.setToolTipText(MAX_STARTS_TIP);
		paramsPanel.add(maxStartsLabel);
		maxStartsField = new IntegerTextField();
		String maxStarts = Preferences.getProperty(MAX_STARTS_PROPERTY, DEFAULT_MAX_STARTS);
		maxStartsField.setValue(Integer.parseInt(maxStarts));
		paramsPanel.add(maxStartsField.getComponent());

		JLabel contextLabel = new GDLabel(CONTEXT_REGISTER_TEXT);
		contextLabel.setToolTipText(CONTEXT_REGISTER_TIP);
		paramsPanel.add(contextLabel);
		contextRegistersField = new JTextField(DEFAULT_CONTEXT_REGISTERS);
		String cRegs = Preferences.getProperty(CONTEXT_REGISTER_PROPERTY, "");
		if (!StringUtils.isEmpty(cRegs)) {
			contextRegistersField.setText(cRegs);
		}
		paramsPanel.add(contextRegistersField);

		JLabel includeBeforeAndAfterLabel = new JLabel(INCLUDE_PRECEDING_FOLLOWING_TEXT);
		includeBeforeAndAfterLabel.setToolTipText(INCLUDE_PRECEDING_FOLLOWING_TIP);
		includeBeforeAndAfterBox = new JCheckBox();
		String defaultUseBeforeAfter =
			Preferences.getProperty(INCLUDE_PRECEDING_AND_FOLLOWING_PROPERTY, DEFAULT_INCLUDE_PF);
		includeBeforeAndAfterBox.setSelected(Boolean.valueOf(defaultUseBeforeAfter));
		paramsPanel.add(includeBeforeAndAfterLabel);
		paramsPanel.add(includeBeforeAndAfterBox);

		JLabel includeSelectionLabel = new JLabel(INCLUDE_BIT_FEATURES_TEXT);
		includeSelectionLabel.setToolTipText(INCLUDE_BIT_FEATURES_TIP);
		includeBitFeaturesBox = new JCheckBox();
		String defaultIncludeBitFeatures =
			Preferences.getProperty(INCLUDE_BIT_FEATURES_PROPERTY, DEFAULT_INCLUDE_BIT_FEATURES);
		includeBitFeaturesBox.setSelected(Boolean.valueOf(defaultIncludeBitFeatures));
		paramsPanel.add(includeSelectionLabel);
		paramsPanel.add(includeBitFeaturesBox);

		JLabel minFuncLabel = new GDLabel(MIN_FUNC_SIZE_TEXT);
		minFuncLabel.setToolTipText(MIN_FUNC_SIZE_TIP);
		paramsPanel.add(minFuncLabel);
		minimumSizeField = new IntegerTextField();
		String minSize =
			Preferences.getProperty(MIN_FUNC_SIZE_PROPERTY, DEFAULT_MINIMUM_FUNCTION_SIZE);
		minimumSizeField.setValue(Integer.parseInt(minSize));
		minimumSizeField.addChangeListener(e -> {
			updateNumFuncsField();
			updateModulusTable();
		});
		paramsPanel.add(minimumSizeField.getComponent());

		JPanel funcDataPanel = new JPanel();
		pairLayout = new PairLayout();
		funcDataPanel.setLayout(pairLayout);

		JLabel numFuncsLabel = new GDLabel(FUNCTIONS_MEETING_SIZE_TEXT);
		numFuncsLabel.setToolTipText(FUNCTIONS_MEETING_SIZE_TIP);
		funcDataPanel.add(numFuncsLabel);
		numFuncsField = new GDLabel();
		updateNumFuncsField();
		funcDataPanel.add(numFuncsField);

		JLabel restrictLabel = new GDLabel(RESTRICT_SEARCH_TEXT);
		restrictLabel.setToolTipText(RESTRICT_SEARCH_TIP);
		funcDataPanel.add(restrictLabel);
		restrictBox = new JCheckBox();
		funcDataPanel.add(restrictBox);

		JLabel modulusLabel = new GDLabel(ALIGNMENT_MODULUS_TEXT);
		modulusLabel.setToolTipText(ALIGNMENT_MODULUS_TIP);
		funcDataPanel.add(modulusLabel);
		modBox = new GComboBox<>(moduli);
		modBox.setSelectedItem(Long.valueOf(16));
		modBox.addActionListener(e -> updateModulusTable());
		funcDataPanel.add(modBox);

		tableScrollPane = getFuncAlignmentScrollPane();

		funcInfoPanel = new JPanel();
		funcInfoPanel.setLayout(new BorderLayout());
		funcInfoPanel.setBorder(BorderFactory.createTitledBorder(FUNCTION_INFO));
		funcInfoPanel.add(funcDataPanel, BorderLayout.NORTH);
		funcInfoPanel.add(tableScrollPane, BorderLayout.CENTER);

		JPanel infoPanel = new JPanel(new BorderLayout());
		infoPanel.add(paramsPanel, BorderLayout.NORTH);
		infoPanel.add(funcInfoPanel, BorderLayout.CENTER);
		mainPanel.add(infoPanel, BorderLayout.WEST);
		return mainPanel;
	}

	private JScrollPane getFuncAlignmentScrollPane() {
		Long modulus = (Long) modBox.getSelectedItem();
		int minSize = minimumSizeField.getIntValue();
		//initialize map
		Map<Long, Long> countMap =
			LongStream.range(0, modulus).boxed().collect(Collectors.toMap(i -> i, i -> 0l));
		FunctionIterator fIter = trainingSource.getFunctionManager().getFunctionsNoStubs(true);
		//needs some thought to determine how to display number of functions compatible
		//with context register restrictions
		for (Function f : fIter) {
			if ((f.getBody().getNumAddresses() >= minSize) &&
				(params == null || params.isContextCompatible(f.getEntryPoint()))) {
				countMap.merge(f.getEntryPoint().getOffset() % modulus, 1l, Long::sum);
			}
		}
		List<FunctionStartAlignmentRowObject> rows = countMap.entrySet()
				.stream()
				.map(e -> new FunctionStartAlignmentRowObject(e.getKey(), e.getValue()))
				.collect(Collectors.toList());
		FunctionStartAlignmentTableModel alignModel = new FunctionStartAlignmentTableModel(rows);
		GTable alignTable = new GTable(alignModel);
		return new JScrollPane(alignTable);
	}

	private void updateModulusTable() {
		funcInfoPanel.remove(tableScrollPane);
		tableScrollPane = getFuncAlignmentScrollPane();

		funcInfoPanel.add(tableScrollPane);
		getComponent().updateUI();
	}

	private void updateNumFuncsField() {
		int numFuncs = 0;
		long bound = minimumSizeField.getLongValue();
		for (Function func : trainingSource.getFunctionManager().getFunctionsNoStubs(true)) {
			if (func.getBody().getNumAddresses() >= bound) {
				numFuncs += 1;
			}
		}
		numFuncsField.setText(Integer.toString(numFuncs));
	}

	private void searchTrainingProgram(RandomForestRowObject modelRow) {
		searchProgram(trainingSource, modelRow);
	}

	private void searchOtherProgram(RandomForestRowObject modelRow) {
		DataTreeDialog dtd = new DataTreeDialog(null, "Select Program", DataTreeDialog.OPEN, f -> {
			Class<?> c = f.getDomainObjectClass();
			return Program.class.isAssignableFrom(c);
		});
		dtd.show();
		DomainFile dFile = dtd.getDomainFile();
		if (dFile == null) {
			return;
		}
		ProgramManager pm = plugin.getTool().getService(ProgramManager.class);
		Program p = pm.openProgram(dFile, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_VISIBLE);
		if (p == null) {
			return;
		}
		if (!isProgramCompatible(p)) {
			Msg.showWarn(this, null, "Incompatible Program", p.getName() +
				" is not compatible with training source program " + trainingSource.getName());
			return;
		}
		searchProgram(p, modelRow);
	}

	private void showTestErrors(RandomForestRowObject modelRow) {
		FunctionStartTableProvider provider = new FunctionStartTableProvider(plugin, trainingSource,
			modelRow.getTestErrors(), modelRow, true);
		addGeneralActions(provider, trainingSource);
	}

	private void searchProgram(Program targetProgram, RandomForestRowObject modelRow) {
		GetAddressesToClassifyTask getTask =
			new GetAddressesToClassifyTask(targetProgram, plugin.getMinUndefinedRangeSize());
		//don't want to use the dialog's progress bar
		TaskLauncher.launchModal("Gathering Addresses To Classify", getTask);
		if (getTask.isCancelled()) {
			return;
		}
		AddressSet execNonFunc = null;
		if (restrictBox.isSelected()) {
			execNonFunc = getTask.getAddressesToClassify((long) modBox.getSelectedItem());
		}
		else {
			execNonFunc = getTask.getAddressesToClassify();
		}
		FunctionStartTableProvider provider =
			new FunctionStartTableProvider(plugin, targetProgram, execNonFunc, modelRow, false);
		addGeneralActions(provider, targetProgram);
		DisassembleFunctionStartsAction disassembleAction = null;
		if (params.isRestrictedByContext()) {
			disassembleAction = new DisassembleAndApplyContextAction(plugin, targetProgram,
				provider.getTable(), provider.getTableModel());
		}
		else {
			disassembleAction = new DisassembleFunctionStartsAction(plugin, targetProgram,
				provider.getTable(), provider.getTableModel());
		}
		plugin.getTool().addLocalAction(provider, disassembleAction);
		CreateFunctionsAction createActions = new CreateFunctionsAction(plugin, targetProgram,
			provider.getTable(), provider.getTableModel());
		plugin.getTool().addLocalAction(provider, createActions);

	}

	private void addGeneralActions(FunctionStartTableProvider provider, Program targetProgram) {
		plugin.addProvider(provider);
		DockingAction programSelectAction =
			new MakeProgramSelectionAction(plugin, provider.getTable());
		programSelectAction.setEnabled(true);
		plugin.getTool().addLocalAction(provider, programSelectAction);
		DockingAction selectNavigationAction =
			new SelectionNavigationAction(plugin, provider.getTable());
		plugin.getTool().addLocalAction(provider, selectNavigationAction);
		ShowSimilarStartsAction similarStarts = new ShowSimilarStartsAction(plugin, trainingSource,
			targetProgram, provider.getTable(), provider.getTableModel());
		plugin.getTool().addLocalAction(provider, similarStarts);
	}

	//checks whether otherProgram contains any specified context registers
	//at some point might be worth adding more restrictions
	private boolean isProgramCompatible(Program otherProgram) {
		if (params == null) {
			//shouldn't happen
			throw new IllegalStateException("null params");
		}
		if (!params.isRestrictedByContext()) {
			return true;
		}
		for (String regName : params.getContextRegisterNames()) {
			if (otherProgram.getRegister(regName) == null) {
				Msg.showError(this, null, "Error Applying Model", "Program " +
					otherProgram.getName() + " does not have a context register named " + regName);
				return false;
			}
		}
		return true;
	}

	private void setEnabled(boolean b) {
		minimumSizeField.setEnabled(b);
		initialBytesField.setEnabled(b);
		preBytesField.setEnabled(b);
		factorField.setEnabled(b);
		minimumSizeField.setEnabled(b);
		maxStartsField.setEnabled(b);
		trainButton.setEnabled(b);
		contextRegistersField.setEnabled(b);
		includeBeforeAndAfterBox.setEnabled(b);
		includeBitFeaturesBox.setEnabled(b);
		restoreDefaultsButton.setEnabled(b);
	}

	private void addRestoreDefaultsButton() {
		restoreDefaultsButton = new JButton("Restore Defaults");
		restoreDefaultsButton.setToolTipText("Restore training parameters to the default values");
		restoreDefaultsButton.addActionListener(e -> restoreDefaults());
		addButton(restoreDefaultsButton);
	}

	private void addHideDialogButton() {
		JButton hideDialogButton = new JButton("Hide Dialog");
		hideDialogButton.setToolTipText("Hide Dialog (does not cancel training or destory models)");
		hideDialogButton.addActionListener(e -> close());
		addButton(hideDialogButton);
	}

	private void restoreDefaults() {
		initialBytesField.setText(DEFAULT_INITIAL_BYTES);
		preBytesField.setText(DEFAULT_PRE_BYTES);
		minimumSizeField.setValue((Integer.parseInt(DEFAULT_MINIMUM_FUNCTION_SIZE)));
		maxStartsField.setValue(Integer.parseInt(DEFAULT_MAX_STARTS));
		factorField.setText(DEFAULT_FACTOR);
		includeBeforeAndAfterBox.setSelected(Boolean.valueOf(DEFAULT_INCLUDE_PF));
		includeBitFeaturesBox.setSelected(Boolean.valueOf(DEFAULT_INCLUDE_BIT_FEATURES));
		contextRegistersField.setText(null);
		setProperties();
	}

	private void setProperties() {
		Preferences.setProperty(INITIAL_BYTES_PROPERTY, initialBytesField.getText());
		Preferences.setProperty(PRE_BYTES_PROPERTY, preBytesField.getText());
		Preferences.setProperty(MIN_FUNC_SIZE_PROPERTY, minimumSizeField.getText());
		Preferences.setProperty(MAX_STARTS_PROPERTY, maxStartsField.getText());
		Preferences.setProperty(FACTOR_PROPERTY, factorField.getText());
		if (StringUtils.isBlank(contextRegistersField.getText())) {
			Preferences.removeProperty(CONTEXT_REGISTER_PROPERTY);
		}
		else {
			Preferences.setProperty(CONTEXT_REGISTER_PROPERTY, contextRegistersField.getText());
		}
		Preferences.setProperty(INCLUDE_PRECEDING_AND_FOLLOWING_PROPERTY,
			Boolean.toString(includeBeforeAndAfterBox.isSelected()));
		Preferences.setProperty(DEFAULT_INCLUDE_BIT_FEATURES,
			Boolean.toString(includeBitFeaturesBox.isSelected()));
	}
}
