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
package ghidra.bitpatterns.gui;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.tool.ToolConstants;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.label.GLabel;
import ghidra.bitpatterns.info.*;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.layout.PairLayout;

/**
 * 
 * The main provider for the FunctionBitPatterns plugin
 *
 */
public class FunctionBitPatternsMainProvider extends ComponentProviderAdapter
		implements OptionsChangeListener {

	//private static final String OPTIONS_TITLE = "Function Bit Pattern Explorer Options";
	private static final String NUM_FUNCS_FIELD_LABEL = "Total Number of Functions   ";
	private static final String NUM_FILES_FIELD_LABEL = "Total Number of Files   ";
	private static final String DATA_GATHERING_TEXT = "Set Data Gathering Parameters";
	private static final String DATA_SOURCE_FIELD_LABEL = "Data Source";

	private static final String FIRST_INSTRUCTIONS_LABEL = "Number of First Instructions";
	private static final String PRE_INSTRUCTIONS_LABEL = "Number of Pre-Instructions";
	private static final String RETURN_INSTRUCTIONS_LABEL = "Number of Return Instructions";

	private static final String FIRST_BYTES_LABEL = "Number of First Bytes";
	private static final String PRE_BYTES_LABEL = "Number of Pre-Bytes";
	private static final String RETURN_BYTES_LABEL = "Number of Return Bytes";

	public static final String EXPLORE_FUNCTION_PATTERNS_TEXT = "Explore Function Bit Patterns";

	private FunctionBitPatternsExplorerPlugin plugin;

	private FileBitPatternInfoReader patternReader = null;

	private JComponent component;
	private JTextField numFunctionsField;
	private JTextField numFilesField;
	private JTextField dataSourceField;

	private JTextField firstInstructionsField;
	private JTextField preInstructionsField;
	private JTextField returnInstructionsField;

	private JTextField firstBytesField;
	private JTextField preBytesField;
	private JTextField returnBytesField;

	private JTabbedPane tabbedPane;

	//first instruction pane
	private static final int FIRST_INSTRUCTION_PANEL_INDEX = 0;
	private InstructionSequenceTreePanelBuilder firstInstPanel;
	private static final String FIRST_INST_TITLE = "First Instructions Tree";

	//pre instruction tree pane 
	private static final int PRE_INSTRUCTION_PANEL_INDEX = 1;
	private InstructionSequenceTreePanelBuilder preInstPanel;
	private static final String PRE_INST_TITLE = "Pre-Instructions Tree";

	//return instructions pane
	private static final int RETURN_INSTRUCTION_PANEL_INDEX = 2;
	private InstructionSequenceTreePanelBuilder returnInstPanel;
	private static final String RETURN_INST_TITLE = "Return Instructions Tree";

	//first bytes pane
	private static final int FIRST_BYTES_PANEL_INDEX = 3;
	private ByteSequencePanelBuilder firstBytesPanel;
	private static final String FIRST_BYTES_TITLE = "First Bytes";

	//pre bytes panel
	private static final int PRE_BYTES_PANEL_INDEX = 4;
	private ByteSequencePanelBuilder preBytesPanel;
	private static final String PRE_BYTES_TITLE = "Pre-Bytes";

	//return bytes panel
	private static final int RETURN_BYTES_PANEL_INDEX = 5;
	private ByteSequencePanelBuilder returnBytesPanel;
	private static final String RETURN_BYTES_TITLE = "Return Bytes";

	//function start alignment pane 
	private static final int ALIGNMENT_PANEL_INDEX = 6;
	private static final String ALIGNMENT_PANEL_TITLE = "Function Start Alignment";
	private AlignmentPanelBuilder alignmentPanel;

	//context register info pane
	private ContextRegisterPanelBuilder contextRegisterPanel;
	private static final int CONTEXT_REGISTER_PANEL_INDEX = 7;
	private static final String CONTEXT_REGISTER_TITLE = "Context Register Information";

	private ClipboardPanel clipboard;
	private static final int CLIPBOARD_PANEL_INDEX = 8;
	private static final String CLIPBOARD_TITLE = "Pattern Clipboard";

	private boolean resetTableData;

	private static final String PATTERN_INFO_DIR =
		"FunctionBitPatternsMainProvider_PATTERN_INFO_DIR";

	private DockingAction gatherDataFromProgramAction;

	/**
	 * 
	 * @param plugin plugin associated with provider
	 */
	public FunctionBitPatternsMainProvider(FunctionBitPatternsExplorerPlugin plugin) {
		super(plugin.getTool(), "Function Bit Patterns Explorer", plugin.getName());
		this.plugin = plugin;
		component = build();
		tool = plugin.getTool();
		tool.addComponentProvider(this, false);
		initializeOptions();
		createActions();
		HelpLocation helpLocation = new HelpLocation("FunctionBitPatternsExplorerPlugin",
			"Function_Bit_Patterns_Explorer_Plugin");
		this.setHelpLocation(helpLocation);
	}

	public void updateClipboard() {
		clipboard.updateClipboard();
		clipboard.updateUI();
	}

	private JComponent build() {
		JPanel panel = new JPanel(new BorderLayout());

		panel.add(buildControlPanel(), BorderLayout.NORTH);
		tabbedPane = new JTabbedPane();

		firstInstPanel = new InstructionSequenceTreePanelBuilder(PatternType.FIRST);
		preInstPanel = new InstructionSequenceTreePanelBuilder(PatternType.PRE);
		alignmentPanel = new AlignmentPanelBuilder();

		firstBytesPanel = new ByteSequencePanelBuilder(plugin, PatternType.FIRST);
		preBytesPanel = new ByteSequencePanelBuilder(plugin, PatternType.PRE);
		returnBytesPanel = new ByteSequencePanelBuilder(plugin, PatternType.RETURN);

		contextRegisterPanel = new ContextRegisterPanelBuilder(null);

		tabbedPane.insertTab(FIRST_INST_TITLE, null, firstInstPanel.buildMainPanel(), null,
			FIRST_INSTRUCTION_PANEL_INDEX);
		firstInstPanel.enableFilterButtons(false);
		firstInstPanel.enablePercentageFilterButtons(false);
		tabbedPane.insertTab(PRE_INST_TITLE, null, preInstPanel.buildMainPanel(), null,
			PRE_INSTRUCTION_PANEL_INDEX);
		preInstPanel.enableFilterButtons(false);
		preInstPanel.enablePercentageFilterButtons(false);

		returnInstPanel = new InstructionSequenceTreePanelBuilder(PatternType.RETURN);
		returnInstPanel.enableFilterButtons(false);
		returnInstPanel.enablePercentageFilterButtons(false);
		tabbedPane.insertTab(RETURN_INST_TITLE, null, returnInstPanel.buildMainPanel(), null,
			RETURN_INSTRUCTION_PANEL_INDEX);

		tabbedPane.insertTab(FIRST_BYTES_TITLE, null, firstBytesPanel.buildMainPanel(), null,
			FIRST_BYTES_PANEL_INDEX);
		firstBytesPanel.enableFilterButtons(false);
		firstBytesPanel.enableLengthFilterButtons(false);

		tabbedPane.insertTab(PRE_BYTES_TITLE, null, preBytesPanel.buildMainPanel(), null,
			PRE_BYTES_PANEL_INDEX);
		preBytesPanel.enableFilterButtons(false);
		preBytesPanel.enableLengthFilterButtons(false);

		tabbedPane.insertTab(RETURN_BYTES_TITLE, null, returnBytesPanel.buildMainPanel(), null,
			RETURN_BYTES_PANEL_INDEX);

		tabbedPane.insertTab(ALIGNMENT_PANEL_TITLE, null, alignmentPanel.buildAlignmentPanel(),
			null, ALIGNMENT_PANEL_INDEX);
		alignmentPanel.enableFilterButtons(false);
		tabbedPane.insertTab(CONTEXT_REGISTER_TITLE, null,
			contextRegisterPanel.buildContextRegisterPanel(), null, CONTEXT_REGISTER_PANEL_INDEX);

		clipboard = new ClipboardPanel(plugin);
		tabbedPane.insertTab(CLIPBOARD_TITLE, null, clipboard, null, CLIPBOARD_PANEL_INDEX);

		panel.add(tabbedPane, BorderLayout.CENTER);
		return panel;
	}

	private Component buildControlPanel() {
		JPanel controlPanel = new JPanel();
		BoxLayout controlLayout = new BoxLayout(controlPanel, BoxLayout.Y_AXIS);
		controlPanel.setLayout(controlLayout);
		JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
		infoPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		JPanel buttonPanel = new JPanel();
		FlowLayout buttonPanelLayout = new FlowLayout(FlowLayout.CENTER);
		buttonPanel.setLayout(buttonPanelLayout);

		JButton readXMLButton = new JButton("Read XML Files");
		readXMLButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				GhidraFileChooser fileChooser = new GhidraFileChooser(component);
				fileChooser.setFileSelectionMode(GhidraFileChooser.DIRECTORIES_ONLY);
				fileChooser.setTitle("Select Directory Containing XML Files");
				String baseDir = Preferences.getProperty(PATTERN_INFO_DIR);
				if (baseDir != null) {
					fileChooser.setCurrentDirectory(new File(baseDir));
				}
				File xmlDir = fileChooser.getSelectedFile();
				if (xmlDir == null) {
					return;
				}
				Preferences.setProperty(PATTERN_INFO_DIR, xmlDir.getAbsolutePath());
				Preferences.store();
				patternReader = new FileBitPatternInfoReader(xmlDir, component);
				if (patternReader.getDataGatheringParams() == null) {
					Msg.showWarn(this, component, "Missing Data Gathering Parameters",
						"No Data Gathering Parameters Read");
					return;
				}
				dataSourceField.setText(xmlDir.getAbsolutePath());
				updatePanel();
			}

		});
		buttonPanel.add(readXMLButton);

		JButton mineProgramButton = new JButton(EXPLORE_FUNCTION_PATTERNS_TEXT);
		mineProgramButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				Program program = plugin.getCurrentProgram();
				if (program == null) {
					Msg.showWarn(this, component, "Current program null", "Please open a program");
				}
				else {
					DataGatheringParamsDialog paramDialog =
						new DataGatheringParamsDialog(DATA_GATHERING_TEXT, component);
					if (paramDialog.isCanceled) {
						return;
					}
					DataGatheringParams params = paramDialog.getDataGatheringParams();
					dataSourceField.setText(program.getName());
					patternReader = new FileBitPatternInfoReader(program, params, component);
					updatePanel();
					tabbedPane.setSelectedIndex(FIRST_INSTRUCTION_PANEL_INDEX);
				}

			}
		});
		buttonPanel.add(mineProgramButton);

		JPanel dataInfoPanel = new JPanel();
		PairLayout pairLayout = new PairLayout();
		dataInfoPanel.setLayout(pairLayout);

		dataInfoPanel.add(new GLabel(DATA_SOURCE_FIELD_LABEL));
		dataSourceField = new JTextField(70);
		dataSourceField.setEditable(false);
		dataInfoPanel.add(dataSourceField);

		dataInfoPanel.add(new GLabel(NUM_FUNCS_FIELD_LABEL));
		numFunctionsField = new JTextField(10);
		numFunctionsField.setEditable(false);
		dataInfoPanel.add(numFunctionsField);

		dataInfoPanel.add(new GLabel(NUM_FILES_FIELD_LABEL));
		numFilesField = new JTextField(10);
		numFilesField.setEditable(false);
		dataInfoPanel.add(numFilesField);

		JPanel instructionInfoPanel = new JPanel();
		PairLayout instructionLayout = new PairLayout();
		instructionInfoPanel.setLayout(instructionLayout);

		instructionInfoPanel.add(new GLabel(FIRST_INSTRUCTIONS_LABEL));
		firstInstructionsField = new JTextField(10);
		firstInstructionsField.setEditable(false);
		instructionInfoPanel.add(firstInstructionsField);

		instructionInfoPanel.add(new GLabel(PRE_INSTRUCTIONS_LABEL));
		preInstructionsField = new JTextField(10);
		preInstructionsField.setEditable(false);
		instructionInfoPanel.add(preInstructionsField);

		instructionInfoPanel.add(new GLabel(RETURN_INSTRUCTIONS_LABEL));
		returnInstructionsField = new JTextField(10);
		returnInstructionsField.setEditable(false);
		instructionInfoPanel.add(returnInstructionsField);

		JPanel bytesInfoPanel = new JPanel();
		PairLayout bytesLayout = new PairLayout();
		bytesInfoPanel.setLayout(bytesLayout);

		bytesInfoPanel.add(new GLabel(FIRST_BYTES_LABEL));
		firstBytesField = new JTextField(10);
		firstBytesField.setEditable(false);
		bytesInfoPanel.add(firstBytesField);

		bytesInfoPanel.add(new GLabel(PRE_BYTES_LABEL));
		preBytesField = new JTextField(10);
		preBytesField.setEditable(false);
		bytesInfoPanel.add(preBytesField);

		bytesInfoPanel.add(new GLabel(RETURN_BYTES_LABEL));
		returnBytesField = new JTextField(10);
		returnBytesField.setEditable(false);
		bytesInfoPanel.add(returnBytesField);

		infoPanel.add(instructionInfoPanel);
		infoPanel.add(bytesInfoPanel);
		infoPanel.add(dataInfoPanel);

		controlPanel.add(infoPanel);
		controlPanel.add(buttonPanel);
		return controlPanel;
	}

	@Override
	public JComponent getComponent() {
		return component;
	}

	private void createActions() {

		DockingAction analyzeInstructionsAction =
			new DockingAction("Analyze Selected Node", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {

					InstructionTreeContext iTreeContext = (InstructionTreeContext) context;
					iTreeContext.analyze();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return context instanceof InstructionTreeContext;
				}
			};
		analyzeInstructionsAction.setPopupMenuData(new MenuData(new String[] { "Analyze Node" }));
		analyzeInstructionsAction.setDescription(
			"Analyze all byte sequences corresponding to this instruction sequence.");
		analyzeInstructionsAction.setHelpLocation(
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Analyzing_Byte_Sequences"));
		tool.addLocalAction(this, analyzeInstructionsAction);

		DockingAction analyzeByteSeqAction =
			new DockingAction("Analyze Selected Sequences", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					ByteSequenceContext byteSeqContext = (ByteSequenceContext) context;
					byteSeqContext.analyze();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return context instanceof ByteSequenceContext;
				}
			};
		analyzeByteSeqAction.setPopupMenuData(new MenuData(new String[] { "Analyze Sequences" }));
		analyzeByteSeqAction.setHelpLocation(
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Analyzing_Byte_Sequences"));
		analyzeByteSeqAction.setDescription("Analyze Selected Byte Sequences");
		tool.addLocalAction(this, analyzeByteSeqAction);

		DockingAction evaluateSelectedAction =
			new DockingAction("Evaluate Selected Sequences", plugin.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					EvaluateContext evalContext = (EvaluateContext) context;
					evalContext.analyze();
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return context instanceof EvaluateContext;
				}
			};
		evaluateSelectedAction.setPopupMenuData(
			new MenuData(new String[] { "Evaluate Selected Patterns" }));
		evaluateSelectedAction.setDescription("Evalute Selected Patterns");
		evaluateSelectedAction.setHelpLocation(
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Evaluating_Patterns"));
		tool.addLocalAction(this, evaluateSelectedAction);

		gatherDataFromProgramAction =
			new DockingAction(EXPLORE_FUNCTION_PATTERNS_TEXT, tool.getName()) {

				@Override
				public void actionPerformed(ActionContext context) {
					Program program = plugin.getCurrentProgram();
					DataGatheringParamsDialog paramDialog =
						new DataGatheringParamsDialog(DATA_GATHERING_TEXT, component);
					if (paramDialog.isCanceled) {
						return;
					}
					DataGatheringParams params = paramDialog.getDataGatheringParams();
					dataSourceField.setText(program.getName());
					tool.showComponentProvider(FunctionBitPatternsMainProvider.this, true);
					patternReader = new FileBitPatternInfoReader(program, params, component);
					updatePanel();
					tabbedPane.setSelectedIndex(FIRST_INSTRUCTION_PANEL_INDEX);
				}

				@Override
				public boolean isEnabledForContext(ActionContext context) {
					return !(plugin.getCurrentProgram() == null);
				}

			};
		gatherDataFromProgramAction.setMenuBarData(new MenuData(
			new String[] { ToolConstants.MENU_TOOLS, EXPLORE_FUNCTION_PATTERNS_TEXT }));
		HelpLocation helpLocation = new HelpLocation("FunctionBitPatternsExplorerPlugin",
			"Function_Bit_Patterns_Explorer_Plugin");
		gatherDataFromProgramAction.setHelpLocation(helpLocation);
		tool.addAction(gatherDataFromProgramAction);
	}

	/**
	 * Removes the action from the tool.
	 */
	public void dispose() {
		firstBytesPanel.dispose();
		clipboard.dispose();
		tool.removeAction(gatherDataFromProgramAction);
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {

		if (event == null) {
			return null;
		}
		int selectedTab = tabbedPane.getSelectedIndex();

		switch (selectedTab) {
			case FIRST_INSTRUCTION_PANEL_INDEX:
				return new InstructionTreeContext(firstInstPanel);
			case PRE_INSTRUCTION_PANEL_INDEX:
				return new InstructionTreeContext(preInstPanel);
			case RETURN_INSTRUCTION_PANEL_INDEX:
				return new InstructionTreeContext(returnInstPanel);
			case FIRST_BYTES_PANEL_INDEX:
				return new ByteSequenceContext(firstBytesPanel);
			case PRE_BYTES_PANEL_INDEX:
				return new ByteSequenceContext(preBytesPanel);
			case RETURN_BYTES_PANEL_INDEX:
				return new ByteSequenceContext(returnBytesPanel);
			case CLIPBOARD_PANEL_INDEX:
				return new EvaluateContext(clipboard.getLastSelectedObjects());
			default:
				break;
		}

		return super.getActionContext(event);
	}

	class EvaluateContext extends ActionContext {
		List<PatternInfoRowObject> selectedRows;

		public EvaluateContext(List<PatternInfoRowObject> selectedRowObjects) {
			selectedRows = selectedRowObjects;
		}

		void analyze() {
			if (plugin.getCurrentProgram() == null) {
				Msg.showWarn(this, component, "Null Program", "Please open a program");
				return;
			}
			if (selectedRows.isEmpty()) {
				return;
			}
			PatternEvaluationStats currentStats = clipboard.evaluatePatterns(selectedRows);
			new PatternEvalTableProvider(currentStats, component, plugin,
				plugin.getCurrentProgram());

		}
	}

	class ByteSequenceContext extends ActionContext {
		ByteSequencePanelBuilder builder;
		List<ByteSequenceRowObject> selectedRows;

		ByteSequenceContext(ByteSequencePanelBuilder builder) {
			this.builder = builder;
			selectedRows = builder.getLastSelectedRows();
		}

		void analyze() {
			if (!builder.isLengthFiltered()) {
				Msg.showWarn(this, component, "Set Length Filter",
					"You must apply a length filter before analyzing sequences of bytes.");
				return;
			}

			new PatternMiningAnalyzerProvider(plugin, selectedRows, component, builder.getType(),
				builder.getContextRegisterFilter());

		}
	}

	class InstructionTreeContext extends ActionContext {
		private FunctionBitPatternsGTree tree;
		private TreePath path;

		InstructionTreeContext(InstructionSequenceTreePanelBuilder panelBuilder) {
			this.tree = panelBuilder.getGTree();
			this.path = panelBuilder.getSelectionPath();
		}

		void analyze() {
			if (tree == null) {
				return;
			}
			if (path == null) {
				return;
			}
			PatternType type = tree.getType();
			InstructionSequenceTreePathFilter pathFilter =
				new InstructionSequenceTreePathFilter(path, type);
			ContextRegisterFilter cRegFilter = null;
			switch (type) {
				case FIRST:
					cRegFilter = firstInstPanel.getContextRegisterFilter();
					break;
				case PRE:
					cRegFilter = preInstPanel.getContextRegisterFilter();
					break;
				case RETURN:
					cRegFilter = returnInstPanel.getContextRegisterFilter();
					break;
				default:
					throw new IllegalArgumentException("Unsupported type " + type.name());
			}
			List<ByteSequenceRowObject> rowObjects =
				ByteSequenceRowObject.getRowObjectsFromInstructionSequences(
					patternReader.getFInfoList(), pathFilter, cRegFilter);
			new SimpleByteSequenceAnalyzerProvider(plugin, pathFilter.toString(), cRegFilter,
				rowObjects, component, type);
		}
	}

	public boolean resetExistingTableData() {
		return resetTableData;
	}

	private void updatePanel() {
		int selectedTab = tabbedPane.getSelectedIndex();

		//set the number of files and the number of functions 
		numFunctionsField.setText(Integer.toString(patternReader.getNumFuncs()));
		numFilesField.setText(Integer.toString(patternReader.getNumFiles()));

		//set the gathering info fields
		DataGatheringParams params = patternReader.getDataGatheringParams();
		firstInstructionsField.setText(Integer.toString(params.getNumFirstInstructions()));
		preInstructionsField.setText(Integer.toString(params.getNumPreInstructions()));
		returnInstructionsField.setText(Integer.toString(params.getNumReturnInstructions()));
		firstBytesField.setText(Integer.toString(params.getNumFirstBytes()));
		preBytesField.setText(Integer.toString(params.getNumPreBytes()));
		returnBytesField.setText(Integer.toString(params.getNumReturnBytes()));

		//update context register info
		tabbedPane.removeTabAt(CONTEXT_REGISTER_PANEL_INDEX);
		contextRegisterPanel =
			new ContextRegisterPanelBuilder(patternReader.getContextRegisterExtent().toString());
		tabbedPane.insertTab(CONTEXT_REGISTER_TITLE, null,
			contextRegisterPanel.buildContextRegisterPanel(), null, CONTEXT_REGISTER_PANEL_INDEX);

		//update the tree of first instructions
		firstInstPanel.setFsReaderAndUpdateExtent(patternReader);

		//update the tree of pre instructions
		preInstPanel.setFsReaderAndUpdateExtent(patternReader);

		//update the tree of return instructions
		returnInstPanel.setFsReaderAndUpdateExtent(patternReader);

		//enable the analyze sequence buttons
		//these should only be null if no xml has been loaded (i.e. on startup, or if the user selected
		//a directory with no xml files)
		if (!firstInstPanel.isTreeEmpty()) {
			firstInstPanel.enablePercentageFilterButtons(true);
		}
		if (!preInstPanel.isTreeEmpty()) {
			preInstPanel.enablePercentageFilterButtons(true);
		}

		//update the first bytes panel
		firstBytesPanel.setFsReader(patternReader);
		firstBytesPanel.enableLengthFilterButtons(true);

		//update the pre bytes panel
		preBytesPanel.setFsReader(patternReader);
		preBytesPanel.enableLengthFilterButtons(true);

		//update the return bytes panel
		returnBytesPanel.setFsReader(patternReader);
		returnBytesPanel.enableLengthFilterButtons(true);

		//update the alignment information	
		alignmentPanel.resetModulus();
		alignmentPanel.updateExtentAndClearFilter(patternReader.getContextRegisterExtent());
		alignmentPanel.setFsReader(patternReader);
		alignmentPanel.updateAlignmentPanel();

		//enable or disable the context register filter buttons
		boolean shouldBeOn =
			(!patternReader.getContextRegisterExtent().getContextRegisters().isEmpty());
		firstInstPanel.enableFilterButtons(shouldBeOn);
		preInstPanel.enableFilterButtons(shouldBeOn);
		alignmentPanel.enableFilterButtons(shouldBeOn);
		firstBytesPanel.enableFilterButtons(shouldBeOn);
		preBytesPanel.enableFilterButtons(shouldBeOn);
		returnInstPanel.enableFilterButtons(shouldBeOn);
		returnBytesPanel.enableFilterButtons(shouldBeOn);

		//restore the selected tab
		tabbedPane.setSelectedIndex(selectedTab);

		//clear any patterns in the clipboard
		plugin.clearPatterns();
		clipboard.updateClipboard();

		return;
	}

	//==================================================================================================
	// Options Methods
	//==================================================================================================

	//TODO
	private void initializeOptions() {
		return;
	}

	// Options changed callback
	@Override
	public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
			Object newValue) {
		return;
	}

}
