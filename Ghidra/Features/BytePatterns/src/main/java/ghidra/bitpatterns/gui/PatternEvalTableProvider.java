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

import javax.swing.*;

import docking.WindowPosition;
import docking.widgets.label.GLabel;
import ghidra.app.services.GoToService;
import ghidra.bitpatterns.info.*;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.table.*;

/**
 * This class is a provider for the table to display pattern evaluation information
 */
public class PatternEvalTableProvider extends ComponentProviderAdapter {

	private JPanel mainPanel;

	/**
	 * Creates a provider for a Pattern Evaluation table
	 * @param currentStats {@link PatternEvaluationStats} object to display in the table
	 * @param parent parent {@link Component} of this provider
	 * @param plugin plugin associated with this table
	 * @param program program being analyzed
	 */
	protected PatternEvalTableProvider(PatternEvaluationStats currentStats, Component parent,
			FunctionBitPatternsExplorerPlugin plugin, Program program) {
		super(plugin.getTool(), "Pattern Evaluator", plugin.getName());
		this.setTransient();
		buildMainPanel(plugin, program, currentStats);
		this.setDefaultWindowPosition(WindowPosition.WINDOW);
		plugin.getTool().addComponentProvider(this, true);
		HelpLocation helpLocation =
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Evaluating_Patterns");
		setHelpLocation(helpLocation);
	}

	private void buildMainPanel(FunctionBitPatternsExplorerPlugin plugin, Program program,
			PatternEvaluationStats stats) {
		mainPanel = new JPanel();
		BoxLayout topLayout = new BoxLayout(mainPanel, BoxLayout.Y_AXIS);
		mainPanel.setLayout(topLayout);
		JPanel patternPanel = new JPanel(new BorderLayout());
		PatternEvalTabelModel patternEvalModel =
			new PatternEvalTabelModel(plugin, program, stats.getRowObjects());
		GhidraThreadedTablePanel<PatternEvalRowObject> threadedPanel =
			new GhidraThreadedTablePanel<>(patternEvalModel, 1000);
		GhidraTable table = threadedPanel.getTable();

		GoToService goToService = tool.getService(GoToService.class);
		if (goToService != null) {
			table.installNavigation(goToService, goToService.getDefaultNavigatable());
		}
		table.setRowSelectionAllowed(true);
		table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
		table.setPreferredScrollableViewportSize(new Dimension(1200, 700));
		GhidraTableFilterPanel<PatternEvalRowObject> tableFilterPanel =
			new GhidraTableFilterPanel<>(table, patternEvalModel);
		patternPanel.add(threadedPanel, BorderLayout.CENTER);
		patternPanel.add(tableFilterPanel, BorderLayout.SOUTH);

		JPanel evalPanel = buildInfoPanel(stats);
		patternPanel.add(evalPanel, BorderLayout.NORTH);
		mainPanel.add(patternPanel);

		JPanel buttonPanel = new JPanel(new FlowLayout());

		JButton highlightButton = new JButton("Highlight Selected");
		highlightButton.addActionListener(e -> {
			AddressSet toHighlight = new AddressSet();
			for (PatternEvalRowObject row : tableFilterPanel.getSelectedItems()) {
				toHighlight.add(row.getMatchedSet());
			}
			plugin.highlightMatches(toHighlight);
		});

		JButton clearButton = new JButton("Clear Highlights");
		clearButton.addActionListener(e -> plugin.highlightMatches(new AddressSet()));

		JButton dismissButton = new JButton("Dismiss");
		dismissButton.addActionListener(e -> closeComponent());

		buttonPanel.add(highlightButton);
		buttonPanel.add(clearButton);
		buttonPanel.add(dismissButton);

		mainPanel.add(buttonPanel);
	}

	private JPanel buildInfoPanel(PatternEvaluationStats stats) {
		JPanel evalPanel = new JPanel(new GridLayout(2, 8));
		evalPanel.add(new GLabel("Match Type"));
		evalPanel.add(new GLabel(PatternMatchType.TRUE_POSITIVE.name()));
		evalPanel.add(new GLabel(PatternMatchType.FP_WRONG_FLOW.name()));
		evalPanel.add(new GLabel(PatternMatchType.FP_MISALIGNED.name()));
		evalPanel.add(new GLabel(PatternMatchType.FP_DATA.name()));
		evalPanel.add(new GLabel(PatternMatchType.POSSIBLE_START_CODE.name()));
		evalPanel.add(new GLabel(PatternMatchType.POSSIBLE_START_UNDEFINED.name()));
		evalPanel.add(new GLabel(PatternMatchType.CONTEXT_CONFLICT.name()));
		evalPanel.add(new GLabel(PatternMatchType.PRE_PATTERN_HIT.name()));
		evalPanel.add(new GLabel("Number"));
		JTextField truePositivesField = new JTextField(8);
		truePositivesField.setEditable(false);
		truePositivesField.setText(Integer.toString(stats.getNumTruePositives()));
		evalPanel.add(truePositivesField);

		JTextField wrongFlowField = new JTextField(8);
		wrongFlowField.setEditable(false);
		wrongFlowField.setText(Integer.toString(stats.getNumWrongFlow()));
		evalPanel.add(wrongFlowField);

		JTextField misalignedField = new JTextField(8);
		misalignedField.setEditable(false);
		misalignedField.setText(Integer.toString(stats.getNumFPMisaligned()));
		evalPanel.add(misalignedField);

		JTextField dataField = new JTextField(8);
		dataField.setEditable(false);
		dataField.setText(Integer.toString(stats.getNumFPData()));
		evalPanel.add(dataField);

		JTextField blockStartField = new JTextField(8);
		blockStartField.setEditable(false);
		blockStartField.setText(Integer.toString(stats.getNumPossibleStartCode()));
		evalPanel.add(blockStartField);

		JTextField undefinedField = new JTextField(8);
		undefinedField.setEditable(false);
		undefinedField.setText(Integer.toString(stats.getNumUndefined()));
		evalPanel.add(undefinedField);

		JTextField regConflictField = new JTextField(8);
		regConflictField.setEditable(false);
		regConflictField.setText(Integer.toString(stats.getNumContextConflicts()));
		evalPanel.add(regConflictField);

		JTextField prePatternFPField = new JTextField(8);
		prePatternFPField.setEditable(false);
		prePatternFPField.setText(Integer.toString(stats.getNumPrePatternHit()));
		evalPanel.add(prePatternFPField);

		return evalPanel;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

}
