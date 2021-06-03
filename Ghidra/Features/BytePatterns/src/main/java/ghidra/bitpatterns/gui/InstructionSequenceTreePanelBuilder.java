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

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.*;
import javax.swing.tree.TreePath;
import javax.swing.tree.TreeSelectionModel;

import docking.widgets.dialogs.NumberInputDialog;
import docking.widgets.label.GDLabel;
import docking.widgets.tree.GTree;
import ghidra.bitpatterns.info.*;
import ghidra.util.layout.PairLayout;

/**
 * 
 * This class describes a panel of instruction sequences (displayed as a tree).
 *
 */

public class InstructionSequenceTreePanelBuilder extends ContextRegisterFilterablePanelBuilder {

	private JPanel treePanel;
	private FunctionBitPatternsGTree gTree;
	private JTextField countField;
	private JPanel countPanel;
	private JButton applyPercentageFilterButton;
	private JButton clearPercentageFilterButton;
	private static final String APPLY_PERCENTAGE_FILTER_BUTTON_TEXT = "Apply Percentage Filter";
	private static final String CLEAR_PERCENTAGE_FILTER_BUTTON_TEXT = "Clear Percentage Filter";
	private static final String COUNT_FIELD_LABEL = " Number of Sequences in Tree ";
	private static final String PERCENTAGE_FILTER_TITLE = "Enter minimum percentage";
	private static final int DEFAULT_PERCENTAGE_FILTER = 5;
	private FileBitPatternInfoReader fsReader;
	private PatternType type;
	private PercentageFilter percentageFilter = new PercentageFilter(0.0);

	/**
	 * Creates an object for building a tree panel for instruction sequences of a given type
	 * @param type instruction sequence type
	 */
	public InstructionSequenceTreePanelBuilder(PatternType type) {
		super();
		this.type = type;
	}

	private JPanel buildTreePanel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(3, 3, 3, 3));
		FunctionBitPatternsGTreeRootNode root = new FunctionBitPatternsGTreeRootNode();
		GTree defaultEmptyTree = new GTree(root);
		panel.add(defaultEmptyTree, BorderLayout.CENTER);
		return panel;
	}

	/**
	 * Builds the main panel
	 * @return panel
	 */
	public JPanel buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());
		treePanel = buildTreePanel();
		buildCountPanel();
		mainPanel.add(countPanel, BorderLayout.NORTH);
		mainPanel.add(treePanel, BorderLayout.CENTER);
		addPercentageFilterButtons();
		mainPanel.add(getButtonPanel(), BorderLayout.SOUTH);
		return mainPanel;
	}

	private void addPercentageFilterButtons() {
		applyPercentageFilterButton = new JButton(APPLY_PERCENTAGE_FILTER_BUTTON_TEXT);
		applyPercentageFilterButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				NumberInputDialog numberDialog =
					new NumberInputDialog(PERCENTAGE_FILTER_TITLE, DEFAULT_PERCENTAGE_FILTER, 0,
						100);
				numberDialog.show();
				double value = 0.0;
				if (!numberDialog.wasCancelled()) {
					value = numberDialog.getValue();
				}
				percentageFilter = new PercentageFilter(value);
				applyFilterAction();
				gTree.expandAll();
			}
		});
		getButtonPanel().add(applyPercentageFilterButton);

		clearPercentageFilterButton = new JButton(CLEAR_PERCENTAGE_FILTER_BUTTON_TEXT);
		clearPercentageFilterButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				percentageFilter = new PercentageFilter(0.0);
				applyFilterAction();
			}
		});
		getButtonPanel().add(clearPercentageFilterButton);
	}

	private void buildCountPanel() {
		countPanel = new JPanel();
		PairLayout countLayout = new PairLayout();
		countPanel.setLayout(countLayout);
		JLabel countLabel = new GDLabel(COUNT_FIELD_LABEL);
		countPanel.add(countLabel);
		countField = new JTextField(25);
		countField.setEditable(false);
		countPanel.add(countField);
	}

	private void updateCountField(int numSeqs) {
		countField.setText(Integer.toString(numSeqs));
	}

	private void updateTreePanel() {
		treePanel.removeAll();
		ContextRegisterFilter regFilter = getContextRegisterFilter();
		List<InstructionSequence> instSeqs =
			InstructionSequence.getInstSeqs(fsReader, type, regFilter);
		gTree = FunctionBitPatternsGTree.createTree(instSeqs, type, percentageFilter);
		gTree.setRootVisible(false);
		gTree.getSelectionModel().setSelectionMode(TreeSelectionModel.SINGLE_TREE_SELECTION);
		treePanel.add(gTree);
		treePanel.updateUI();
		updateCountField(instSeqs.size());
	}

	/**
	 * Sets the data source and updates the context register extent
	 * @param fsReader {@link FileBitPatternInfoReader} data source
	 */
	public void setFsReaderAndUpdateExtent(FileBitPatternInfoReader fsReader) {
		this.fsReader = fsReader;
		updateExtentAndClearFilter(fsReader.getContextRegisterExtent());
		updateTreePanel();
		this.percentageFilter = new PercentageFilter(0.0);
	}

	/**
	 * Check whether the instruction tree is empty
	 * @return {@code true} precisely when the instruction tree is null or empty
	 */
	public boolean isTreeEmpty() {
		if (gTree == null) {
			return true;
		}
		return (gTree.getTotalNum() == 0);
	}

	@Override
	public void applyFilterAction() {
		updateTreePanel();
	}

	@Override
	public void clearFilterAction() {
		updateExtentAndClearFilter(fsReader.getContextRegisterExtent());
		updateTreePanel();
	}

	/**
	 * Enables the "Apply Percentage Filter" and "Clear Percentage Filter" buttons.
	 * @param enable enables buttons precisely when true
	 */
	public void enablePercentageFilterButtons(boolean enable) {
		if (applyPercentageFilterButton != null) {
			applyPercentageFilterButton.setEnabled(enable);
		}
		if (clearPercentageFilterButton != null) {
			clearPercentageFilterButton.setEnabled(enable);
		}
		return;
	}

	/**
	 * Returns the selection path of the {@link FunctionBitPatternsGTree} associated with this panel.
	 * @return the selection path
	 */
	public TreePath getSelectionPath() {
		if (gTree == null) {
			return null;
		}
		TreePath[] paths = gTree.getSelectionPaths();
		if (paths == null || paths.length == 0) {
			return null;
		}
		return paths[0];
	}

	/**
	 * Returns the {@link FunctionBitPatternsGTree} associated with this panel.
	 * @return the tree
	 */
	public FunctionBitPatternsGTree getGTree() {
		return gTree;
	}
}
