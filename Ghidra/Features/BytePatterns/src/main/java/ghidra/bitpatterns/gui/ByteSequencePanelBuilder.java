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
import java.util.List;

import javax.swing.*;

import docking.widgets.label.GLabel;
import docking.widgets.table.GFilterTable;
import ghidra.bitpatterns.info.*;
import ghidra.util.layout.PairLayout;

/**
 * This class is used to create panels for displaying sequences of bytes
 */
public class ByteSequencePanelBuilder extends ContextRegisterFilterablePanelBuilder {

	private DisassembledByteSequenceTableModel byteSeqTable;
	private List<ByteSequenceRowObject> rowObjects;
	private FunctionBitPatternsExplorerPlugin plugin;
	private FileBitPatternInfoReader fsReader;
	private PatternType type;
	private static final int TABLE_INDEX = 1;
	private ByteSequenceLengthFilter lengthFilter;
	private JButton applyLengthFilterButton;
	private JButton clearLengthFilterButton;
	private JTextField numSeqsField;
	private GFilterTable<ByteSequenceRowObject> filterTable;
	private static final String APPLY_LENGTH_FILTER_BUTTON_TEXT = "Apply Length Filter";
	private static final String CLEAR_LENGTH_FILTER_BUTTON_TEXT = "Clear Length Filter";
	private static final String BYTE_SEQUENCE_LENGTH_FILTER_CREATER_TEXT = "Set Length Filter";
	private static final String NUM_SEQS_LABEL_TEXT = " Number of Sequences ";

	/**
	 * Creates a {@link ByteSequencePanelBuilder} in a given {@link FunctionBitPatternsExplorerPlugin} for sequences of a
	 * given {@PatternType}
	 * @param plugin plugin
	 * @param type {@PatternType} of sequences
	 */
	public ByteSequencePanelBuilder(FunctionBitPatternsExplorerPlugin plugin, PatternType type) {
		this.plugin = plugin;
		this.type = type;
	}

	/**
	 * Returns the last selected {@link ByteSequenceRowObject}s of the table associated to
	 * this panel
	 * @return the selected objects
	 */
	public List<ByteSequenceRowObject> getLastSelectedRows() {
		return byteSeqTable.getLastSelectedObjects();
	}

	@Override
	public void applyFilterAction() {
		updateTable();
	}

	@Override
	public void clearFilterAction() {
		updateExtentAndClearFilter(fsReader.getContextRegisterExtent());
		updateTable();

	}

	/**
	 * Determines whether there is an active length filter
	 * @return true precisely when there is a length filter
	 */
	public boolean isLengthFiltered() {
		return lengthFilter != null;
	}

	/**
	 * Gets the length filter
	 * @return the length filter
	 */
	public ByteSequenceLengthFilter getLengthFilter() {
		return lengthFilter;
	}

	/**
	 * Gets the {@code PatternType} of the byte sequences
	 * @return the type
	 */
	public PatternType getType() {
		return type;
	}

	/**
	 * Build the main panel
	 * @return the main panel
	 */
	public JPanel buildMainPanel() {
		mainPanel = new JPanel(new BorderLayout());

		JPanel numSeqsPanel = new JPanel();
		PairLayout numSeqsLayout = new PairLayout();
		numSeqsPanel.setLayout(numSeqsLayout);
		numSeqsPanel.add(new GLabel(NUM_SEQS_LABEL_TEXT));
		numSeqsField = new JTextField(25);
		numSeqsField.setEditable(false);
		numSeqsPanel.add(numSeqsField);
		mainPanel.add(numSeqsPanel, BorderLayout.NORTH);

		mainPanel.add(getButtonPanel(), BorderLayout.SOUTH);
		byteSeqTable = new DisassembledByteSequenceTableModel(plugin, rowObjects);
		filterTable = new GFilterTable<>(byteSeqTable);
		mainPanel.add(filterTable, BorderLayout.CENTER, TABLE_INDEX);
		addLengthFilterAndAnalysisButtons();
		mainPanel.setVisible(true);
		return mainPanel;
	}

	/**
	 * Updates the table
	 */
	public void updateTable() {
		mainPanel.remove(TABLE_INDEX);
		filterTable.dispose();

		rowObjects = ByteSequenceRowObject.getFilteredRowObjects(fsReader.getFInfoList(), type,
			getContextRegisterFilter(), lengthFilter);
		byteSeqTable = new DisassembledByteSequenceTableModel(plugin, rowObjects);
		filterTable = new GFilterTable<>(byteSeqTable);

		int totalNumSeqs = 0;
		for (ByteSequenceRowObject row : rowObjects) {
			totalNumSeqs += row.getNumOccurrences();
		}
		numSeqsField.setText(Integer.toString(totalNumSeqs));

		mainPanel.add(filterTable, BorderLayout.CENTER, TABLE_INDEX);
		mainPanel.updateUI();
	}

	/**
	 * Sets the {@link FileBitPatternInfoReader} object to use a data source
	 * @param fsReader {@link FileBitPatternInfoReader} object containing the sequences to analyze
	 */
	public void setFsReader(FileBitPatternInfoReader fsReader) {
		this.fsReader = fsReader;
		updateExtentAndClearFilter(fsReader.getContextRegisterExtent());
		lengthFilter = null;
		updateTable();
	}

	private void addLengthFilterAndAnalysisButtons() {

		applyLengthFilterButton = new JButton(APPLY_LENGTH_FILTER_BUTTON_TEXT);
		getButtonPanel().add(applyLengthFilterButton);
		applyLengthFilterButton.addActionListener(e -> {
			ByteSequenceLengthFilterInputDialog filterCreator =
				new ByteSequenceLengthFilterInputDialog(
					BYTE_SEQUENCE_LENGTH_FILTER_CREATER_TEXT, mainPanel);
			if (filterCreator.isCanceled()) {
				return;
			}
			lengthFilter = filterCreator.getValue();
			applyFilterAction();
		});

		clearLengthFilterButton = new JButton(CLEAR_LENGTH_FILTER_BUTTON_TEXT);
		getButtonPanel().add(clearLengthFilterButton);
		clearLengthFilterButton.addActionListener(e -> {
			lengthFilter = null;
			updateTable();
		});
	}

	/**
	 * Enables the "Apply Length Filter" and "Clear Length Filter" buttons based on a boolean input
	 * @param enabled will be enabled precisely when this parameter is {@code true}
	 */
	public void enableLengthFilterButtons(boolean enabled) {
		if (applyLengthFilterButton != null) {
			applyLengthFilterButton.setEnabled(enabled);
		}
		if (clearLengthFilterButton != null) {
			clearLengthFilterButton.setEnabled(enabled);
		}
		return;
	}

	public void dispose() {
		filterTable.dispose();
	}
}
