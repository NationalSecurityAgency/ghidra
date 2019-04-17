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

import docking.widgets.table.GTable;
import docking.widgets.textfield.IntegerTextField;
import ghidra.bitpatterns.info.FileBitPatternInfoReader;
import ghidra.util.layout.PairLayout;

/**
 * The class builds the "Function Start Alignment" panel, which allows the user 
 * to see whether function starts are more likely to occur at certain alignments.
 */
public class AlignmentPanelBuilder extends ContextRegisterFilterablePanelBuilder {
	private static final int DEFAULT_MODULUS = 16;
	private static final String[] alignmentTableColumnNames =
		{ "Modulus", "Number of Functions", "Percentage" };
	private static final String MODULUS_FIELD_TEXT = " Alignment Modulus ";
	private static final String RECOMPUTE_BUTTON_TEXT = "Compute Alignment Info";

	private GTable alignmentTable;
	private IntegerTextField modulusField;
	private JScrollPane scrollPane;
	private int savedNumFuncs;
	private List<Long> savedStartingAddresses = null;
	private FileBitPatternInfoReader fsReader;
	private int modulus;

	/**
	 * Creates a new {@link AlignmentPanelBuilder}
	 */
	public AlignmentPanelBuilder() {
		super();
	}

	/**
	 * Builds the alignment panel GUI components.
	 * @return
	 */
	public JPanel buildAlignmentPanel() {
		alignmentTable = createAlignmentTable(null, 0);
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
		alignmentTable.setColumnHeaderPopupEnabled(true);
		scrollPane = new JScrollPane(alignmentTable);
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		JPanel modulusPanel = new JPanel();
		PairLayout modulusLayout = new PairLayout();
		modulusPanel.setLayout(modulusLayout);
		modulusPanel.add(new JLabel(MODULUS_FIELD_TEXT));
		modulusField = new IntegerTextField();
		modulusField.setValue(DEFAULT_MODULUS);
		modulusPanel.add(modulusField.getComponent());

		JButton recomputeButton = new JButton(RECOMPUTE_BUTTON_TEXT);
		recomputeButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				updateAlignmentPanel();
			}
		});

		getButtonPanel().add(recomputeButton);

		mainPanel.add(modulusPanel, BorderLayout.NORTH);

		mainPanel.add(getButtonPanel(), BorderLayout.SOUTH);

		return mainPanel;
	}

	/**
	 * Updates the alignment panel.
	 */
	public void updateAlignmentPanel() {
		modulus = modulusField.getValue().intValue();
		if (modulus < 1) {
			modulus = DEFAULT_MODULUS;
			modulusField.setValue(DEFAULT_MODULUS);
		}
		mainPanel.remove(scrollPane);
		alignmentTable = createAlignmentTable(savedStartingAddresses, savedNumFuncs);
		alignmentTable.setColumnHeaderPopupEnabled(true);
		scrollPane = new JScrollPane(alignmentTable);
		mainPanel.add(scrollPane, BorderLayout.CENTER);
		mainPanel.updateUI();
	}

	private GTable createAlignmentTable(List<Long> startingAddresses, int numFuncs) {
		String[][] modulusInfo = new String[modulus][3];
		if (startingAddresses != null) {
			for (int i = 0; i < modulus; i++) {
				modulusInfo[i][0] = Long.toString(i);
			}
			long[] countsAsLongs = new long[modulus];
			for (Long currentAddress : startingAddresses) {
				countsAsLongs[(int) (Long.remainderUnsigned(currentAddress, modulus))] =
					countsAsLongs[(int) (Long.remainderUnsigned(currentAddress, modulus))] + 1;
			}
			for (int i = 0; i < modulus; i++) {
				double percent = (100.0 * countsAsLongs[i]) / numFuncs;
				modulusInfo[i][2] = Double.toString(Math.round(percent));
				modulusInfo[i][1] = Long.toString(countsAsLongs[i]);
			}
		}
		GTable table = new GTable(modulusInfo, alignmentTableColumnNames);
		return table;
	}

	/**
	 * Resets the alignment modules to the default value.
	 */
	public void resetModulus() {
		modulus = DEFAULT_MODULUS;
	}

	/**
	 * Sets the {@link FileBitPatternInfoReader} used by this panel as a data source.
	 * @param fsReader {@link FileBitPatternInfoReader} to use
	 */
	public void setFsReader(FileBitPatternInfoReader fsReader) {
		this.fsReader = fsReader;
		this.savedStartingAddresses = fsReader.getStartingAddresses();
		this.savedNumFuncs = fsReader.getNumFuncs();
	}

	@Override
	public void applyFilterAction() {
		savedStartingAddresses = fsReader.getFilteredAddresses(getContextRegisterFilter());
		savedNumFuncs = savedStartingAddresses.size();
		updateAlignmentPanel();

	}

	@Override
	public void clearFilterAction() {
		savedStartingAddresses = fsReader.getStartingAddresses();
		savedNumFuncs = fsReader.getNumFuncs();
		updateAlignmentPanel();
	}

}
