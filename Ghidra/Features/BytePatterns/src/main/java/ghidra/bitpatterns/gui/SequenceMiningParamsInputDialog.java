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

import java.awt.Component;

import javax.swing.*;

import docking.DockingWindowManager;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.closedpatternmining.SequenceMiningParams;
import ghidra.framework.preferences.Preferences;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * 
 * Objects of this class present the user with a pop-up window for setting parameters for the
 * closed sequence pattern mining algorithm.
 *
 */

public class SequenceMiningParamsInputDialog extends InputDialogComponentProvider {

	private JTextField percentageBox;
	private IntegerTextField minFixedBitsBox;
	private JRadioButton nibbleButton;
	private JRadioButton binaryButton;
	private ButtonGroup bGroup;
	private static final String PERCENTAGE_BOX_TEXT = "Minimum Support Percentage ";
	private static final String MIN_FIXED_BITS_BOX_TEXT = "Minimum Number of Fixed Bits ";
	private static final String BINARY_BUTTON_TEXT = "Binary Sequences";
	private static final String NIBBLE_BUTTON_TEXT = "Character Sequences";
	private static final String DEFAULT_PERCENTAGE = "10.0";
	private static final String DEFAULT_MIN_FIXED_BITS = "16";
	private static final char BINARY_MNEMONIC = 'B';
	private static final char NIBBLE_MNEMONIC = 'N';
	private static final String PERCENTAGE_PROPERTY = "SequenceMiningParamsCreator_percentage";
	private static final String MIN_FIXED_BITS_PROPERTY = "SequenceMiningParamsCreator_minbits";
	private static final String BINARY_SEQUENCES_PROPERTY =
		"SequenceMiningParamsCreator_binarySequences";
	private static final String BINARY_SEQUENCES_DEFAULT = Boolean.toString(false);

	/**
	 * Creates a dialog for entering sequence mining parameters
	 * @param title dialog title
	 * @param parent parent component
	 */
	public SequenceMiningParamsInputDialog(String title, Component parent) {
		super(title);
		JPanel panel = createPanel();
		addWorkPanel(panel);
		addOKButton();
		okButton.setText("OK");
		addCancelButton();
		setDefaultButton(okButton);
		HelpLocation helpLocation = new HelpLocation("FunctionBitPatternsExplorerPlugin",
			"Mining_Closed_Sequential_Patterns");
		setHelpLocation(helpLocation);
		DockingWindowManager.showDialog(parent, this);
	}

	@Override
	protected JPanel createPanel() {
		JPanel mainPanel = new JPanel();
		PairLayout mainLayout = new PairLayout();
		mainPanel.setLayout(mainLayout);

		mainPanel.add(new GLabel(PERCENTAGE_BOX_TEXT));
		percentageBox = new JTextField(16);
		double percentage =
			Double.parseDouble(Preferences.getProperty(PERCENTAGE_PROPERTY, DEFAULT_PERCENTAGE));
		percentageBox.setText(Double.toString(percentage));
		percentageBox.setEditable(true);
		mainPanel.add(percentageBox);

		mainPanel.add(new GLabel(MIN_FIXED_BITS_BOX_TEXT));
		minFixedBitsBox = new IntegerTextField();
		int minFixBits = Integer.parseInt(
			Preferences.getProperty(MIN_FIXED_BITS_PROPERTY, DEFAULT_MIN_FIXED_BITS));
		minFixedBitsBox.setValue(minFixBits);
		mainPanel.add(minFixedBitsBox.getComponent());

		boolean useBinary = Boolean.parseBoolean(
			Preferences.getProperty(BINARY_SEQUENCES_PROPERTY, BINARY_SEQUENCES_DEFAULT));
		binaryButton = new GRadioButton(BINARY_BUTTON_TEXT, useBinary);
		binaryButton.setMnemonic(BINARY_MNEMONIC);
		nibbleButton = new GRadioButton(NIBBLE_BUTTON_TEXT, !useBinary);
		nibbleButton.setMnemonic(NIBBLE_MNEMONIC);
		mainPanel.add(binaryButton);
		mainPanel.add(nibbleButton);

		bGroup = new ButtonGroup();
		bGroup.add(binaryButton);
		bGroup.add(nibbleButton);

		return mainPanel;
	}

	/**
	 * Get a {@link SequenceMiningParams} object populated with values from the dialog.
	 * @return mining params
	 */
	public SequenceMiningParams getSequenceMiningParams() {
		String percentageString = percentageBox.getText();
		double parsedPercentage;
		try {
			parsedPercentage = Double.parseDouble(percentageString);
			Preferences.setProperty(PERCENTAGE_PROPERTY, Double.toString(parsedPercentage));
		}
		catch (NumberFormatException e) {
			parsedPercentage = Double.parseDouble(DEFAULT_PERCENTAGE);
		}

		if (parsedPercentage <= 0.0 || parsedPercentage >= 100.0) {
			parsedPercentage = Double.parseDouble(DEFAULT_PERCENTAGE);
		}

		String minFixedBitsString = minFixedBitsBox.getText();
		int parsedMinFixedBits;
		try {
			parsedMinFixedBits = Integer.parseInt(minFixedBitsString);
			Preferences.setProperty(MIN_FIXED_BITS_PROPERTY, Integer.toString(parsedMinFixedBits));
		}
		catch (NumberFormatException e) {
			parsedMinFixedBits = Integer.parseInt(DEFAULT_MIN_FIXED_BITS);
		}

		if (parsedMinFixedBits < 0) {
			parsedMinFixedBits = Integer.parseInt(DEFAULT_MIN_FIXED_BITS);
		}

		boolean useBinary = false;

		if (bGroup.getSelection().getMnemonic() == BINARY_MNEMONIC) {
			useBinary = true;
			Preferences.setProperty(BINARY_SEQUENCES_PROPERTY, Boolean.toString(true));
		}
		else {
			Preferences.setProperty(BINARY_SEQUENCES_PROPERTY, Boolean.toString(false));
		}
		Preferences.store();
		return new SequenceMiningParams(parsedPercentage / 100.0, parsedMinFixedBits, useBinary);
	}

}
