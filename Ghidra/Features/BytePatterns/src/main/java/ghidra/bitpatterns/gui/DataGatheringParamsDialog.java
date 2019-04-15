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

import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.DockingWindowManager;
import docking.widgets.label.GLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.bitpatterns.info.DataGatheringParams;
import ghidra.util.HelpLocation;
import ghidra.util.layout.PairLayout;

/**
 * This class creates a dialog for the user to input data gathering parameters 
 * when mining the current program (for instance, the number of bytes and instructions
 * to record at the beginning of each function).
 */

public class DataGatheringParamsDialog extends InputDialogComponentProvider {

	private static final String FIRST_BYTES_TEXT = "Number of first bytes";
	private static final String PRE_BYTES_TEXT = "Number of pre-bytes";
	private static final String RETURN_BYTES_TEXT = "Number of return bytes";
	private static final String FIRST_INSTRUCTIONS_TEXT = "Number of first instructions";
	private static final String PRE_INSTRUCTIONS_TEXT = "Number of pre-instructions";
	private static final String RETURN_INSTRUCTIONS_TEXT = "Number of return instructions";
	private static final String CONTEXT_REGISTER_TEXT = "Context Registers (CSV)";

	private static final int DEFAULT_FIRST_BYTES = 16;
	private static final int DEFAULT_PRE_BYTES = 12;
	private static final int DEFAULT_RETURN_BYTES = 12;
	private static final int DEFAULT_FIRST_INSTRUCTIONS = 4;
	private static final int DEFAULT_PRE_INSTRUCTIONS = 3;
	private static final int DEFAULT_RETURN_INSTRUCTIONS = 3;
	private static final String DEFAULT_CONTEXT_REGISTERS = "";

	private IntegerTextField firstBytesField;
	private IntegerTextField preBytesField;
	private IntegerTextField returnBytesField;
	private IntegerTextField firstInstructionsField;
	private IntegerTextField preInstructionsField;
	private IntegerTextField returnInstructionsField;
	private JTextField contextRegistersField;

	/**
	 * Creates a dialog for creating a {@link DataGatheringParams} object
	 * @param title
	 * @param parent
	 */
	public DataGatheringParamsDialog(String title, Component parent) {
		super(title);
		JPanel panel = createPanel();
		addWorkPanel(panel);
		addOKButton();
		okButton.setText("OK");
		addCancelButton();
		setDefaultButton(okButton);
		HelpLocation helpLocation =
			new HelpLocation("FunctionBitPatternsExplorerPlugin", "Data_Gathering_Parameters");
		setHelpLocation(helpLocation);
		DockingWindowManager.showDialog(parent, this);
	}

	@Override
	protected JPanel createPanel() {
		JPanel mainPanel = new JPanel();
		PairLayout pairLayout = new PairLayout();
		mainPanel.setLayout(pairLayout);

		mainPanel.add(new GLabel(FIRST_BYTES_TEXT));
		firstBytesField = new IntegerTextField();
		firstBytesField.setValue(DEFAULT_FIRST_BYTES);
		mainPanel.add(firstBytesField.getComponent());

		mainPanel.add(new GLabel(PRE_BYTES_TEXT));
		preBytesField = new IntegerTextField();
		preBytesField.setValue(DEFAULT_PRE_BYTES);
		mainPanel.add(preBytesField.getComponent());

		mainPanel.add(new GLabel(RETURN_BYTES_TEXT));
		returnBytesField = new IntegerTextField();
		returnBytesField.setValue(DEFAULT_RETURN_BYTES);
		mainPanel.add(returnBytesField.getComponent());

		mainPanel.add(new GLabel(FIRST_INSTRUCTIONS_TEXT));
		firstInstructionsField = new IntegerTextField();
		firstInstructionsField.setValue(DEFAULT_FIRST_INSTRUCTIONS);
		mainPanel.add(firstInstructionsField.getComponent());

		mainPanel.add(new GLabel(PRE_INSTRUCTIONS_TEXT));
		preInstructionsField = new IntegerTextField();
		preInstructionsField.setValue(DEFAULT_PRE_INSTRUCTIONS);
		mainPanel.add(preInstructionsField.getComponent());

		mainPanel.add(new GLabel(RETURN_INSTRUCTIONS_TEXT));
		returnInstructionsField = new IntegerTextField();
		returnInstructionsField.setValue(DEFAULT_RETURN_INSTRUCTIONS);
		mainPanel.add(returnInstructionsField.getComponent());

		mainPanel.add(new GLabel(CONTEXT_REGISTER_TEXT));
		contextRegistersField = new JTextField(DEFAULT_CONTEXT_REGISTERS);
		mainPanel.add(contextRegistersField);

		return mainPanel;
	}

	/**
	 * Creates a {@link DataGatheringParams} object from the values in the dialog fields
	 * @return
	 */
	public DataGatheringParams getDataGatheringParams() {
		DataGatheringParams params = new DataGatheringParams();
		params.setNumFirstBytes(firstBytesField.getIntValue());
		params.setNumPreBytes(preBytesField.getIntValue());
		params.setNumReturnBytes(returnBytesField.getIntValue());
		params.setNumFirstInstructions(firstInstructionsField.getIntValue());
		params.setNumPreInstructions(preInstructionsField.getIntValue());
		params.setNumReturnInstructions(returnInstructionsField.getIntValue());
		String cRegsCSV = contextRegistersField.getText();
		params.setContextRegisters(DataGatheringParams.getContextRegisterList(cRegsCSV));
		return params;
	}

}
