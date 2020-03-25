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
package ghidra.app.plugin.core.instructionsearch.ui;

import java.awt.*;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.DialogComponentProvider;
import ghidra.app.plugin.core.instructionsearch.model.*;
import ghidra.app.plugin.core.instructionsearch.ui.SelectionModeWidget.InputMode;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.PseudoInstruction;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * Widget that allows the user to input bytes in binary or hex format. The bytes
 * will then be disassembled and displayed in the {@link InstructionTable}.
 *
 */
public class InsertBytesWidget extends DialogComponentProvider implements KeyListener {

	// The input text area.  This is a generic JTextArea but displays a textual 'hint' to inform
	// the user of what type of input is required.
	private HintTextAreaIS inputBytesTA;

	private SelectionModeWidget selectionModeWidget;
	private EndianFlipWidget endianFlipWidget;

	// Add a simple label to show warnings/errors that crop up from this dialog.
	private MessagePanel msgPanel;

	// This is the class that does the work of converting a string of bytes into a meaningful
	// set of instructions.
	private PseudoDisassembler disassembler;

	private InstructionSearchDialog dialog = null;

	private Program program;

	// Error text to show when the user has entered invalid input.
	private String errorMsg = "";
	private static String ERROR_MSG_FULL_BYTE =
		"Input must consist of full bytes (no nibbles or individual bits).";
	private static String ERROR_MSG_HEX_INPUT =
		"Hex mode selected. Please adjust your input to be valid";
	private static String ERROR_MSG_BINARY_INPUT =
		"Binary mode selected. Please adjust your input to be valid";
	private static String ERROR_NO_INPUT = "No input specified!";
	private static String ERROR_MSG_GROUPS =
		"Groups must contain full bytes (no individual bits or nibbles!).";

	private final String HINT_TEXT = "<input hex or binary data; full bytes only>";

	/**
	 * Constructor.
	 * 
	 * @param program the current program
	 * @param dialog the parent search dialog
	 */
	public InsertBytesWidget(Program program, InstructionSearchDialog dialog) {
		super("Edit Bytes", false, true, true, false);

		this.dialog = dialog;
		this.program = program;

		disassembler = new PseudoDisassembler(program);

		addWorkPanel(createWorkPanel());
		addApplyButton();
		addCancelButton();
	}

	/**
	 * The callback method for when the "Apply" button is pressed.
	 */
	@Override
	protected void applyCallback() {
		disassemble();
	}

	/**
	 * Load a set of bytes (in string form; hex or binary) into the search
	 * dialog. The bytes are disassembled and displayed in the
	 * {@link InstructionTable}.
	 * 
	 * @param bytes the bytes to load
	 */
	public void loadBytes(String bytes) {

		SystemUtilities.runSwingLater(() -> {
			inputBytesTA.setText(bytes);
			applyButton.doClick();
		});
	}

	public String getInputString() {
		return inputBytesTA.getText();
	}

	public void setInputString(String input) {
		inputBytesTA.setText(input);
	}

	@Override
	protected void dialogShown() {
		populateDialog();
		toFront();
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	/**
	 * Creates the visual components for this dialog.
	 * 
	 * @return the new panel
	 */
	protected JPanel createWorkPanel() {

		JPanel contentPanel = new JPanel();
		contentPanel.setMinimumSize(new Dimension(500, 300));

		// Create the input text widget and give it a scrollbar.
		inputBytesTA = new HintTextAreaIS(HINT_TEXT);
		JScrollPane scrollPane = new JScrollPane(inputBytesTA);
		inputBytesTA.addKeyListener(this);

		selectionModeWidget = new SelectionModeWidget("Input Mode", this);
		endianFlipWidget = new EndianFlipWidget("Endianness", this);
		msgPanel = new MessagePanel();

		JPanel southPanel = new JPanel();
		southPanel.setLayout(new BorderLayout());
		southPanel.add(selectionModeWidget, BorderLayout.WEST);
		southPanel.add(endianFlipWidget, BorderLayout.CENTER);
		southPanel.add(msgPanel, BorderLayout.SOUTH);

		// Use a border layout so we can put the text area in the CENTER location and have it
		// grow automatically as the panel is resized.
		contentPanel.setLayout(new BorderLayout());
		contentPanel.add(scrollPane, BorderLayout.CENTER);
		contentPanel.add(southPanel, BorderLayout.SOUTH);

		return contentPanel;
	}

	/**
	 * Displays a pop-up containing any error message text set by the validator.
	 */
	public void showError() {
		Msg.showError(this, this.getComponent(), "Instruction Search Input Error", errorMsg);
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	private void populateDialog() {

		// Clear out the message panel, if there was anything in there.
		msgPanel.clear();

		// When bringing up the dialog, always populate it with whatever is in the main dialog so
		// the user can edit those instructions if desired.  And make sure to set the entire 
		// string to be selected so they can quickly delete them with a single keystroke.
		//
		// Note: To get the correct string for the instruction, we go to the search data
		//       object and pull out the 'combined string'...this contains ALL instructions with
		//       all masking applied. Since we want to show each instruction on a separate line
		//       here, we take that string, and break it apart with newlines after each
		//       instruction.
		StringBuilder sb = new StringBuilder();
		List<InstructionMetadata> instrs = dialog.getSearchData().getInstructions();
		String comb = dialog.getSearchData().getCombinedString();
		for (InstructionMetadata instr : instrs) {
			int instrLen = instr.getMaskContainer().toBinaryString().length();
			String instrStr = comb.substring(0, instrLen);
			instrStr = instrStr.replaceAll("\\.", "0");
			comb = comb.substring(instrLen);
			instrStr = InstructionSearchUtils.addSpaceOnByteBoundary(instrStr, InputMode.BINARY);
			sb.append(instrStr + "\n");
		}

		// Set the text and initialize it to binary mode, since that's the format of the data
		// we're given.  When done initializing the dialog, we'll switch it to hex view by
		// clicking the appropriate button.
		inputBytesTA.setText(sb.toString());
		selectionModeWidget.setInputMode(InputMode.BINARY);

		inputBytesTA.setSelectionStart(0);
		inputBytesTA.setSelectionEnd(inputBytesTA.getText().length());
	}

	public void disassemble() {

		if (dialog == null) {
			return;
		}

		// Clear the message panel.
		msgPanel.clear();

		// Get the input and strip out any spaces.
		String input = inputBytesTA.getText();

		// Now make sure the input is valid. This means it is in binary or hex format
		// and contains full bytes (no nibbles or individual bits).
		if (!validateInput(input)) {
			showError();
			return;
		}

		// Now strip off all spaces and process.
		input = inputBytesTA.getText().replaceAll("\\s", "");

		// Now convert the input from hex to binary (if it's hex).  We process the input from
		// here on out assuming it's binary.
		if (selectionModeWidget.getInputMode() == InputMode.HEX) {
			input = InstructionSearchUtils.toBinary(input);
		}

		// Everything looks good, so take the input and convert it to a Byte list, which we'll
		// need for the PsuedoDisassembler.
		List<Byte> allBytes = InstructionSearchUtils.toByteArray(input);

		// Now we have a valid byte string so we can start disassembling. To do this, we pass
		// the entire string to the pseudo-disassembler and it will return the first 
		// instruction. We save that one off, then remove those bytes from the main string and
		// pass the now-shorter string to the disassembler, where it will return the next 
		// instruction, and so on, and so on...
		//
		// TODO: Possibly modify the PseudoDisassembler to disassemble the entire thing at 
		// once, not just one instruction at a time.
		//
		// NOTE: Some instructions have operands that cannot be accurately calculated
		//       without having a specific instruction instance (ie: an operand that is an 
		//       offset from the instruction address). This is obviously problematic because we
		//       aren't dealing with 'real' instructions that map to an address in a program; 
		//       we're just loading bytes and trying to figure out what instructions they 
		//       might represent. In these cases we just use the minimum address of the loaded 
		//       program as the base address.

		List<InstructionMetadata> instructions = new ArrayList<>();

		while (allBytes.size() > 0) {
			try {

				// First call the disassembler to get the first instruction.  
				Byte[] bytearray = new Byte[allBytes.size()];
				bytearray = allBytes.toArray(bytearray);

				PseudoInstruction instruction = disassembler.disassemble(program.getMinAddress(),
					InstructionSearchUtils.toPrimitive(bytearray));

				// Now create the metadata for the instruction and operands.
				InstructionMetadata instructionMD = createInstructionMetadata(instruction);
				List<OperandMetadata> operands = createOperandMetadata(instruction);
				instructionMD.setOperands(operands);

				// Finally add the complete metadata to the main list.
				instructions.add(instructionMD);

				// Now remove the bytes we just processed.  If, for some reason, the bytes
				// array does not contain at least as many bytes as the instruction, then
				// there's a problem with the input. Just print a message to the user and
				// exit.
				if (allBytes.size() < instruction.getLength()) {
					msgPanel.setMessageText("Input invalid: unknown disassembly error.", Color.RED);
					return;
				}
				allBytes.subList(0, instruction.getLength()).clear();
			}
			catch (InsufficientBytesException | UnknownInstructionException
					| UnknownContextException | MemoryAccessException e) {

				// If there's an exception, just stop and let the user figure out what went
				// wrong - no need to continue.
				msgPanel.setMessageText("Input invalid: unknown disassembly error.", Color.RED);
				Msg.debug(this, "Error disassembling instruction", e);

				return;
			}
		}

		// Now add the instructions to the instruction table and display them.
		dialog.getSearchData().setInstructions(instructions);
	}

	/**
	 * Creates {@link OperandMetadata} objects for each operand in the
	 * instruction provided.
	 * 
	 * @param instruction the instruction to parse
	 * @return list of operand metadata
	 * @throws MemoryAccessException
	 */
	private List<OperandMetadata> createOperandMetadata(PseudoInstruction instruction)
			throws MemoryAccessException {

		List<OperandMetadata> operands = new ArrayList<>();

		for (int i = 0; i < instruction.getNumOperands(); i++) {
			OperandMetadata operandMD = new OperandMetadata();
			operandMD.setOpType(instruction.getOperandType(i));
			operandMD.setTextRep(instruction.getDefaultOperandRepresentation(i));

			// The mask container is a bit tricky.  The mask string we can get directly from the 
			// prototype object in the pseudo instruction. For the value string we have to do
			// a bit of calculating: we know the entire instruction byte string and we know
			// this operand mask, so AND them together and we get the operand bytes.
			byte[] mask = instruction.getPrototype().getOperandValueMask(i).getBytes();
			byte[] value = InstructionSearchUtils.byteArrayAnd(mask, instruction.getBytes());
			MaskContainer maskContainer = new MaskContainer(mask, value);

			operandMD.setMaskContainer(maskContainer);
			operands.add(operandMD);
		}

		return operands;
	}

	/**
	 * Creates a {@link InstructionMetadata} object for the instruction
	 * provided.
	 * 
	 * @param instruction the instruction to parse
	 * @return the instruction metadata
	 * @throws MemoryAccessException
	 */
	private InstructionMetadata createInstructionMetadata(PseudoInstruction instruction)
			throws MemoryAccessException {

		// The mask array we can get directly from the prototype. For the value array we 
		// have to figure out which bits pertain to operands and just zero them out, so we're
		// just left with the instruction (mnemonic) bits.
		byte[] mask = instruction.getPrototype().getInstructionMask().getBytes();
		byte[] value = clearOperandBits(mask, instruction.getBytes());
		MaskContainer mnemonicMask = new MaskContainer(mask, value);

		InstructionMetadata instructionMD = new InstructionMetadata(mnemonicMask);
		instructionMD.setIsInstruction(true);
		instructionMD.setTextRep(instruction.getMnemonicString());

		return instructionMD;
	}

	/**
	 * Clears out the parts of the given value array that correspond to
	 * operands, and leaves the mnemonic alone. This can be done using a simple
	 * AND of the two byte arrays.
	 * <p>
	 * eg:
	 * <li>mask = 11111000 11000000</li>
	 * <li>value = 01101100 10001110</li>
	 * <li>--------------------------</li>
	 * <li>ret = 01101000 10000000</li>
	 * 
	 * @param mask the mnemonic mask
	 * @param value the full instruction value string
	 * @return the cleared byte array
	 */
	private byte[] clearOperandBits(byte[] mask, byte[] value) {
		return InstructionSearchUtils.byteArrayAnd(mask, value);
	}

	/**
	 * Verifies that the input entered by the user is valid. Meaning:
	 * <li>The string represents a hex or binary number.</li>
	 * <li>The string contains only full bytes.</li>
	 * 
	 * @return true if input is valid
	 */
	public boolean validateInput() {
		return validateInput(inputBytesTA.getText());
	}

	/**
	 * Verifies that the given string is valid binary or hex input.
	 * 
	 * @param input the string to validate
	 * @return true if valid
	 */
	public boolean validateInput(String input) {

		String text = input.trim();

		if (text.isEmpty()) {
			errorMsg = ERROR_NO_INPUT;
			return false;
		}
		if (selectionModeWidget.getInputMode() == InputMode.BINARY) {

			// Get the byte groups and check them for validity. Note that this method throws an
			// exception if there's a problem with the groups, so there's no need to check
			// the return values.
			try {
				InstructionSearchUtils.getGroupSizes(text, InputMode.BINARY);
			}
			catch (Exception e) {
				inputBytesTA.setError();
				errorMsg = ERROR_MSG_GROUPS;
				return false;
			}

			if (!InstructionSearchUtils.isBinary(text)) {
				inputBytesTA.setError();
				errorMsg = ERROR_MSG_BINARY_INPUT;
				return false;
			}
			if (!InstructionSearchUtils.isFullBinaryByte(text)) {
				inputBytesTA.setError();
				errorMsg = ERROR_MSG_FULL_BYTE;
				return false;
			}
		}
		else if (selectionModeWidget.getInputMode() == InputMode.HEX) {

			// Get the byte groups and check them for validity. Note that this method throws an
			// exception if there's a problem with the groups, so there's no need to check
			// the return values.
			try {
				InstructionSearchUtils.getGroupSizes(text, InputMode.HEX);
			}
			catch (Exception e) {
				inputBytesTA.setError();
				errorMsg = ERROR_MSG_GROUPS;
				return false;
			}

			if (!InstructionSearchUtils.isHex(text)) {
				inputBytesTA.setError();
				errorMsg = ERROR_MSG_HEX_INPUT;
				return false;
			}
			if (!InstructionSearchUtils.isFullHexByte(text)) {
				inputBytesTA.setError();
				errorMsg = ERROR_MSG_FULL_BYTE;
				return false;
			}
		}

		// If we're here then it's in good shape.
		inputBytesTA.setValid();
		errorMsg = "";
		return true;
	}

	/**
	 * Flags the given string as invalid input
	 * 
	 */
	public void setInputInvalid() {
		inputBytesTA.setError();
		if (selectionModeWidget.getInputMode() == InputMode.BINARY) {
			errorMsg = ERROR_MSG_BINARY_INPUT;
		}
		else {
			errorMsg = ERROR_MSG_HEX_INPUT;
		}
	}

	@Override
	public void keyTyped(KeyEvent e) {
		// Do nothing.
	}

	@Override
	public void keyPressed(KeyEvent e) {
		// Do nothing.
	}

	/**
	 * Need to capture keystrokes so we can validate input on the fly. Every
	 * time a character is typed we check the entire input for correctness.
	 * 
	 * Note that this MUST be done in the release handler; in the type or press
	 * handler the input widget has not officially been updated with the new
	 * character.
	 * 
	 * @param e
	 */
	@Override
	public void keyReleased(KeyEvent e) {
		validateInput(inputBytesTA.getText());

		// Clear the message panel.
		msgPanel.clear();
	}

	public SelectionModeWidget getSelectionModeWidget() {
		return this.selectionModeWidget;
	}
}
