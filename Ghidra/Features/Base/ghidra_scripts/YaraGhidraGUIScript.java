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
//
//Launches a GUI allowing users to generate YARA search strings based on a set of selected instructions.
//
//@category Search.YARA
import java.awt.BorderLayout;
import java.util.Observable;
import java.util.Observer;

import javax.swing.*;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData.UpdateType;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionSearchDialog;
import ghidra.app.plugin.core.instructionsearch.ui.InstructionTablePanel;
import ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils;
import ghidra.app.script.GhidraScript;
import ghidra.util.Msg;

/**
 * This script launches the {@link InstructionSearchDialog} and populates it
 * with the currently- selected bytes in the listing. The YARA search string
 * matching the instructions selected is displayed in a text window and may be
 * modified in two ways:
 * 
 * 1. By directly editing the text 2. By toggling the cells in the instruction
 * table, which masks the appropriate mnemonic/instruction
 * 
 * The generated string will appear similar to the following:
 * 
 * rule <rule name> { strings: $STR1 = { 4? 56 4? 55 4? 54 ?? 50 4? 8b ?? c7 4d
 * 00 00 4?8d 1d 08 4e 00 00 }
 *
 * condition: $STR1 }
 * 
 * Note that this script uses only a portion of the existing search dialog
 * mentioned above; that entire dialog is far too bulky for what is needed here,
 * so we just launch the part that allows users to toggle the mnemonics and
 * operands on/off (masking).
 * 
 * In addition to this existing dialog, some custom components are added to it
 * in order to display the resulting Yara string. {@link #YaraDialog}.
 * 
 */
public class YaraGhidraGUIScript extends GhidraScript {

	/**
	 * The plugin provides all access to the {@link InstructionSearchDialog} and
	 * its components.
	 */
	private InstructionSearchPlugin plugin;

	private InstructionSearchDialog dialog;

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	@Override
	protected void run() throws Exception {

		// First we have to find the plugin - if this hasn't been installed it won't be available,
		// hence the null check.
		plugin = InstructionSearchUtils.getInstructionSearchPlugin(state.getTool());

		// Now check some error conditions and notify the user if there are issues.
		if (plugin == null) {
			popup("Instruction Pattern Search plugin not installed! Please install and " +
				"re-run script.");
			return;
		}

		if (currentProgram == null) {
			popup("Please open a program before running this script.");
			return;
		}

		if (currentSelection == null) {
			popup(
				"Please make a valid selection in the program and select 'reload'. Or select the " +
					"'manual entry' option from the toolbar.");
		}

		// Next, create and open a new Yara dialog.
		dialog = new YaraDialog();
		state.getTool().showDialog(dialog);

		// Finally, load whatever instructions are selected in the listing.
		dialog.loadInstructions(plugin);
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Creates a correctly-formatted Yara string with masking where appropriate.
	 * Yara strings have the following general format:
	 * 
	 * rule <rule name> { strings: $STR1 = { 4? 56 4? 55 4? 54 ?? 50 4? 8b ?? c7
	 * 4d 00 00 4?8d 1d 08 4e 00 00 }
	 *
	 * condition: $STR1 }
	 * 
	 * @param ruleName
	 * @return
	 */
	private String generateYaraString(String ruleName) {

		StringBuilder yaraString = new StringBuilder("\n\nrule " + ruleName + "\n");
		yaraString.append("{\n\tstrings:\n");

		String fullStr = "";

		// Get the "combined string" from the search data object; this is the ENTIRE set of 
		// instructions in one string, with all masking applied.
		if (dialog == null || dialog.getSearchData() == null) {
			return null;
		}
		String instrStr = dialog.getSearchData().getCombinedString();

		// Loop over the combined string, converting each nibble to hex. If we don't have enough
		// bytes to create a nibble, or if part of the nibble is masked, fill with a '?' char. This
		// is a Yara constraint - it can only handle displaying data down to the nibble level.
		//
		// ie: 10100110 -> A6
		//     101001.. -> A?
		//     ..11.001 -> ??
		//
		for (int i = 0; i < instrStr.length(); i += 8) {

			String curByte =
				instrStr.length() >= 8 ? instrStr.substring(i, i + 8) : instrStr.substring(i);
			String nibble1 = curByte.length() >= 4 ? curByte.substring(0, 4) : curByte.substring(0);
			String nibble2 = curByte.length() >= 8 ? curByte.substring(4, 8)
					: curByte.length() >= 4 ? curByte.substring(4) : "";

			if (nibble1.contains(".")) {
				fullStr += "?";
			}
			else {
				fullStr += InstructionSearchUtils.toHex(nibble1, false).trim();
			}

			if (nibble2.contains(".")) {
				fullStr += "?";
			}
			else {
				fullStr += InstructionSearchUtils.toHex(nibble2, false).trim();
			}

			fullStr += " ";
		}

		// Add the formatted string to our final output, and add some boilerplate Yara 
		// stuff.
		yaraString.append("\t\t$STR" + 1 + " = { " + fullStr + " }\n");
		yaraString.append("\n\tcondition:\n");
		yaraString.append("\t\t$STR1");
		yaraString.append(" or $STR" + (1));
		yaraString.append("\n}\n");

		return yaraString.toString();
	}

	/*********************************************************************************************
	 * PRIVATE CLASSES
	 ********************************************************************************************/

	/**
	 * This dialog is a hybrid, containing parts of the
	 * {@link InstructionTablePanel}, which allows users to mask
	 * mnemonics/operands in an instruction set, and some custom pieces for
	 * displaying the Yara string.
	 * 
	 * The layout:
	 * 
	 * --------------------------- | | | Instruction Table Panel | | |
	 * |-------------------------| | | | YARA Text | | |
	 * ---------------------------
	 */
	private class YaraDialog extends InstructionSearchDialog {

		// The area where the yara search string is displayed.
		private JTextArea yaraTA;
		JScrollPane scrollPane;

		// Use a splitter to separate the masking panel from the yara text area.
		private JSplitPane verticalSplitter;

		// Keep track of the splitter location so it can be restored when the dialog is
		// refreshed.  
		private int splitterSave = 200;

		/**
		 * Constructor.
		 */
		private YaraDialog() {
			super(plugin, "Yara Search String Generator", null);
			revalidate();
			setPreferredSize(500, 400);
		}

		/**
		 * The dialog we're using here is a modified form of the
		 * {@link InstructionSearchDialog}; this one contains only the
		 * {@link InstructionTablePanel} portion, which provides the operand
		 * masking capability.
		 * 
		 * To accomplish this we override the method that constructs the UI
		 * components and add just the components we need.
		 * 
		 * @return
		 */
		@Override
		protected JPanel createWorkPanel() {

			// Create the main text area and give it a scroll bar. 
			yaraTA = new JTextArea(12, 0);
			scrollPane = new JScrollPane(yaraTA);
			yaraTA.setWrapStyleWord(true);
			yaraTA.setLineWrap(true);

			// Create the instruction table and set it as a listener of the table model, so 
			// this gui will be notified when changes have been made (when the user has adjusted
			// the mask settings).  This allows us to dynamically update the yara string as 
			// the user is changing things.
			InstructionTablePanel instructionTablePanel =
				new InstructionTablePanel(searchData.getMaxNumOperands(), plugin, this);
			instructionTablePanel.getTable().getModel().addTableModelListener(e -> {
				generateYara();
			});

			// Finally, set up the main panel and create a split pane so the user can adjust
			// the dimensions of the masking table and the yara text display.
			JPanel mainPanel = new JPanel();
			mainPanel.setLayout(new BorderLayout());
			verticalSplitter = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
				instructionTablePanel.getWorkPanel(), scrollPane);
			mainPanel.add(verticalSplitter);

			// Tell the data model to listen for changes the table; when the GUI is updated, the
			// model needs to be told to update itself to reflect the new mask settings. 
			searchData.registerForGuiUpdates(instructionTablePanel.getTable());

			// Now restore the splitter location to whatever it was before.
			verticalSplitter.setDividerLocation(splitterSave);

			return mainPanel;
		}

		/**
		 * Creates a properly-formatted yara string and displays it in the text
		 * area.
		 */
		private void generateYara() {
			try {
				yaraTA.setText(generateYaraString("<insert name>"));
			}
			catch (Exception e1) {
				Msg.error(this, "Error generating yara string: " + e1);
			}
		}

		/**
		 * Part of the {@link Observer} structure. This is invoked whenever the
		 * {@link InstructionSearchData} class is updated, indicating that the
		 * user has selected a new set of instructions, or changed mask
		 * settings. When this happens we need to save off the splitter location
		 * and reload the dialog if necessary.
		 * 
		 * @param o
		 * @param arg
		 */
		@Override
		public void update(Observable o, Object arg) {

			// Before rebuilding the UI, remember the splitter location so we can reset it
			// afterwards.
			if (verticalSplitter != null) {
				splitterSave = verticalSplitter.getDividerLocation();
			}

			if (arg instanceof UpdateType) {
				UpdateType type = (UpdateType) arg;
				switch (type) {
					case RELOAD:
						revalidate();
						break;
					case UPDATE:
						// do nothing
				}
			}
		}

		/**
		 * Updates the GUI when the user has made a new selection.
		 */
		@Override
		protected void revalidate() {
			removeWorkPanel();
			addWorkPanel(createWorkPanel());
			generateYara();
		}
	}
}
