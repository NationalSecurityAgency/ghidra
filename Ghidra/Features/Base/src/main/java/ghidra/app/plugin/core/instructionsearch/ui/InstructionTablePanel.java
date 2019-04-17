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

import java.awt.BorderLayout;

import javax.swing.JPanel;
import javax.swing.JScrollPane;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.util.Msg;
import ghidra.util.exception.InvalidInputException;

/**
 * Container for the {@link InstructionTable}.
 */
public class InstructionTablePanel extends JPanel {

	private JScrollPane scrollPane;

	private InstructionTable instructionTable;

	private InstructionSearchPlugin plugin;

	private InstructionSearchDialog dialog;

	private int numColumns;

	private JPanel workPanel;

	/**
	 * 
	 * @param numColumns
	 * @param plugin
	 * @param dialog
	 */
	public InstructionTablePanel(int numColumns, InstructionSearchPlugin plugin,
			InstructionSearchDialog dialog) {

		this.plugin = plugin;
		this.dialog = dialog;
		this.numColumns = numColumns;

		try {
			setup();
		}
		catch (InvalidInputException e) {
			Msg.error(this, "error creating instruction table: " + e);
		}
	}

	public JScrollPane getScrollPane() {
		return scrollPane;
	}

	public InstructionTable getTable() {
		return instructionTable;
	}

	public JPanel getWorkPanel() {
		return workPanel;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 * @throws InvalidInputException 
	 ********************************************************************************************/

	private void setup() throws InvalidInputException {

		workPanel = new JPanel();
		workPanel.setLayout(new BorderLayout());

		// Must set the name so this panel is available to tests/screenshots.
		workPanel.setName("InstructionTablePanel");

		instructionTable = new InstructionTable(numColumns + 1, plugin, dialog);
		scrollPane = new JScrollPane(instructionTable);

		workPanel.add(instructionTable.getToolbar(), BorderLayout.NORTH);
		workPanel.add(scrollPane, BorderLayout.CENTER);
	}

}
