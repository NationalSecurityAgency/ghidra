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

import javax.swing.*;

import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.app.plugin.core.instructionsearch.model.InstructionSearchData;
import ghidra.util.exception.InvalidInputException;

/**
 * Container for the {@link InstructionTable} and {@link PreviewTable}.
 */
public class InstructionSearchMainPanel extends JPanel {

	// Contains the instruction mnemonics/operands.
	private InstructionTablePanel instructionTablePanel;

	// Contains the preview strings associated with instructions in the InstructionTable.
	private PreviewTablePanel previewTablePanel;

	/**
	 * Saves the position of the splitter so when we reload the tables we can
	 * restore the last position the user set. This is static so it won't be
	 * recreated when a new search panel is created (which will happen every
	 * time a selection is initiated).
	 * 
	 * -1 ensures that the initial position will use the preferred pos of the
	 * splitter (50%).
	 */
	private static int splitterVal = -1;

	// The data model for this dialog.
	private InstructionSearchData searchData;

	/**
	 * Constructor.
	 * 
	 * @param plugin the instruction search plugin
	 * @param dialog the parent dialog
	 * @throws InvalidInputException if the search data is invalid
	 */
	public InstructionSearchMainPanel(final InstructionSearchPlugin plugin,
			InstructionSearchDialog dialog) throws InvalidInputException {

		super(new BorderLayout());

		this.searchData = dialog.getSearchData();

		// Get the number of operands we need to show (across all instructions); this 
		// will define the number of columns to create.
		if (searchData == null) {
			throw new InvalidInputException("Search data object cannot be null");
		}
		int operands = searchData.getMaxNumOperands();

		// Create the two main panels and link their scroll panes so they'll always
		// stay in sync, and add a splitter so we can adjust the view.
		instructionTablePanel = new InstructionTablePanel(operands, plugin, dialog);
		previewTablePanel = new PreviewTablePanel(1, plugin, dialog);
		linkScrollPanes(instructionTablePanel.getScrollPane(), previewTablePanel.getScrollPane());
		JSplitPane splitter = splitPanels(instructionTablePanel.getWorkPanel(), previewTablePanel);

		// And finally add to the main border layout.
		add(splitter, BorderLayout.CENTER);
	}

	public PreviewTable getPreviewTable() {
		return previewTablePanel.getTable();
	}

	public PreviewTablePanel getPreviewTablePanel() {
		return previewTablePanel;
	}

	public InstructionTablePanel getInstructionTablePanel() {
		return instructionTablePanel;
	}

	public InstructionTable getInstructionTable() {
		return instructionTablePanel.getTable();
	}

	/**
	 * Displays the current search strings based on all user settings. What is
	 * displayed in the {@link PreviewTablePanel} is what will be used for any
	 * subsequent searches.
	 * 
	 * @throws InvalidInputException
	 */
	public void buildPreview() throws InvalidInputException {
		previewTablePanel.buildPreview();
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Provides a link between the two given panels such that when one is
	 * scrolled (vertically) the other is scrolled accordingly.
	 * 
	 * @param panel1 left panel
	 * @param panel2 right panel
	 */
	private void linkScrollPanes(JScrollPane panel1, JScrollPane panel2) {
		BoundedRangeModel model = panel1.getVerticalScrollBar().getModel();
		panel2.getVerticalScrollBar().setModel(model);
	}

	/**
	 * Creates a splitter between the two given panels.
	 * 
	 * @param panel1 left panel
	 * @param panel2 right panel
	 * @return
	 */
	private JSplitPane splitPanels(JPanel panel1, JPanel panel2) {

		// Set up a split pane to divide the two tables and set the current splitter 
		// position to whatever is in splitterVal; this ensures that if the user sets
		// a splitter position, the next time the table is loaded it will use that
		// position.
		JSplitPane splitter = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, panel1, panel2);
		splitter.setDividerLocation(splitterVal);

		splitter.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
			pce -> splitterVal = (int) pce.getNewValue());
		return splitter;
	}
}
