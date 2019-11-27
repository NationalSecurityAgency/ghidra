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

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.util.*;

import javax.swing.*;

import docking.widgets.button.GRadioButton;
import ghidra.app.plugin.core.instructionsearch.InstructionSearchPlugin;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;

/**
 * Allows the user to define a custom search range for the {@link InstructionSearchDialog}.
 *
 */
public class SelectionScopeWidget extends ControlPanelWidget {

	// Toggle button that when active, allows the user to set a new search range.
	private JRadioButton searchAllRB;
	private JRadioButton searchSelectionRB;

	// Stores the current search range settings.
	private List<AddressRange> searchRanges = new ArrayList<>();

	private InstructionSearchDialog dialog;
	private InstructionSearchPlugin plugin;

	/**
	 * 
	 * @param plugin
	 * @param title
	 * @param dialog
	 */
	public SelectionScopeWidget(InstructionSearchPlugin plugin, String title,
			InstructionSearchDialog dialog) {
		super(title);

		this.plugin = plugin;
		this.dialog = dialog;
	}

	/**
	 * Returns the current search range.
	 */
	public List<AddressRange> getSearchRange() {
		if (searchAllRB.isSelected()) {
			updateSearchRangeAll();
		}
		else {
			updateSearchRangeBySelection();

		}

		return searchRanges;
	}

	/**
	 * Updates the current search range to encompass the entire program.
	 */
	public void updateSearchRangeAll() {

		if (plugin == null) {
			return;
		}

		searchRanges.clear();
		AddressRangeIterator iterator =
			plugin.getCurrentProgram().getMemory().getLoadedAndInitializedAddressSet().getAddressRanges();
		while (iterator.hasNext()) {
			searchRanges.add(iterator.next());
		}

	}

	/**
	 * Retrieves the currently-selected region in the listing and makes that the new search
	 * range.
	 */
	public void updateSearchRangeBySelection() {

		// if the user has set the toggle to "search selection", then update the search range,
		// otherwise leave alone.
		if (!searchSelectionRB.isSelected()) {
			return;
		}

		// If were here, then the user has selected the "search selection" radio button, so
		// we're about to update our range based on what is currently selected; start by clearing
		// out our current range.
		searchRanges.clear();

		if (plugin.getProgramSelection() == null) {
			return;
		}
		if (plugin.getProgramSelection().getMinAddress() == null ||
			plugin.getProgramSelection().getMaxAddress() == null) {
			return;
		}

		Iterator<AddressRange> iter = plugin.getProgramSelection().getAddressRanges();
		while (iter.hasNext()) {
			searchRanges.add(iter.next());
		}
	}

	/*********************************************************************************************
	 * PROTECTED METHODS
	 ********************************************************************************************/

	@Override
	protected JPanel createContent() {

		JPanel contentPanel = new JPanel();
		contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.X_AXIS));
		contentPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

		searchAllRB = createSearchRB(new SearchAllAction(), "Entire Program",
			"When active, the entire program will be used for the search.");
		searchAllRB.setSelected(true);
		contentPanel.add(searchAllRB);

		searchSelectionRB = createSearchRB(new SearchSelectionAction(), "Search Selection",
			"When active, code selections on the listing will change the search range.");
		contentPanel.add(searchSelectionRB);

		ButtonGroup group = new ButtonGroup();
		group.add(searchAllRB);
		group.add(searchSelectionRB);

		return contentPanel;
	}

	/*********************************************************************************************
	 * PRIVATE METHODS
	 ********************************************************************************************/

	/**
	 * Invoked when the user clicks the radio button that allows them to select a 
	 * custom search range.
	 */
	private class SearchSelectionAction extends AbstractAction {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			updateSearchRangeBySelection();
			dialog.getMessagePanel().clear();
		}
	}

	/**
	 * Invoked when the user selects the button to set the search range to cover the
	 * entire program.
	 */
	private class SearchAllAction extends AbstractAction {
		@Override
		public void actionPerformed(ActionEvent arg0) {
			updateSearchRangeAll();
			dialog.getMessagePanel().clear();
		}
	}

	/**
	 * Creates a radio button with the given attributes.
	 * 
	 * @param action
	 * @param name
	 * @param tooltip
	 * @return
	 */
	private JRadioButton createSearchRB(AbstractAction action, String name, String tooltip) {
		GRadioButton button = new GRadioButton(action);
		button.setName(name);
		button.setText(name);
		button.setToolTipText(tooltip);
		button.setAlignmentX(Component.LEFT_ALIGNMENT);
		return button;
	}
}
