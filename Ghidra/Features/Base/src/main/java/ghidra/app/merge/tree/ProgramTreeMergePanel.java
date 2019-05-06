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
package ghidra.app.merge.tree;

import java.awt.CardLayout;
import java.awt.Dimension;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.checkbox.GCheckBox;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.util.ConflictCountPanel;
import ghidra.program.model.listing.Program;

/**
 * Panel for getting user input to resolve tree conflicts.
 * 
 * 
 */
class ProgramTreeMergePanel extends JPanel {
	private TreeChangePanel panelOne; // tree from Program One
	private TreeChangePanel panelTwo; // tree from Program Two

	private CardLayout cardLayout;
	private JPanel conflictPanel;
	private NamePanel namePanel;
	private NameConflictsPanel conflictsPanel;
	private ConflictCountPanel countPanel;

	private JPanel currentPanel;

	private int totalConflicts;
	private ProgramMultiUserMergeManager mergeManager;

	private static final String USE_FOR_ALL_CHECKBOX = "UseForAllConflictCheckBox";
	private JCheckBox useForAllCB;

	static final String KEEP_OTHER_BUTTON_NAME = MergeConstants.LATEST_TITLE;
	static final String KEEP_PRIVATE_BUTTON_NAME = MergeConstants.MY_TITLE;
	static final String ADD_NEW_BUTTON_NAME = "Add New";
	static final String RENAME_PRIVATE_BUTTON_NAME = "Rename My";
	static final String ORIGINAL_BUTTON_NAME = MergeConstants.ORIGINAL_TITLE;

	ProgramTreeMergePanel(ProgramMultiUserMergeManager mergeManager, int totalConflicts) {
		this.mergeManager = mergeManager;
		this.totalConflicts = totalConflicts;
		create();

	}

	/**
	 * Show the panel with the given panelID. Update the name fields on
	 * the checkboxes.
	 * @param panelID
	 * @param conflictIndex
	 * @param resultProgram the program where results are written ("other" program).
	 * @param name1 name from "other" program
	 * @param name2 name from "private" program
	 * @param origName name in ORIGINAL program
	 * @param name1Changed true if name changed in latest version
	 * @param structure1Changed true if structure changed in latest version
	 * @param name2Changed true if name changed in private version
	 * @param structure2Changed true if structure changed in private version
	 */
	void setConflictInfo(String panelID, int conflictIndex, Program resultProgram, String name1,
			String name2, String origName, boolean name1Changed, boolean structure1Changed,
			boolean name2Changed, boolean structure2Changed) {

		mergeManager.clearStatusText();
		mergeManager.setApplyEnabled(true);
		panelOne.setStates(name1, name1Changed, structure1Changed);
		panelTwo.setStates(name2, name2Changed, structure2Changed);
		setUseForAll(false);

		cardLayout.show(conflictPanel, panelID);
		if (panelID == ProgramTreeMergeManager.NAME_PANEL_ID) {
			currentPanel = namePanel;
			namePanel.setNames(name1, name2, origName);
		}
		else {
			currentPanel = conflictsPanel;
			conflictsPanel.setNames(resultProgram, name1, name2, origName,
				!structure1Changed && !structure2Changed);
		}
		countPanel.updateCount(conflictIndex, totalConflicts);

	}

	int getSelectedOption() {
		if (currentPanel == namePanel) {
			return namePanel.getSelectedOption();
		}
		return conflictsPanel.getSelectedOption();
	}

	private void create() {

		countPanel = new ConflictCountPanel();
		panelOne = new TreeChangePanel("Latest Version");
		panelTwo = new TreeChangePanel("Current Checked Out Version");

		conflictPanel = createConflictPanel();

		JPanel treePanel = new JPanel();
		treePanel.setLayout(new BoxLayout(treePanel, BoxLayout.X_AXIS));
		treePanel.add(panelOne);
		treePanel.add(Box.createHorizontalStrut(10));
		treePanel.add(panelTwo);

		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
		add(countPanel);
		add(Box.createVerticalStrut(10));
		add(treePanel);
		add(Box.createVerticalStrut(10));
		add(conflictPanel);
		add(Box.createVerticalStrut(5));
		JPanel useForAllPanel = new JPanel();
		useForAllPanel.add(createUseForAllCheckBox());
		add(useForAllPanel);
	}

	private JPanel createConflictPanel() {
		ChangeListener changeListener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				mergeManager.clearStatusText();
				mergeManager.setApplyEnabled(true);
			}
		};

		cardLayout = new CardLayout();
		JPanel panel = new JPanel(cardLayout);
		namePanel = new NamePanel(changeListener);
		conflictsPanel = new NameConflictsPanel(changeListener);
		panel.add(namePanel, ProgramTreeMergeManager.NAME_PANEL_ID);
		panel.add(conflictsPanel, ProgramTreeMergeManager.CONFLICTS_PANEL_ID);
		Dimension d = panel.getPreferredSize();
		panel.setPreferredSize(new Dimension(400, d.height));
		return panel;
	}

	private JCheckBox createUseForAllCheckBox() {
		useForAllCB = new GCheckBox(getUseAllString(""));
		useForAllCB.setName(USE_FOR_ALL_CHECKBOX);
		return useForAllCB;
	}

	private String getUseAllString(String conflictDescription) {
		return "Use the selected option for resolving all remaining 'Program Tree' conflicts" +
			conflictDescription + ".";
	}

	/**
	 * Sets the more specific part of the program tree conflict description for the checkbox.
	 * @param conflictDescription indicates the type of program tree conflict.
	 */
	void setConflictDetails(String conflictDescription) {
		useForAllCB.setText(getUseAllString(conflictDescription));
	}

	/**
	 * Selects or deselects the checkbox.
	 * @param useForAll true means select the checkbox.
	 */
	void setUseForAll(boolean useForAll) {
		useForAllCB.setSelected(useForAll);
	}

	/**
	 * Returns whether or not the checkbox is selected.
	 * @return true if the checkbox is selected.
	 */
	boolean getUseForAll() {
		return useForAllCB.isSelected();
	}
}
