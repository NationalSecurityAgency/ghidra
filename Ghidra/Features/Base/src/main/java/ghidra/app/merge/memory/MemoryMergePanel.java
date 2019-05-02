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
package ghidra.app.merge.memory;

import java.awt.BorderLayout;
import java.awt.CardLayout;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.checkbox.GCheckBox;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.util.ConflictCountPanel;

/**
 *
 * Panel to resolve conflicts on memory blocks.
 * 
 * 
 */
class MemoryMergePanel extends JPanel {

	private ProgramMultiUserMergeManager mergeManager;
	private int totalConflicts;
	private ConflictCountPanel countPanel;
	private CommentsConflictPanel commentPanel;
	private BlockConflictPanel namePanel;
	private CardLayout cardLayout;
	private JPanel cardPanel;
	private JPanel currentPanel;

	private static final String USE_FOR_ALL_CHECKBOX = "UseForAllConflictCheckBox";
	private JCheckBox useForAllCB;

	static String COMMENT_PANEL_ID = "Comment Conflict";
	static String CONFLICT_PANEL_ID = "Block Conflict";

	static final String LATEST_BUTTON_NAME = MergeConstants.LATEST_TITLE;
	static final String MY_BUTTON_NAME = MergeConstants.MY_TITLE;
	static final String ORIGINAL_BUTTON_NAME = MergeConstants.ORIGINAL_TITLE;

	/**
	 * Constructor
	 * @param mergeManager merge manager needed to enable the Apply button
	 * when an option is chosen to resolve a conflict
	 * @param totalConflicts total number of conflicts to be resolved 
	 */
	MemoryMergePanel(ProgramMultiUserMergeManager mergeManager, int totalConflicts) {
		super(new BorderLayout());
		this.mergeManager = mergeManager;
		this.totalConflicts = totalConflicts;
		create();
	}

	/**
	 * Set the conflict information on the panel.
	 * @param conflictIndex current conflict index
	 * @param panelID ID of which panel to show, either COMMENT_PANEL_ID or
	 * CONFLICT_PANEL_ID
	 * @param title title to use in the border of this panel
	 * @param latestStr text to show from LATEST program
	 * @param myStr text to show from MY program
	 * @param origStr text to show from ORIGINAL program
	 */
	void setConflictInfo(int conflictIndex, String panelID, String title, String latestStr,
			String myStr, String origStr) {
		countPanel.updateCount(conflictIndex, totalConflicts);
		cardPanel.setBorder(BorderFactory.createTitledBorder(title));
		if (panelID == COMMENT_PANEL_ID) {
			cardLayout.show(cardPanel, COMMENT_PANEL_ID);
			currentPanel = commentPanel;
			commentPanel.setComments(latestStr, myStr, origStr);
		}
		else {
			cardLayout.show(cardPanel, CONFLICT_PANEL_ID);
			currentPanel = namePanel;
			namePanel.setConflictInfo(latestStr, myStr, origStr);
		}
	}

	/**
	 * Get the selected option; called after the Apply button was hit.
	 */
	int getSelectedOption() {
		return (currentPanel == commentPanel) ? commentPanel.getSelectedOption()
				: namePanel.getSelectedOption();
	}

	private void create() {
		setLayout(new BorderLayout());

		JPanel boxPanel = new JPanel();
		boxPanel.setLayout(new BoxLayout(boxPanel, BoxLayout.Y_AXIS));

		cardLayout = new CardLayout();
		cardPanel = new JPanel(cardLayout);
		cardPanel.setBorder(BorderFactory.createTitledBorder("Resolve Block Conflict"));
		ChangeListener listener = new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				mergeManager.setApplyEnabled(true);
			}
		};
		commentPanel = new CommentsConflictPanel(listener);
		cardPanel.add(commentPanel, COMMENT_PANEL_ID);

		namePanel = new BlockConflictPanel(listener);
		cardPanel.add(namePanel, CONFLICT_PANEL_ID);

		cardLayout.show(cardPanel, CONFLICT_PANEL_ID);

		countPanel = new ConflictCountPanel();
		boxPanel.add(countPanel);
		boxPanel.add(Box.createVerticalStrut(10));
		boxPanel.add(cardPanel);

		add(boxPanel, BorderLayout.CENTER);
		add(createUseForAllCheckBox(), BorderLayout.SOUTH);
	}

	private JCheckBox createUseForAllCheckBox() {
		useForAllCB = new GCheckBox(getUseAllString("Memory Block"));
		useForAllCB.setName(USE_FOR_ALL_CHECKBOX);
		return useForAllCB;
	}

	private String getUseAllString(String conflictType) {
		return "Use the selected option for resolving all remaining '" + conflictType +
			"' conflicts.";
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
