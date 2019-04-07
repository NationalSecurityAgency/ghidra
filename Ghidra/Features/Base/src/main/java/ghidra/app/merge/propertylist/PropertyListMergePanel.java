/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package ghidra.app.merge.propertylist;

import ghidra.app.merge.ProgramMultiUserMergeManager;
import ghidra.app.merge.util.ConflictCountPanel;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

/**
 * Panel to show conflicts for properties and the number of conflicts.
 * 
 * 
 */
class PropertyListMergePanel extends JPanel {

	public static final String LATEST_BUTTON_NAME = ConflictPanel.LATEST_BUTTON_NAME;
	public static final String CHECKED_OUT_BUTTON_NAME = ConflictPanel.CHECKED_OUT_BUTTON_NAME;
	public static final String ORIGINAL_BUTTON_NAME = ConflictPanel.ORIGINAL_BUTTON_NAME;

	private int totalConflicts;
	private ConflictPanel conflictPanel;
	private ConflictCountPanel countPanel;

	private ProgramMultiUserMergeManager mergeManager;

	PropertyListMergePanel(ProgramMultiUserMergeManager mergeManager, int totalConflicts) {
		this.mergeManager = mergeManager;
		this.totalConflicts = totalConflicts;
		create();
	}

	/**
	 * Update the panel with conflict information.
	 * @param info info to show conflict information
	 * @param conflictIndex conflict #n 
	 */
	void setConflictInfo(int conflictIndex, ConflictInfo info) {

		mergeManager.clearStatusText();
		conflictPanel.setConflictInfo(info);
		countPanel.updateCount(conflictIndex, totalConflicts);
	}

	int getSelectedOption() {
		return conflictPanel.getSelectedOption();
	}

	private void create() {

		countPanel = new ConflictCountPanel();
		conflictPanel = createConflictPanel();

		setLayout(new BorderLayout(0, 20));
		setBorder(BorderFactory.createEmptyBorder(10, 5, 0, 5));
		add(countPanel, BorderLayout.NORTH);
		add(conflictPanel, BorderLayout.CENTER);
	}

	private ConflictPanel createConflictPanel() {
		ChangeListener changeListener = new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				mergeManager.clearStatusText();
				mergeManager.setApplyEnabled(true);
			}
		};

		conflictPanel = new ConflictPanel(changeListener);
		Dimension d = conflictPanel.getPreferredSize();
		conflictPanel.setPreferredSize(new Dimension(400, d.height));
		return conflictPanel;
	}

	/**
	 * Selects or deselects the checkbox.
	 * @param useForAll true means select the checkbox.
	 */
	void setUseForAll(boolean useForAll) {
		conflictPanel.setUseForAll(useForAll);
	}

	/**
	 * Returns whether or not the checkbox is selected.
	 * @return true if the checkbox is selected.
	 */
	boolean getUseForAll() {
		return conflictPanel.getUseForAll();
	}
}
