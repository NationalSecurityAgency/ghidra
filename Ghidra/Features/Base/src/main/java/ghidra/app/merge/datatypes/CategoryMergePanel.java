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
package ghidra.app.merge.datatypes;

import java.awt.BorderLayout;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import docking.widgets.checkbox.GCheckBox;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.util.ConflictCountPanel;
import ghidra.framework.data.DomainObjectMergeManager;

/**
 * Panel that shows a conflict for a category; gets user input to resolve
 * the conflict.
 * 
 * 
 */
class CategoryMergePanel extends JPanel {

	private DomainObjectMergeManager mergeManager;
	private int totalConflicts;
	private ConflictCountPanel countPanel;
	private CategoryConflictPanel resolvePanel;
	private int selectedOption;

	private static final String USE_FOR_ALL_CHECKBOX = "UseForAllConflictCheckBox";
	private JCheckBox useForAllCB;

	CategoryMergePanel(DomainObjectMergeManager mergeManager, int totalConflicts) {
		super(new BorderLayout());
		this.mergeManager = mergeManager;
		this.totalConflicts = totalConflicts;
		create();
	}

	void setConflictInfo(int conflictIndex, String latestPath, String path, String origPath,
			boolean latestRenamed, boolean renamed, boolean latestMoved, boolean moved,
			boolean latestDeleted, boolean deleted) {
		mergeManager.setApplyEnabled(false);
		countPanel.updateCount(conflictIndex, totalConflicts);

		String s1 = "Use '" + latestPath + "' (" + MergeConstants.LATEST_TITLE + ")";
		String s2 = "Use '" + path + "' (" + MergeConstants.MY_TITLE + ")";
		String s3 = "Use '" + origPath + "' (" + MergeConstants.ORIGINAL_TITLE + ")";
		if ((latestRenamed || renamed) && !deleted) {
			s1 = "Use name '" + latestPath + "' (" + MergeConstants.LATEST_TITLE + ")";
			s2 = "Use name '" + path + "' (" + MergeConstants.MY_TITLE + ")";
			s3 = "Use name '" + origPath + "' (" + MergeConstants.ORIGINAL_TITLE + ")";
		}
		else if (latestDeleted || deleted) {
			if (latestDeleted) {
				s1 = "Delete '" + origPath + "' (" + MergeConstants.LATEST_TITLE + ")";
				s2 = "Keep Category '" + path + "' (Checked Out)";
			}
			else {
				s1 = "Keep Category '" + latestPath + "' (" + MergeConstants.LATEST_TITLE + ")";
				s2 = "Delete Category '" + origPath + "' (" + MergeConstants.MY_TITLE + ")";
			}
			s3 = "Keep Category '" + origPath + "' (" + MergeConstants.ORIGINAL_TITLE + ")";
		}
		resolvePanel.setConflictInfo(origPath, s1, s2, s3);
	}

	int getSelectedOption() {
		selectedOption = resolvePanel.getSelectedOption();
		return selectedOption;
	}

	private void create() {
		countPanel = new ConflictCountPanel();
		resolvePanel = new CategoryConflictPanel("Resolve Conflict", new ChangeListener() {
			@Override
			public void stateChanged(ChangeEvent e) {
				mergeManager.clearStatusText();
				mergeManager.setApplyEnabled(true);
			}
		});

		setLayout(new BorderLayout(0, 10));
		add(countPanel, BorderLayout.NORTH);
		add(resolvePanel, BorderLayout.CENTER);
		add(createUseForAllCheckBox(), BorderLayout.SOUTH);
	}

	public static void main(String[] args) {
		JFrame frame = new JFrame("Test");

		CategoryMergePanel p = new CategoryMergePanel(null, 8);
		p.setConflictInfo(3, "/Category1/Category2/Category3/My Category",
			"/Category1/Category2/Category3/Another Category",
			"/Category1/Category2/Category3/Category4", true, true, false, false, false, false);
		frame.getContentPane().add(p);
		frame.pack();
		frame.setVisible(true);

	}

	private JCheckBox createUseForAllCheckBox() {
		useForAllCB = new GCheckBox(getUseAllString("Category"));
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
