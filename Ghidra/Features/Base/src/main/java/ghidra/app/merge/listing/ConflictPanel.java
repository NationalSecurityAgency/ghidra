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
package ghidra.app.merge.listing;

import java.awt.LayoutManager;

import javax.swing.JCheckBox;

import docking.widgets.checkbox.GCheckBox;

/**
 * Abstract class that should be implemented by the conflict panel that appears 
 * below the 4 listings in the merge window.
 */
public abstract class ConflictPanel extends ChoiceComponent {

	static final String USE_FOR_ALL_CHECKBOX = "UseForAllPropertyConflictCheckBox";
	JCheckBox useForAllCB;

	public ConflictPanel() {
		super();
	}

	public ConflictPanel(boolean isDoubleBuffered) {
		super(isDoubleBuffered);
	}

	public ConflictPanel(LayoutManager layout, boolean isDoubleBuffered) {
		super(layout, isDoubleBuffered);
	}

	public ConflictPanel(LayoutManager layout) {
		super(layout);
	}

	/**
	 * Returns an int value that indicates the choices currently selected for 
	 * the Use For All choice in the conflict resolution table. If there are
	 * multiple rows of choices, then all selected choices must be the same for each
	 * row or 0 is returned.
	 * Each button or check box has an associated value that can be bitwise 'OR'ed together
	 * to get the entire choice for the row.
	 * @return the choice(s) currently selected.
	 */
	public abstract int getUseForAllChoice();

	/**
	 * Returns true if the conflict panel currently provides at least one choice
	 * to the user.
	 * @return true if the panel has a choice the user can select.
	 */
	public abstract boolean hasChoice();

	/**
	 * Removes all listeners that were set on this panel for indicating user
	 * choices were being made or changed.
	 */
	public abstract void removeAllListeners();

	/**
	 * Called to reset the panel back to an empty state so it can be reused.
	 */
	public abstract void clear();

	protected JCheckBox createUseForAllCheckBox() {
		useForAllCB = new GCheckBox(getUseAllString("unknown"));
		useForAllCB.setName(USE_FOR_ALL_CHECKBOX);
		return useForAllCB;
	}

	private String getUseAllString(String conflictType) {
		return "Use the selected option for resolving all remaining '" + conflictType +
			"' conflicts.";
	}

	/**
	 * Sets the name of the conflict type that is displayed as part of the text for the checkbox.
	 * @param conflictType the type of markup that is in conflict.
	 */
	void setConflictType(String conflictType) {
		useForAllCB.setText(getUseAllString(conflictType));
	}

	/**
	 * Selects or deselects the checkbox.
	 * @param useForAll true means select the checkbox.
	 */
	void setUseForAll(boolean useForAll) {
		if (useForAllCB.isSelected() != useForAll) {
			useForAllCB.setSelected(useForAll);
		}
	}

	/**
	 * Returns whether or not the checkbox is selected.
	 * @return true if the checkbox is selected.
	 */
	boolean getUseForAll() {
		return useForAllCB.isSelected();
	}
}
