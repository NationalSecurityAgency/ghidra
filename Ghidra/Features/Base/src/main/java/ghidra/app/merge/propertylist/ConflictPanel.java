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
package ghidra.app.merge.propertylist;

import java.awt.BorderLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GDLabel;
import ghidra.app.merge.MergeConstants;

/**
 * Panel that shows differences for properties in Property Lists.
 */
class ConflictPanel extends JPanel {

	public static final String LATEST_BUTTON_NAME = MergeConstants.LATEST_TITLE;
	public static final String CHECKED_OUT_BUTTON_NAME = MergeConstants.MY_TITLE;
	public static final String ORIGINAL_BUTTON_NAME = MergeConstants.ORIGINAL_TITLE;

	private JRadioButton latestRB;
	private JRadioButton myRB;
	private JRadioButton originalRB;

	private static final String USE_FOR_ALL_CHECKBOX = "UseForAllConflictCheckBox";
	private JCheckBox useForAllCB;

	private ButtonGroup group;
	private JLabel propertyGroupLabel;

	private ChangeListener listener;

	ConflictPanel(ChangeListener listener) {
		super(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder("Resolve Property Name Conflict"));
		create();
		this.listener = listener;
	}

	void setConflictInfo(ConflictInfo info) {
		propertyGroupLabel.setText("Property Group: " + info.getGroupName());

		String origText = null;
		Object origValue = info.getOrigValue();
		if (origValue == null) {
			origText = "Value deleted (" + MergeConstants.ORIGINAL_TITLE + ")";
		}

		if (info.isTypeMatch()) {
			setBorder(BorderFactory.createTitledBorder(
				"Resolve Type Mismatch for Property " + info.getDisplayedPropertyName()));

			latestRB.setText("Use type '" + info.getLatestTypeString() + "', value = '" +
				info.getLatestValue() + "' (" + MergeConstants.LATEST_TITLE + ")");
			myRB.setText("Use type '" + info.getMyTypeString() + "', value = '" +
				info.getMyValue() + "' (" + MergeConstants.MY_TITLE + ")");
			if (origValue != null) {
				origText = "Use type '" + info.getOrigTypeString() + "', value = '" +
					info.getOrigValue() + "' (" + MergeConstants.ORIGINAL_TITLE + ")";
			}
		}
		else {

			setBorder(BorderFactory.createTitledBorder(
				"Resolve Property Conflict for " + info.getDisplayedPropertyName()));

			latestRB.setText(
				"Use value '" + info.getLatestValue() + "' (" + MergeConstants.LATEST_TITLE + ")");
			myRB.setText(
				"Use value '" + info.getMyValue() + "' (" + MergeConstants.MY_TITLE + " )");
			if (origValue != null) {
				origText = "Use value '" + origValue + "' (" + MergeConstants.ORIGINAL_TITLE + " )";
			}

		}
		originalRB.setText(origText);

		resetButtons();
	}

	/**
	 * Get the option that the user selected to resolve the conflict.
	 * @return either PropertyListMergeManager.LATEST_VERSION or
	 * PropertyListMergeManager.MY_VERSION
	 */
	int getSelectedOption() {
		if (latestRB.isSelected()) {
			return PropertyListMergeManager.LATEST_VERSION;
		}
		if (myRB.isSelected()) {
			return PropertyListMergeManager.MY_VERSION;
		}
		if (originalRB.isSelected()) {
			return PropertyListMergeManager.ORIGINAL_VERSION;
		}
		return -1;
	}

	private void resetButtons() {
		group.remove(latestRB);
		group.remove(myRB);
		group.remove(originalRB);

		latestRB.setSelected(false);
		myRB.setSelected(false);
		originalRB.setSelected(false);

		group.add(latestRB);
		group.add(myRB);
		group.add(originalRB);

		invalidate();
	}

	private void create() {
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		propertyGroupLabel = new GDLabel("Property Group:  ");

		JPanel namePanel = new JPanel(new BorderLayout());
		namePanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 10, 5));
		namePanel.add(propertyGroupLabel);

		latestRB = new GRadioButton("Use " + MergeConstants.LATEST_TITLE);
		myRB = new GRadioButton("Use " + MergeConstants.MY_TITLE);
		originalRB = new GRadioButton("Use " + MergeConstants.ORIGINAL_TITLE);

		latestRB.setName(LATEST_BUTTON_NAME);
		myRB.setName(CHECKED_OUT_BUTTON_NAME);
		originalRB.setName(ORIGINAL_BUTTON_NAME);

		group = new ButtonGroup();
		group.add(latestRB);
		group.add(myRB);
		group.add(originalRB);

		JPanel rbPanel = new JPanel();
		rbPanel.setLayout(new BoxLayout(rbPanel, BoxLayout.Y_AXIS));
		rbPanel.add(latestRB);
		rbPanel.add(myRB);
		rbPanel.add(originalRB);

		panel.add(namePanel, BorderLayout.NORTH);
		panel.add(rbPanel, BorderLayout.CENTER);
		panel.add(createUseForAllCheckBox(), BorderLayout.SOUTH);

		ItemListener itemListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (listener != null) {
					listener.stateChanged(null);
				}
			}
		};
		latestRB.addItemListener(itemListener);
		myRB.addItemListener(itemListener);
		originalRB.addItemListener(itemListener);

		add(panel);
	}

	protected JCheckBox createUseForAllCheckBox() {
		useForAllCB = new GCheckBox(getUseAllString("Property"));
		useForAllCB.setName(USE_FOR_ALL_CHECKBOX);
		return useForAllCB;
	}

	protected String getUseAllString(String conflictType) {
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
