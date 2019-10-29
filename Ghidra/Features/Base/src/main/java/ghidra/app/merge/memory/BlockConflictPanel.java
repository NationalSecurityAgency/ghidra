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

import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GRadioButton;

/**
 * Panel to show radio buttons to choose a name or a set of permissions
 * for a memory block, or to resolve the conflict for the image base
 * of the program.
 * 
 * 
 */
class BlockConflictPanel extends JPanel {

	private JRadioButton latestRB;
	private JRadioButton myRB;
	private JRadioButton originalRB;
	private ButtonGroup group;
	private ChangeListener listener;

	/**
	 * Constructor
	 * @param listener listener that is notified when a radio button is
	 * selected
	 */
	BlockConflictPanel(ChangeListener listener) {
		super();
		this.listener = listener;
		create();
	}

	/**
	 * Set the text on the radio buttons.
	 * @param latestStr text for Latest radio button
	 * @param myStr text for MY radio button
	 * @param origStr text for Original radio button
	 */
	void setConflictInfo(String latestStr, String myStr, String origStr) {
		latestRB.setText(latestStr);
		myRB.setText(myStr);
		originalRB.setText(origStr);
		group.remove(latestRB);
		group.remove(myRB);
		group.remove(originalRB);
		latestRB.setSelected(false);
		myRB.setSelected(false);
		originalRB.setSelected(false);
		group.add(latestRB);
		group.add(myRB);
		group.add(originalRB);
	}

	int getSelectedOption() {
		if (latestRB.isSelected()) {
			return MemoryMergeManager.OPTION_LATEST;
		}
		if (myRB.isSelected()) {
			return MemoryMergeManager.OPTION_MY;
		}
		if (originalRB.isSelected()) {
			return MemoryMergeManager.OPTION_ORIGINAL;
		}
		return MemoryMergeManager.ASK_USER;
	}

	private void create() {
		BoxLayout bl = new BoxLayout(this, BoxLayout.Y_AXIS);
		setLayout(bl);

		group = new ButtonGroup();

		ItemListener itemListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
					listener.stateChanged(null);
				}
			}
		};

		latestRB = new GRadioButton("Latest");
		latestRB.setName(MemoryMergePanel.LATEST_BUTTON_NAME);
		latestRB.addItemListener(itemListener);
		myRB = new GRadioButton("My");
		myRB.addItemListener(itemListener);
		myRB.setName(MemoryMergePanel.MY_BUTTON_NAME);
		originalRB = new GRadioButton("Original");
		originalRB.addItemListener(itemListener);
		originalRB.setName(MemoryMergePanel.ORIGINAL_BUTTON_NAME);

		group.add(latestRB);
		group.add(myRB);
		group.add(originalRB);

		add(latestRB);
		add(Box.createVerticalStrut(10));
		add(myRB);
		add(Box.createVerticalStrut(10));
		add(originalRB);
	}

}
