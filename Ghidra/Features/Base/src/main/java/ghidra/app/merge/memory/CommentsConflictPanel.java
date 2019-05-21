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
import ghidra.app.merge.MergeConstants;
import ghidra.util.layout.PairLayout;

/**
 * Panel that shows the block comments; has radio buttons to choose
 * which comment to use.
 * 
 * 
 */
class CommentsConflictPanel extends JPanel {

	private JRadioButton latestRB;
	private JRadioButton myRB;
	private JRadioButton originalRB;
	private ButtonGroup group;
	private JTextField latestField;
	private JTextField myField;
	private JTextField origField;
	private ChangeListener listener;

	/**
	 * Constructor
	 * @param listener listener that is notified when a radio button is
	 * selected
	 */
	CommentsConflictPanel(ChangeListener listener) {
		super();
		this.listener = listener;
		create();
	}

	/**
	 * Set the comments so the user can resolve the conflict
	 * @param latestComment comment from block in LATEST program
	 * @param myComment comment from block in MY program
	 * @param origComment comment from block in ORIGINAL program
	 */
	void setComments(String latestComment, String myComment, String origComment) {
		group.remove(latestRB);
		group.remove(myRB);
		group.remove(originalRB);
		latestRB.setSelected(false);
		myRB.setSelected(false);
		originalRB.setSelected(false);
		group.add(latestRB);
		group.add(myRB);
		group.add(originalRB);
		latestField.setText(latestComment);
		myField.setText(myComment);
		origField.setText(origComment);
	}

	/**
	 * Get the selected option.
	 */
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
		setLayout(new PairLayout(20, 5));

		group = new ButtonGroup();
		latestField = new JTextField(20);
		latestField.setEditable(false);

		myField = new JTextField(20);
		myField.setEditable(false);

		origField = new JTextField(20);
		origField.setEditable(false);

		add(createRadioButton(MergeConstants.LATEST));
		add(latestField);
		add(createRadioButton(MergeConstants.MY));
		add(myField);
		add(createRadioButton(MergeConstants.ORIGINAL));
		add(origField);
	}

	private JRadioButton createRadioButton(int id) {
		String str = null;
		switch (id) {
			case MergeConstants.LATEST:
				str = MergeConstants.LATEST_TITLE;
				break;
			case MergeConstants.MY:
				str = MergeConstants.MY_TITLE;
				break;
			case MergeConstants.ORIGINAL:
				str = MergeConstants.ORIGINAL_TITLE;
		}
		GRadioButton rb = new GRadioButton("Use comments from " + str);
		rb.addItemListener(new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
					listener.stateChanged(null);
				}
			}
		});
		if (id == MergeConstants.LATEST) {
			latestRB = rb;
			latestRB.setName(MemoryMergePanel.LATEST_BUTTON_NAME);
		}
		else if (id == MergeConstants.MY) {
			myRB = rb;
			myRB.setName(MemoryMergePanel.MY_BUTTON_NAME);
		}
		else {
			originalRB = rb;
			originalRB.setName(MemoryMergePanel.ORIGINAL_BUTTON_NAME);
		}
		group.add(rb);
		return rb;
	}
}
