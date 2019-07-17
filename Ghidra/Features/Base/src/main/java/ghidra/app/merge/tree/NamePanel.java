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

import java.awt.BorderLayout;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GRadioButton;
import ghidra.app.merge.MergeConstants;

/**
 * Panel for resolving name conflicts among program trees when private
 * name of tree does not exist in destination program.
 * 
 */
class NamePanel extends JPanel {

	private JRadioButton keepOtherRB;
	private JRadioButton keepMyRB;
	private JRadioButton newTreeRB;
	private JRadioButton originalRB;
	private ButtonGroup group;
	private ChangeListener listener;

	NamePanel(ChangeListener listener) {
		super(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder("Resolve Tree Name Conflict"));
		this.listener = listener;
		create();
	}

	void setNames(String name1, String name2, String origName) {
		keepOtherRB.setText("Use name '" + name1 + "' (" + MergeConstants.LATEST_TITLE + ")");

		keepMyRB.setText("Use name '" + name2 + "' (" + MergeConstants.MY_TITLE + ")");

		newTreeRB.setText("Add new tree named '" + name2 + "'");
		originalRB.setText("Use name '" + origName + "' (" + MergeConstants.ORIGINAL_TITLE + ")");

		group.remove(keepOtherRB);
		group.remove(keepMyRB);
		group.remove(newTreeRB);
		group.remove(originalRB);

		keepOtherRB.setSelected(false);
		keepMyRB.setSelected(false);
		newTreeRB.setSelected(false);
		originalRB.setSelected(false);
		addToButtonGroup();
	}

	int getSelectedOption() {
		if (keepOtherRB.isSelected()) {
			return ProgramTreeMergeManager.KEEP_OTHER_NAME;
		}
		if (keepMyRB.isSelected()) {
			return ProgramTreeMergeManager.KEEP_PRIVATE_NAME;
		}
		if (newTreeRB.isSelected()) {
			return ProgramTreeMergeManager.ADD_NEW_TREE;
		}
		if (originalRB.isSelected()) {
			return ProgramTreeMergeManager.ORIGINAL_NAME;
		}
		return ProgramTreeMergeManager.ASK_USER;
	}

	private void create() {

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		keepOtherRB = new GRadioButton("Keep 'Other' Name");
		keepMyRB = new GRadioButton("Keep 'My' Name");
		newTreeRB = new GRadioButton("Add New Tree");
		originalRB = new GRadioButton("Use Original Name");

		keepOtherRB.setName(ProgramTreeMergePanel.KEEP_OTHER_BUTTON_NAME);
		keepMyRB.setName(ProgramTreeMergePanel.KEEP_PRIVATE_BUTTON_NAME);
		newTreeRB.setName(ProgramTreeMergePanel.ADD_NEW_BUTTON_NAME);
		originalRB.setName(ProgramTreeMergePanel.ORIGINAL_BUTTON_NAME);

		group = new ButtonGroup();
		addToButtonGroup();

		JPanel rbPanel = new JPanel();
		rbPanel.setLayout(new BoxLayout(rbPanel, BoxLayout.Y_AXIS));
		rbPanel.add(keepOtherRB);
		rbPanel.add(keepMyRB);
		rbPanel.add(newTreeRB);
		rbPanel.add(originalRB);

		panel.add(rbPanel, BorderLayout.CENTER);

		add(panel);
		ItemListener itemListener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (listener != null) {
					listener.stateChanged(null);
				}
			}
		};
		keepOtherRB.addItemListener(itemListener);
		keepMyRB.addItemListener(itemListener);
		newTreeRB.addItemListener(itemListener);
		originalRB.addItemListener(itemListener);
	}

	private void addToButtonGroup() {
		group.add(keepOtherRB);
		group.add(keepMyRB);
		group.add(newTreeRB);
		group.add(originalRB);
	}
}
