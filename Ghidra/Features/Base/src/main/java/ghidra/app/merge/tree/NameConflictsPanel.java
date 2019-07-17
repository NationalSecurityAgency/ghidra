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
import docking.widgets.label.GDLabel;
import docking.widgets.label.GIconLabel;
import ghidra.app.merge.MergeConstants;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

/**
 * Panel to get user input to resolve name conflicts when private name of tree
 * exists in destination program.
 * 
 */
class NameConflictsPanel extends JPanel {

	private JRadioButton keepOtherRB;
	private JRadioButton addOrRenameRB;
	private JRadioButton originalRB;
	private ButtonGroup group;
	private JLabel conflictsLabel;
	private ChangeListener listener;

	NameConflictsPanel(ChangeListener listener) {
		super(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder("Resolve Program Tree Conflict"));
		create();
		this.listener = listener;
	}

	void setNames(Program resultProgram, String latestName, String myName, String origName,
			boolean nameChangeOnly) {

		conflictsLabel.setText("Tree named '" + latestName + "' (" + MergeConstants.LATEST_TITLE +
			")" + " conflicts with '" + myName + "' (" + MergeConstants.MY_TITLE + ")");

		String text;
		if (nameChangeOnly) {
			text = "Use name '" + latestName + "' (" + MergeConstants.LATEST_TITLE + ")";
		}
		else {
			text = "Use '" + latestName + "' (" + MergeConstants.LATEST_TITLE + ") & lose '" +
				myName + "' (" + MergeConstants.MY_TITLE + ")";
		}
		keepOtherRB.setText(text);

		String myText;
		if (myName.equals(latestName)) {
			myText = "Add '" + myName + "' (" + MergeConstants.MY_TITLE + ") as '" +
				ProgramTreeMergeManager.getUniqueTreeName(resultProgram, myName) + "'";
		}
		else {
			myText = "Add tree '" + myName + "' (" + MergeConstants.MY_TITLE + ")";
		}
		addOrRenameRB.setText(myText);

		String origText;
		if (nameChangeOnly) {
			origText =
				"Use original name '" + origName + "' (" + MergeConstants.ORIGINAL_TITLE + ")";
		}
		else {
			if (origName.equals(latestName)) {
				origText = "Restore '" + origName + "' (" + MergeConstants.ORIGINAL_TITLE +
					") as '" + ProgramTreeMergeManager.getUniqueTreeName(resultProgram, origName) +
					"'" + " & lose '" + myName + "' (" + MergeConstants.MY_TITLE + ")";
			}
			else {
				origText = "Restore '" + origName + "' (" + MergeConstants.ORIGINAL_TITLE +
					") & lose '" + myName + "' (" + MergeConstants.MY_TITLE + ")";
			}
		}
		originalRB.setText(origText);

		group.remove(keepOtherRB);
		group.remove(addOrRenameRB);
		group.remove(originalRB);

		keepOtherRB.setSelected(false);
		addOrRenameRB.setSelected(false);
		originalRB.setSelected(false);
		group.add(keepOtherRB);
		group.add(addOrRenameRB);
		group.add(originalRB);
		invalidate();
	}

	int getSelectedOption() {
		if (keepOtherRB.isSelected()) {
			return ProgramTreeMergeManager.KEEP_OTHER_NAME;
		}
		if (addOrRenameRB.isSelected()) {
			return ProgramTreeMergeManager.RENAME_PRIVATE;
		}
		if (originalRB.isSelected()) {
			return ProgramTreeMergeManager.ORIGINAL_NAME;
		}
		return -1;
	}

	private void create() {
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JPanel iconPanel = new JPanel();
		iconPanel.setLayout(new BoxLayout(iconPanel, BoxLayout.X_AXIS));

		conflictsLabel = new GDLabel("'My' name already exists in Latest Version");
		ImageIcon icon = ResourceManager.loadImage("images/information.png");
		iconPanel.add(new GIconLabel(icon));
		iconPanel.add(Box.createHorizontalStrut(5));
		iconPanel.add(conflictsLabel);
		iconPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));

		keepOtherRB = new GRadioButton("Keep 'Other' Name");
		addOrRenameRB = new GRadioButton("Rename 'My' name to My.username");
		originalRB = new GRadioButton("Use 'Original' name");

		keepOtherRB.setName(ProgramTreeMergePanel.KEEP_OTHER_BUTTON_NAME);
		addOrRenameRB.setName(ProgramTreeMergePanel.RENAME_PRIVATE_BUTTON_NAME);
		originalRB.setName(ProgramTreeMergePanel.ORIGINAL_BUTTON_NAME);

		group = new ButtonGroup();
		group.add(keepOtherRB);
		group.add(addOrRenameRB);
		group.add(originalRB);

		JPanel rbPanel = new JPanel();
		rbPanel.setLayout(new BoxLayout(rbPanel, BoxLayout.Y_AXIS));
		rbPanel.add(keepOtherRB);
		rbPanel.add(addOrRenameRB);
		rbPanel.add(originalRB);

		panel.add(iconPanel, BorderLayout.NORTH);
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
		addOrRenameRB.addItemListener(itemListener);
		originalRB.addItemListener(itemListener);
	}
}
