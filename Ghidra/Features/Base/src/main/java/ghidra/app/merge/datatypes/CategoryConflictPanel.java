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
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;
import javax.swing.event.ChangeListener;

import docking.widgets.button.GRadioButton;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GLabel;
import ghidra.app.merge.MergeConstants;

/**
 * Shows radio buttons to resolve conflict for category.
 * 
 * 
 */
class CategoryConflictPanel extends JPanel {

	public static final String LATEST_BUTTON_NAME = "LatestVersionRB";
	public static final String CHECKED_OUT_BUTTON_NAME = "CheckedOutVersionRB";
	public static final String ORIGINAL_BUTTON_NAME = "OriginalVersionRB";
	private ChangeListener listener;
	private JRadioButton latestRB;
	private JRadioButton myRB;
	private JRadioButton originalRB;
	private ButtonGroup group;
	private JPanel rbPanel;
	private JLabel categoryLabel;

	CategoryConflictPanel(String title, ChangeListener listener) {
		super(new BorderLayout());
		setBorder(BorderFactory.createTitledBorder(title));
		create();
		this.listener = listener;
	}

	void setConflictInfo(String categoryName, String latestStr, String myStr, String origStr) {
		categoryLabel.setText(categoryName);
		group.remove(latestRB);
		group.remove(myRB);
		group.remove(originalRB);

		latestRB.setText(latestStr);

		myRB.setText(myStr);
		originalRB.setText(origStr);

		latestRB.setSelected(false);
		myRB.setSelected(false);
		originalRB.setSelected(false);
		addToButtonGroup();
	}

	int getSelectedOption() {
		if (latestRB.isSelected()) {
			return DataTypeMergeManager.OPTION_LATEST;
		}
		if (myRB.isSelected()) {
			return DataTypeMergeManager.OPTION_MY;
		}
		if (originalRB.isSelected()) {
			return DataTypeMergeManager.OPTION_ORIGINAL;
		}
		return -1;
	}

	private void create() {
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		categoryLabel = new GDLabel("CategoryName");
		categoryLabel.setForeground(MergeConstants.CONFLICT_COLOR);

		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(0, 0, 10, 0));
		labelPanel.setLayout(new BoxLayout(labelPanel, BoxLayout.X_AXIS));
		labelPanel.add(new GLabel("Category: "));
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(categoryLabel);

		latestRB = new GRadioButton("Use Latest");
		myRB = new GRadioButton("Use My Version");
		originalRB = new GRadioButton("Use Original");
		latestRB.setName(LATEST_BUTTON_NAME);
		myRB.setName(CHECKED_OUT_BUTTON_NAME);
		originalRB.setName(ORIGINAL_BUTTON_NAME);

		group = new ButtonGroup();
		addToButtonGroup();

		rbPanel = new JPanel();
		rbPanel.setLayout(new BoxLayout(rbPanel, BoxLayout.Y_AXIS));

		rbPanel.add(latestRB);
		rbPanel.add(myRB);
		rbPanel.add(originalRB);
		panel.add(labelPanel, BorderLayout.NORTH);
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
		latestRB.addItemListener(itemListener);
		myRB.addItemListener(itemListener);
		originalRB.addItemListener(itemListener);

	}

	private void addToButtonGroup() {
		group.add(latestRB);
		group.add(myRB);
		group.add(originalRB);
	}
}
