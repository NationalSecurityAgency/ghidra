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
import java.awt.Dimension;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;

import javax.swing.*;

import docking.widgets.MultiLineLabel;
import docking.widgets.button.GRadioButton;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GIconLabel;
import ghidra.app.merge.MergeConstants;
import ghidra.app.merge.util.ConflictCountPanel;
import ghidra.framework.data.DomainObjectMergeManager;
import ghidra.program.model.data.*;
import resources.ResourceManager;

/**
 * Panel to select a data type in order to resolve a conflict.
 * 
 * 
 */
class DataTypeMergePanel extends JPanel {

	public static final String LATEST_BUTTON_NAME = MergeConstants.LATEST_TITLE;
	public static final String CHECKED_OUT_BUTTON_NAME = MergeConstants.MY_TITLE;
	public static final String ORIGINAL_BUTTON_NAME = MergeConstants.ORIGINAL_TITLE;

	private DomainObjectMergeManager mergeManager;
	private int totalConflicts;
	private ConflictCountPanel countPanel;
	private DataTypePanel latestPanel;
	private DataTypePanel myPanel;
	private DataTypePanel origPanel;
	private JRadioButton latestRB;
	private JRadioButton myRB;
	private JRadioButton originalRB;
	private ButtonGroup buttonGroup;

	private static final String USE_FOR_ALL_CHECKBOX = "UseForAllConflictCheckBox";
	private JCheckBox useForAllCB;

	DataTypeMergePanel(DomainObjectMergeManager mergeManager, int totalConflicts) {
		super();
		this.mergeManager = mergeManager;
		this.totalConflicts = totalConflicts;
		create();

	}

	void setConflictInfo(int conflictIndex, DataType latestDt, DataType myDt, DataType origDt) {
		mergeManager.setApplyEnabled(false);
		countPanel.updateCount(conflictIndex, totalConflicts);

		latestPanel.setDataType(latestDt);
		myPanel.setDataType(myDt);
		origPanel.setDataType(origDt);

		buttonGroup.remove(latestRB);
		buttonGroup.remove(myRB);
		buttonGroup.remove(originalRB);

		latestRB.setSelected(false);
		myRB.setSelected(false);
		originalRB.setSelected(false);

		buttonGroup.add(latestRB);
		buttonGroup.add(myRB);
		buttonGroup.add(originalRB);
	}

	/**
	 * 
	 */
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
		return DataTypeMergeManager.ASK_USER; // shouldn't get here 
	}

	private void create() {

		buttonGroup = new ButtonGroup();
		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
					mergeManager.clearStatusText();
					mergeManager.setApplyEnabled(true);
				}
			}
		};

		latestRB = new GRadioButton(MergeConstants.LATEST_TITLE);
		latestRB.setName(LATEST_BUTTON_NAME);
		latestRB.addItemListener(listener);

		myRB = new GRadioButton(MergeConstants.MY_TITLE);
		myRB.setName(CHECKED_OUT_BUTTON_NAME);
		myRB.addItemListener(listener);

		originalRB = new GRadioButton(MergeConstants.ORIGINAL_TITLE);
		originalRB.setName(ORIGINAL_BUTTON_NAME);
		originalRB.addItemListener(listener);

		buttonGroup.add(latestRB);
		buttonGroup.add(myRB);
		buttonGroup.add(originalRB);

		setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));

		countPanel = new ConflictCountPanel();
		JPanel dtPanel = new JPanel();
		dtPanel.setLayout(new BoxLayout(dtPanel, BoxLayout.X_AXIS));
		dtPanel.add(createDataTypePanel(latestRB));
		dtPanel.add(createDataTypePanel(myRB));
		dtPanel.add(createDataTypePanel(originalRB));

		JPanel innerPanel = new JPanel();
		innerPanel.setLayout(new BoxLayout(innerPanel, BoxLayout.Y_AXIS));

		innerPanel.add(createInfoPanel());
		innerPanel.add(dtPanel);
		innerPanel.add(Box.createVerticalStrut(10));

		setLayout(new BorderLayout());
		add(countPanel, BorderLayout.NORTH);
		add(innerPanel, BorderLayout.CENTER);
		add(createUseForAllCheckBox(), BorderLayout.SOUTH);
	}

	private JPanel createDataTypePanel(JRadioButton rb) {
		JPanel panel = new JPanel(new BorderLayout());
		Structure s = new StructureDataType("Test", 0);
		s.add(new ByteDataType());
		s.add(new WordDataType());
		s.add(new QWordDataType());

		DataTypePanel dtPanel = new DataTypePanel(s);
		JScrollPane sp = new JScrollPane(dtPanel);
		sp.getViewport().setPreferredSize(new Dimension(300, 400));

		panel.add(sp);
		panel.add(rb, BorderLayout.SOUTH);
		if (rb == latestRB) {
			latestPanel = dtPanel;
		}
		else if (rb == myRB) {
			myPanel = dtPanel;
		}
		else {
			origPanel = dtPanel;
		}
		return panel;
	}

	private JPanel createInfoPanel() {

		Icon icon = ResourceManager.loadImage("images/information.png");
		JLabel imageLabel = new GIconLabel(icon);

		MultiLineLabel label =
			new MultiLineLabel("A data type change in your checked out version conflicts with a " +
				"data type change in the latest version.\n" +
				"Select the data type change you want included in the version " +
				"that will result from this check-in.");

		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 0, 0));
		BoxLayout bl = new BoxLayout(labelPanel, BoxLayout.X_AXIS);
		labelPanel.setLayout(bl);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(imageLabel);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(label);

		return labelPanel;
	}

	private JCheckBox createUseForAllCheckBox() {
		useForAllCB = new GCheckBox(getUseAllString("Data Type"));
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
