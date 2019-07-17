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
package ghidra.app.plugin.core.datamgr.util;

import java.awt.BorderLayout;
import java.awt.event.*;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.button.GRadioButton;
import docking.widgets.label.GIconLabel;
import docking.widgets.label.GLabel;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * Dialog to get user input on how to handle data type conflicts.
 */
public class ConflictDialog extends DialogComponentProvider {

	final static int REPLACE = 1;
	final static int USE_EXISTING = 2;
	final static int RENAME = 3;

	private boolean applyToAll;
	private JRadioButton replaceRB;
	private JRadioButton useExistingRB;
	private JRadioButton renameRB;
	private JButton applyToAllButton;
	private int selectedOption = RENAME;

	private ImageIcon INFORM_ICON = ResourceManager.loadImage("images/warning.png");

	/**
	 * Constructor
	 * @param dtName data type name
	 * @param categoryName category path
	 * @param newDTName new name to resolve conflict
	 */
	public ConflictDialog(String dtName, String categoryPath, String newDTName) {
		super("Data Type Conflict for " + dtName);
		setHelpLocation(new HelpLocation("DataManagerPlugin", "DataTypeConflicts"));
		addWorkPanel(buildMainPanel(dtName, categoryPath, newDTName));

		addOKButton();
		applyToAllButton = new JButton("Apply to All");
		applyToAllButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				applyToAll = true;
				close();
			}
		});
		addButton(applyToAllButton);
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#okCallback()
	 */
	@Override
	protected void okCallback() {
		close();
	}

	/* (non-Javadoc)
	 * @see ghidra.util.bean.GhidraDialog#cancelCallback()
	 */
	@Override
	protected void cancelCallback() {
		close();
	}

	int getSelectedOption() {
		return selectedOption;
	}

	boolean applyChoiceToAll() {
		return applyToAll;
	}

	private JPanel buildMainPanel(String dtName, String categoryPath, String newDTName) {
		JPanel outerPanel = new JPanel(new BorderLayout(20, 0));

		outerPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
		JPanel mainPanel = new JPanel();
		mainPanel.setBorder(BorderFactory.createTitledBorder("Resolve Data Type Conflict"));

		mainPanel.setLayout(new BoxLayout(mainPanel, BoxLayout.Y_AXIS));

		ItemListener listener = new ItemListener() {
			@Override
			public void itemStateChanged(ItemEvent e) {
				if (e.getStateChange() == ItemEvent.SELECTED) {
					Object source = e.getSource();
					if (source == replaceRB) {
						selectedOption = REPLACE;
					}
					else if (source == useExistingRB) {
						selectedOption = USE_EXISTING;
					}
					else {
						selectedOption = RENAME;
					}
				}
			}
		};

		ButtonGroup bg = new ButtonGroup();
		renameRB = new GRadioButton("Rename new data type to " + newDTName, true);
		replaceRB = new GRadioButton("Replace existing data type");
		useExistingRB = new GRadioButton("Use existing data type");

		renameRB.addItemListener(listener);
		useExistingRB.addItemListener(listener);
		replaceRB.addItemListener(listener);

		bg.add(renameRB);
		bg.add(replaceRB);
		bg.add(useExistingRB);

		mainPanel.add(Box.createVerticalStrut(5));
		mainPanel.add(renameRB);
		mainPanel.add(replaceRB);
		mainPanel.add(useExistingRB);

		outerPanel.add(createLabelPanel(dtName, categoryPath), BorderLayout.NORTH);
		outerPanel.add(mainPanel, BorderLayout.CENTER);
		return outerPanel;
	}

	private JPanel createLabelPanel(String dtName, String categoryPath) {
		JPanel labelPanel = new JPanel();
		labelPanel.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 20));
		BoxLayout bl = new BoxLayout(labelPanel, BoxLayout.X_AXIS);
		labelPanel.setLayout(bl);
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(new GIconLabel(INFORM_ICON));
		labelPanel.add(Box.createHorizontalStrut(5));
		labelPanel.add(new GLabel("Conflict exists in " + categoryPath + " for " + dtName));

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(labelPanel);
		panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 20, 0));
		return panel;
	}

}
