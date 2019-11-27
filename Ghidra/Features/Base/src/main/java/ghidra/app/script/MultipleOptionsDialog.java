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
package ghidra.app.script;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.checkbox.GCheckBox;
import docking.widgets.label.GLabel;
import ghidra.util.Msg;

public class MultipleOptionsDialog<T> extends DialogComponentProvider {

	private boolean isCanceled;

	private GCheckBox[] selectOptions;
	private List<T> actualChoices;
	private List<String> stringChoices;
	private List<T> chosenByUser;
	private boolean includeSelectAll;
	private SelectAllCheckBox selectAllGroup;

	protected MultipleOptionsDialog(String title, String message, List<T> choices,
			boolean includeSelectAllBox) {
		super(title, true);

		stringChoices = new ArrayList<>();

		for (int i = 0; i < choices.size(); i++) {
			stringChoices.add(choices.get(i).toString());
		}

		actualChoices = choices;
		includeSelectAll = includeSelectAllBox;

		setup(message);
	}

	protected MultipleOptionsDialog(String title, String message, List<T> choices,
			List<String> stringRepresentationOfChoices, boolean includeSelectAllBox) {
		super(title, true);
		stringChoices = stringRepresentationOfChoices;
		actualChoices = choices;
		includeSelectAll = includeSelectAllBox;

		setup(message);
	}

	protected void setup(String message) {

		JPanel panel = new JPanel(new GridLayout(0, 1));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		panel.add(new GLabel(message), BorderLayout.WEST);

		if (includeSelectAll) {
			selectAllGroup = new SelectAllCheckBox();

			GCheckBox selectAllCheckBox = new GCheckBox("[ Select All ]", false);
			selectAllCheckBox.setName("select.all.check.box");
			panel.add(selectAllCheckBox);
			panel.add(new JSeparator());

			selectAllGroup.setSelectAllCheckBox(selectAllCheckBox);
		}

		selectOptions = new GCheckBox[stringChoices.size()];

		for (int i = 0; i < selectOptions.length; i++) {
			GCheckBox newCheckBox = new GCheckBox(stringChoices.get(i));
			newCheckBox.setActionCommand(Integer.toString(i));
			newCheckBox.setName("choice.check.box." + (i + 1));
			newCheckBox.setSelected(false);

			selectOptions[i] = newCheckBox;
			panel.add(selectOptions[i]);

			if (includeSelectAll) {
				selectAllGroup.addCheckBox(newCheckBox);
			}
		}

		addWorkPanel(panel);
		addOKButton();
		addCancelButton();

		if (SwingUtilities.isEventDispatchThread()) {
			DockingWindowManager.showDialog(null, this);
		}
		else {
			try {
				SwingUtilities.invokeAndWait(
					() -> DockingWindowManager.showDialog(null, MultipleOptionsDialog.this));
			}
			catch (Exception e) {
				Msg.error(this, "Unable to get choices from the user; error showing dialog - " +
					e.getMessage());
			}
		}

	}

	@Override
	protected void okCallback() {
		List<T> choicesMade = new ArrayList<>();
		for (int i = 0; i < selectOptions.length; i++) {
			if (selectOptions[i].isSelected()) {
				choicesMade.add(actualChoices.get(i));
			}
		}

		chosenByUser = choicesMade;

		close();
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		close();
	}

	protected boolean isCanceled() {
		return isCanceled;
	}

	protected List<T> getUserChoices() {
		return chosenByUser;
	}
}

class SelectAllCheckBox implements ActionListener {

	ArrayList<JCheckBox> otherBoxes = new ArrayList<>();
	JCheckBox selectAllCB = null;

	public void setSelectAllCheckBox(JCheckBox selAllCB) {
		selectAllCB = selAllCB;
		selectAllCB.addActionListener(this);
	}

	public void addCheckBox(JCheckBox newCB) {
		newCB.addActionListener(this);
		otherBoxes.add(newCB);
	}

	@Override
	public void actionPerformed(ActionEvent ae) {

		Object source = ae.getSource();

		// If user checks select-all checkbox, want to check all unchecked boxes.
		// If user unchecks select-all checkbox, want to uncheck all checked boxes.
		// If the select-all checkbox is checked, and the user unchecks a checked box, want to uncheck select-all checkbox.

		if (selectAllCB != null && selectAllCB.equals(source)) {
			if (selectAllCB.isSelected()) {
				for (JCheckBox otherCB : otherBoxes) {
					if (!otherCB.isSelected()) {
						otherCB.setSelected(true);
					}
				}
			}
			else {
				for (JCheckBox otherCB : otherBoxes) {
					if (otherCB.isSelected()) {
						otherCB.setSelected(false);
					}
				}
			}
		}
		else if (otherBoxes.contains(source)) {
			JCheckBox thisCB = (JCheckBox) source;

			if (!thisCB.isSelected() && selectAllCB.isSelected()) {
				selectAllCB.setSelected(false);
			}
		}
	}
}
