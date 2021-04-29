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
package docking.widgets.dialogs;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.NoSuchElementException;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.label.GDLabel;
import docking.widgets.label.GHtmlLabel;

/**
 * A dialog that has text fields to get user input. 
 * 
 */
public class InputWithChoicesDialog extends DialogComponentProvider {

	private boolean isCanceled;
	private GhidraComboBox<String> combo;
	private boolean allowEdits;

	/**
	 * Creates a provider for a generic input dialog with the specified title,
	 * a label and a editable comboBox pre-populated with selectable values. The user
	 * can check the value of {@link #isCanceled()} to know whether or not 
	 * the user canceled the operation. To get the user selected value use the
	 * {@link #getValue()} value(s) entered by the user.  If the user cancelled the operation, then
	 * null will be returned from <code>getValue()</code>.
	 * <P>
	 * 
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param label value to use for the label of the text field
	 * @param optionValues values to populate the combo box
	 * @param initialValue the initial value - can be null
	 * @param messageIcon the icon to display on the dialog--can be null
	 */
	public InputWithChoicesDialog(String dialogTitle, String label, String[] optionValues,
			String initialValue, Icon messageIcon) {

		super(dialogTitle, true, false, true, false);

		setTransient(true);
		addOKButton();
		addCancelButton();
		setRememberSize(false);
		setRememberLocation(false);
		buildMainPanel(label, optionValues, initialValue, messageIcon);

		setFocusComponent(combo);
	}

	/**
	 * Creates a provider for a generic input dialog with the specified title,
	 * a label and a editable comboBox pre-populated with selectable values. The user
	 * can check the value of {@link #isCanceled()} to know whether or not 
	 * the user canceled the operation. To get the user selected value use the
	 * {@link #getValue()} value(s) entered by the user.  If the user cancelled the operation, then
	 * null will be returned from <code>getValue()</code>.
	 * <P>
	 * 
	 * @param dialogTitle used as the name of the dialog's title bar
	 * @param label value to use for the label of the text field
	 * @param optionValues values to populate the combo box
	 * @param initialValue the initial value - can be null
	 * @param allowEdits true allows the user to add custom entries to the combo box by entering text
	 * @param messageIcon the icon to display on the dialog--can be null
	 */
	public InputWithChoicesDialog(String dialogTitle, String label, String[] optionValues,
			String initialValue, boolean allowEdits, Icon messageIcon) {

		super(dialogTitle, true, false, true, false);

		this.addOKButton();
		this.addCancelButton();
		this.setRememberSize(false);
		this.setRememberLocation(false);
		this.allowEdits = allowEdits;
		buildMainPanel(label, optionValues, initialValue, messageIcon);

		setFocusComponent(combo);
	}

	@Override
	protected void dialogShown() {
		combo.requestFocusInWindow();
	}

	/**
	 * completes the construction of the gui for this dialog
	 */
	private void buildMainPanel(String labelText, String[] optionValues, String initialValue,
			Icon messageIcon) {

		// The main panel to be returned
		JPanel workPanel = new JPanel(new BorderLayout());
		workPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		// COMBO BOX PANEL
		JLabel messageLabel = new GHtmlLabel(labelText);
		messageLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
		combo = createComboBox(optionValues, initialValue);

		JPanel dataPanel = new JPanel(new BorderLayout());
		dataPanel.add(messageLabel, BorderLayout.NORTH);
		dataPanel.add(combo, BorderLayout.SOUTH);

		workPanel.add(dataPanel, BorderLayout.CENTER);

		// ICON PANEL (if an icon has been supplied)
		if (messageIcon != null) {
			JLabel iconLabel = new GDLabel();
			iconLabel.setIcon(messageIcon);
			iconLabel.setVerticalAlignment(SwingConstants.TOP);

			JPanel separatorPanel = new JPanel();
			separatorPanel.setPreferredSize(new Dimension(15, 1));

			JPanel iconPanel = new JPanel(new BorderLayout());
			iconPanel.add(iconLabel, BorderLayout.CENTER);
			iconPanel.add(separatorPanel, BorderLayout.EAST);

			workPanel.add(iconPanel, BorderLayout.WEST);
		}

		addWorkPanel(workPanel);
	}

	private GhidraComboBox<String> createComboBox(String[] optionValues, String initialValue) {
		GhidraComboBox<String> newComboBox = new GhidraComboBox<>(optionValues);
		newComboBox.setEditable(allowEdits);
		newComboBox.addActionListener(e -> okCallback());

		if (initialValue != null) {
			newComboBox.setSelectedItem(initialValue);
		}

		return newComboBox;
	}

	@Override
	protected void okCallback() {
		isCanceled = false;
		close();
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		close();
	}

	/**
	 * Returns if this dialog is canceled.
	 */
	public boolean isCanceled() {
		return isCanceled;
	}

	/**
	 * return the value of the first combo box
	 */
	public String getValue() {
		if (isCanceled) {
			return null;
		}
		Object selectedItem = combo.getSelectedItem();
		return selectedItem == null ? null : selectedItem.toString();
	}

	/**
	 * Set the current choice to value.
	 * @param value updated choice
	 * @throws NoSuchElementException if choice does not permit edits and value is
	 * not a valid choice. 
	 */
	public void setValue(String value) {
		combo.setSelectedItem(value);
		if (!combo.isEditable() && !combo.getSelectedItem().equals(value)) {
			throw new NoSuchElementException();
		}
	}
}
