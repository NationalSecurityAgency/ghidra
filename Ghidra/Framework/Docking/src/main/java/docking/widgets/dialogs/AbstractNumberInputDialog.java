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
import java.math.BigInteger;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.label.GDLabel;
import docking.widgets.textfield.IntegerTextField;
import ghidra.util.Swing;

/**
 * A base class for prompting users to enter a number into this dialog
 */
public abstract class AbstractNumberInputDialog extends DialogComponentProvider {

	protected boolean wasCancelled = false;
	protected IntegerTextField numberInputField;
	protected BigInteger min;
	protected BigInteger max;
	protected JLabel label;
	protected String defaultMessage;

	/**
	 * Show a number input dialog
	 * @param title The title of the dialog
	 * @param prompt the prompt to display before the number input field
	 * @param initialValue the default value to display, null will leave the field blank
	 * @param min the minimum allowed value of the field
	 * @param max the maximum allowed value of the field
	 * @param showAsHex if true, the initial value will be displayed as hex
	 */
	public AbstractNumberInputDialog(String title, String prompt, Integer initialValue, int min,
			int max,
			boolean showAsHex) {
		this(title, prompt, toBig(initialValue), toBig(min), toBig(max), showAsHex);
	}

	/**
	 * Show a number input dialog
	 * @param title The title of the dialog
	 * @param prompt the prompt to display before the number input field
	 * @param initialValue the default value to display, null will leave the field blank
	 * @param min the minimum allowed value of the field
	 * @param max the maximum allowed value of the field
	 * @param showAsHex if true, the initial value will be displayed as hex
	 */
	public AbstractNumberInputDialog(String title, String prompt, BigInteger initialValue,
			BigInteger min,
			BigInteger max,
			boolean showAsHex) {
		super(title, true, true, true, false);

		this.min = min;
		if (max.compareTo(min) < 0) {
			throw new IllegalArgumentException(
				"'min' cannot be less than 'max'. 'min' = " + min + ", 'max' = " + max);
		}
		this.max = max;

		setTransient(true);
		addWorkPanel(buildMainPanel(prompt, showAsHex));
		addOKButton();
		addCancelButton();
		setRememberLocation(false);
		setRememberSize(false);

		initializeDefaultValue(initialValue);

		selectAndFocusText();
	}

	private static String nonNull(String s) {
		if (s == null) {
			return "items";
		}
		return s;
	}

	/**
	 * Define the Main panel for the dialog here
	 * @param prompt the prompt label text
	 * @param showAsHex if true, show the value as hex
	 * @return JPanel the completed <CODE>Main Panel</CODE>
	 */
	protected JPanel buildMainPanel(String prompt, boolean showAsHex) {
		JPanel panel = createPanel(prompt);
		numberInputField.addActionListener(e -> okCallback());

		if (showAsHex) {
			numberInputField.setHexMode();
		}
		if (min.compareTo(BigInteger.valueOf(0)) >= 0) {
			numberInputField.setAllowNegativeValues(false);
		}
		return panel;
	}

	/**
	 * Gets called when the user clicks on the OK Action for the dialog.
	 */
	@Override
	protected void okCallback() {
		if (checkInput()) {
			close();
		}
	}

	/**
	 * Gets called when the user clicks on the Cancel Action for the dialog.
	 */
	@Override
	protected void cancelCallback() {
		wasCancelled = true;
		close();
	}

	/**
	 * Return whether the user cancelled the input dialog
	 * @return true if cancelled
	 */
	public boolean wasCancelled() {
		return wasCancelled;
	}

	/**
	 * Get the current input value
	 * @return the value
	 * @throws NumberFormatException if entered value cannot be parsed
	 * @throws IllegalStateException if the dialog was cancelled
	 */
	public BigInteger getBigIntegerValue() {
		if (wasCancelled()) {
			throw new IllegalStateException("User cancelled the dialog");
		}
		return numberInputField.getValue();
	}

	/**
	 * Get the current input value as a long
	 * @return the value
	 * @throws NumberFormatException if entered value cannot be parsed
	 * @throws IllegalStateException if the dialog was cancelled
	 * @throws ArithmeticException if the value in this field will not fit into a long
	 */
	public long getLongValue() {
		if (wasCancelled()) {
			throw new IllegalStateException("User cancelled the dialog");
		}
		return numberInputField.getLongValue();
	}

	/**
	 * Get the current input value as an int
	 * @return the value
	 * @throws NumberFormatException if entered value cannot be parsed
	 * @throws IllegalStateException if the dialog was cancelled
	 * @throws ArithmeticException if the value in this field will not fit into an int
	 */
	public int getIntValue() {
		if (wasCancelled()) {
			throw new IllegalStateException("User cancelled the dialog");
		}
		return numberInputField.getIntValue();
	}

	private void initializeDefaultValue(BigInteger initial) {
		if (initial == null) {
			return;
		}

		// Adjust the initial value if it is not valid
		BigInteger value = initial;
		if (initial.compareTo(min) < 0) {
			value = min;
		}
		else if (initial.compareTo(max) > 0) {
			value = max;
		}
		numberInputField.setValue(value);
	}

	private void selectAndFocusText() {
		Swing.runLater(() -> {
			numberInputField.requestFocus();
			numberInputField.selectAll();
		});

	}

	/**
	 * <code>show</code> displays the dialog, gets the user input
	 *
	 * @return false if the user cancelled the operation
	 */
	public boolean show() {
		DockingWindowManager.showDialog(this);
		return !wasCancelled;
	}

	/**
	 * Sets the value in the input field to the indicated value.
	 * @param value the value
	 */
	public void setInput(int value) {
		numberInputField.setValue(value);
	}

	/**
	 * Sets the default message to be displayed when valid values are in the text fields.
	 * @param defaultMessage the message to be displayed when valid values are in the text fields.
	 */
	public void setDefaultMessage(String defaultMessage) {
		this.defaultMessage = defaultMessage;
		setStatusText(defaultMessage);
	}

	/**
	 * Return the minimum acceptable value.
	 * @return the min
	 */
	public int getMin() {
		return min.intValue();
	}

	/**
	 * Return the maximum acceptable value.
	 * @return the max
	 */
	public int getMax() {
		return max.intValue();
	}

//==================================================================================================
// Test Methods
//==================================================================================================

	IntegerTextField getNumberInputField() {
		return numberInputField;
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	/**
	 * Create the main panel.
	 */
	private JPanel createPanel(String prompt) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		label = new GDLabel(prompt);
		numberInputField = new IntegerTextField(12);
		numberInputField.addChangeListener(e -> updateOKButtonEnablement());

		// Actually assemble the parts into a status panel.
		panel.add(label, BorderLayout.WEST);
		panel.add(numberInputField.getComponent(), BorderLayout.CENTER);

		return panel;
	}

	protected void updateOKButtonEnablement() {
		clearStatusText();
		BigInteger value = numberInputField.getValue();
		if (value == null) {
			setOkEnabled(false);
			if (defaultMessage != null) {
				setStatusText(defaultMessage);
			}
			else {
				setStatusText("Enter a value between " + min + " and " + max);
			}
			return;
		}
		setOkEnabled(checkInput());
	}

	/**
	 * Check the entry;
	 *
	 * @return boolean true if input is OK
	 */
	private boolean checkInput() {
		BigInteger value = numberInputField.getValue();
		if (value.compareTo(min) >= 0 && value.compareTo(max) <= 0) {
			if (defaultMessage != null) {
				setStatusText(defaultMessage);
			}
			return true;
		}

		setStatusText("Value must be between " + min + " and " + max);
		return false;
	}

	protected static String buildDefaultPrompt(String entryType, int min, int max) {
		String type = nonNull(entryType);
		if (min == 0 && max == Integer.MAX_VALUE) {
			// full range
			return "Enter number of " + type + ": ";
		}
		else if (max == Integer.MAX_VALUE) {
			return "Enter number of " + type + " (minimum is " + min + ") : ";
		}
		else {
			return "Enter number of " + type + " (" + min + ", " + max + ") : ";
		}
	}

	protected static BigInteger toBig(Integer i) {
		if (i == null) {
			return null;
		}
		return BigInteger.valueOf(i);
	}

}
