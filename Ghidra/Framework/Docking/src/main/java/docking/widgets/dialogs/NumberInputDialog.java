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
import java.awt.Component;
import java.math.BigInteger;

import javax.swing.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.label.GDLabel;
import docking.widgets.textfield.IntegerTextField;

/**
 * <P>DialogComponentProvider that provides information to create a modal dialog
 * to prompt for a number (int) to be input by the user.</P>
 *
 * <P>If an initial value is specified it is not in the range of min,max, it will be set to the min.</P>
 *
 * <P>If the maximum value indicated is less than the minimum then the max
 * is the largest positive integer. Otherwise the maximum valid value is
 * as indicated.</P>
 *
 * <P>This dialog component provider class can be used by various classes and
 * therefore should not have its size or position remembered by the
 * tool.showDialog() call parameters.</P>
 * <br>To display the dialog call:
 * <pre>
 * <code>
 *     String entryType = "items";
 *     int initial = 5; // initial value in text field.
 *     int min = 1;     // minimum valid value in text field.
 *     int max = 10;    // maximum valid value in text field.
 *
 *     NumberInputDialog numInputProvider = new NumberInputProvider(entryType, initial, min, max);
 *     if (numInputProvider.show()) {
 *     	   // not cancelled
 *     	   int result = numInputProvider.getValue();
 *     }
 * </code>
 * </pre>
 */
public class NumberInputDialog extends DialogComponentProvider {

	private boolean wasCancelled = false;
	private IntegerTextField numberInputField;
	private int min;
	private int max;
	private JLabel label;
	private String defaultMessage;

	public NumberInputDialog(String entryType, int initial, int min) {
		this("Enter Number", buildDefaultPrompt(entryType, min, min - 1), initial, min,
			Integer.MAX_VALUE, false);
	}

	/**
	 * Constructs a new NumberInputDialog.
	 *
	 * @param entryType item type the number indicates
	 *                  (i.e. "duplicates", "items", or "elements").
	 * @param initial default value displayed in the text field.
	 * @param min minimum value allowed.
	 * @param max maximum value allowed.
	 */
	public NumberInputDialog(String entryType, int initial, int min, int max) {
		this("Enter Number", buildDefaultPrompt(entryType, min, max), initial, min, max, false);
	}

	/**
	 * Create a numberInputDialog where the the min is 0 and the max is INTEGER.MAX_VALUE
	 * @param title the title of the dialog
	 * @param prompt the prompt in the dialog
	 * @param initialValue the initial value.  If null, the text input will be blank.
	 */
	public NumberInputDialog(String title, String prompt, Integer initialValue) {
		this(title, prompt, initialValue, 0, Integer.MAX_VALUE, false);
	}

	/**
	 * Show a number input dialog.
	 * @param title The title of the dialog.
	 * @param prompt the prompt to display before the number input field.
	 * @param initialValue the default value to display, null will leave the field blank.
	 * @param min the minimum allowed value of the field.
	 * @param max the maximum allowed value of the field.
	 * @param showAsHex if true, the initial value will be displayed as hex.
	 */
	public NumberInputDialog(String title, String prompt, Integer initialValue, int min, int max,
			boolean showAsHex) {
		super(title, true, true, true, false);

		this.min = min;
		if (max < min) {
			throw new IllegalArgumentException(
				"'min' cannot be less than 'max'. 'min' = " + min + ", 'max' = " + max);
		}
		this.max = max;

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
	 * Define the Main panel for the dialog here.
	 * @param showAsHex
	 * @return JPanel the completed <CODE>Main Panel</CODE>
	 */
	protected JPanel buildMainPanel(String prompt, boolean showAsHex) {
		JPanel panel = createPanel(prompt);
		numberInputField.addActionListener(e -> okCallback());

		if (showAsHex) {
			numberInputField.setHexMode();
		}
		if (min >= 0) {
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
	 * Return whether the user cancelled the input dialog.
	 */
	public boolean wasCancelled() {
		return wasCancelled;
	}

	private void initializeDefaultValue(Integer initial) {
		if (initial == null) {
			return;
		}
		int value = initial.intValue();
		// Adjust the initial value if it is not valid.
		if (value < min) {
			value = min;
		}
		else if (value > max) {
			value = max;
		}
		numberInputField.setValue(value);
	}

	private void selectAndFocusText() {
		SwingUtilities.invokeLater(() -> {

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
		Component parent = DockingWindowManager.getActiveInstance().getActiveComponent();
		DockingWindowManager.showDialog(parent, this);
		return !wasCancelled;
	}

	/**
	 * Convert the input to an int value.
	 * @throws NumberFormatException if entered value cannot be parsed.
	 */
	public int getValue() {
		if (wasCancelled()) {
			throw new IllegalStateException();
		}
		return numberInputField.getIntValue();
	}

	/**
	 * Sets the value in the input field to the indicated value.
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
	 */
	public int getMin() {
		return min;
	}

	/**
	 * Return the maximum acceptable value.
	 */
	public int getMax() {
		return max;
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
		int value = numberInputField.getIntValue();
		return checkDecimalRange(value);
	}

	private boolean checkDecimalRange(int decimalValue) {

		if (decimalValue >= min && decimalValue <= max) {
			if (defaultMessage != null) {
				setStatusText(defaultMessage);
			}
			return true;
		}
		setStatusText("Value must be between " + min + " and " + max);
		return false;
	}

	private static String buildDefaultPrompt(String entryType, int min, int max) {
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
}
