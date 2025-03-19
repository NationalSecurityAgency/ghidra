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
package docking.widgets.textfield;

import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JTextField;
import javax.swing.event.*;
import javax.swing.text.*;

import ghidra.util.SystemUtilities;

/**
 * TextField for entering integer numbers, either in decimal or hex.
 *
 * <P>
 * This field does continuous checking, so you can't enter a bad value.
 *
 * <P>
 * Internally, values are maintained using BigIntegers so this field can contain numbers as large as
 * desired. There are convenience methods for getting the value as either an int or long. If using
 * these convenience methods, you should also set the max allowed value so that users can't enter a
 * value larger than can be represented by the {@link #getIntValue()} or {@link #getLongValue()}
 * methods as appropriate.
 *
 * <P>
 * There are several configuration options as follows:
 * <UL>
 * <LI>Allows negative numbers - either support all integer numbers or just non-negative numbers.
 * See {@link #setAllowNegativeValues(boolean)}</LI>
 * <LI>Allows hex prefix - If this mode is on, then hex mode is turned on and off automatically
 * depending whether or not the text starts with 0x. Otherwise, the hex/decimal mode is set
 * externally (either programmatically or pressing &lt;CTRL&gt; M) and the user is restricted to the
 * numbers/letters appropriate for that mode. See {@link #setAllowsHexPrefix(boolean)}</LI>
 * <LI>Have a max value - a max value can be set (must be positive) such that the user can not type
 * a number whose absolute value is greater than the max. Otherwise, the value is unlimited if max
 * is null/unspecified. See {@link #setMaxValue(BigInteger)}</LI>
 * <LI>Show the number mode as hint text - If on either "Hex" or "Dec" is displayed lightly in the
 * bottom right portion of the text field. See {@link #setShowNumberMode(boolean)}</LI>
 * </UL>
 *
 */

public class IntegerTextField {
	private HexDecimalModeTextField textField;

	private boolean isHexMode = false;
	private boolean allowsNegative = true;
	private boolean allowsHexPrefix = true;
	private BigInteger maxValue;
	private BigInteger minValue;

	private List<ChangeListener> listeners = new ArrayList<>();

	/**
	 * Creates a new IntegerTextField with 5 columns and no initial value
	 */
	public IntegerTextField() {
		this(5, null);
	}

	/**
	 * Creates a new IntegerTextField with the specified number of columns and no initial value
	 *
	 * @param columns the number of columns.
	 */
	public IntegerTextField(int columns) {
		this(columns, null);
	}

	/**
	 * Creates a new IntegerTextField with the specified number of columns and an initial value
	 *
	 * @param columns the number of columns to display in the JTextField.
	 * @param initialValue the initial value. This constructor takes an initialValue as a long. If
	 *            you need a value that is bigger (or smaller) than can be specified as a long, then
	 *            use the constructor that takes a BigInteger as an initial value.
	 */
	public IntegerTextField(int columns, long initialValue) {
		this(columns, BigInteger.valueOf(initialValue));
	}

	/**
	 * Creates a new IntegerTextField with the specified number of columns and initial value
	 *
	 * @param columns the number of columns
	 * @param initialValue the initial value
	 */
	public IntegerTextField(int columns, BigInteger initialValue) {
		textField = new HexDecimalModeTextField(columns, b -> textFieldHexModeChanged(b));

		AbstractDocument document = (AbstractDocument) textField.getDocument();
		document.setDocumentFilter(new HexDecimalDocumentFilter());
		setValue(initialValue);

		document.addDocumentListener(new DocumentListener() {

			@Override
			public void removeUpdate(DocumentEvent e) {
				SystemUtilities.runSwingLater(() -> valueChanged());
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				SystemUtilities.runSwingLater(() -> valueChanged());
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				SystemUtilities.runSwingLater(() -> valueChanged());
			}
		});
	}

	/**
	 * Adds a change listener that will be notified whenever the value changes.
	 *
	 * @param listener the change listener to add.
	 */
	public void addChangeListener(ChangeListener listener) {
		listeners.add(listener);
	}

	/**
	 * Sets the accessible name for the component of this input field.
	 * @param name the accessible name for this field
	 */
	public void setAccessibleName(String name) {
		textField.getAccessibleContext().setAccessibleName(name);
	}

	/**
	 * Removes the changes listener.
	 *
	 * @param listener the listener to be removed.
	 */
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	/**
	 * Returns the current value of the field or null if the field has no current value.
	 *
	 * @return the current value of the field or null if the field has no current value.
	 */
	public BigInteger getValue() {
		String text = textField.getText();
		return computeValueFromString(text, isHexMode);
	}

	/**
	 * Returns the current value as an int.
	 *
	 * <P>
	 * If the field has no current value, 0 will be returned. If the value is bigger (or smaller)
	 * than an int, it will be cast to an int.
	 *
	 * <P>
	 * If using this method, it is highly recommended that you set the max value to
	 * {@link Integer#MAX_VALUE} or lower.
	 *
	 * @return the current value as an int. Or 0 if there is no value
	 * @throws ArithmeticException if the value in this field will not fit into an int
	 */
	public int getIntValue() {
		BigInteger currentValue = getValue();
		if (currentValue == null) {
			return 0;
		}
		return currentValue.intValueExact();
	}

	/**
	 * Returns the current value as a long.
	 *
	 * <P>
	 * If the field has no current value, 0 will be returned. If the value is bigger (or smaller)
	 * than an long, it will be cast to a long.
	 *
	 * <P>
	 * If using this method, it is highly recommended that you set the max value to
	 * {@link Long#MAX_VALUE} or lower.
	 *
	 * @return the current value as a long. Or 0 if there is no value
	 * @throws ArithmeticException if the value in this field will not fit into a long
	 */
	public long getLongValue() {
		BigInteger currentValue = getValue();
		if (currentValue == null) {
			return 0;
		}
		return currentValue.longValueExact();
	}

	/**
	 * Convenience method for setting the value to a long value;
	 *
	 * @param newValue the new value for the field.
	 */
	public void setValue(long newValue) {
		setValue(BigInteger.valueOf(newValue));
	}

	/**
	 * Convenience method for setting the value to an int value;
	 *
	 * @param newValue the new value for the field.
	 */
	public void setValue(int newValue) {
		setValue(BigInteger.valueOf(newValue));
	}

	/**
	 * Sets the field to the given text. The text must be a properly formated string that is a value
	 * that is valid for this field. If the field is set to not allow "0x" prefixes, then the input
	 * string cannot start with 0x and furthermore, if the field is in decimal mode, then input
	 * string cannot take in hex digits a-f. On the other hand, if "0x" prefixes are allowed, then
	 * the input string can be either a decimal number or a hex number depending on if the input
	 * string starts with "0x". In this case, the field's hex mode will be set to match the input
	 * text. If the text is not valid, the field will not change.
	 * 
	 * @param text the value as text to set on this field
	 * @return true if the set was successful
	 */
	public boolean setText(String text) {
		String oldText = textField.getText();
		textField.setText(text);
		return !oldText.equals(textField.getText());
	}

	/**
	 * Sets the value of the field to the given value. A null value will clear the field.
	 *
	 * @param newValue the new value or null.
	 */
	public void setValue(BigInteger newValue) {

		if (!allowsNegative && newValue != null && newValue.signum() < 0) {
			newValue = null;
		}

		updateTextField(newValue);
	}

	/**
	 * Turns on or off the faded text that displays the field's radix mode (hex or decimal).
	 *
	 * @param show true to show the radix mode.
	 */
	public void setShowNumberMode(boolean show) {
		textField.setShowNumberMode(show);
	}

	/**
	 * Sets the radix mode to Hex.
	 *
	 * <P>
	 * If the field is currently in decimal mode, the current text will be change from displaying
	 * the current value from decimal to hex.
	 */
	public void setHexMode() {
		BigInteger value = getValue();
		setHexMode(true);
		setValue(value);

	}

	private void setHexMode(boolean hexMode) {
		this.isHexMode = hexMode;
		textField.setHexMode(hexMode);
	}

	/**
	 * Sets the mode to Decimal.
	 *
	 * <P>
	 * If the field is currently in hex mode, the current text will be change from displaying the
	 * current value from hex to decimal.
	 */
	public void setDecimalMode() {
		BigInteger value = getValue();
		setHexMode(false);
		setValue(value);
	}

	/**
	 * Sets whether on not the field supports the 0x prefix.
	 *
	 * <P>
	 * If 0x is supported, hex numbers will be displayed with the 0x prefix. Also, when typing, you
	 * must type 0x first to enter a hex number, otherwise it will only allow digits 0-9. If the 0x
	 * prefix option is turned off, then hex numbers are displayed without the 0x prefix and you
	 * can't change the decimal/hex mode by typing 0x. The field will either be in decimal or hex
	 * mode and the typed text will be interpreted appropriately for the mode.
	 *
	 * @param allowsHexPrefix true to use the 0x convention for hex.
	 */
	public void setAllowsHexPrefix(boolean allowsHexPrefix) {
		BigInteger currentValue = getValue();
		this.allowsHexPrefix = allowsHexPrefix;
		updateTextField(currentValue);
	}

	/**
	 * Returns the current text displayed in the field.
	 *
	 * @return the current text displayed in the field.
	 */
	public String getText() {
		return textField.getText();
	}

	/**
	 * Returns true if in hex mode, false if in decimal mode.
	 *
	 * @return true if in hex mode, false if in decimal mode.
	 */
	public boolean isHexMode() {
		return isHexMode;
	}

	/**
	 * Sets whether or not negative numbers are accepted.
	 *
	 * @param b if true, negative numbers are allowed.
	 */
	public void setAllowNegativeValues(boolean b) {
		BigInteger currentValue = getValue();
		allowsNegative = b;
		if (!allowsNegative) {
			if (currentValue != null && currentValue.signum() < 0) {
				currentValue = null;
			}
		}
		updateTextField(currentValue);
	}

	/**
	 * Returns the current maximum allowed value. Null indicates that there is no maximum value. If
	 * negative values are permitted (see {@link #setAllowNegativeValues(boolean)}) this value will
	 * establish the upper and lower limit of the absolute value.
	 * 
	 * @return the current maximum value allowed.
	 */
	public BigInteger getMaxValue() {
		return maxValue;
	}

	/**
	 * Sets the maximum allowed value. The maximum must be a positive number. Null indicates that
	 * there is no maximum value.
	 * <p>
	 * If negative values are permitted (see {@link #setAllowNegativeValues(boolean)}) this value
	 * will establish the upper and lower limit of the absolute value.
	 *
	 * @param maxValue the maximum value to allow.
	 */
	public void setMaxValue(BigInteger maxValue) {
		if (maxValue != null && maxValue.signum() < 0) {
			throw new IllegalArgumentException("Max value must be positive");
		}
		BigInteger currentValue = getValue();
		this.maxValue = maxValue;
		if (maxValue != null && !passesMaxCheck(currentValue)) {
			if (currentValue.signum() < 0) {
				setValue(maxValue.negate());
			}
			else {
				setValue(maxValue);
			}
		}
	}

	/**
	 * Sets the minimum allowed value.  The minimum must be a positive number.  Null indicates that
	 * there is no minimum value.
	 * <p>
	 * If negative values are permitted (see {@link #setAllowNegativeValues(boolean)}) this value
	 * will establish the minimum limit of the absolute value.
	 *
	 * @param minValue the minimum value to allow.
	 */
	public void setMinValue(BigInteger minValue) {
		if (minValue != null && minValue.signum() < 0) {
			throw new IllegalArgumentException("Min value must be positive");
		}
		BigInteger currentValue = getValue();
		this.minValue = minValue;
		if (minValue != null && !passesMinCheck(currentValue)) {
			if (currentValue.signum() < 0) {
				setValue(minValue.negate());
			}
			else {
				setValue(minValue);
			}
		}
	}

	/**
	 * Returns the JTextField component that this class manages.
	 *
	 * @return the JTextField component that this class manages.
	 */
	public JComponent getComponent() {
		return textField;
	}

	/**
	 * Adds an ActionListener to the TextField.
	 *
	 * @param listener the ActionListener to add.
	 */
	public void addActionListener(ActionListener listener) {
		textField.addActionListener(listener);
	}

	/**
	 * Removes an ActionListener from the TextField.
	 *
	 * @param listener the ActionListener to remove.
	 */
	public void removeActionListener(ActionListener listener) {
		textField.removeActionListener(listener);
	}

	/**
	 * Sets the enablement on the JTextField component;
	 *
	 * @param enabled true for enabled, false for disabled.
	 */
	public void setEnabled(boolean enabled) {
		textField.setEnabled(enabled);
	}

	/**
	 * Sets the editable mode for the JTextField component
	 * 
	 * @param editable boolean flag, if true component is editable
	 */
	public void setEditable(boolean editable) {
		textField.setEditable(editable);
	}

	/**
	 * Requests focus to the JTextField
	 */
	public void requestFocus() {
		textField.requestFocus();
	}

	/**
	 * Selects the text in the JTextField
	 */
	public void selectAll() {
		textField.selectAll();
	}

	/**
	 * Sets the horizontal alignment of the JTextField
	 * 
	 * @param alignment the alignment as in {@link JTextField#setHorizontalAlignment(int)}
	 */
	public void setHorizontalAlignment(int alignment) {
		textField.setHorizontalAlignment(alignment);
	}

	private void textFieldHexModeChanged(boolean hexMode) {
		BigInteger value = getValue();
		this.isHexMode = hexMode;
		setValue(value);
	}

	private String computeTextForValue(BigInteger value) {
		if (value == null) {
			return "";
		}
		if (isHexMode) {
			String text = value.toString(16);
			if (allowsHexPrefix) {
				if (text.startsWith("-")) {
					return "-0x" + text.substring(1);
				}
				return "0x" + text;
			}
			return text;
		}

		// otherwise, show as decimal
		return value.toString(10);
	}

	private BigInteger computeValueFromString(String text, boolean parseAsHex) {
		if (text.isEmpty() || isValidPrefix(text)) {
			return null;
		}

		if (!parseAsHex) {
			return new BigInteger(text, 10);
		}

		if (allowsHexPrefix) {
			if (text.startsWith("0x")) {
				text = text.substring(2);
			}
			else if (text.startsWith("-0x")) {
				text = "-" + text.substring(3);
			}
		}
		if (text.isEmpty()) {
			return null;
		}
		return new BigInteger(text, 16);
	}

	private void valueChanged() {
		for (ChangeListener listener : listeners) {
			listener.stateChanged(new ChangeEvent(this));
		}
	}

	private boolean passesMaxCheck(BigInteger value) {
		if (value == null) {
			return true;
		}
		if (maxValue == null) {
			return true;
		}
		return value.abs().compareTo(maxValue) <= 0;
	}

	private boolean passesMinCheck(BigInteger value) {
		if (value == null) {
			return true;
		}
		if (minValue == null) {
			return true;
		}
		return value.abs().compareTo(minValue) >= 0;
	}

	private boolean shouldParseAsHex(String text) {
		if (allowsHexPrefix) {
			// if allowing "0x" prefix, let the incoming text determine if we should parse as hex
			return text.startsWith("0x") || text.startsWith("-0x");
		}
		// otherwise parse the input string is whatever mode this field has been set to.
		return isHexMode;
	}

	/**
	 * Sets the textField to the given value taking into account the current configuration.
	 *
	 * @param value the value to convert to a string for the textField.
	 */
	private void updateTextField(BigInteger value) {
		String text = computeTextForValue(value);
		textField.setText(text);
	}

	private boolean isValidPrefix(String s) {
		switch (s) {
			case "0x":
				return allowsHexPrefix;
			case "-0x":
				return allowsHexPrefix && allowsNegative;
			case "-":
				return allowsNegative;
			default:
				return false;
		}

	}

	/**
	 * DocumentFilter that prevents users from entering invalid data into the field.
	 */
	private class HexDecimalDocumentFilter extends DocumentFilter {
		@Override
		public void insertString(FilterBypass fb, int offset, String text, AttributeSet attr)
				throws BadLocationException {

			// form a string that is the current document text with the inserted new text
			text = text.replace('X', 'x');
			StringBuilder builder = getText(fb);
			builder.insert(offset, text);

			// if the newly formed text is valid, allow the operation
			if (isValid(builder)) {
				super.insertString(fb, offset, text, attr);
			}
		}

		@Override
		public void replace(FilterBypass fb, int offset, int length, String text,
				AttributeSet attrs) throws BadLocationException {

			// form a string that is the current document text with the replaced text
			text = text.replace('X', 'x');
			StringBuilder builder = getText(fb);
			builder.replace(offset, offset + length, text);

			// if the newly formed text is valid, allow the operation
			if (isValid(builder)) {
				super.replace(fb, offset, length, text, attrs);
			}
		}

		@Override
		public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {

			// form a string that is the current document text with the indicated part deleted
			StringBuilder builder = getText(fb);
			builder.delete(offset, offset + length);

			// if the new formed text is valid, allow the operation.
			if (isValid(builder)) {
				super.remove(fb, offset, length);
			}
		}

		private boolean isValid(StringBuilder builder) {
			String valueString = builder.toString();

			// Depending on configuration and input string, determine if we should parse as hex.
			// If we don't allow "0x" prefix, then use the current hex/integer mode, Otherwise,
			// parse as hex depending on whether or not the input string starts with the
			// "0x" prefix.
			boolean parseAsHex = shouldParseAsHex(valueString);

			// allow the string if it is the beginning of a valid string even though
			// it doesn't evaluate to a number yet.
			if (isValidPrefix(valueString)) {
				// When the input is valid, update the hex mode to match how the text was parsed.
				// See parseAsHex variable comment above.
				setHexMode(parseAsHex);
				return true;
			}

			// otherwise, it must parse to a number to be valid.
			try {
				BigInteger value = computeValueFromString(valueString, parseAsHex);
				if (isNonAllowedNegativeNumber(value)) {
					return false;
				}
				if (passesMaxCheck(value) && passesMinCheck(value)) {
					// When the input is valid, update the hex mode to match how the text was parsed.
					// See parseAsHex variable comment above.
					setHexMode(parseAsHex);
					return true;
				}
			}
			catch (NumberFormatException e) {
				return false;
			}
			return false;
		}

		// Retrieves the current document text from inside the document filter.
		private StringBuilder getText(FilterBypass fb) throws BadLocationException {
			StringBuilder builder = new StringBuilder();
			Document document = fb.getDocument();
			builder.append(document.getText(0, document.getLength()));
			return builder;
		}

	}

	private boolean isNonAllowedNegativeNumber(BigInteger value) {
		if (value == null) {
			return false;
		}
		if (allowsNegative) {
			return false;
		}

		// so we don't allow negatives
		return value.signum() < 0;
	}
}
