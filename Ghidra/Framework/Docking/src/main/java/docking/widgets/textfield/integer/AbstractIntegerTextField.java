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
package docking.widgets.textfield.integer;

import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.JTextField;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.*;

/**
 * Base class for IntegerTextFields that allow entering integer values based on some 
 * integer format (i.e., hex, decimal, unsigned hex, binary, etc.). This field does input
 * validation, so only valid text for the current format can be typed.
 */
public class AbstractIntegerTextField {
	private MultiFormatTextField textField;
	private List<ChangeListener> listeners = new ArrayList<>();

	protected List<IntegerFormat> allFormats;
	protected IntegerFormat currentFormat;
	private BigInteger minValue;
	private BigInteger maxValue;
	private boolean usePrefix = true;

	/**
	 * Creates a new IntegerTextField with the specified number of columns and initial value
	 *
	 * @param columns the number of columns
	 * @param initialValue the initial value
	 * @param formats the supported InputNumberModes
	 */
	@SafeVarargs
	public AbstractIntegerTextField(int columns, BigInteger initialValue,
			IntegerFormat... formats) {
		allFormats = Arrays.asList(formats);
		currentFormat = allFormats.get(0);

		textField = new MultiFormatTextField(columns, allFormats, m -> setFormat(m));

		AbstractDocument document = (AbstractDocument) textField.getDocument();
		document.setDocumentFilter(new HexDecimalDocumentFilter());
		setValue(initialValue);
		textField.addTextChangedCallback(this::valueChanged);
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
		return parse(text, currentFormat);
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
			if (minValue != null && minValue.equals(BigInteger.ONE)) {
				return 1;
			}
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
			if (minValue != null && minValue.equals(BigInteger.ONE)) {
				return 1;
			}
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
	 * Sets the field to the given text. The text must be a properly formated string that is a valid
	 * value for this field. If the field is set to not allow "0x" prefixes, then the input
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
		String text = "";
		if (newValue != null && isInBounds(newValue)) {
			text = currentFormat.format(newValue);
			text = addPrefix(text);
		}
		textField.setText(text);
	}

	private String addPrefix(String text) {
		if (!usePrefix) {
			return text;
		}
		String prefix = currentFormat.getPrefix();
		if (prefix.isBlank()) {
			return text;
		}
		if (text.startsWith("-")) {
			return "-" + prefix + text.substring(1);
		}
		return prefix + text;
	}

	/**
	 * Turns on or off the faded text that displays the field's radix mode (hex or decimal).
	 *
	 * @param show true to show the radix mode.
	 */
	public void setShowNumberMode(boolean show) {
		textField.setShowInputFormatHint(show);
	}

	/**
	 * Sets the format for entering an integer into this field. The current text in the field
	 * will change to keep the same numeric value, but in the new input format.
	 * @param format the format for entering an integer into the field.
	 */
	public void setFormat(IntegerFormat format) {
		if (!allFormats.contains(format)) {
			throw new IllegalArgumentException(format.getName() + "is not valid for this field");
		}
		BigInteger currentValue = getValue();
		currentFormat = format;
		textField.setFormat(format);
		setValue(currentValue);
	}

	/**
	 * {@return the current format for entering numbers into this field}
	 */
	public IntegerFormat getFormat() {
		return currentFormat;
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
	 * Returns the current minimum allowed value. Null indicates that there is no minimum value.
	 * 
	 * @return the current maximum value allowed.
	 */
	public BigInteger getMinValue() {
		return minValue;
	}

	/**
	 * Returns the current maximum allowed value. Null indicates that there is no maximum value.
	 * 
	 * @return the current maximum value allowed.
	 */
	public BigInteger getMaxValue() {
		return maxValue;
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

	/**
	 * Sets whether or not that non-decimal formats require using a prefix (i.e., "0x" for hex).
	 * Generally, using a prefix is preferred as it allows the mode to auto-switch as the user
	 * types (or not types) a prefix. If the prefix is not used, the only way to change input
	 * formats is to use the built-in cntr-M action.
	 * @param usePrefix true to require a prefix, false to not require a prefix
	 */
	public void setUseNumberPrefix(boolean usePrefix) {
		BigInteger value = getValue();
		this.usePrefix = usePrefix;
		setValue(value);
	}

	/**
	 * Returns a list of all support {@link IntegerFormat}s supported by this field.
	 * @return a list of all support number formats for this field.
	 */
	public List<IntegerFormat> getAllFormats() {
		return new ArrayList<>(allFormats);
	}

	protected void setMinValue(BigInteger minValue) {
		BigInteger value = getValue();
		this.minValue = minValue;
		setValue(value);
	}

	protected void setMaxValue(BigInteger maxValue) {
		BigInteger value = getValue();
		this.maxValue = maxValue;
		setValue(value);
	}

	private void valueChanged() {
		for (ChangeListener listener : listeners) {
			listener.stateChanged(new ChangeEvent(this));
		}
	}

	private boolean allowsNegative() {
		return minValue == null || minValue.compareTo(BigInteger.ZERO) < 0;
	}

	protected boolean isInBounds(BigInteger value) {
		if (minValue != null && minValue.compareTo(value) > 0) {
			return false;
		}
		return maxValue == null || maxValue.compareTo(value) >= 0;
	}

	private BigInteger parse(String text, IntegerFormat format) {
		String prefix = format.getPrefix();
		if (usePrefix && !prefix.isBlank()) {
			if (text.startsWith(prefix)) {
				text = text.substring(prefix.length());
			}
			else if (text.startsWith("-" + prefix)) {
				text = "-" + text.substring(prefix.length() + 1);
			}
			else {
				return null;
			}
		}
		return format.parse(text);
	}

	private boolean isValidPrefix(String text, IntegerFormat format) {
		if (text.startsWith("-")) {
			if (!allowsNegative()) {
				return false;
			}
			if (text.length() == 1) {
				return true;
			}
			text = text.substring(1);
		}
		if (!usePrefix) {
			return false;
		}
		return usePrefix && format.getPrefix().startsWith(text);
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
			if (isValid(builder.toString())) {
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
			if (isValid(builder.toString())) {
				super.replace(fb, offset, length, text, attrs);
			}
		}

		@Override
		public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {

			// form a string that is the current document text with the indicated part deleted
			StringBuilder builder = getText(fb);
			builder.delete(offset, offset + length);

			// if the new formed text is valid, allow the operation.
			if (isValid(builder.toString())) {
				super.remove(fb, offset, length);
			}
		}

		private boolean isValid(String text) {
			if (text.isEmpty()) {
				return true;
			}
			if (isValidPrefix(text, currentFormat)) {
				return true;
			}

			BigInteger value = parse(text, currentFormat);
			if (value != null) {
				return isInBounds(value);
			}

			if (usePrefix) {
				// only allow auto switching if using number prefix
				return autoSwitchFormat(text);
			}
			return false;
		}

		private boolean autoSwitchFormat(String text) {
			for (IntegerFormat format : allFormats) {
				if (isValidPrefix(text, format)) {
					currentFormat = format;
					textField.setFormat(format);
					return true;
				}
				BigInteger value = parse(text, format);
				if (value != null && isInBounds(value)) {
					currentFormat = format;
					textField.setFormat(format);
					return true;
				}
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

}
