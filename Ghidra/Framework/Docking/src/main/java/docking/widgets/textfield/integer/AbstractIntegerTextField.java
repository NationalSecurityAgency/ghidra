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

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.Strings;

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
	private boolean autoSwitch = true;

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

		textField = new CustomHintMultiFormatTextField(columns);

		AbstractDocument document = (AbstractDocument) textField.getDocument();
		document.setDocumentFilter(new HexDecimalDocumentFilter());
		setValue(initialValue);
		textField.addTextChangedCallback(this::valueChanged);
	}

	/**
	 * Sets the accessible name for the component of this input field.
	 * @param name the accessible name for this field
	 */
	public void setAccessibleName(String name) {
		textField.getAccessibleContext().setAccessibleName(name);
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
	 * Removes the changes listener.
	 *
	 * @param listener the listener to be removed.
	 */
	public void removeChangeListener(ChangeListener listener) {
		listeners.remove(listener);
	}

	/**
	 * {@return true if the text field will select the text when it initially gains focus.}
	 */
	public boolean isSelectTextOnFocusGainedEnabled() {
		Object value = textField.getClientProperty("JTextField.selectAllOnFocusPolicy");
		if (value == null) {
			return false;
		}
		return Strings.CI.containsAny(value.toString(), "once", "always");
	}

	/**
	 * Returns the current value of the field or null if the field has no current value.
	 *
	 * @return the current value of the field or null if the field has no current value.
	 */
	public BigInteger getValue() {
		String text = textField.getText();
		BigInteger value = parse(text, currentFormat);
		if (isInBounds(value)) {
			return value;
		}
		return null;
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

		// 'autoSwitch' requires a prefix. When not using auto-switch, do not add a prefix if the
		// user has not added one.
		boolean usePrefix = autoSwitch;
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
	 * Clears the current selection and places the caret at the end of the text.
	 */
	public void clearSelection() {
		String text = textField.getText();
		int end = 0;
		if (!StringUtils.isBlank(text)) {
			end = text.length();
		}
		textField.setCaretPosition(end);
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
	 * Sets whether this text field will switch the input mode format when typing a matching prefix.
	 * For example, assuming DEC and HEX modes are available, while in DEC mode, typing {@code 0x}
	 * will switch the mode format to HEX. 
	 * <P>
	 * Auto-switching is on by default.
	 * 
	 * @param newAutoSwitch true to auto-switch; false requires user to change modes manually
	 */
	public void setAutoSwitchMode(boolean newAutoSwitch) {
		this.autoSwitch = newAutoSwitch;
		textField.repaint();
	}

	/**
	 * Returns a list of all support {@link IntegerFormat}s supported by this field.
	 * @return a list of all support number formats for this field.
	 */
	public List<IntegerFormat> getAllFormats() {
		return new ArrayList<>(allFormats);
	}

	/**
	 * Sets the minimum value.  The given value must be less than or equal to 0.
	 * @param minValue the value
	 */
	protected void setMinValue(BigInteger minValue) {

		if (minValue != null) {
			if (minValue.compareTo(BigInteger.ZERO) > 0) {
				throw new IllegalArgumentException("Min value must be <= 0");
			}
		}

		BigInteger value = getValue();
		this.minValue = minValue;
		setValue(value);
	}

	/**
	 * Sets the maximum value.  The given value must be greater than 0.
	 * @param maxValue the value
	 */
	protected void setMaxValue(BigInteger maxValue) {

		if (maxValue != null) {
			if (maxValue.compareTo(BigInteger.ZERO) <= 0) {
				throw new IllegalArgumentException("Max value must be > 0");
			}
		}

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
		if (value == null) {
			return false;
		}
		if (minValue != null && minValue.compareTo(value) > 0) {
			return false;
		}
		return maxValue == null || maxValue.compareTo(value) >= 0;
	}

	private BigInteger parse(String text, IntegerFormat format) {
		if (text.equals("0") || text.equals("-0")) {
			return BigInteger.ZERO;
		}

		String prefix = format.getPrefix();
		if (prefix.isBlank()) {
			return format.parse(text);
		}

		// auto-switching requires a prefix so we know when we should switch formats
		boolean requiresPrefix = autoSwitch;
		boolean hasPrefix = hasPrefix(text, prefix);
		if (requiresPrefix && !hasPrefix) {
			return null;
		}

		text = text.replaceFirst(prefix, "");
		return format.parse(text);
	}

	private boolean hasPrefix(String text, String prefix) {
		return text.startsWith(prefix) || text.startsWith("-" + prefix);
	}

	private boolean hasFormatPrefix(String text, IntegerFormat format) {
		if (text.startsWith("-")) {
			if (!allowsNegative()) {
				return false;
			}
			if (text.length() == 1) {
				return true;
			}
			text = text.substring(1);
		}

		return format.getPrefix().startsWith(text);
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
		return format.getPrefix().startsWith(text);
	}

//=================================================================================================
// Inner Classes
//=================================================================================================	

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
				return true; // just a prefix and is valid
			}

			BigInteger value = parse(text, currentFormat);
			if (value != null) {
				return isInBounds(value);
			}

			// only allow auto switching if using number prefix
			if (autoSwitch) {
				return autoSwitchFormat(text);
			}
			return false;
		}

		private boolean autoSwitchFormat(String text) {
			for (IntegerFormat format : allFormats) {
				if (hasFormatPrefix(text, format)) {
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

	private class CustomHintMultiFormatTextField extends MultiFormatTextField {

		public CustomHintMultiFormatTextField(int columns) {
			super(columns, allFormats, m -> AbstractIntegerTextField.this.setFormat(m));
		}

		@Override
		protected String getHintToolTipText() {
			String superText = super.getHintToolTipText();
			if (autoSwitch) {
				return superText;
			}

			return superText + "<br><br><i>*Auto-switch mode disabled</i>";
		}

		@Override
		protected String getHint() {
			String superHint = super.getHint();
			if (autoSwitch) {
				return superHint;
			}

			return superHint + "*";
		}
	}
}
