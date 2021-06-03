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

import java.util.ArrayList;
import java.util.List;

import java.awt.*;
import java.awt.event.*;
import java.math.BigInteger;

import javax.swing.*;
import javax.swing.event.*;
import javax.swing.text.*;

import docking.DockingUtils;
import docking.util.GraphicsUtils;
import ghidra.util.SystemUtilities;

/**
 * TextField for entering integer numbers, either in decimal or hex.
 *
 * <P> This field does continuous checking, so
 * you can't enter a bad value.
 *
 * <P> Internally, values are maintained using BigIntegers so this field can
 * contain numbers as large as desired.  There are convenience methods for getting the value as
 * either an int or long.  If using these convenience methods, you should also set the max allowed
 * value so that users can't enter a value larger than can be represented by the {@link #getIntValue()}
 * or {@link #getLongValue()} methods as appropriate.
 *
 * <P> There are several configuration options as follows:
 * <UL>
 *      <LI> Allows negative numbers - either support all integer numbers or just non-negative
 *           numbers. See {@link #setAllowNegativeValues(boolean)} </LI>
 *      <LI> Allows hex prefix - If this mode is on, then hex mode is turned on and off automatically
 *           depending whether or not the text starts with 0x. Otherwise, the hex/decimal mode is set externally
 *           (either programmatically or pressing &lt;CTRL&gt; M) and the user is restricted to the numbers/letters
 *           appropriate for that mode. See {@link #setAllowsHexPrefix(boolean)}</LI>
 *      <LI> Have a max value - a max value can be set (must be positive) such that the user can not type a
 *           number greater than the max. Otherwise, the number is unlimited. See {@link #setMaxValue(BigInteger)}</LI>
 *      <LI> Show the number mode as hint text - If on either "Hex" or "Dec" is displayed lightly in the
 * 		     bottom right portion of the text field. See {@link #setShowNumberMode(boolean)}</LI>
 * </UL>
 *
 */

public class IntegerTextField {
	private JTextField textField;

	private boolean isHexMode = false;
	private boolean allowsNegative = true;
	private boolean allowsHexPrefix = true;
	private boolean showNumbericDecoration = true;
	private BigInteger maxValue;

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
	 * @param initialValue the initial value. This constructor takes an initialValue as a long.  If
	 * you need a value that is bigger (or smaller) than can be specified as a long, then use
	 * the constructor that takes a BigInteger as an initial value.
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
		textField = new MyTextField(columns);
		setValue(initialValue);
		textField.getDocument().addDocumentListener(new DocumentListener() {

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
		return computeValueFromString(text);
	}

	/**
	 * Returns the current value as an int.
	 *
	 * <P> If the field has no current value, 0 will be returned. If
	 * the value is bigger (or smaller) than an int, it will be cast to an int.
	 *
	 * <P> If using this method, it is highly recommended that you set the max value to {@link Integer#MAX_VALUE}
	 * or lower.
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
	 * <P> If the field has no current value, 0 will be returned. If
	 * the value is bigger (or smaller) than an long, it will be cast to a long.
	 *
	 * <P> If using this method, it is highly recommended that you set the max value to {@link Long#MAX_VALUE}
	 * or lower.
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
	 * Sets the value of the field to the given value.  A null value will clear the field.
	 *
	 * @param newValue the new value or null.
	 */
	public void setValue(BigInteger newValue) {

		if (!allowsNegative && newValue != null && newValue.compareTo(BigInteger.ZERO) < 0) {
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
		this.showNumbericDecoration = show;
		textField.repaint();
	}

	/**
	 * Sets the radix mode to Hex.
	 *
	 * <P> If the field is currently in decimal mode, the current text will be
	 * change from displaying the current value from decimal to hex.
	 */
	public void setHexMode() {
		BigInteger currentValue = getValue();
		isHexMode = true;
		updateTextField(currentValue);
	}

	/**
	 * Sets the mode to Decimal.
	 *
	 * <P> If the field is currently in hex mode, the current text will be
	 * change from displaying the current value from hex to decimal.
	 */
	public void setDecimalMode() {
		BigInteger currentValue = getValue();
		isHexMode = false;
		updateTextField(currentValue);
	}

	/**
	 * Sets whether on not the field supports the 0x prefix.
	 *
	 * <P> If 0x is supported, hex numbers
	 * will be displayed with the 0x prefix.  Also, when typing, you must type 0x first to enter
	 * a hex number, otherwise it will only allow digits 0-9.  If the 0x prefix option is turned
	 * off, then hex numbers are displayed without the 0x prefix and you can't change the decimal/hex
	 * mode by typing 0x.  The field will either be in decimal or hex mode and the typed text
	 * will be interpreted appropriately for the mode.
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
			if (currentValue != null && currentValue.compareTo(BigInteger.ZERO) < 0) {
				currentValue = null;
			}
		}
		updateTextField(currentValue);
	}

	/**
	 * Returns the current maximum allowed value.  Null indicates that there is no maximum value.
	 *
	 * @return the current maximum value allowed.
	 */
	public BigInteger getMaxValue() {
		return maxValue;
	}

	/**
	 * Sets the maximum allowed value.  The maximum must be a positive number.  Null indicates that
	 * there is no maximum value.
	 *
	 * @param maxValue the maximum value to allow.
	 */
	public void setMaxValue(BigInteger maxValue) {
		if (maxValue != null && maxValue.compareTo(BigInteger.ZERO) < 0) {
			throw new IllegalArgumentException("Max value must be positive");
		}
		BigInteger currentValue = getValue();
		this.maxValue = maxValue;
		if (!passesMaxCheck(currentValue)) {
			setValue(maxValue);
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

	private BigInteger computeValueFromString(String text) {
		if (text.isEmpty() || isValidPrefix(text)) {
			return null;
		}

		if (!isHexMode) {
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

	private void toggleMode() {
		if (isHexMode) {
			setDecimalMode();
		}
		else {
			setHexMode();
		}
	}

	private boolean passesMaxCheck(BigInteger value) {
		if (value == null) {
			return true;
		}
		if (maxValue == null) {
			return true;
		}

		return value.compareTo(maxValue) <= 0;
	}

	private void updateNumberMode(String text) {
		if (allowsHexPrefix) {
			isHexMode = text.contains("0x");
		}
	}

	/**
	 * Sets the textField to the given value taking into account the current configuation.
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

			// maybe switch radix mode depending on if the string starts with 0x
			updateNumberMode(valueString);

			// allow the string if it is the beginning of a valid string, allow it even though
			// it doesn't evaluate to a number yet.
			if (isValidPrefix(valueString)) {
				return true;
			}

			// otherwise, it must parse to a number to be valid.
			try {
				BigInteger value = computeValueFromString(valueString);
				if (!allowsNegative && value != null && value.signum() < 0) {
					return false;
				}
				return passesMaxCheck(value);
			}
			catch (NumberFormatException e) {
				return false;
			}

		}

		// Retrieves the current document text from inside the document filter.
		private StringBuilder getText(FilterBypass fb) throws BadLocationException {
			StringBuilder builder = new StringBuilder();
			Document document = fb.getDocument();
			builder.append(document.getText(0, document.getLength()));
			return builder;
		}

	}

	/**
	 * Overrides the JTextField mainly to allow hint painting for the current radix mode.
	 */
	private class MyTextField extends JTextField {

		private Font hintFont = new Font("Monospaced", Font.PLAIN, 10);
		private int hintWidth;

		public MyTextField(int columns) {
			super(columns);

			FontMetrics fontMetrics = getFontMetrics(hintFont);
			String mode = isHexMode ? "Hex" : "Dec";
			hintWidth = fontMetrics.stringWidth(mode);

			AbstractDocument document = (AbstractDocument) getDocument();
			document.setDocumentFilter(new HexDecimalDocumentFilter());

			addKeyListener(new KeyAdapter() {
				@Override
				public void keyPressed(KeyEvent e) {
					if (e.getKeyCode() == KeyEvent.VK_M && DockingUtils.isControlModifier(e)) {
						toggleMode();
						repaint();
					}
				}
			});

			// make sure tooltips will be activated
			ToolTipManager.sharedInstance().registerComponent(this);
		}

		@Override
		public String getToolTipText(MouseEvent event) {

			int hintStart = getBounds().width - hintWidth;
			if (event.getX() > hintStart) {
				String key = DockingUtils.CONTROL_KEY_NAME;
				return "Press '" + key + "-M' to toggle Hex or Decimal Mode";
			}

			return null;
		}

		@Override
		protected void paintComponent(Graphics g) {
			super.paintComponent(g);
			if (!showNumbericDecoration) {
				return;
			}

			Font savedFont = g.getFont();
			g.setFont(hintFont);
			g.setColor(Color.LIGHT_GRAY);

			Dimension size = getSize();
			Insets insets = getInsets();
			int x = size.width - insets.right - hintWidth;
			int y = size.height - insets.bottom - 1;
			String mode = isHexMode ? "Hex" : "Dec";
			GraphicsUtils.drawString(this, g, mode, x, y);
			g.setFont(savedFont);
		}
	}

}
