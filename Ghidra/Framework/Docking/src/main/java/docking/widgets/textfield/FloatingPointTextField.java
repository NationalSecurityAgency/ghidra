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

import javax.swing.JTextField;
import javax.swing.text.*;

/**
 * A simple text field for inputing floating point numbers. The field is continuously validated so 
 * that only valid characters and values can be entered. If the text is blank or contains only "-",
 * ".", or "-.", the value is considered to be 0. You can optionally set a min and max value. In 
 * order for the continuous validation to work, the max must be a non-negative number and the min 
 * must be a non-positive number.
 */
public class FloatingPointTextField extends JTextField {
	private Double minValue = Double.NEGATIVE_INFINITY;
	private Double maxValue = Double.POSITIVE_INFINITY;

	/**
	 * Constructs a new empty FloatingPointTextField.
	 * @param columns  the number of columns for determining the preferred width
	 */
	public FloatingPointTextField(int columns) {
		super(columns);
		AbstractDocument doc = (AbstractDocument) getDocument();
		doc.setDocumentFilter(new FloatingPointDocumentFilter());
	}

	/**
	 * Constructs a new FloatingPointTextField initialized with the given value.
	 * @param columns  the number of columns for determining the preferred width
	 */
	public FloatingPointTextField(int columns, double initialValue) {
		this(columns);
		setValue(initialValue);
	}

	/**
	 * Returns the value represented by the text in the field. If the field only contains "-",".",
	 * or "-.", the value returned will be 0.
	 * @return the value represented by the text in the field
	 */
	public double getValue() {
		return parseDouble(getText());
	}

	/**
	 * Sets the text in the field to the given value.
	 * @param value the value to display in the text field
	 */
	public void setValue(double value) {
		setText(Double.toString(value));
	}

	/**
	 * Sets the maximum allowed value. The max must be 0 or positive so that continuous validation
	 * can work.
	 * @param max the maximum allowed value.
	 */
	public void setMaxValue(double max) {
		if (max < 0.0) {
			throw new IllegalArgumentException("Max value can not be negative!");
		}
		maxValue = max;
	}

	/**
	 * Sets the minimum allowed value. The min must be 0 or negative so that continuous validation
	 * can work.
	 * @param min the minimum allowed value.
	 */
	public void setMinValue(double min) {
		if (min > 0.0) {
			throw new IllegalArgumentException("Min value can not be positive!");
		}
		minValue = min;
	}

	private double parseDouble(String text) {
		if (text.equals("")) {
			text = "0";
		}
		else if (text.equals("-")) {
			text = "-0"; // will parse a negative 0, which compares less than 0. Prevents
						// allowing user to type in a "-" char when the minimum is set to 0
		}
		else if (text.equals(".")) {
			text = "0";
		}
		else if (text.equals("-.")) {
			text = "-0";
		}
		// because the field only allows valid values, we don't have to check for an exception
		return Double.parseDouble(text);

	}

	private class FloatingPointDocumentFilter extends DocumentFilter {
		// optional single "-", followed by 0 or more digits, followed by an optional single ".",
		// followed by 0 or more digits
		private static final String FLOATING_POINT_REGEX = "-?[0-9]*\\.?[0-9]*";

		@Override
		public void insertString(FilterBypass fb, int offset, String text, AttributeSet attr)
			throws BadLocationException {
			text = text.trim();
			StringBuilder builder = getText(fb);
			builder.insert(offset, text);
			if (isValid(builder)) {
				super.insertString(fb, offset, text, attr);
			}
		}

		@Override
		public void replace(FilterBypass fb, int offset, int length, String text,
			AttributeSet attrs) throws BadLocationException {
			text = text.trim();
			StringBuilder builder = getText(fb);
			builder.replace(offset, offset + length, text);
			if (isValid(builder)) {
				super.replace(fb, offset, length, text, attrs);
			}
		}

		@Override
		public void remove(FilterBypass fb, int offset, int length) throws BadLocationException {
			StringBuilder builder = getText(fb);
			builder.delete(offset, offset + length);
			if (isValid(builder)) {
				super.remove(fb, offset, length);
			}
		}

		private boolean isValid(StringBuilder builder) {
			if (builder.isEmpty()) {
				return true;
			}
			String value = builder.toString();
			if (!value.matches(FLOATING_POINT_REGEX)) {
				return false;
			}

			double d = parseDouble(value);
			if (minValue.compareTo(d) > 0) {
				return false;
			}
			if (maxValue.compareTo(d) < 0) {
				return false;
			}
			return true;
		}

		private StringBuilder getText(FilterBypass fb) throws BadLocationException {
			StringBuilder builder = new StringBuilder();
			Document document = fb.getDocument();
			builder.append(document.getText(0, document.getLength()));
			return builder;
		}
	}
}
