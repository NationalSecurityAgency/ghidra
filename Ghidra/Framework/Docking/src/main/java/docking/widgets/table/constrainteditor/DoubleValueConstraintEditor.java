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
package docking.widgets.table.constrainteditor;

import java.awt.BorderLayout;
import java.awt.Component;
import java.text.ParseException;

import javax.swing.*;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.JSpinner.NumberEditor;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.numberformat.BoundedRangeDecimalFormatterFactory;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.SingleValueColumnConstraint;
import ghidra.util.SystemUtilities;

/**
 * A constraint editor for specifying comparison with a single floating-point value (Float and Double).
 */
public class DoubleValueConstraintEditor extends AbstractColumnConstraintEditor<Double> {
	public static final String FLOATING_POINT_FORMAT = "0.##########;-0.##########";

	private JSpinner spinner;
	private SpinnerNumberModel spinnerModel;
	private String errorMessage;

	public DoubleValueConstraintEditor(ColumnConstraint<Double> constraint) {
		super(constraint);
	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new BorderLayout());

		Double value = getConstraint().getConstraintValue().doubleValue();

		Number stepSize = Double.valueOf(.1);

		spinnerModel = new SpinnerNumberModel(value, null, null, stepSize);
		spinner = new JSpinner(spinnerModel);
		spinner.setName("double.spinner");

		NumberEditor numEditor = (NumberEditor) spinner.getEditor();
		JFormattedTextField textField = numEditor.getTextField();
		textField.setHorizontalAlignment(SwingConstants.RIGHT);

		textField.setValue(value);
		textField.setFormatterFactory(
			new BoundedRangeDecimalFormatterFactory(FLOATING_POINT_FORMAT));

		textField.setColumns(12);

		textField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				textChanged(textField);
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				textChanged(textField);
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				textChanged(textField);
			}
		});
		spinner.addMouseWheelListener(e -> {
			Number val = (Number) spinner.getValue();
			try {
				double step = spinnerModel.getStepSize().doubleValue();
				if (e.getWheelRotation() > 0) {
					spinner.setValue(decrement(val, step));
				}
				else {
					spinner.setValue(increment(val, step));
				}
			}
			catch (IllegalArgumentException iae) {
				// ignored
			}
		});

		spinnerModel.addChangeListener(e -> valueChanged());

		panel.add(spinner);

		return panel;
	}

	/**
	 * This method updates the spinner model as the user types. (We are called from inside a
	 * document listener).  Unfortunately, that causes the textfield to get updated from the
	 * spinner model, which resets the cursor, so we have to save it and then restore it
	 * after doing the commitEdit.
	 *
	 * @param textField the text field that changed.s
	 */
	private void textChanged(JTextField textField) {
		// update later because can't modify textField inside document listener
		SystemUtilities.runSwingLater(() -> {
			try {
				// remember position relative to end of field and then restore it from the end.
				int caretPosition = textField.getCaretPosition();
				int length = textField.getText().length();
				int fromEnd = length - caretPosition;
				spinner.commitEdit();
				length = textField.getText().length();
				textField.setCaretPosition(Math.max(length - fromEnd, 0));
			}
			catch (ParseException e) {
				// do nothing
			}
			valueChanged();
		});
	}

	private Number increment(Number base, Number by) {
		if (base instanceof Byte || base instanceof Short || base instanceof Integer ||
			base instanceof Long) {
			return base.longValue() + by.longValue();
		}
		return base.doubleValue() + by.doubleValue();
	}

	private Number decrement(Number base, Number by) {
		if (base instanceof Byte || base instanceof Short || base instanceof Integer ||
			base instanceof Long) {
			return base.longValue() - by.longValue();
		}
		return base.doubleValue() - by.doubleValue();
	}

	@Override
	protected ColumnConstraint<Double> getValueFromComponent() {
		double v = (double) spinnerModel.getValue();
		return getConstraint().copy(v);
	}

	@Override
	protected void updateEditorComponent() {
		double constraintValue = getConstraint().getConstraintValue();
		spinner.setValue(constraintValue);
	}

	@Override
	public void reset() {
		setValue(getConstraint().copy(0d));
	}

	@Override
	protected boolean checkEditorValueValidity() {
		boolean valid = checkEditorValue();
		return valid;
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		spinner.getEditor().setBackground(isValid ? VALID_INPUT_COLOR : INVALID_INPUT_COLOR);
	}

	private boolean checkEditorValue() {
		NumberEditor numEditor = (NumberEditor) spinner.getEditor();
		JFormattedTextField textField = numEditor.getTextField();
		AbstractFormatter formatter = textField.getFormatter();

		// to test if the textfield has a valid value, we try and parse it.  There are two ways
		// in which it is invalid - it can't be parsed or when parsed it doesn't match the spinner
		// value.
		String text = textField.getText();
		try {
			Double valueFromTextField = (Double) formatter.stringToValue(text);
			Double spinnerValue = (Double) spinner.getValue();

			// to compare the two values, convert them back to formatted strings to avoid rounding issues
			String valueFromField = formatter.valueToString(valueFromTextField);
			String valueFromSpinner = formatter.valueToString(spinnerValue);

			if (valueFromField.equals(valueFromSpinner)) {
				errorMessage = "";
				return true;
			}
		}
		catch (ParseException e) {
			// Do nothing
		}
		errorMessage = "Invalid Value!";
		return false;
	}

	@Override
	public String getErrorMessage() {
		return errorMessage;
	}

	private SingleValueColumnConstraint<Double> getConstraint() {
		return (SingleValueColumnConstraint<Double>) currentConstraint;
	}

//==================================================================================================
//	Methods for testing
//==================================================================================================

	JSpinner getSpinner() {
		return spinner;
	}

}
