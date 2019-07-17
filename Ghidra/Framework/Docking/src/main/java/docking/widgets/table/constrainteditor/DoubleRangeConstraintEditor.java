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

import java.awt.Component;
import java.awt.GridLayout;
import java.text.*;

import javax.swing.*;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.JSpinner.NumberEditor;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.widgets.label.GDHtmlLabel;
import docking.widgets.numberformat.BoundedRangeDecimalFormatterFactory;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.RangeColumnConstraint;
import ghidra.util.layout.VerticalLayout;

/**
 * A constraint editor for specifying ranges of floating-point numbers (Float and Double)
 */
public class DoubleRangeConstraintEditor extends AbstractColumnConstraintEditor<Double> {
	public static final String FLOATING_POINT_FORMAT = "0.##########;-0.##########";
	public static final String DISPLAY_FORMAT = "#,##0.##########;-#,##0.##########";

	private JSpinner lowerSpinner;
	private JSpinner upperSpinner;
	private JLabel infoLabel;

	private NumberFormat infoLabelNumberFormat;

	private String errorMessage;

	/**
	 * Constructor.
	 *
	 * @param constraint Floating-point constraint for which this component is an editor.
	 */
	public DoubleRangeConstraintEditor(ColumnConstraint<Double> constraint) {
		super(constraint);
	}

	@Override
	protected Component buildInlineEditorComponent() {

		double minValue = getConstraint().getMinValue();
		double maxValue = getConstraint().getMaxValue();

		JPanel panel = new JPanel(new VerticalLayout(2));

		lowerSpinner = createSpinner(minValue);
		upperSpinner = createSpinner(maxValue);
		lowerSpinner.setName("double.lower.spinner");
		upperSpinner.setName("double.upper.spinner");

		JPanel rangeControlPanel = new JPanel(new GridLayout(1, 2));
		rangeControlPanel.add(lowerSpinner);
		rangeControlPanel.add(upperSpinner);

		panel.add(rangeControlPanel);

		infoLabelNumberFormat = new DecimalFormat(DISPLAY_FORMAT);

		infoLabel = new GDHtmlLabel();
		infoLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(infoLabel);

		return panel;
	}

	private JSpinner createSpinner(Number value) {

		Number stepSize = new Double(.1);
		SpinnerNumberModel spinnerModel = new SpinnerNumberModel(value, null, null, stepSize);

		JSpinner spinner = new JSpinner(spinnerModel);
		NumberEditor numEditor = (NumberEditor) spinner.getEditor();
		JFormattedTextField textField = numEditor.getTextField();
		textField.setHorizontalAlignment(SwingConstants.RIGHT);

		textField.setValue(value);
		textField.setFormatterFactory(
			new BoundedRangeDecimalFormatterFactory(FLOATING_POINT_FORMAT));

		textField.setName("editor");
		textField.setColumns(12);

		textField.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void removeUpdate(DocumentEvent e) {
				textChanged(spinner, textField);
			}

			@Override
			public void insertUpdate(DocumentEvent e) {
				textChanged(spinner, textField);
			}

			@Override
			public void changedUpdate(DocumentEvent e) {
				textChanged(spinner, textField);
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

		spinnerModel.addChangeListener(e -> {
			valueChanged();
		});
		return spinner;
	}

	private void textChanged(JSpinner spinner, JTextField textField) {
		SwingUtilities.invokeLater(() -> {
			try {
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

	private static Number increment(Number base, Number by) {
		if (base instanceof Byte || base instanceof Short || base instanceof Integer ||
			base instanceof Long) {
			return base.longValue() + by.longValue();
		}
		return base.doubleValue() + by.doubleValue();
	}

	private static Number decrement(Number base, Number by) {
		if (base instanceof Byte || base instanceof Short || base instanceof Integer ||
			base instanceof Long) {
			return base.longValue() - by.longValue();
		}
		return base.doubleValue() - by.doubleValue();
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		if (isValid) {
			Number start = (Number) lowerSpinner.getValue();
			Number end = (Number) upperSpinner.getValue();

			double dblStart = start.doubleValue();
			double dblEnd = end.doubleValue();

			double delta = dblEnd - dblStart + 1;

			String message = String.format("Range size: %s", infoLabelNumberFormat.format(delta));
			infoLabel.setText(formatStatus(message, false));
		}
		else {
			infoLabel.setText(formatStatus(getErrorMessage(), true));
		}
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			double minValue = getConstraint().getMinValue();
			double maxValue = getConstraint().getMaxValue();
			lowerSpinner.setValue(minValue);
			upperSpinner.setValue(maxValue);
		}
		valueChanged();
	}

	@Override
	public void reset() {
		setValue(getConstraint().copy(0d, 0d));
	}

	@Override
	protected ColumnConstraint<Double> getValueFromComponent() {
		double lowerValue = (double) lowerSpinner.getValue();
		double upperValue = (double) upperSpinner.getValue();
		return getConstraint().copy(lowerValue, upperValue);
	}

	@Override
	protected boolean checkEditorValueValidity() {

		boolean isValidLower = hasValidValue(lowerSpinner);
		boolean isValidUpper = hasValidValue(upperSpinner);

		markSpinnerAsValid(lowerSpinner, isValidLower);
		markSpinnerAsValid(upperSpinner, isValidUpper);

		errorMessage = "";

		if (!isValidLower && !isValidUpper) {
			errorMessage = "Invalid lower and upper bounds!";
			return false;
		}

		if (!isValidLower) {
			errorMessage = "Invalid lower bounds!";
			return false;
		}
		if (!isValidUpper) {
			errorMessage = "Invalid upper bounds!";
			return false;
		}

		double lVal = (double) lowerSpinner.getValue();
		double uVal = (double) upperSpinner.getValue();

		if (lVal > uVal) {
			errorMessage = "Upper bounds value must be greater than lower bounds!";
			return false;
		}

		return true;

	}

	private boolean hasValidValue(JSpinner spinner) {
		NumberEditor numEditor = (NumberEditor) spinner.getEditor();
		JFormattedTextField textField = numEditor.getTextField();
		AbstractFormatter formatter = textField.getFormatter();
		String text = textField.getText();
		try {
			String roundTrip = formatter.valueToString(formatter.stringToValue(text));

			Double textDouble = Double.valueOf(text);
			Double roundTripDouble = Double.valueOf(roundTrip);

			return Double.compare(textDouble, roundTripDouble) == 0;
		}
		catch (ParseException e) {
			return false;
		}
		catch (NumberFormatException nfe) {
			return false;
		}
	}

	private static void markSpinnerAsValid(JSpinner spinner, boolean valid) {
		NumberEditor numEditor = (NumberEditor) spinner.getEditor();
		JFormattedTextField textField = numEditor.getTextField();

		textField.setBackground(valid ? VALID_INPUT_COLOR : INVALID_INPUT_COLOR);
	}

	@Override
	public String getErrorMessage() {
		return errorMessage;
	}

	private RangeColumnConstraint<Double> getConstraint() {
		return (RangeColumnConstraint<Double>) currentConstraint;
	}

//==================================================================================================
//	Methods for testing
//==================================================================================================
	JSpinner getLowerSpinner() {
		return lowerSpinner;
	}

	JSpinner getUpperSpinner() {
		return upperSpinner;
	}

}
