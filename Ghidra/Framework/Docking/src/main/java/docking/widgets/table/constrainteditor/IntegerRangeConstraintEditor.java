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

import java.awt.*;
import java.math.BigInteger;

import javax.swing.*;

import docking.widgets.label.GDHtmlLabel;
import docking.widgets.spinner.IntegerSpinner;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.RangeColumnConstraint;
import ghidra.util.layout.VerticalLayout;

/**
 * A constraint editor for specifying ranges of integer-type numbers (Byte, Short, Integer,
 * and Long).
 *
 * @param <T> Integer-type number
 */
public class IntegerRangeConstraintEditor<T extends Number>
		extends AbstractColumnConstraintEditor<T> {

	private IntegerSpinner lowerSpinner;
	private BoundedSpinnerNumberModel lowerSpinnerModel;

	private IntegerSpinner upperSpinner;
	private BoundedSpinnerNumberModel upperSpinnerModel;

	private JLabel infoLabel;
	private LongConverter<T> converter;
	private String errorMessage;

	/**
	 * Constructor.
	 *
	 * @param constraint Integer-type constraint for which this component is an editor.
	 * @param converter Utility class to convert integer types to Long-type for internal operation.
	 */
	public IntegerRangeConstraintEditor(ColumnConstraint<T> constraint,
			LongConverter<T> converter) {
		super(constraint);
		this.converter = converter;
	}

	private void initLowerSpinner(Long value, Long minValue, Long maxValue, Long stepSize) {

		lowerSpinnerModel = new BoundedSpinnerNumberModel(value, minValue, maxValue, stepSize);

		lowerSpinner = new IntegerSpinner(lowerSpinnerModel);
		lowerSpinner.getTextField().setShowNumberMode(true);
		lowerSpinner.getTextField().addChangeListener(e -> valueChanged());
		lowerSpinner.getSpinner().setName("lowerSpinner");

		lowerSpinner.addChangeListener(e -> {
			valueChanged();
		});
	}

	private void initUpperSpinner(Long value, Long minValue, Long maxValue, Long stepSize) {

		upperSpinnerModel = new BoundedSpinnerNumberModel(value, minValue, maxValue, stepSize);

		upperSpinner = new IntegerSpinner(upperSpinnerModel);
		upperSpinner.getTextField().setShowNumberMode(true);
		upperSpinner.getTextField().addChangeListener(e -> valueChanged());
		upperSpinner.getSpinner().setName("upperSpinner");

		upperSpinner.addChangeListener(e -> {
			valueChanged();
		});

	}

	@Override
	protected Component buildInlineEditorComponent() {

		long minValue = getConstraint().getMinValue().longValue();
		long maxValue = getConstraint().getMaxValue().longValue();
		Long stepSize = Long.valueOf(1);

		JPanel panel = new JPanel(new VerticalLayout(2));

		initLowerSpinner(minValue, getMinAllowedValue(), getMaxAllowedValue(), stepSize);
		initUpperSpinner(maxValue, getMinAllowedValue(), getMaxAllowedValue(), stepSize);

		JPanel rangeControlPanel = new JPanel(new GridLayout(1, 2));
		rangeControlPanel.add(lowerSpinner.getSpinner());
		rangeControlPanel.add(upperSpinner.getSpinner());

		panel.add(rangeControlPanel);

		infoLabel = new GDHtmlLabel();
		infoLabel.setForeground(Color.GRAY);
		infoLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(infoLabel);

		return panel;
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {

		if (isValid) {

			Number start = (Number) lowerSpinnerModel.getValue();
			Number end = (Number) upperSpinnerModel.getValue();

			// using BigInteger because the range may be larger than Long.MAX_VALUE
			BigInteger bigStart = BigInteger.valueOf(start.longValue());
			BigInteger bigEnd = BigInteger.valueOf(end.longValue());

			BigInteger delta = bigEnd.subtract(bigStart).add(BigInteger.ONE);

			boolean hexMode =
				lowerSpinner.getTextField().isHexMode() || upperSpinner.getTextField().isHexMode();

			String statusMsg = formatStatus(
				String.format("Range Size: " + (hexMode ? "0x%x" : "%,d"), delta), false);
			infoLabel.setText(statusMsg);
		}
		else {
			infoLabel.setText(formatStatus(getErrorMessage(), true));
		}

	}

	@Override
	public void reset() {
		T newMinValue = converter.fromLong(0);
		T newMaxValue = converter.fromLong(0);
		setValue(getConstraint().copy(newMinValue, newMaxValue));
	}

	@Override
	public String getErrorMessage() {
		return errorMessage;
	}

	@Override
	protected ColumnConstraint<T> getValueFromComponent() {
		long lowerValue = lowerSpinner.getTextField().getLongValue();
		long upperValue = upperSpinner.getTextField().getLongValue();
		return getConstraint().copy(converter.fromLong(lowerValue), converter.fromLong(upperValue));
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

		long lVal = (long) lowerSpinnerModel.getValue();
		long uVal = (long) upperSpinnerModel.getValue();
		if (lVal > uVal) {
			errorMessage = "Upper bounds value must be greater than lower bounds!";
			return false;
		}

		return true;

	}

	private static boolean hasValidValue(IntegerSpinner spinner) {
		long textFieldValue = spinner.getTextField().getLongValue();
		Long value = (Long) spinner.getSpinner().getValue();
		return textFieldValue == value;
	}

	private static void markSpinnerAsValid(IntegerSpinner spinner, boolean valid) {
		JTextField textField = (JTextField) spinner.getTextField().getComponent();
		textField.setBackground(valid ? VALID_INPUT_COLOR : INVALID_INPUT_COLOR);
	}

	private long getMinAllowedValue() {
		T value = getConstraint().getMinValue();
		Class<? extends Number> class1 = value.getClass();

		if (class1 == Byte.class) {
			return Byte.MIN_VALUE;
		}
		if (class1 == Short.class) {
			return Short.MIN_VALUE;
		}
		if (class1 == Integer.class) {
			return Integer.MIN_VALUE;
		}
		if (class1 == Long.class) {
			return Long.MIN_VALUE;
		}
		throw new IllegalArgumentException(
			"IntegerValueConstraintEditor does not suppport values of type " + class1);
	}

	private long getMaxAllowedValue() {
		T value = getConstraint().getMinValue();
		Class<? extends Number> class1 = value.getClass();

		if (class1 == Byte.class) {
			return Byte.MAX_VALUE;
		}
		if (class1 == Short.class) {
			return Short.MAX_VALUE;
		}
		if (class1 == Integer.class) {
			return Integer.MAX_VALUE;
		}
		if (class1 == Long.class) {
			return Long.MAX_VALUE;
		}
		throw new IllegalArgumentException(
			"IntegerValueConstraintEditor does not suppport values of type " + class1);
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			T minValue = getConstraint().getMinValue();
			T maxValue = getConstraint().getMaxValue();
			lowerSpinnerModel.setValue(minValue.longValue());
			upperSpinnerModel.setValue(maxValue.longValue());
		}
		valueChanged();
	}

	private RangeColumnConstraint<T> getConstraint() {
		return (RangeColumnConstraint<T>) currentConstraint;
	}

//==================================================================================================
//	Methods for testing
//==================================================================================================
	IntegerSpinner getLowerSpinner() {
		return lowerSpinner;
	}

	IntegerSpinner getUpperSpinner() {
		return upperSpinner;
	}

}
