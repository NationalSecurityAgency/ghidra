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
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.RangeColumnConstraint;
import docking.widgets.textfield.IntegerTextField;
import ghidra.util.layout.VerticalLayout;

/**
 * A constraint editor for specifying ranges of unsigned long values.  There are no direct
 * constraints that use the editor since java doesn't have unsigned long types. This exists for
 * objects that represent an unsigned long value and are converted to BigInteger for editing.
 *
 */
public class UnsignedLongRangeConstraintEditor extends AbstractColumnConstraintEditor<BigInteger> {
	private static BigInteger MAX_VALUE = UnsignedLongConstraintEditor.MAX_VALUE;

	private IntegerTextField lowerField;
	private IntegerTextField upperField;

	private JLabel infoLabel;
	private String errorMessage;

	/**
	 * Constructor.
	 *
	 * @param constraint Integer-type constraint for which this component is an editor.
	 */
	public UnsignedLongRangeConstraintEditor(ColumnConstraint<BigInteger> constraint) {
		super(constraint);
	}

	@Override
	protected Component buildInlineEditorComponent() {

		BigInteger minValue = getConstraint().getMinValue();
		BigInteger maxValue = getConstraint().getMaxValue();

		JPanel panel = new JPanel(new VerticalLayout(2));
		lowerField = new IntegerTextField(16, minValue);
		upperField = new IntegerTextField(16, maxValue);

		configureField(lowerField);
		configureField(upperField);

		JPanel rangeControlPanel = new JPanel(new GridLayout(1, 2));
		rangeControlPanel.add(lowerField.getComponent());
		rangeControlPanel.add(upperField.getComponent());

		panel.add(rangeControlPanel);

		infoLabel = new GDHtmlLabel();
		infoLabel.setForeground(Color.GRAY);
		infoLabel.setHorizontalAlignment(SwingConstants.CENTER);
		panel.add(infoLabel);

		return panel;
	}

	private void configureField(IntegerTextField field) {
		field.setHexMode();
		field.setAllowNegativeValues(false);
		field.setMaxValue(MAX_VALUE);
		field.addChangeListener(e -> valueChanged());
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// using &nbsp for the no message case so that the lable retains its height.
		String status = formatStatus(isValid ? "&nbsp;" : errorMessage, true);
		infoLabel.setText(status);
	}

	@Override
	public void reset() {
		BigInteger newMinValue = BigInteger.ZERO;
		BigInteger newMaxValue = MAX_VALUE;
		setValue(getConstraint().copy(newMinValue, newMaxValue));
	}

	@Override
	public String getErrorMessage() {
		return errorMessage;
	}

	@Override
	protected ColumnConstraint<BigInteger> getValueFromComponent() {
		BigInteger lowerValue = lowerField.getValue();
		BigInteger upperValue = upperField.getValue();
		return getConstraint().copy(lowerValue, upperValue);
	}

	@Override
	protected boolean checkEditorValueValidity() {

		boolean isValidLower = hasValidValue(lowerField);
		boolean isValidUpper = hasValidValue(upperField);

		errorMessage = "";

		if (!isValidLower || !isValidUpper) {
			errorMessage = "Please enter a value for both the lower and upper bounds";
			return false;
		}

		BigInteger lowerValue = lowerField.getValue();
		BigInteger upperValue = upperField.getValue();
		if (lowerValue.compareTo(upperValue) > 0) {
			errorMessage = "Upper bound must be greater or equal to lower bound!";
			return false;
		}

		return true;

	}

	private static boolean hasValidValue(IntegerTextField field) {
		return field.getValue() != null;
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			BigInteger minValue = getConstraint().getMinValue();
			BigInteger maxValue = getConstraint().getMaxValue();
			lowerField.setValue(minValue);
			upperField.setValue(maxValue);
		}
		valueChanged();
	}

	private RangeColumnConstraint<BigInteger> getConstraint() {
		return (RangeColumnConstraint<BigInteger>) currentConstraint;
	}

//==================================================================================================
//	Methods for testing
//==================================================================================================
	IntegerTextField getLowerField() {
		return lowerField;
	}

	IntegerTextField getUpperField() {
		return upperField;
	}

}
