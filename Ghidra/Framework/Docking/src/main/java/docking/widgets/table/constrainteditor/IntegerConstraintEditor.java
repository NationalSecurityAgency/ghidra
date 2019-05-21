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

import javax.swing.*;

import org.apache.commons.lang3.StringUtils;

import docking.widgets.label.GDHtmlLabel;
import docking.widgets.spinner.IntegerSpinner;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.SingleValueColumnConstraint;
import docking.widgets.textfield.IntegerTextField;

/**
 * A constraint editor for specifying comparison with a single integer-type value (Byte, Short,
 * Integer, and Long).
 *
 * @param <T> Integer-type number
 */
public class IntegerConstraintEditor<T extends Number> extends AbstractColumnConstraintEditor<T> {

	private IntegerSpinner spinner;
	private BoundedSpinnerNumberModel spinnerModel;
	private LongConverter<T> converter;
	private JLabel statusLabel;

	/**
	 * Constructor.
	 *
	 * @param constraint Integer-type constraint for which this component is an editor.
	 * @param converter Utility class to convert integer types to Long-type for internal operation.
	 */
	public IntegerConstraintEditor(ColumnConstraint<T> constraint, LongConverter<T> converter) {
		super(constraint);
		this.converter = converter;
	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new BorderLayout());

		T constraintValue = getConstraint().getConstraintValue();
		long value = constraintValue.longValue();
		long minValue = getMinValue();
		long maxValue = getMaxValue();
		Number stepSize = Long.valueOf(1);

		spinnerModel = new BoundedSpinnerNumberModel(value, minValue, maxValue, stepSize);

		spinner = new IntegerSpinner(spinnerModel);
		spinner.getTextField().setShowNumberMode(true);
		IntegerTextField textField = spinner.getTextField();
		textField.addChangeListener(e -> valueChanged());
		spinnerModel.addChangeListener(e -> valueChanged());

		panel.add(spinner.getSpinner(), BorderLayout.CENTER);
		statusLabel = new GDHtmlLabel();
		panel.add(statusLabel, BorderLayout.SOUTH);
		statusLabel.setForeground(Color.RED);
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);

		return panel;
	}

	@Override
	public void reset() {
		T newValue = converter.fromLong(0);
		setValue(getConstraint().copy(newValue));
	}

	@Override
	protected ColumnConstraint<T> getValueFromComponent() {
		long value = spinner.getTextField().getLongValue();
		return getConstraint().copy(converter.fromLong(value));
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			T constraintValue = getConstraint().getConstraintValue();
			spinner.setValue(constraintValue.longValue());
		}
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return !StringUtils.isBlank(spinner.getTextField().getText());
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// using &nbsp for the no message case so that the lable retains its height.
		String status = formatStatus(isValid ? "&nbsp;" : "Please enter a value!", true);
		statusLabel.setText(status);
	}

	@Override
	public String getErrorMessage() {
		return "";
	}

	private SingleValueColumnConstraint<T> getConstraint() {
		return (SingleValueColumnConstraint<T>) currentConstraint;
	}

	private long getMinValue() {
		T value = getConstraint().getConstraintValue();
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

	private long getMaxValue() {
		T value = getConstraint().getConstraintValue();
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

}
