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
import docking.widgets.table.constraint.SingleValueColumnConstraint;
import docking.widgets.textfield.IntegerTextField;

/**
 * A constraint editor for 64 bit unsigned numbers.
 *
 */
public class UnsignedLongConstraintEditor extends AbstractColumnConstraintEditor<BigInteger> {
	public static BigInteger MAX_VALUE = new BigInteger("ffffffffffffffff", 16);

	private IntegerTextField field;
	private JLabel statusLabel;

	/**
	 * Constructor.
	 *
	 * @param constraint uses BigInteger to represent unsigned 64 bit values.
	 */
	public UnsignedLongConstraintEditor(ColumnConstraint<BigInteger> constraint) {
		super(constraint);
	}

	@Override
	protected Component buildInlineEditorComponent() {

		JPanel panel = new JPanel(new BorderLayout());

		getConstraint().getConstraintValue();

		field = new IntegerTextField(16, 0);
		field.setHexMode();
		field.setAllowNegativeValues(false);
		field.setMaxValue(new BigInteger("FFFFFFFFFFFFFFFF", 16));
		field.addChangeListener(e -> valueChanged());

		panel.add(field.getComponent(), BorderLayout.CENTER);
		statusLabel = new GDHtmlLabel();
		panel.add(statusLabel, BorderLayout.SOUTH);
		statusLabel.setForeground(Color.RED);
		statusLabel.setHorizontalAlignment(SwingConstants.CENTER);

		return panel;
	}

	@Override
	public void reset() {
		BigInteger newValue = BigInteger.ZERO;
		setValue(getConstraint().copy(newValue));
	}

	@Override
	protected ColumnConstraint<BigInteger> getValueFromComponent() {
		return getConstraint().copy(field.getValue());
	}

	@Override
	protected void updateEditorComponent() {
		if (hasEditorComponents()) {
			BigInteger constraintValue = getConstraint().getConstraintValue();
			field.setValue(constraintValue);
		}
	}

	@Override
	protected boolean checkEditorValueValidity() {
		return field.getValue() != null;
	}

	@Override
	protected void updateInfoMessage(boolean isValid) {
		// using &nbsp for the no message case so that the lable retains its height.
		String status = formatStatus(isValid ? "&nbsp;" : "Please enter a value.", true);
		statusLabel.setText(status);
	}

	@Override
	public String getErrorMessage() {
		return "";
	}

	private SingleValueColumnConstraint<BigInteger> getConstraint() {
		return (SingleValueColumnConstraint<BigInteger>) currentConstraint;
	}

}
