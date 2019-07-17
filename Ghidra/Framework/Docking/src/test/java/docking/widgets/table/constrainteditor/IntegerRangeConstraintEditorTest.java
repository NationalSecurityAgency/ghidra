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

import static org.junit.Assert.*;

import java.awt.Component;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.spinner.IntegerSpinner;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.InRangeColumnConstraint;
import docking.widgets.table.constraint.provider.NumberColumnConstraintProvider;
import docking.widgets.textfield.IntegerTextField;

public class IntegerRangeConstraintEditorTest extends AbstractDockingTest {

	private InRangeColumnConstraint<Integer> constraint;
	private IntegerRangeConstraintEditor<Integer> editor;
	private IntegerSpinner lowerSpinner;
	private IntegerSpinner upperSpinner;
	private IntegerTextField lowerTextField;
	private IntegerTextField upperTextField;

	@Before
	public void setup() {
		constraint = findIntegerInRangeConstraint();
		editor = (IntegerRangeConstraintEditor<Integer>) constraint.getEditor(null);
		forceBuildOfGuiComponents();
		lowerSpinner = editor.getLowerSpinner();
		lowerTextField = lowerSpinner.getTextField();
		upperSpinner = editor.getUpperSpinner();
		upperTextField = upperSpinner.getTextField();

		assertNotNull("Unable to locate JTextField editor component of lower-bound spinner",
			lowerTextField);
		assertNotNull("Unable to locate JTextField editor component of upper-bound spinner",
			upperTextField);
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testSetValue() {
		setEditorValue("[5,25]");

		assertEquals("5", lowerTextField.getText());
		assertEquals("25", upperTextField.getText());
	}

	@Test
	public void testGetValue() {
		setLowerValue(10);
		setUpperValue(20);

		assertEquals("[10,20]", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		setLowerValue(10);
		setUpperValue(20);

		runSwing(() -> editor.reset());
		waitForSwing();

		assertEquals("0", lowerTextField.getText());
		assertEquals("0", upperTextField.getText());
	}

	@Test
	public void testMinValueGreaterThanMaxValue() {
		lowerTextField.setValue(20);
		upperTextField.setValue(10);
		waitForSwing();
		assertTrue(!editor.hasValidValue());
		assertEquals("Upper bounds value must be greater than lower bounds!",
			editor.getErrorMessage());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	@SuppressWarnings("unchecked")
	private InRangeColumnConstraint<Integer> findIntegerInRangeConstraint() {
		Collection<ColumnConstraint<?>> columnConstraints =
			new NumberColumnConstraintProvider().getColumnConstraints();

		for (ColumnConstraint<?> columnConstraint : columnConstraints) {
			if (columnConstraint.getColumnType().equals(Integer.class) &&
				columnConstraint.getName().equals("In Range")) {
				return (InRangeColumnConstraint<Integer>) columnConstraint;
			}
		}
		return null;
	}

	private void setLowerValue(int value) {
		runSwing(() -> lowerTextField.setValue(value));
		waitForSwing();
	}

	private void setUpperValue(int value) {
		runSwing(() -> upperTextField.setValue(value));
		waitForSwing();
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private ColumnConstraint<Integer> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}
}
