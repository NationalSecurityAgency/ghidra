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

import javax.swing.JSpinner;
import javax.swing.JSpinner.NumberEditor;
import javax.swing.JTextField;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.InRangeColumnConstraint;
import docking.widgets.table.constraint.provider.NumberColumnConstraintProvider;

public class DoubleRangeConstraintEditorTest extends AbstractDockingTest {

	private InRangeColumnConstraint<Double> constraint;
	private DoubleRangeConstraintEditor editor;
	private JSpinner lowerSpinner;
	private JSpinner upperSpinner;
	private JTextField lowerTextField;
	private JTextField upperTextField;

	@Before
	public void setup() {
		constraint = findDoubleConstraint();
		editor = (DoubleRangeConstraintEditor) constraint.getEditor(null);
		forceBuildOfGuiComponents();
		lowerSpinner = editor.getLowerSpinner();
		NumberEditor numEditor = (NumberEditor) lowerSpinner.getEditor();
		lowerTextField = numEditor.getTextField();
		upperSpinner = editor.getUpperSpinner();
		numEditor = (NumberEditor) upperSpinner.getEditor();
		upperTextField = numEditor.getTextField();
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

		setLowerText("123.456");
		setUpperText("234.567");
		assertEquals("[123.456,234.567]", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		setLowerText("123.456");
		setUpperText("234.567");

		runSwing(() -> editor.reset());

		assertEquals("0", lowerTextField.getText());
		assertEquals("0", upperTextField.getText());
	}

	@Test
	public void testMinValueGreaterThanMaxValue() {
		setLowerText("234.567");
		setUpperText("123.456");

		assertTrue(!editor.hasValidValue());
		assertEquals("Upper bounds value must be greater than lower bounds!",
			editor.getErrorMessage());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	@SuppressWarnings("unchecked")
	private InRangeColumnConstraint<Double> findDoubleConstraint() {
		Collection<ColumnConstraint<?>> columnConstraints =
			new NumberColumnConstraintProvider().getColumnConstraints();

		for (ColumnConstraint<?> colConstraint : columnConstraints) {
			if (colConstraint.getName().equals("In Range") &&
				colConstraint.getColumnType().equals(Double.class)) {
				return (InRangeColumnConstraint<Double>) colConstraint;
			}
		}
		return null;
	}

	private void setLowerText(String s) {
		setText(lowerTextField, s);
		waitForSwing();
	}

	private void setUpperText(String s) {
		setText(upperTextField, s);
		waitForSwing();
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private ColumnConstraint<Double> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}
}
