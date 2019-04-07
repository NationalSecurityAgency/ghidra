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
import docking.widgets.table.constraint.SingleValueColumnConstraint;
import docking.widgets.table.constraint.provider.NumberColumnConstraintProvider;
import docking.widgets.textfield.IntegerTextField;

public class IntegerValueConstraintEditorTest extends AbstractDockingTest {

	private SingleValueColumnConstraint<Integer> constraint;
	private ColumnConstraintEditor<Integer> editor;
	private IntegerSpinner spinner;
	private IntegerTextField textField;

	@Before
	public void setup() {
		constraint = (SingleValueColumnConstraint<Integer>) findIntegerConstraint();
		editor = constraint.getEditor(null);
		forceBuildOfGuiComponents();
		spinner = (IntegerSpinner) getInstanceField("spinner", editor);
		textField = spinner.getTextField();

		assertNotNull("Unable to locate JTextField editor component of spinner", textField);
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testSetValue() {
		setEditorValue("128");

		assertEquals("128", textField.getText());
	}

	@Test
	public void testGetValue() {
		setEditorValue("923");
		assertEquals("923", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		setTextValue(23);
		editor.reset();
		assertEquals("0", textField.getText());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	@SuppressWarnings("unchecked")
	private ColumnConstraint<Integer> findIntegerConstraint() {
		Collection<ColumnConstraint<?>> columnConstraints =
			new NumberColumnConstraintProvider().getColumnConstraints();

		for (ColumnConstraint<?> columnConstraint : columnConstraints) {
			if (columnConstraint.getColumnType().equals(Integer.class)) {
				return (ColumnConstraint<Integer>) columnConstraint;
			}
		}
		return null;
	}

	private void setTextValue(int value) {
		runSwing(() -> textField.setValue(value));
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
