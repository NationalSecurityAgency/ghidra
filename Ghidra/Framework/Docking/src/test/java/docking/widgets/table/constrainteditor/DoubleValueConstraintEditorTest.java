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
import docking.widgets.table.constraint.provider.NumberColumnConstraintProvider;

public class DoubleValueConstraintEditorTest extends AbstractDockingTest {

	private ColumnConstraint<Double> constraint;
	private DoubleValueConstraintEditor editor;
	private JSpinner spinner;
	private JTextField textField;

	@Before
	public void setup() {
		constraint = findFloatConstraint();
		editor = (DoubleValueConstraintEditor) constraint.getEditor(null);
		forceBuildOfGuiComponents();
		spinner = editor.getSpinner();
		NumberEditor numEditor = (NumberEditor) spinner.getEditor();
		textField = numEditor.getTextField();

		assertNotNull("Unable to locate JTextField component", textField);
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testSetValue() {
		Double origValue = 128.123d;
		setEditorValue(origValue.toString());
		Double textValue = Double.parseDouble(textField.getText());
		assertEquals(origValue, textValue);
	}

	@Test
	public void testGetValue() {
		Double origValue = 923.123d;
		setText(origValue.toString());

		Double textValue = Double.parseDouble(getEditorValue().getConstraintValueString());
		assertEquals(origValue, textValue);
	}

	@Test
	public void testReset() {
		Double origValue = 123.456d;
		setText(origValue.toString());

		Double textValue = Double.parseDouble(textField.getText());
		assertEquals(origValue, textValue);

		runSwing(() -> editor.reset());

		textValue = Double.parseDouble(textField.getText());
		assertEquals(Double.valueOf(0d), textValue);
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	@SuppressWarnings("unchecked")
	private ColumnConstraint<Double> findFloatConstraint() {
		Collection<ColumnConstraint<?>> columnConstraints =
			new NumberColumnConstraintProvider().getColumnConstraints();

		for (ColumnConstraint<?> columnConstraint : columnConstraints) {
			if (columnConstraint.getColumnType().equals(Double.class)) {
				return (ColumnConstraint<Double>) columnConstraint;
			}
		}
		return null;
	}

	private void setText(String s) {
		setText(textField, s);
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
