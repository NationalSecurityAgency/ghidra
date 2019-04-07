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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.awt.Component;
import java.awt.Container;
import java.util.Collection;

import javax.swing.JSpinner;
import javax.swing.JSpinner.NumberEditor;
import javax.swing.JTextField;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.MappedColumnConstraint;
import docking.widgets.table.constraint.provider.FloatColumnTypeMapper;
import docking.widgets.table.constraint.provider.NumberColumnConstraintProvider;

public class FloatValueConstraintEditorTest extends AbstractDockingTest {

	private ColumnConstraint<Float> constraint;
	private ColumnConstraintEditor<Float> editor;
	private JTextField textField;

	@Before
	public void setup() {
		constraint = findFloatConstraint();
		editor = constraint.getEditor(null);

		Component editorComponent = forceBuildOfGuiComponents();

		Container container = (Container) editorComponent;

		textField = findEditorForSpinner(container, "double.spinner");
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	private JTextField findEditorForSpinner(Container container, String spinnerName) {
		Component comp = findComponentByName(container, spinnerName);
		if (comp != null) {
			JSpinner lowerSpinner = (JSpinner) comp;
			NumberEditor numberEditor = (NumberEditor) lowerSpinner.getEditor();
			return numberEditor.getTextField();
		}
		return null;
	}

	@Test
	public void testSetValue() {
		setEditorValue("128.123");
		assertEquals("128.123", textField.getText());
	}

	@Test
	public void testGetValue() {
		setText("923.123");
		assertEquals("923.123", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		setText("123.456");
		assertEquals("123.456", textField.getText());
		runSwing(() -> editor.reset());
		assertEquals("0", textField.getText());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	@SuppressWarnings("unchecked")
	private ColumnConstraint<Float> findFloatConstraint() {
		Collection<ColumnConstraint<?>> columnConstraints =
			new NumberColumnConstraintProvider().getColumnConstraints();
		for (ColumnConstraint<?> columnConstraint : columnConstraints) {
			if (columnConstraint.getColumnType().equals(Double.class)) {
				return new MappedColumnConstraint<>(new FloatColumnTypeMapper(),
					(ColumnConstraint<Double>) columnConstraint);
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

	private ColumnConstraint<Float> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}

}
