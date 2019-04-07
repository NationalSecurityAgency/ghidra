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
import java.awt.Container;
import java.time.LocalDate;
import java.util.Collection;
import java.util.Date;

import javax.swing.JSpinner;
import javax.swing.JTextField;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.MappedColumnConstraint;
import docking.widgets.table.constraint.provider.DateColumnConstraintProvider;
import docking.widgets.table.constraint.provider.DateColumnTypeMapper;

public class DateRangeConstraintEditorTest extends AbstractDockingTest {

	private ColumnConstraint<Date> constraint;
	private ColumnConstraintEditor<Date> editor;

	private JTextField lowerTextField;
	private JTextField upperTextField;

	@Before
	public void setup() {
		constraint = findDateInRangeConstraint();
		editor = constraint.getEditor(null);
		Component editorComponent = forceBuildOfGuiComponents();

		Container container = (Container) editorComponent;

		lowerTextField = findEditorForSpinner(container, "lower.date.spinner");
		upperTextField = findEditorForSpinner(container, "upper.date.spinner");

		assertNotNull("Unable to locate JTextField editor component of lower-bound spinner",
			lowerTextField);
		assertNotNull("Unable to locate JTextField editor component of upper-bound spinner",
			upperTextField);
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	private JTextField findEditorForSpinner(Container container, String spinnerName) {
		Component comp = findComponentByName(container, spinnerName);
		if (comp != null) {
			JSpinner spinner = (JSpinner) comp;
			container = spinner.getEditor();
			return (JTextField) findComponentByName(container, "date.spinner.editor");
		}
		return null;
	}

	@Test
	public void testSetValue() {
		setEditorValue("[01/20/2013,02/13/2014]");
		assertEquals("01/20/2013", lowerTextField.getText());
		assertEquals("02/13/2014", upperTextField.getText());
	}

	@Test
	public void testGetValue() {
		setLowerText("01/10/1999");
		setUpperText("01/12/1999");
		assertEquals("[01/10/1999,01/12/1999]", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		String originalLower = lowerTextField.getText();
		String originalUpper = upperTextField.getText();

		setLowerText("01/10/1999");
		setUpperText("01/12/1999");

		runSwing(() -> editor.reset());
		waitForPostedSwingRunnables();

		assertEquals(originalLower, getText(lowerTextField));
		assertEquals(originalUpper, getText(upperTextField));
	}

	@Test
	public void testMinValueGreaterThanMaxValue() {
		setLowerText("01/12/1999");
		setUpperText("01/01/1998");

		assertTrue(!editor.hasValidValue());
		assertEquals("Upper bounds value must be greater than lower bounds!",
			editor.getErrorMessage());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	@SuppressWarnings("unchecked")
	private ColumnConstraint<Date> findDateInRangeConstraint() {
		Collection<ColumnConstraint<?>> columnConstraints =
			new DateColumnConstraintProvider().getColumnConstraints();

		for (ColumnConstraint<?> colConstraint : columnConstraints) {
			if (colConstraint.getColumnType().equals(LocalDate.class) &&
				colConstraint.getName().equals("Between Dates")) {
				return new MappedColumnConstraint<>(new DateColumnTypeMapper(),
					(ColumnConstraint<LocalDate>) colConstraint);
			}
		}
		return null;
	}

	private void setUpperText(String s) {
		setText(upperTextField, s);
		waitForSwing();
	}

	private void setLowerText(String s) {
		setText(lowerTextField, s);
		waitForSwing();
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private ColumnConstraint<Date> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}

	private String getText(JTextField field) {
		return runSwing(() -> field.getText());
	}
}
