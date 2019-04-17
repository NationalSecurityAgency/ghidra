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
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.DropDownTextField;
import docking.widgets.table.constraint.*;

/**
 * A test for the various String constraints.
 */
public class StringConstraintEditorTest extends AbstractDockingTest {

	private StringStartsWithColumnConstraint constraint;
	private ColumnConstraintEditor<String> editor;
	private DropDownTextField<String> textField;
	String[] columnData = new String[] { "foo", "foot", "football", "base", "basement" };

	@SuppressWarnings("unchecked")
	@Before
	public void setup() throws Exception {
		constraint = new StringStartsWithColumnConstraint("");
		editor = constraint.getEditor(new TestColumnData());

		waitForTasks();
		forceBuildOfGuiComponents();
		textField = (DropDownTextField<String>) getInstanceField("textField", editor);
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testSetValue() {
		setEditorValue("Hey");
		assertEquals("Hey", textField.getText());
	}

	@Test
	public void testAutocompleteModelIntializedWithColumnData() {
		@SuppressWarnings("unchecked")
		List<String> matches = (List<String>) invokeInstanceMethod("getMatchingData", textField,
			new Class[] { String.class }, new Object[] { "fo" });

		assertEquals(3, matches.size());
	}

	@Test
	public void testGetValue() {
		setText("ABC");

		assertEquals("ABC", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testHasValidValue() {
		setText("");
		assertTrue(!editor.hasValidValue());

		setText("ABC");
		assertTrue(editor.hasValidValue());
	}

	@Test
	public void testReset() {
		setText("ABC");

		runSwing(() -> editor.reset());
		waitForSwing();

		assertEquals("", textField.getText());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	private void setText(String s) {
		setText(textField, s);
		waitForSwing();
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private ColumnConstraint<String> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}

	class TestColumnData implements ColumnData<String> {

		@Override
		public String getColumnName() {
			return "Test";
		}

		@Override
		public int getCount() {
			return columnData.length;
		}

		@Override
		public String getColumnValue(int row) {
			return columnData[row];
		}

		@Override
		public Object getTableDataSource() {
			return null;
		}
	}
}
