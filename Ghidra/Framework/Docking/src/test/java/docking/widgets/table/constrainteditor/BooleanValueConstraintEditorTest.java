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

import javax.swing.JComboBox;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.constraint.BooleanMatchColumnConstraint;
import docking.widgets.table.constraint.ColumnConstraint;

public class BooleanValueConstraintEditorTest extends AbstractDockingTest {

	private BooleanMatchColumnConstraint constraint;
	private BooleanConstraintEditor editor;
	private JComboBox<Boolean> combo;

	@Before
	public void setup() {
		constraint = new BooleanMatchColumnConstraint(Boolean.TRUE);
		editor = (BooleanConstraintEditor) constraint.getEditor(null);
		forceBuildOfGuiComponents();
		combo = editor.getComboBox();

		assertNotNull("Unable to locate JComboBox component", combo);
	}

	private void forceBuildOfGuiComponents() {
		runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testSetValue() {
		setEditorValue("true");
		assertEquals(true, combo.getSelectedItem());
	}

	@Test
	public void testGetValue() {
		setComboBoxSelection(combo, Boolean.FALSE);
		assertEquals("false", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testReset() {
		setComboBoxSelection(combo, Boolean.FALSE);
		runSwing(() -> editor.reset());
		assertEquals("true", getEditorValue().getConstraintValueString());
	}

	@Test
	public void testDetailComponent() {
		assertNull(editor.getDetailComponent());
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private ColumnConstraint<Boolean> getEditorValue() {
		return runSwing(() -> editor.getValue());
	}
}
