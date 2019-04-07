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
import java.util.*;

import javax.swing.JCheckBox;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.table.constraint.EnumColumnConstraint;

public class EnumValueConstraintEditorTest extends AbstractDockingTest {

	private enum TestEnum {
		Value1("Value 1"),
		Value2("A more verbose caption for Value2"),
		Value3("Value 3"),
		Value4("Value 4"),
		Value5("Value 5"),
		Value6("Value 6");

		private final String displayName;

		private TestEnum(String display) {
			this.displayName = display;
		}

		@SuppressWarnings("unused")  // used by reflection
		public String getDisplayName() {
			return displayName;
		}
	}

	private EnumColumnConstraint<TestEnum> constraint;
	private EnumConstraintEditor<TestEnum> editor;

	@Before
	public void setup() {
		constraint = new EnumColumnConstraint<>(TestEnum.class, Collections.emptySet());
		editor = (EnumConstraintEditor<TestEnum>) constraint.getEditor(null);
		forceBuildOfGuiComponents();
	}

	private Component forceBuildOfGuiComponents() {
		return runSwing(() -> editor.getInlineComponent());
	}

	@Test
	public void testDisplayNames() {
		setEditorValue("{Value1, Value2}");

		EnumColumnConstraint<TestEnum> newConstraint = getEditorValue();

		Set<TestEnum> selected = newConstraint.getSelectedValues();
		assertEquals(2, selected.size());

		Component component = runSwing(() -> editor.getInlineComponent());
		assertTrue(component instanceof Container);

		Container container = (Container) component;

		List<JCheckBox> checkboxes = getEnumCheckboxes(container);

		JCheckBox value1Checkbox = checkboxes.get(0);
		assertEquals(value1Checkbox.getText(), "Value 1");

		JCheckBox value2Checkbox = checkboxes.get(1);
		assertEquals(value2Checkbox.getText(), "A more verbose caption for Value2");
	}

	@Test
	public void testNoneSelected() {
		setEditorValue("{}");

		EnumColumnConstraint<TestEnum> newConstraint = getEditorValue();

		Set<TestEnum> selected = newConstraint.getSelectedValues();
		assertEquals(0, selected.size());

		Component component = runSwing(() -> editor.getInlineComponent());
		assertTrue(component instanceof Container);

		Container container = (Container) component;

		List<JCheckBox> checkboxes = getEnumCheckboxes(container);

		for (JCheckBox cb : checkboxes) {
			assertFalse(cb.isSelected());
		}
	}

	@Test
	public void testSelectEvenValues() {
		setEditorValue("{Value2, Value4, Value6}");

		EnumColumnConstraint<TestEnum> newConstraint = getEditorValue();

		Set<TestEnum> selected = newConstraint.getSelectedValues();
		assertEquals(3, selected.size());
		assertFalse(selected.contains(TestEnum.Value1));
		assertTrue(selected.contains(TestEnum.Value2));
		assertFalse(selected.contains(TestEnum.Value3));
		assertTrue(selected.contains(TestEnum.Value4));
		assertFalse(selected.contains(TestEnum.Value5));
		assertTrue(selected.contains(TestEnum.Value6));
	}

	@Test
	public void testSelectAll() {
		setEditorValue("{Value1,Value2,Value3,Value4,Value5,Value6}");

		EnumColumnConstraint<TestEnum> newConstraint = getEditorValue();

		Set<TestEnum> selected = newConstraint.getSelectedValues();
		assertEquals(6, selected.size());
		assertTrue(selected.contains(TestEnum.Value1));
		assertTrue(selected.contains(TestEnum.Value2));
		assertTrue(selected.contains(TestEnum.Value3));
		assertTrue(selected.contains(TestEnum.Value4));
		assertTrue(selected.contains(TestEnum.Value5));
		assertTrue(selected.contains(TestEnum.Value6));

		Component component = runSwing(() -> editor.getInlineComponent());
		assertTrue(component instanceof Container);

		Container container = (Container) component;

		List<JCheckBox> checkboxes = getEnumCheckboxes(container);

		for (JCheckBox cb : checkboxes) {
			assertTrue(cb.isSelected());
		}

	}

	@Test
	public void testReset() {
		EnumColumnConstraint<TestEnum> newConstraint = null;
		setEditorValue("{Value1,Value2,Value3,Value4,Value5,Value6}");

		newConstraint = getEditorValue();

		Set<TestEnum> selected = newConstraint.getSelectedValues();
		assertEquals(6, selected.size());

		runSwing(() -> editor.reset());

		newConstraint = getEditorValue();
		selected = newConstraint.getSelectedValues();

		assertEquals(0, selected.size());

		Component component = runSwing(() -> editor.getInlineComponent());
		assertTrue(component instanceof Container);

		Container container = (Container) component;

		List<JCheckBox> checkboxes = getEnumCheckboxes(container);

		for (JCheckBox cb : checkboxes) {
			assertFalse(cb.isSelected());
		}
	}

	@Test
	public void testCheckboxToggleOne() {
		EnumColumnConstraint<TestEnum> newConstraint = null;

		Component component = runSwing(() -> editor.getInlineComponent());
		assertTrue(component instanceof Container);

		// Ensure model & UI have no elements selected...
		runSwing(() -> editor.reset());

		newConstraint = getEditorValue();

		Set<TestEnum> selected = newConstraint.getSelectedValues();
		assertEquals(0, selected.size());

		Container container = (Container) component;

		List<JCheckBox> checkboxes = getEnumCheckboxes(container);

		// select the 0-th checkbox...
		checkboxes.get(0).setSelected(!checkboxes.get(0).isSelected());

		newConstraint = (EnumColumnConstraint<TestEnum>) editor.getValueFromComponent();

		selected = newConstraint.getSelectedValues();
		// ensure one value is returned.
		assertEquals(1, selected.size());
		assertTrue(selected.contains(TestEnum.Value1));
	}

	@Test
	public void testCheckBoxToggleMany() {
		// Initialize the constraint with Value2, Value4, and Value6...
		setEditorValue("{Value2, Value4, Value6}");

		EnumColumnConstraint<TestEnum> newConstraint = getEditorValue();

		// and ensure those are the only values selected...
		Set<TestEnum> selected = newConstraint.getSelectedValues();
		assertEquals(3, selected.size());
		assertFalse(selected.contains(TestEnum.Value1));
		assertTrue(selected.contains(TestEnum.Value2));
		assertFalse(selected.contains(TestEnum.Value3));
		assertTrue(selected.contains(TestEnum.Value4));
		assertFalse(selected.contains(TestEnum.Value5));
		assertTrue(selected.contains(TestEnum.Value6));

		Component component = runSwing(() -> editor.getInlineComponent());
		assertTrue(component instanceof Container);

		Container container = (Container) component;

		List<JCheckBox> checkboxes = getEnumCheckboxes(container);

		// and be sure the corresponding checkboxes are properly selected...
		boolean even = false;
		for (JCheckBox check : checkboxes) {
			if (even) {
				assertTrue(check.isSelected());
			}
			else {
				assertFalse(check.isSelected());
			}
			even = !even;
		}

		// then invert the selection via checkbox toggle...
		boolean select = true;
		for (JCheckBox check : checkboxes) {
			check.setSelected(select);
			select = !select;
		}

		// and ensure proper selection again...
		newConstraint = (EnumColumnConstraint<TestEnum>) editor.getValueFromComponent();

		selected = newConstraint.getSelectedValues();
		assertEquals(3, selected.size());
		assertTrue(selected.contains(TestEnum.Value1));
		assertFalse(selected.contains(TestEnum.Value2));
		assertTrue(selected.contains(TestEnum.Value3));
		assertFalse(selected.contains(TestEnum.Value4));
		assertTrue(selected.contains(TestEnum.Value5));
		assertFalse(selected.contains(TestEnum.Value6));

	}

	private List<JCheckBox> getEnumCheckboxes(Container container) {
		List<JCheckBox> checkboxes = new ArrayList<>();
		for (Component comp : container.getComponents()) {
			if (comp instanceof Container) {
				checkboxes.addAll(getEnumCheckboxes((Container) comp));
			}
			if (comp instanceof JCheckBox &&
				comp.getName().startsWith(EnumConstraintEditor.CHECKBOX_NAME_PREFIX)) {
				checkboxes.add((JCheckBox) comp);
			}
		}

		checkboxes.sort((cb1, cb2) -> cb1.getName().compareTo(cb2.getName()));

		return checkboxes;
	}

	private void setEditorValue(String constraintValue) {
		runSwing(() -> editor.setValue(constraint.parseConstraintValue(constraintValue, null)));
		waitForSwing();
	}

	private EnumColumnConstraint<TestEnum> getEditorValue() {
		return (EnumColumnConstraint<TestEnum>) runSwing(() -> editor.getValue());
	}
}
