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
package docking.widgets.values;

import static org.junit.Assert.*;

import org.junit.Test;

import docking.widgets.combobox.GComboBox;
import docking.widgets.values.AbstractValue;
import docking.widgets.values.ChoiceValue;

public class ChoiceValueTest extends AbstractValueTest {
	private static final String NAME = "Choice";

	@Test
	public void testChoiceValueNoDefault() {
		values.defineChoice(NAME, null, "A", "B", "C");

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setChoice(NAME, "B");
		assertTrue(values.hasValue(NAME));

		assertEquals("B", values.getChoice(NAME));
	}

	@Test
	public void testChoiceValueWithDefault() {
		values.defineChoice(NAME, "A", "A", "B", "C");

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals("A", values.getChoice(NAME));

		values.setChoice(NAME, "C");
		assertTrue(values.hasValue(NAME));

		assertEquals("C", values.getChoice(NAME));

		values.setChoice(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		ChoiceValue v1 = new ChoiceValue(NAME, "A", "A", "B");
		ChoiceValue v2 = new ChoiceValue(NAME, null, "A", "B");

		assertEquals("A", v1.getAsText());
		assertNull(v2.getAsText());
	}

	@Test
	public void testSetAsText() {
		ChoiceValue result = new ChoiceValue(NAME, null, "A", "B");

		assertEquals("A", result.setAsText("A"));

		try {
			result.setAsText("Z");
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testChoiceWithInValidDefault() {
		try {
			values.defineChoice(NAME, "Z", "A", "B", "C");
			fail("Was able to set bad default value in choice");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineChoice(NAME, null, "A", "B", "C");
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getChoice(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineChoice(NAME, null, "A", "B", "C");
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setCombo(values.getAbstractValue(NAME), "C");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals("C", values.getChoice(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineChoice(NAME, "B", "A", "B", "C");
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals("B", values.getChoice(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineChoice(NAME, "C", "A", "B", "C");
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setCombo(values.getAbstractValue(NAME), "A");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals("A", values.getChoice(NAME));
	}

	private void setCombo(AbstractValue<?> choiceValue, String choice) {
		runSwing(() -> {
			GComboBox<?> combo = (GComboBox<?>) choiceValue.getComponent();
			combo.setSelectedItem(choice);
		});
	}
}
