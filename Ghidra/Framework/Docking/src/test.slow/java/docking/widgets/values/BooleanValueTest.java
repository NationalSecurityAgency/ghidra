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

import javax.swing.JCheckBox;

import org.junit.Test;

import docking.widgets.values.AbstractValue;
import docking.widgets.values.BooleanValue;

public class BooleanValueTest extends AbstractValueTest {
	private static final String NAME = "YesNo";

	@Test
	public void testBooleanValue() {
		values.defineBoolean(NAME, false);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(false, values.getBoolean(NAME));

		values.setBoolean(NAME, true);
		assertTrue(values.hasValue(NAME));

		assertEquals(true, values.getBoolean(NAME));
	}

	@Test
	public void testGetAsText() {
		BooleanValue value1 = new BooleanValue(NAME, true);
		BooleanValue value2 = new BooleanValue(NAME, false);

		assertEquals("true", value1.getAsText());
		assertEquals("false", value2.getAsText());
	}

	@Test
	public void testSetAsText() {
		BooleanValue result = new BooleanValue(NAME, false);

		assertTrue(result.setAsText("true"));
		assertFalse(result.setAsText("false"));
		assertTrue(result.setAsText("TRUE"));
		assertFalse(result.setAsText("asdas"));
	}

	@Test
	public void testValueWithNoDialogInput() {
		values.defineBoolean(NAME, false);

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertEquals(false, values.getBoolean(NAME));
	}

	@Test
	public void testValueWithDialogInput() {
		values.defineBoolean(NAME, false);

		showDialogOnSwingWithoutBlocking();
		setBoolean(values.getAbstractValue(NAME), true);
		pressOk();

		assertEquals(true, values.getBoolean(NAME));
	}

	private void setBoolean(AbstractValue<?> boolValue, boolean b) {
		runSwing(() -> {
			JCheckBox checkBox = (JCheckBox) boolValue.getComponent();
			checkBox.setSelected(b);
		});
	}
}
