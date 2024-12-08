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

import docking.widgets.values.IntValue;

public class IntValueTest extends AbstractValueTest {
	private static final String NAME = "Count";

	@Test
	public void testIntValueNoDefault() {
		values.defineInt(NAME);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));
		assertEquals(0, values.getInt(NAME)); // the getPrimitive returns 0 when value is null

		values.setInt(NAME, 6);
		assertTrue(values.hasValue(NAME));

		assertEquals(6, values.getInt(NAME));
	}

	@Test
	public void testIntValueWithDefault() {
		values.defineInt(NAME, 32);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(32, values.getInt(NAME));

		values.setInt(NAME, 6);
		assertTrue(values.hasValue(NAME));

		assertEquals(6, values.getInt(NAME));
	}

	@Test
	public void testGetAsText() {
		IntValue v1 = new IntValue(NAME, 12);
		IntValue v2 = new IntValue(NAME);
		IntValue v3 = new IntValue(NAME, 10, true /*displayAsHex*/);
		assertEquals("12", v1.getAsText());
		assertNull(v2.getAsText());
		assertEquals("a", v3.getAsText());
	}

	@Test
	public void testSetAsText() {
		IntValue v1 = new IntValue(NAME);
		IntValue v2 = new IntValue(NAME, null, true /*displayAsText*/);

		assertEquals((Integer) 10, v1.setAsText("10"));
		assertEquals((Integer) 16, v2.setAsText("10"));
		assertEquals((Integer) 10, v2.setAsText("A"));
		assertEquals((Integer) 10, v2.setAsText("a"));
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineInt(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertEquals(0, values.getInt(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineInt(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "123");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(123, values.getInt(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineInt(NAME, 12);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(12, values.getInt(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineInt(NAME, 12);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "43");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(43, values.getInt(NAME));
	}

	@Test
	public void testHexMode() {
		values.defineHexInt(NAME, 12);

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "A");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(10, values.getInt(NAME));
	}
}
