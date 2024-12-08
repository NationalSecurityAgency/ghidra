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

import docking.widgets.values.LongValue;

public class LongValueTest extends AbstractValueTest {
	private static final String NAME = "Count";

	@Test
	public void testlongValueNoDefault() {
		values.defineLong(NAME);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));
		assertEquals(0, values.getLong(NAME)); // the getPrimitive returns 0 when value is null

		values.setLong(NAME, 6);
		assertTrue(values.hasValue(NAME));

		assertEquals(6, values.getLong(NAME));
	}

	@Test
	public void testlongValueWithDefault() {
		values.defineLong(NAME, 32);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(32, values.getLong(NAME));

		values.setLong(NAME, 6);
		assertTrue(values.hasValue(NAME));

		assertEquals(6, values.getLong(NAME));
	}

	@Test
	public void testGetAsText() {
		LongValue v1 = new LongValue(NAME, 12L);
		LongValue v2 = new LongValue(NAME);
		LongValue v3 = new LongValue(NAME, 10L, true /*displayAsHex*/);
		assertEquals("12", v1.getAsText());
		assertNull(v2.getAsText());
		assertEquals("a", v3.getAsText());
	}

	@Test
	public void testSetAsText() {
		LongValue v1 = new LongValue(NAME);
		LongValue v2 = new LongValue(NAME, null, true /*displayAsText*/);

		assertEquals((Long) 10L, v1.setAsText("10"));
		assertEquals((Long) 16L, v2.setAsText("10"));
		assertEquals((Long) 10L, v2.setAsText("A"));
		assertEquals((Long) 10L, v2.setAsText("a"));
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineLong(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertEquals(0, values.getLong(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineLong(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "123");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(123, values.getLong(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineLong(NAME, 12);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(12, values.getLong(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineLong(NAME, 12);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "43");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(43, values.getLong(NAME));
	}

	@Test
	public void testHexMode() {
		values.defineHexLong(NAME, 12);

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "A");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(10, values.getLong(NAME));
	}
}
