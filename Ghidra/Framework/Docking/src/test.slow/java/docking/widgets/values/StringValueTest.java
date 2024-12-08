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

import docking.widgets.values.StringValue;

public class StringValueTest extends AbstractValueTest {
	private static final String NAME = "Name";

	@Test
	public void testStringValueNoDefault() {
		values.defineString(NAME);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));

		values.setString(NAME, "abc");
		assertTrue(values.hasValue(NAME));

		assertEquals("abc", values.getString(NAME));
	}

	@Test
	public void testStringValueWithDefault() {
		values.defineString(NAME, "ABC");

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));

		values.setString(NAME, "xyz");
		assertTrue(values.hasValue(NAME));

		assertEquals("xyz", values.getString(NAME));

		values.setString(NAME, null);
		assertFalse(values.hasValue(NAME));
	}

	@Test
	public void testGetAsText() {
		StringValue v1 = new StringValue(NAME, "A");
		StringValue v2 = new StringValue(NAME);

		assertEquals("A", v1.getAsText());
		assertNull(v2.getAsText());
	}

	@Test
	public void testSetAsText() {
		StringValue result = new StringValue(NAME);

		assertEquals("A", result.setAsText("A"));

		try {
			result.setAsText(null);
			fail("Expected exception");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineString(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertNull(values.getString(NAME));
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineString(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "xyz");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals("xyz", values.getString(NAME));
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineString(NAME, "abc");
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals("abc", values.getString(NAME));
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineString(NAME, "abc");
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "xyz");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals("xyz", values.getString(NAME));
	}
}
