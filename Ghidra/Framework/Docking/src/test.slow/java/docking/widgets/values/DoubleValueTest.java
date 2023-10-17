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

import docking.widgets.values.DoubleValue;

public class DoubleValueTest extends AbstractValueTest {
	private static final String NAME = "Fraction";
	private static double DELTA = 0.0001;

	@Test
	public void testDoubleValueNoDefault() {
		values.defineDouble(NAME);

		assertTrue(values.isDefined(NAME));
		assertFalse(values.hasValue(NAME));
		assertEquals(0, values.getDouble(NAME), DELTA); // the getPrimitive returns 0 when value is null

		values.setDouble(NAME, 6);
		assertTrue(values.hasValue(NAME));

		assertEquals(6, values.getDouble(NAME), DELTA);
	}

	@Test
	public void testDoubleValueWithDefault() {
		values.defineDouble(NAME, 3.2);

		assertTrue(values.isDefined(NAME));
		assertTrue(values.hasValue(NAME));
		assertEquals(3.2, values.getDouble(NAME), DELTA);

		values.setDouble(NAME, 6.5);
		assertTrue(values.hasValue(NAME));

		assertEquals(6.5, values.getDouble(NAME), DELTA);
	}

	@Test
	public void testGetAsText() {
		DoubleValue v1 = new DoubleValue(NAME, 1.23);
		DoubleValue v2 = new DoubleValue(NAME);
		assertEquals("1.23", v1.getAsText());
		assertNull(v2.getAsText());
	}

	@Test
	public void testSetAsText() {
		DoubleValue v1 = new DoubleValue(NAME);

		assertEquals((Double) 1.23, v1.setAsText("1.23"));
	}

	@Test
	public void testNoDefaultValueWithNoDialogInput() {
		values.defineDouble(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertFalse(values.hasValue(NAME));
		assertEquals(0, values.getDouble(NAME), DELTA);
	}

	@Test
	public void testNoDefaultValueWithDialogInput() {
		values.defineDouble(NAME);
		assertFalse(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "1.23");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(1.23, values.getDouble(NAME), DELTA);
	}

	@Test
	public void testDefaultValueWithNoDialogInput() {
		values.defineDouble(NAME, 1.2);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(1.2, values.getDouble(NAME), DELTA);
	}

	@Test
	public void testDefaultValueWithDialogInput() {
		values.defineDouble(NAME, 1.2);
		assertTrue(values.hasValue(NAME));

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(values.getAbstractValue(NAME), "4.3");
		pressOk();

		assertTrue(values.hasValue(NAME));
		assertEquals(4.3, values.getDouble(NAME), DELTA);
	}

}
