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

public class ValuesMapDialogTest extends AbstractValueTest {

	@Test
	public void testGetValueAsWrongType() {
		AbstractValue<Long> ageValue = values.defineLong("Age");

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(ageValue, "42");
		pressOk();

		try {
			assertEquals(42, values.getInt("Age"));
			fail("Should not be able to retrieve a value with the wrong type!");
		}
		catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testCancelDoesntChangeValue() {
		AbstractValue<String> nameValue = values.defineString("Name", "abc");

		showDialogOnSwingWithoutBlocking();
		setTextOnComponent(nameValue, "Joe");
		pressCancel();

		assertTrue(dialog.isCancelled());
		assertEquals("abc", values.getString("Name"));
	}

}
