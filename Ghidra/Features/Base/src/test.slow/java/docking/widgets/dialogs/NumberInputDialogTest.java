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
package docking.widgets.dialogs;

import static org.junit.Assert.*;

import org.junit.Test;

/**
 * {@link NumberInputDialog} test. 
 * 
 * <p>Note: most of the tests for the base class are in {@link BigIntegerNumberInputDialogTest}.
 */
public class NumberInputDialogTest extends AbstractNumberInputDialogTest {

	@Test
	public void testTypeIntTooBigWithOverflow() {
		int initial = 2;
		createAndShowDialog(initial, 0, Integer.MAX_VALUE);

		String okInt = "500000000";
		setText(okInt);
		assertTrue(okButton.isEnabled());

		setText(okInt + "0");
		assertEquals("Value must be between 0 and " + Integer.MAX_VALUE, dialog.getStatusText());

		setText(okInt + "00");
		assertEquals("Value must be between 0 and " + Integer.MAX_VALUE, dialog.getStatusText());

		setText(okInt + "000");
		assertEquals("Value must be between 0 and " + Integer.MAX_VALUE, dialog.getStatusText());

		int valid = Integer.MAX_VALUE - 1;
		setText(Integer.toString(valid));
		oK();
		assertEquals(valid, getValue());
	}

	private int getValue() {
		return ((NumberInputDialog) dialog).getValue();
	}
}
