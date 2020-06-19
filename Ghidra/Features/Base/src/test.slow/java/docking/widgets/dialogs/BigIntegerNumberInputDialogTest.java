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

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.math.BigInteger;

import javax.swing.JButton;

import org.junit.Test;

public class BigIntegerNumberInputDialogTest extends AbstractNumberInputDialogTest {

	@Test
	public void testOkWithInitialValue() throws Exception {

		int initial = 2;
		int min = 2;
		int max = 5;
		createAndShowDialog(initial, min, max);

		oK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the expected value", 2, getValue());
	}

	@Test
	public void testOkWithNewAllowedValue() throws Exception {
		int initial = 2;
		int min = 2;
		int max = 5;
		createAndShowDialog(initial, min, max);

		setText("4");

		oK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", 4, getValue());
	}

	@Test
	public void testTypingInHigherThanAllowed() {
		int initial = 2;
		int min = 2;
		int max = 5;

		createAndShowDialog(initial, min, max);

		setText("7");

		assertTrue(!okButton.isEnabled());

		assertEquals("Value must be between 2 and 5", dialog.getStatusText());
	}

	@Test
	public void testTypingInLowerThanAllowed() {
		int initial = 2;
		int min = 2;
		int max = 5;

		createAndShowDialog(initial, min, max);

		setText("1");

		assertTrue(!okButton.isEnabled());

		assertEquals("Value must be between 2 and 5", dialog.getStatusText());

	}

	@Test
	public void testTypingValidHex() {
		int initial = 2;
		int min = 2;
		int max = 5;

		createAndShowDialog(initial, min, max);

		setText("0x4");
		oK();

		assertTrue("The dialog is open after pressing 'OK' with a valid hex value",
			!dialog.isVisible());

		assertEquals("The returned value is not the entered value", 4, getValue());
	}

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
	}

	@Test
	public void testTypeHexTooBig() {
		int initial = 2;
		int min = 2;
		int max = 5;

		createAndShowDialog(initial, min, max);

		setText("0x7");

		assertTrue(!okButton.isEnabled());

		assertEquals("Value must be between 2 and 5", dialog.getStatusText());
	}

	@Test
	public void testTypeLargeHexValue() {
		int initial = 2;
		int min = 2;
		int max = Integer.MAX_VALUE;
		createAndShowDialog(initial, min, max);

		setText("0xfff");

		oK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", 4095, getValue());
	}

	@Test
	public void testTypingNegativeValidNumber() {
		int initial = 2;
		int min = -5;
		int max = 10;
		createAndShowDialog(initial, min, max);

		setText("-3");

		oK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", -3, getValue());
	}

	@Test
	public void testTypingNegativeValidHexNumber() {
		int initial = 2;
		int min = -5;
		int max = 10;
		createAndShowDialog(initial, min, max);

		setText("-0x3");

		oK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", -3, getValue());
	}

	@Test
	public void testSettingNoMaximum() {

		int initial = 1;
		int min = 1;
		createAndShowDialog(initial, min);

		int max = dialog.getMax();
		assertThat(max, is(Integer.MAX_VALUE));

		setText(Integer.toString(min + 1));

		oK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", (min + 1), getValue());
	}

	@Test
	public void testBigInteger() {

		createAndShowDialog(BigInteger.valueOf(0), new BigInteger("fffffffffffffffffffff", 16));

		String okInt = "500000000";
		setText(okInt);
		assertTrue(okButton.isEnabled());

		setText(okInt + "0");
		assertTrue(okButton.isEnabled());

		setText(okInt + "00");
		assertTrue(okButton.isEnabled());

		setText(okInt + "000");
		assertTrue(okButton.isEnabled());

		oK();
		assertEquals(new BigInteger(okInt + "000"), dialog.getBigIntegerValue());
	}

	private void createAndShowDialog(BigInteger min, BigInteger max) {
		dialog = new BigIntegerNumberInputDialog("Title", null, null, min, max, false);
		showDialogOnSwingWithoutBlocking(dialog);
		okButton = (JButton) getInstanceField("okButton", dialog);
		textField = getTextFieldForDialog(dialog);
	}

	private int getValue() {
		return dialog.getIntValue();
	}
}
