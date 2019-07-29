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

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.*;

import java.awt.Image;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JTextField;

import org.junit.After;
import org.junit.Test;

import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;
import docking.widgets.textfield.IntegerTextField;
import ghidra.test.DummyTool;

public class NumberInputDialogTest extends AbstractDockingTest {

	private DockingWindowManager dwm =
		new DockingWindowManager(new DummyTool(), (List<Image>) null);
	private NumberInputDialog dialog;
	private JButton okButton;
	private JTextField textField;

	@After
	public void tearDown() throws Exception {
		if (dialog != null) {
			runSwing(() -> dialog.close());
		}
	}

	@Test
	public void testOkWithInitialValue() throws Exception {

		int initial = 2;
		int min = 2;
		int max = 5;
		createAndShowDialog(initial, min, max);

		clickOK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the expected value", 2, dialog.getValue());
	}

	@Test
	public void testOkWithNewAllowedValue() throws Exception {
		int initial = 2;
		int min = 2;
		int max = 5;
		createAndShowDialog(initial, min, max);

		setText("4");

		clickOK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", 4, dialog.getValue());
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
		clickOK();

		assertTrue("The dialog is open after pressing 'OK' with a valid hex value",
			!dialog.isVisible());

		assertEquals("The returned value is not the entered value", 4, dialog.getValue());
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

		clickOK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", 4095, dialog.getValue());
	}

	@Test
	public void testTypingNegativeValidNumber() {
		int initial = 2;
		int min = -5;
		int max = 10;
		createAndShowDialog(initial, min, max);

		setText("-3");

		clickOK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", -3, dialog.getValue());
	}

	@Test
	public void testTypingNegativeValidHexNumber() {
		int initial = 2;
		int min = -5;
		int max = 10;
		createAndShowDialog(initial, min, max);

		setText("-0x3");

		clickOK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", -3, dialog.getValue());
	}

	@Test
	public void testSettingNoMaximum() {

		int initial = 1;
		int min = 1;
		createAndShowDialog(initial, min);

		int max = dialog.getMax();
		assertThat(max, is(Integer.MAX_VALUE));

		setText(Integer.toString(min + 1));

		clickOK();

		assertFalse("The dialog is open after pressing 'OK' with valid value", dialog.isVisible());

		assertEquals("The returned value is not the entered value", (min + 1), dialog.getValue());
	}

	@Test
	public void testSettingInvalidMaximum() {

		int initial = 1;
		int min = 2;
		int max = min - 1;

		try {
			new NumberInputDialog(null, initial, min, max);
			fail("Expected an exception with a max lower than min");
		}
		catch (IllegalArgumentException e) {
			// good
		}
	}

	private void createAndShowDialog(int initialValue, int min, int max) {
		dialog = new NumberInputDialog(null, initialValue, min, max);
		showDialogOnSwingWithoutBlocking(dialog);
		okButton = (JButton) getInstanceField("okButton", dialog);
		textField = getTextFieldForDialog(dialog);
	}

	private void createAndShowDialog(int initial, int min) {
		dialog = new NumberInputDialog(null, initial, min);
		showDialogOnSwingWithoutBlocking(dialog);
		okButton = (JButton) getInstanceField("okButton", dialog);
		textField = getTextFieldForDialog(dialog);
	}

	private void clickOK() {
		runSwing(() -> okButton.doClick());
	}

	private void setText(String value) {
		triggerText(textField, value);
	}

	private void showDialogOnSwingWithoutBlocking(NumberInputDialog theDialog) {

		runSwing(() -> {

			dwm.showDialog(theDialog);
			theDialog.getValue();
		}, false);

		waitForDialogComponent(null, NumberInputDialog.class, DEFAULT_WINDOW_TIMEOUT);
	}

	private JTextField getTextFieldForDialog(NumberInputDialog theDialog) {
		IntegerTextField inputField = theDialog.getNumberInputField();
		return (JTextField) getInstanceField("textField", inputField);
	}
}
