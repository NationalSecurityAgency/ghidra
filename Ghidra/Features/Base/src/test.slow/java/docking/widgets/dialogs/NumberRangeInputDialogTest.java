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

import java.util.HashSet;
import java.util.Set;

import javax.swing.JTextField;

import org.junit.*;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;
import ghidra.util.datastruct.Range;
import ghidra.util.datastruct.SortedRangeList;

public class NumberRangeInputDialogTest extends AbstractDockingTest {

	private NumberRangeInputDialog dialog;
	private JTextField textField;

	@Before
	public void setUp() throws Exception {
		createAndShowDialog();
	}

	@After
	public void tearDown() throws Exception {
		close(dialog);
	}

	@Test
	public void testRangeInput_SingleValue_Hex() {

		setText("0x4");

		ok();

		assertValue(0x4);
	}

	@Test
	public void testRangeInput_MultiValue_Mixed() {

		setText("0x4,0x12, 100");

		ok();

		assertValues(0x4, 0x12, 100);
	}

	@Test
	public void testRangeInput_Range_OneRange() {

		setText("0x4:0x12");

		ok();

		assertValues(new Range(0x4, 0x12));
	}

	@Test
	public void testRangeInput_MixedValues_RangeAndSingleValues() {

		setText("100, -20, 0x4:0x6, -100");

		ok();

		assertValues(-100, -20, 0x4, 0x5, 0x6, 100);
	}

	@Test
	public void testRangeInput_SingleValue_InvalidNumber() {

		setText("0xBob");

		ok();

		assertStatusText("Unable to parse as a number: '0xBob'");
	}

	@Test
	public void testRangeInput_MixedValues_InvalidNumber() {

		setText("100, 0xBob");

		ok();

		assertStatusText("Unable to parse as a number: '0xBob'");
	}

	@Test
	public void testRangeInput_Range_InvalidNumber() {

		setText("100:0xBob");

		ok();

		assertStatusText("Unable to parse as a number: '100:0xBob'");
	}

	private void assertStatusText(String expected) {
		String actual = runSwing(() -> dialog.getStatusText());
		assertEquals(expected, actual);
	}

	private void assertValues(Range range) {
		SortedRangeList ranges = dialog.getValue();
		assertEquals(range.size(), ranges.getNumValues());
		assertEquals(range, ranges.getRange(0));
	}

	private void assertValues(int... values) {
		SortedRangeList ranges = dialog.getValue();
		assertEquals(values.length, ranges.getNumValues());

		Set<Integer> set = new HashSet<>();
		for (int value : values) {
			set.add(value);
		}

		for (Range range : ranges) {
			for (int value : range) {
				assertTrue("Range value not expected: " + value, set.contains(value));
			}
		}
	}

	private void assertValue(int expected) {
		SortedRangeList ranges = dialog.getValue();
		assertEquals(1, ranges.getNumValues());
		assertEquals(expected, ranges.getRange(0).min);
		assertEquals(expected, ranges.getRange(0).max);
	}

	private void createAndShowDialog() {
		dialog = new NumberRangeInputDialog("My Dialog Title", "Offset(s)");
		show(dialog);
		textField = getTextField(dialog);
	}

	private void ok() {
		pressButtonByText(dialog, "OK");
	}

	private void setText(String value) {
		setText(textField, value);
	}

	private void show(DialogComponentProvider theDialog) {

		runSwing(() -> {
			DockingWindowManager.showDialog(theDialog);
		}, false);

		waitForDialogComponent(NumberRangeInputDialog.class);
	}

	private JTextField getTextField(NumberRangeInputDialog theDialog) {
		return theDialog.getTextField();
	}
}
