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
package docking.widgets;

import static org.junit.Assert.*;

import javax.swing.AbstractButton;
import javax.swing.JCheckBox;

import org.junit.*;

import docking.test.AbstractDockingTest;

public class OptionDialogTest extends AbstractDockingTest {

	private OptionDialog dialog;

	@Before
	public void setUp() {
		OptionDialogBuilder builder = new OptionDialogBuilder("Title", "What time is it?");
		builder.setMessageType(OptionDialog.INFORMATION_MESSAGE);
		builder.setMessage("msg");
		builder.addApplyToAllOption();
		builder.addCancel();
		builder.addOption("One");
		builder.addOption("Two");
		dialog = builder.build();
	}

	@After
	public void tearDown() {
		closeAllWindowsAndFrames();
	}

	@Test
	public void testApplyToAllCheckbox() {

		showDialog();
		assertDialogIsShowing();
		pressButton("One");
		assertEquals(1, dialog.getResult());

		showDialog();
		assertDialogIsShowing();
		selectApplyToAll(); // select checkbox to apply to all
		pressButton("Two");
		assertEquals(2, dialog.getResult());

		showDialog();
		assertNoDialog(); // because we hit the checkBox before, no dialog now
		assertEquals(2, dialog.getResult());
	}

	@Test
	public void testBuilder() {
		OptionDialogBuilder builder = new OptionDialogBuilder("Title");
		builder.setMessage("msg");
		builder.addOption("AAA");
		builder.addOption("BBB");
		builder.addOption("CCC");
		builder.addCancel();
		dialog = builder.build();

		showDialog();

		assertDialogButtons("AAA", "BBB", "CCC", "Cancel");
	}

	@Test
	public void testBuilderWithApplyToAll() {
		OptionDialogBuilder builder = new OptionDialogBuilder("Title");
		dialog =
			builder.setMessage("msg").addOption("AAA").addCancel().addApplyToAllOption().build();

		showDialog();

		assertDialogButtons("AAA", "Cancel");

		pressButtonByText(getDialog(), "Apply to all");
		pressButtonByText(getDialog(), "AAA");
		assertEquals(1, dialog.getResult());

		showDialog();
		assertNoDialog();

	}

	private OptionDialog getDialog() {
		return waitForDialogComponent(OptionDialog.class);
	}

	private void assertNoDialog() {
		waitForSwing();
		assertNull(getDialogComponent(OptionDialog.class));
	}

	private void assertDialogButtons(String... buttonNames) {

		for (String buttonName : buttonNames) {
			AbstractButton button = findAbstractButtonByText(dialog.getComponent(), buttonName);
			if (button == null) {
				fail("Can't find expected button: " + buttonName);
			}
		}
	}

	private void selectApplyToAll() {
		runSwing(() -> {
			JCheckBox checkbox = findComponent(dialog.getComponent(), JCheckBox.class);
			checkbox.setSelected(true);
		});
	}

	private void pressButton(String buttonText) {
		pressButtonByText(dialog, buttonText);
	}

	private void assertDialogIsShowing() {

		OptionDialog optionDialog = waitForDialogComponent(OptionDialog.class);
		if (optionDialog == null) {
			fail("Dialog should be showing, but isn't");
		}
	}

	private void showDialog() {
		// note: can't call runSwing with true, but use false and then waitForSwing() or
		// else this thread blocks forever.
		runSwing(() -> dialog.show(), false);
		waitForSwing();
	}

}
