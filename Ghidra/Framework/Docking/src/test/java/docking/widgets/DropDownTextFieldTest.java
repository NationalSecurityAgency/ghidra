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

import java.awt.Dimension;
import java.awt.Point;
import java.awt.event.KeyEvent;
import java.awt.event.MouseEvent;

import javax.swing.JList;
import javax.swing.JWindow;

import org.junit.Test;

/**
 * This test achieves partial coverage of {@link DropDownTextField}.  Further coverage is
 * provided by {@link DropDownSelectionTextFieldTest}, as that test enables item selection 
 * in the widget being tested.
 */
public class DropDownTextFieldTest extends AbstractDropDownTextFieldTest<String> {

	@Override
	protected DropDownTextFieldDataModel<String> createModel() {
		return DefaultDropDownSelectionDataModel.getStringModel(createDefaultTestModel());
	}

	@Test
	public void testClickingList() {

		//
		// Since this text field does not allow selection, test that no selection is made when
		// clicking the list and that the list does not go away when double-clicked (both of
		// these are things that happen when selection in the list is enabled).
		//

		typeText("d", true);
		assertMatchingWindowShowing();

		// fire a mouse click into the window
		int index = 1; // pick an item
		JList<String> list = textField.getJList();
		Point clickPoint = list.indexToLocation(index);
		String clickedItem = list.getModel().getElementAt(index);
		int clickCount = 1; // single-click
		clickMouse(list, MouseEvent.BUTTON1, clickPoint.x, clickPoint.y, clickCount, 0);
		assertMatchingWindowShowing();
		assertNoSelectedListItem();

		// double-click *will* work, as a special case, even when no selections are allowed
		// in the list
		clickCount = 2; // double-click
		clickMouse(list, MouseEvent.BUTTON1, clickPoint.x, clickPoint.y, clickCount, 0);
		assertMatchingWindowHidden();
		assertNoSelectedListItem();
		assertSelectedValue(clickedItem);
	}

	// tests that:
	// -the completion window is shown when text is typed in the selection field
	// -the completion window is updated as the text changes while the window is visible
	@Test
	public void testShowDropDownOnTextEntry() {

		JWindow matchingWindow = textField.getActiveMatchingWindow();

		// the window needs to be null initially because it must be properly parented when it is
		// created
		assertNull(
			"The completion window has been created before any completion work " + "has began.",
			matchingWindow);

		// insert some text and make sure the window is created
		typeText("d", true);

		// get the contents of the window and make sure that they are updated
		JList<String> jList = textField.getJList();
		int size = jList.getModel().getSize();

		// this will produce 'd2'
		typeText("2", true);

		assertNotEquals(
			"The number of matching items in the list did not change after typing more " + "text.",
			size, jList.getModel().getSize());
	}

	@Test
	public void testEnterKey_MatchingWindowOpen() {
		// insert some text and make sure the window is created
		typeText("d", true);

		// press the 'Enter' key; the window does not go away
		enter();
		assertMatchingWindowShowing();
		assetNoListSelection();
	}

	// Tests that:
	// -the completion window is made hidden, the text field is updated upon an 'Enter', and
	//  that an editingStopped() *is* fired (this last part only happens when we are not 
	//  consuming the Enter event)
	@Test
	public void testEnterKey_MatchingWindowOpen_DontConsumeEvent() {

		//
		// The default is to consume the event.  The test executes the code paths when the 
		// event is not to be consumed.
		//

		runSwing(() -> textField.setConsumeEnterKeyPress(false));

		// insert some text and make sure the window is created
		typeText("d", true);
		assetNoListSelection();

		// press the 'Enter' key; the window does will go away in this case, as we are not 
		// consuming the event--we assume the client will use the ENTER as a signal to grab
		// the text content, regardless of the fact that there is no selected item
		enter();
		assertMatchingWindowHidden();

	}

	// Tests that:
	// -the completion window is hidden and the text field is updated upon an 'Enter' key press
	// -an 'Enter' key press with no completion window open triggers an editingStopped()
	@Test
	public void testEnterKey_MatchingWindowClosed() {

		// no editing events should be triggered on ENTER press while the drop-down is open
		assertNoEditingStoppedEvent();
		assertNoEditingCancelledEvent();

		// make sure that the 'Enter' key press triggers works when there is no drop-down open
		enter();
		assertEditingStoppedEvent();
	}

	@Test
	public void testEnterKey_MatchingWindowClosed_EnterKeyDisabled() {

		//
		// By default, the ENTER key will trigger an editingStopped() notification when the 
		// matching list is not showing.  When we disable the ENTER key listener, we should
		// not get any events.
		//
		runSwing(() -> textField.setIgnoreEnterKeyPress(true));

		// insert some text and make sure the window is created
		typeText("d", true);
		closeMatchingWindow();

		// press the 'Enter' key; the window does not go away
		enter();
		assertNoEditingStoppedEvent();
		assertMatchingWindowHidden();
		assetNoListSelection();
	}

	// Tests that:
	// -the completion window is hidden and the text field is NOT updated upon an 'ESC' key press
	@Test
	public void testEscapeKey_MatchingWindowOpen() {

		typeText("d", true);

		// hide the window without updating the contents of the text field
		escape();

		assertMatchingWindowHidden();
		assertNoEditingCancelledEvent();
	}

	// Tests that:
	// -an 'ESC' key press with no completion window triggers an editingCancelled()
	@Test
	public void testEscapeKey_MatchingWindowClosed() {

		assertNoEditingCancelledEvent();

		escape();
		assertEditingCancelledEvent();
	}

	// tests that the completion window moves with the text field to give the appearance that
	// they are attached
	@Test
	public void testDropdownLocationOnParentMove() {

		// insert some text and make sure the window is created
		typeText("d", true);

		JWindow matchingWindow = textField.getActiveMatchingWindow();
		Point location = runSwing(() -> matchingWindow.getLocationOnScreen());
		Point frameLocation = parentFrame.getLocationOnScreen();
		Point p = new Point(frameLocation.x + 100, frameLocation.y + 100);
		runSwing(() -> parentFrame.setLocation(p));
		waitForSwing();

		JWindow currentMatchingWindow = textField.getActiveMatchingWindow();
		Point newLocation = runSwing(() -> currentMatchingWindow.getLocationOnScreen());
		assertNotEquals("The completion window's location did not update when its parent window " +
			"was moved.", location, newLocation);
	}

	@Test
	public void testDropdownLocationOnResize() {

		// insert some text and make sure the window is created
		typeText("d", true);

		JWindow matchingWindow = textField.getActiveMatchingWindow();
		Dimension windowSize = matchingWindow.getSize();
		Dimension size = parentFrame.getSize();
		Dimension newSize = new Dimension(size.width - 50, size.height);

		runSwing(() -> parentFrame.setSize(newSize));
		waitForSwing();

		// we have to wait here; it seems like that there may be an 'invokeLater' happening
		// in the Swing components
		waitForCondition(() -> !windowSize.equals(matchingWindow.getSize()),
			"The completion window's size did not update when its parent window was resized.");
	}

	@Test
	public void testSetText() {

		setText("d");

		JWindow matchingWindow = textField.getActiveMatchingWindow();

		// make sure our set text call did not trigger the window to be created
		assertNull(
			"The completion window has been created before any completion work " + "has began.",
			matchingWindow);

		clearText();
		typeText("d", true);

		// one more time
		clearText();
		setText("c");

		// make sure our set text call did not trigger the window to be created
		matchingWindow = textField.getActiveMatchingWindow();
		assertNull("The completion window has been created before any completion work has started",
			matchingWindow);
	}

	@Test
	public void testNavigationKeys_UpArrow_NoSelectionTriggered() {

		// insert some text and make sure the window is created
		typeText("d", true);

		up();
		assertNoSelectedListItem();

		// repeated presses will cycle through the list when selections are enabled; they 
		// should do nothing when selections are disabled
		up();
		assertNoSelectedListItem();
	}

	@Test
	public void testNavigationKeys_DownArrow_NoSelectionTriggered() {

		// insert some text and make sure the window is created
		typeText("d", true);

		down();
		assertNoSelectedListItem();

		// repeated presses will cycle through the list when selections are enabled; they 
		// should do nothing when selections are disabled
		down();
		assertNoSelectedListItem();
	}

	// test that:
	// -up and down arrow keys trigger the completion window if it is not showing and there is
	//     completion data
	// -up and down arrow keys navigate the list if the completion window is open
	@Test
	public void testNavigationKeysTriggerCompletionWindowToShow() {

		// insert some text and make sure the window is created
		typeText("d", true);

		// hide the window to test its triggering on up		
		hideWindowPressKeyThenValidate(KeyEvent.VK_UP);

		// hide the window to test its triggering on down
		hideWindowPressKeyThenValidate(KeyEvent.VK_DOWN);

		// hide the window to test its triggering on keypad up
		hideWindowPressKeyThenValidate(KeyEvent.VK_KP_UP);

		// hide the window to test its triggering on keypad down
		hideWindowPressKeyThenValidate(KeyEvent.VK_KP_DOWN);

		// now with no text in the text field
		clearText();
		JWindow matchingWindow = textField.getActiveMatchingWindow();
		assertTrue("The completion window is showing after a clearing the text field",
			!matchingWindow.isShowing());

		up();
		assertTrue("The completion window is showing after pressing the up key in the text field " +
			"while the text field is empty", !matchingWindow.isShowing());

		down();
		assertTrue(
			"The completion window is showing after pressing the down key in the text field" +
				"while the text field is empty",
			!matchingWindow.isShowing());
	}

	@Test
	public void testSetSelectedValue_EmptyField() {

		setSelectedValue("d1");

		assertTextFieldText("d1");
		assertSelectedValue("d1");
	}

	@Test
	public void testSetSelectedValue_TextInField_NoItemSelected() {

		typeText("zombie", false);

		String newValue = "zed";
		setSelectedValue(newValue);

		assertTextFieldText(newValue);
		assertSelectedValue(newValue);
	}

	@Test
	public void testSetSelectedValue_TextInField_MatchingWindowOpen() {

		typeText("d1", true);

		setSelectedValue("a2");
		assertMatchingWindowHidden();

		assertTextFieldText("a2");
		assertSelectedValue("a2");
	}

	@Test
	public void testMovingCaret_WhenFocused() {

		//
		// The field is wired to show the popup list as the user moves the caret around the
		// field.  
		//

		// use a string that allows us to move the caret and still have matches
		typeText("e123", true);

		closeMatchingWindow();

		setCaretPosition(1);
		assertMatchingWindowShowing();

		setCaretPosition(2);
		assertMatchingWindowShowing();
	}

	// @Test
	// Here if we wish to test manually; focus tests are bad for headless tests
	public void testMovingCaret_WhenNotFocused() {

		//
		// The field is wired to show the popup list as the user moves the caret around the
		// field.  It should not show the list if the field is not focused.
		//

		// use a string that allows us to move the caret and still have matches
		typeText("e123", true);

		closeMatchingWindow();

		simulateFocusLost();

		setCaretPosition(1);
		assertMatchingWindowHidden();

		setCaretPosition(2);
		assertMatchingWindowHidden();
	}

	@Test
	public void testSetMatchingWindowHeight() {

		int newSize = 200;
		runSwing(() -> textField.setMatchingWindowHeight(newSize));
		waitForSwing();

		typeText("d", true);

		JWindow matchingWindow = textField.getActiveMatchingWindow();
		Dimension windowSize = matchingWindow.getSize();
		assertEquals(newSize, windowSize.height);
	}

	@Test
	public void testSetMatchingWindowHeight_MatchingWindowOpen() {

		typeText("d", true);

		int newSize = 200;
		runSwing(() -> textField.setMatchingWindowHeight(newSize));
		waitForSwing();

		JWindow matchingWindow = textField.getActiveMatchingWindow();
		Dimension windowSize = matchingWindow.getSize();
		assertEquals(newSize, windowSize.height);
	}
}
