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

import java.awt.Point;
import java.awt.event.MouseEvent;

import javax.swing.JList;
import javax.swing.JWindow;

import org.junit.Test;

public class DropDownSelectionTextFieldTest extends AbstractDropDownTextFieldTest<String> {

	@Override
	protected DropDownTextField<String> createTextField(DropDownTextFieldDataModel<String> model) {
		return new TestDropDownSelectionTextField(model);
	}

	@Override
	protected DropDownTextFieldDataModel<String> createModel() {
		return DefaultDropDownSelectionDataModel.getStringModel(createDefaultTestModel());
	}

	// Tests that:
	// -the completion window is made hidden and the text field is updated upon an 'Enter' key press
	@Test
	public void testEnterKey_MatchingWindowOpen() {
		// insert some text and make sure the window is created
		typeText("d", true);

		String item = getSelectedListItem();

		// press the 'Enter' key to trigger a selection
		enter();
		assertMatchingWindowHidden();

		// press 'Enter' again to fire the editingStopped()
		enter();
		assertTextFieldText(item);

		// no editing events should be triggered on ENTER press while the drop-down is open
		assertEditingStoppedEvent();
		assertNoEditingCancelledEvent();
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

		String item = getSelectedListItem();

		// press the 'Enter' key to trigger a selection
		enter();
		assertMatchingWindowHidden();
		assertTextFieldText(item);

		// for this test, editing events should be triggered on ENTER press while the 
		// drop-down is open
		assertEditingStoppedEvent();
	}

	@Test
	public void testEnterKey_MatchingWindowOpen_WithNoSelection_DontConsumeEvent() {

		//
		// The default is to consume the event.  The test executes the code paths when the 
		// event is not to be consumed.
		//

		runSwing(() -> textField.setConsumeEnterKeyPress(false));

		// insert some text and make sure the window is created
		typeText("d", true);

		clearListSelection();

		// press the 'Enter' key; this normally will not close the window, but since we are 
		// consuming the event, it will close the window and keep the text unchanged.
		enter();
		assertMatchingWindowHidden();
		assertTextFieldText("d");

		// for this test, editing events should be triggered on ENTER press while the 
		// drop-down is open
		assertEditingStoppedEvent();
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

	// Tests that:
	// -the completion window is hidden and the text field is NOT updated upon an 'ESC' key press
	@Test
	public void testEscapeKey_MatchingWindowOpen() {

		typeText("d", true);

		String item = getSelectedListItem();

		// hide the window without updating the contents of the text field
		escape();

		JWindow matchingWindow = textField.getActiveMatchingWindow();
		assertTrue("The selection window is still showing after cancelling editing.",
			!matchingWindow.isVisible());
		assertNotEquals("Cancelling the completion window incorrectly updated the contents " +
			"of the text field with the selected item in the list.", item, textField.getText());
		assertNoEditingCancelledEvent();
	}

	@Test
	public void testEnterKey_SelectingValue_ThenChangingText_SimilarTextKeepsSelectedValue() {

		//
		// Test that the user can select a value from the list, then update the text in the list,
		// force the previously selected value to be discarded.  This allows the user to pick
		// an item and add a pointer or array notation to it, without losing the selected value.
		//

		typeText("d1", true);

		String item = getSelectedListItem();

		enter();
		assertSelectedValue(item);

		// this will update the field to be 'd1*', which is not in our data
		clearTextSelection();
		typeText("*", false);
		assertMatchingWindowHidden();

		enter();

		// the text is as we left it, with no 'selected value' in the text field
		assertTextFieldText("d1*");
		assertSelectedValue("d1");
	}

	@Test
	public void testEnterKey_SelectingValue_ThenChangingText_DifferentTextLosesSelectedValue() {

		//
		// Test that the user can select a value from the list, then update the text in the list,
		// force the previously selected value to be discarded.  This allows the user to pick
		// an item and add a pointer or array notation to it, without losing the selected value.
		//

		typeText("d1", true);

		String item = getSelectedListItem();

		enter();
		assertSelectedValue(item);

		// this will update the field to be 'd1*', which is not in our data
		clearTextSelection();
		setCaretPosition(0);
		typeText("!", false);
		assertMatchingWindowHidden();

		enter();

		// the text is as we left it, with no 'selected value' in the text field
		assertTextFieldText("!d1");
		assertSelectedValue(null);
	}

	// Tests that:
	// -an 'ESC' key press with no completion window triggers an editingCancelled()
	@Test
	public void testEscapeKey_MatchingWindowClosed() {

		assertNoEditingCancelledEvent();

		escape();
		assertEditingCancelledEvent();
	}

	@Test
	public void testSelectionFromWindowByClicking() {

		typeText("d", true);

		JList<String> dataList = textField.getJList();
		String selected = getSelectedListItem();

		// fire a mouse click into the window
		Point clickPoint = dataList.indexToLocation(dataList.getSelectedIndex());
		clickMouse(dataList, MouseEvent.BUTTON1, clickPoint.x, clickPoint.y, 2, 0);

		JWindow matchingWindow = textField.getActiveMatchingWindow();
		assertNull("The selection window is still showing after cancelling editing.",
			matchingWindow);
		assertEquals("The text of the selected item was not placed in the selection field.",
			selected, textField.getText());
	}

	@Test
	public void testNavigationKeys_UpArrow_NoListSelection() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);

		clearListSelection();

		// pressing up with no selected item will then select the first item
		up();
		assertSelectedListItem(0);
	}

	@Test
	public void testNavigationKeys_UpArrow_FirstListItemSelected() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);
		JList<String> list = textField.getJList();
		int size = list.getModel().getSize();

		setSelectedListIndex(0);

		// pressing up with the first item selected will wrap around to the last item
		up();
		assertSelectedListItem(size - 1);
	}

	@Test
	public void testNavigationKeys_UpArrow_LastListItemSelected() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);
		JList<String> list = textField.getJList();
		int size = list.getModel().getSize();

		setSelectedListIndex(size - 1);

		// pressing up with the first item selected the item above
		up();
		assertSelectedListItem(size - 2);

		setSelectedListIndex(size - 1);

		// pressing up with the first item selected will wrap around to the first item
		down();
		assertSelectedListItem(0);
	}

	@Test
	public void testNavigationKeys_UpArrow_MiddleListItemSelected() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);

		int middleItemIndex = 1;
		setSelectedListIndex(middleItemIndex);

		// pressing up with the first item selected the item above
		up();
		assertSelectedListItem(middleItemIndex - 1);
	}

	@Test
	public void testNavigationKeys_DownArrow_NoListSelection() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);

		clearListSelection();

		// pressing down with no selected item will then select the first item
		down();
		assertSelectedListItem(0);
	}

	@Test
	public void testNavigationKeys_DownArrow_FirstListItemSelected() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);

		setSelectedListIndex(0);

		// pressing down with the first item selected will select the second item
		down();
		assertSelectedListItem(1);
	}

	@Test
	public void testNavigationKeys_DownArrow_LastListItemSelected() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);
		JList<String> list = textField.getJList();
		int size = list.getModel().getSize();

		setSelectedListIndex(size - 1);

		// pressing up with the first item selected will wrap around to the first item
		down();
		assertSelectedListItem(0);
	}

	@Test
	public void testNavigationKeys_DownArrow_MiddleListItemSelected() {

		//
		// This tests is designed to get code coverage based upon the user pressing an 
		// arrow key.  This code functions differently depending upon what item is selected in
		// the drop-down list.
		//

		// insert some text and make sure the window is created
		typeText("d", true);

		int middleItemIndex = 1;
		setSelectedListIndex(middleItemIndex);

		// pressing up with the first item selected the item below
		down();
		assertSelectedListItem(middleItemIndex + 1);
	}

	@Test
	public void testSetSelectedValue_TextInField_ItemSelected() {

		//
		// Tests that the API can set the selected item when there was already a selected 
		// item choice made by the user.
		//

		typeText("d1", true);

		enter();
		assertTextFieldText("d1");
		assertSelectedValue("d1");

		setSelectedValue("a2");
		assertTextFieldText("a2");
		assertSelectedValue("a2");
	}

	@Test
	public void testTypeAfterSelectingItem_NoItemSelected() {

		//
		// Make sure that pressing ENTER with no item selected will not update the text field
		//

		// insert some text and make sure the window is created
		typeText("d", true);

		clearListSelection();

		// pressing ENTER with no selection will not close the selection window
		enter();
		assertMatchingWindowShowing();

		assertTextFieldText("d");
	}

	@Test
	public void testTypeAfterSelectingItem_TextInFieldDoesNotStartWithSelectedItemText() {

		//
		// Test the case where the user selects an item, the text field gets the text of that
		// item, then the user changes the text--the text field should not take the value
		// of the selected item.
		//
		// Note: this test is a bit contrived, as it is trying to execute code that can only
		//       fail due to a user timing issue of typing before a SwingManager has run.
		//

		typeText("d", true);

		assertSelectedListItem(0);

		String updated = "zed"; // "d1" does not start with "zed"
		((TestDropDownSelectionTextField) textField).setInectionText(updated);

		enter();

		assertTextFieldText(updated);
	}

	@Test
	public void testAddDropDownSelectionChoiceListener() {

		TestChoiceListener testListener = new TestChoiceListener();
		textField.addDropDownSelectionChoiceListener(testListener);

		typeText("d", true);
		setSelectedListIndex(0);
		enter();

		assertEquals("d1", testListener.getLastSelection());
	}

	@Test
	public void testExistingSelectedValueWillGetSelectedInDropDownList() {

		String startValue = "e123";
		typeText(startValue, true);
		enter();
		assertSelectedValue(startValue);

		setCaretPosition(startValue.length() - 1); // move in one character; this triggers the popup
		closeMatchingWindow();

		down();

		assertSelectedListItem(startValue);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	protected class TestDropDownSelectionTextField extends DropDownSelectionTextField<String> {

		public TestDropDownSelectionTextField(DropDownTextFieldDataModel<String> dataModel) {
			super(dataModel);
		}

		protected volatile String injectionText;

		void setInectionText(String text) {
			this.injectionText = text;
		}

		@Override
		public String getText() {
			if (injectionText != null) {
				return injectionText;
			}
			return super.getText();
		}
	}

}
