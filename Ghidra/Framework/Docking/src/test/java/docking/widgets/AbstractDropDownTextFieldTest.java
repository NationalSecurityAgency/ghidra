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

import java.awt.BorderLayout;
import java.awt.event.*;
import java.util.Arrays;
import java.util.List;

import javax.swing.*;
import javax.swing.event.CellEditorListener;
import javax.swing.event.ChangeEvent;

import org.junit.After;
import org.junit.Before;

import docking.test.AbstractDockingTest;

public abstract class AbstractDropDownTextFieldTest<T> extends AbstractDockingTest {

	protected DropDownTextField<T> textField;
	protected JFrame parentFrame;
	protected SpyTestCellEditorListener listener = new SpyTestCellEditorListener();

	@Before
	public void setUp() throws Exception {

		initializeGui();
	}

	protected void initializeGui() {
		DropDownTextFieldDataModel<T> model = createModel();

		textField = createTextField(model);
		removeFocusIssues(textField);
		textField.addCellEditorListener(listener);

		parentFrame = new JFrame(DropDownTextField.class.getName());

		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());

		panel.add(textField, BorderLayout.NORTH);

		installTextFieldIntoFrame();
		parentFrame.setSize(300, 300);
		parentFrame.setVisible(true);

		assertTrue("The text field is not showing at the start of the test", textField.isShowing());
	}

	protected abstract DropDownTextFieldDataModel<T> createModel();

	protected DropDownTextField<T> createTextField(DropDownTextFieldDataModel<T> model) {
		DropDownTextField<T> field = new DropDownTextField<>(model);
		return field;
	}

	private void removeFocusIssues(DropDownTextField<?> field) {
		FocusListener[] focusListeners = field.getFocusListeners();
		for (FocusListener l : focusListeners) {
			field.removeFocusListener(l);
		}
	}

	@After
	public void tearDown() throws Exception {

		// flush any pending events, so they don't happen while we are disposing
		waitForSwing();
		parentFrame.setVisible(false);
	}

	protected List<String> createDefaultTestModel() {
		//@formatter:off
		return Arrays.asList(
			"a1","a2",		
			"b", 
			"c", 
			"d1", "d2", "d3", "d4",
			"e", "e1", "e12", "e123");
		//@formatter:on
	}

	protected void installTextFieldIntoFrame() {
		parentFrame.getContentPane().removeAll();
		JPanel panel = new JPanel();
		panel.setLayout(new BorderLayout());
		panel.add(textField, BorderLayout.NORTH);
		parentFrame.getContentPane().add(panel);
		parentFrame.validate();
	}

//==================================================================================================
// Helper methods
//==================================================================================================

	protected void setSelectedValue(T t) {
		runSwing(() -> textField.setSelectedValue(t));
	}

	protected void clearListSelection() {
		JList<T> list = textField.getJList();
		runSwing(() -> list.clearSelection());
	}

	protected void clearTextSelection() {
		runSwing(() -> {
			int end = textField.getText().length();
			textField.setCaretPosition(end);
		});
	}

	protected String getTextFieldText() {
		return runSwing(() -> textField.getText());
	}

	protected void setSelectedListIndex(int index) {
		JList<T> list = textField.getJList();
		runSwing(() -> list.setSelectedIndex(index));
	}

	protected T getSelectedListItem() {
		JList<T> dataList = textField.getJList();
		int index = dataList.getSelectedIndex();
		if (index < 0) {
			return null;
		}
		T item = dataList.getModel().getElementAt(index);
		return item;
	}

	protected T getListItemAt(int index) {
		JList<T> dataList = textField.getJList();
		T item = dataList.getModel().getElementAt(index);
		return item;
	}

	/** The item that is selected in the JList; not the 'selectedValue' in the text field */
	protected void assertSelectedListItem(int expected) {
		JList<T> list = textField.getJList();
		int actual = runSwing(() -> list.getSelectedIndex());
		assertEquals(expected, actual);
	}

	/** The item that is selected in the JList; not the 'selectedValue' in the text field */
	protected void assertSelectedListItem(T expected) {
		JList<T> list = textField.getJList();
		T actual = runSwing(() -> list.getSelectedValue());
		assertEquals(expected, actual);
	}

	/** The 'selectedValue' made after the user makes a choice */
	protected void assertSelectedValue(T expected) {
		T actual = runSwing(() -> textField.getSelectedValue());
		assertEquals(expected, actual);
	}

	protected void assertNoSelectedListItem() {
		JList<T> list = textField.getJList();
		T actual = runSwing(() -> list.getSelectedValue());
		assertNull(actual);
	}

	protected void assertNoEditingCancelledEvent() {
		assertEquals("Received unexpected editingCanceled() invocations.", listener.canceledCount,
			0);
	}

	protected void assertNoEditingStoppedEvent() {
		assertEquals("Received unexpected editingStopped() invocations.", listener.stoppedCount, 0);
	}

	protected void assertEditingStoppedEvent() {
		// the editingStopped event is how the client can use the enter key to close the widget
		assertEquals("Pressing 'Enter' on the text field did not trigger an editingStopped() " +
			"invocation.", listener.stoppedCount, 1);
	}

	protected void assertEditingCancelledEvent() {
		assertEquals("Did not receive editingCanceled() invocations.", 1, listener.canceledCount);
	}

	protected void assertTextFieldText(String text) {
		String actual = runSwing(() -> textField.getText());
		assertEquals(text, actual);
	}

	protected void assertMatchingWindowHidden() {
		JWindow window = textField.getActiveMatchingWindow();
		if (window == null) {
			return; // null means not active
		}
		assertFalse(window.isShowing());
	}

	protected void assertMatchingWindowShowing() {
		boolean isShowing = runSwing(() -> textField.isMatchingListShowing());
		assertTrue(isShowing);
	}

	protected void assetNoListSelection() {
		assertNull(getSelectedListItem());
	}

	protected void simulateFocusLost() {
		FocusListener[] listeners = textField.getFocusListeners();
		FocusEvent e = new FocusEvent(textField, 1);
		for (FocusListener l : listeners) {
			runSwing(() -> l.focusLost(e));
		}
	}

	protected void setCaretPosition(int pos) {
		runSwing(() -> textField.setCaretPosition(pos));
		waitForSwing();
	}

	protected void hideWindowPressKeyThenValidate(int keyCode) {
		JWindow matchingWindow = textField.getActiveMatchingWindow();
		runSwing(() -> matchingWindow.setVisible(false));
		waitForSwing();
		assertFalse("The completion window is showing after a call to setVisible(false).",
			matchingWindow.isShowing());
		tpyeActionKey(keyCode);
		assertTrue("The completion window is not showing after being trigger by a navigation key.",
			matchingWindow.isShowing());
	}

	protected void tpyeActionKey(int keyCode) {

		triggerActionKey(textField, 0, keyCode);
		waitForSwing();
	}

	protected void setText(final String text) {
		runSwing(() -> textField.setText(text));
	}

	protected void closeMatchingWindow() {
		JWindow window = runSwing(() -> textField.getActiveMatchingWindow());
		if (window == null) {
			return;
		}
		runSwing(() -> window.setVisible(false));
	}

	protected void clearText() {
		runSwing(() -> {
			textField.setSelectionStart(0);
			textField.setSelectionEnd(textField.getText().length());
		});
		waitForSwing();
		delete();
	}

	protected void delete() {
		tpyeActionKey(KeyEvent.VK_BACK_SPACE);
		waitForSwing();
	}

	protected void enter() {
		tpyeActionKey(KeyEvent.VK_ENTER);
		waitForSwing();
	}

	protected void escape() {
		tpyeActionKey(KeyEvent.VK_ESCAPE);
		waitForSwing();
	}

	protected void up() {
		tpyeActionKey(KeyEvent.VK_UP);
		waitForSwing();
	}

	protected void down() {
		tpyeActionKey(KeyEvent.VK_DOWN);
		waitForSwing();
	}

	protected void typeText(final String text, boolean expectWindow) {
		waitForSwing();
		triggerText(textField, text);

		JWindow matchingWindow = textField.getActiveMatchingWindow();
		assertNotNull("The completion window was not created after inserting text into the " +
			"selection field.", matchingWindow);

		if (!expectWindow) {
			waitForSwing();
			assertFalse("Window was showing when it should not be.", matchingWindow.isShowing());
			return;
		}

		assertTrue("Window is not showing when it should be", matchingWindow.isShowing());
	}

	protected JList<T> getJList() {
		return textField.getJList();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	protected class TestChoiceListener implements DropDownSelectionChoiceListener<String> {

		protected volatile String lastSelection;

		@Override
		public void selectionChanged(String t) {
			this.lastSelection = t;
		}

		String getLastSelection() {
			return lastSelection;
		}
	}

	protected class SpyTestCellEditorListener implements CellEditorListener {
		protected int canceledCount;
		protected int stoppedCount;

		@Override
		public void editingCanceled(ChangeEvent e) {
			canceledCount++;
		}

		@Override
		public void editingStopped(ChangeEvent e) {
			stoppedCount++;
		}
	}

}
