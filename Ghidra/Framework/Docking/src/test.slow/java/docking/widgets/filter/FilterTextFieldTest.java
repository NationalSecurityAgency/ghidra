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
package docking.widgets.filter;

import static docking.test.AbstractDockingTest.triggerEnter;
import static docking.test.AbstractDockingTest.triggerKey;
import static generic.test.AbstractGTest.sleep;
import static generic.test.AbstractGenericTest.runSwing;
import static org.junit.Assert.*;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import utility.function.Callback;

public class FilterTextFieldTest {

	// this overrides the values inside of the filter so that our tests run faster
	private static final long FLASH_DELAY = 500;
	private static final int FLASH_FREQUENCY = 10;

	private EnterListener enterListener = new EnterListener();
	private TestFilterListener filterListener = new TestFilterListener();

	private FilterTextField filter;
	private BackgroundColorSpy spy = new BackgroundColorSpy();
	private TestJTextArea filterPartnerComponent = new TestJTextArea();

	@Before
	public void setUp() {

		JTextField nonFocusComponent = new JTextField(20);

		filter = new FilterTextField(filterPartnerComponent, 20) {
			@Override
			void doSetBackground(Color c) {
				super.doSetBackground(c);
				spy.colorChagned(c);
			}

			@Override
			long getMinimumTimeBetweenFlashes() {
				return FLASH_DELAY;
			}

			@Override
			int getFlashFrequency() {
				return FLASH_FREQUENCY;
			}
		};

		JPanel mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(nonFocusComponent, BorderLayout.NORTH);
		mainPanel.add(filterPartnerComponent, BorderLayout.CENTER);
		mainPanel.add(filter, BorderLayout.SOUTH);

		JFrame frame = new JFrame("Filter Text Field Test");
		frame.setSize(400, 300);
		frame.getContentPane().add(mainPanel);
		frame.setVisible(true);

		spy.reset(); // ignore all changes while constructing
	}

	@Test
	public void testClearIcon() {

		assertClearIconVisible(false);

		setFilter("Hi");

		assertClearIconVisible(true);

		clickClearFilterIcon();
		assertClearIconVisible(false);
		assertFilterText("");
	}

	@Test
	public void testAlert_WhenEmpty() {

		runSwing(() -> filter.alert());
		assertNoBackgroundFlashing();

		runSwing(() -> filter.alert(true));
		assertNoBackgroundFlashing();
	}

	@Test
	public void testAlert_WhenFiltered() {

		setFilter("Hi");
		assertBackgroundChanged();
		spy.reset();

		runSwing(() -> filter.alert());
		assertNoBackgroundFlashing(); // no flash; not enough time has passed
		spy.reset();

		sleep(FLASH_DELAY + 1);

		runSwing(() -> filter.alert());
		assertBackgroundChanged();
	}

	@Test
	public void testForceAlert_WhenFiltered() {

		setFilter("Hi");
		assertBackgroundChanged();
		spy.reset();

		// forcing the alert ignores the wait delay
		runSwing(() -> filter.alert(true));
		assertBackgroundChanged();
	}

	@Test
	public void testFocusFlashing_WhenEmpty() {

		filterPartnerComponent.simulateFocusGained();

		// don't flash when not filtered
		assertNoBackgroundFlashing();
	}

	@Test
	public void testFocusFlashing_WhenNotEditable() {

		runSwing(() -> filter.setEditable(false));

		filterPartnerComponent.simulateFocusGained();

		// the color does not change when not editable
		assertBackgroundColor(FilterTextField.UNEDITABLE_BACKGROUND_COLOR);
	}

	private void assertBackgroundColor(Color expected) {
		boolean matches = runSwing(() -> spy.allColorsMatch(expected));
		assertTrue(matches);
	}

	@Test
	public void testFocusFlashing_WhenNotEnabled() {

		runSwing(() -> filter.setEnabled(false));

		filterPartnerComponent.simulateFocusGained();

		// the color does not change when not enabled
		assertBackgroundColor(FilterTextField.UNEDITABLE_BACKGROUND_COLOR);
	}

	@Test
	public void testFocusFlashing_WhenFiltered() {

		filterPartnerComponent.simulateFocusGained();

		// don't flash when not filtered
		setFilter("Hi!");
		assertBackgroundChanged();
	}

	@Test
	public void testEnterListener() {

		triggerEnter(filter.getTextField());
		assertEnterNotTriggered();

		filter.addEnterListener(enterListener);
		triggerEnter(filter.getTextField());
		assertEnterTriggered(1);
	}

	@Test
	public void testFilterListener() {

		String text = "Hi";
		setFilter(text);
		assertFilterListenerNotCalled();

		filter.addFilterListener(filterListener);

		setFilter(text);
		assertFilterListenerCalled(text);

		text = "";
		setFilter(text);
		assertFilterListenerCalled(text);

	}

	@Test
	public void testNavigation() {

		boolean focusRequested = runSwing(() -> filterPartnerComponent.wasFocusRequested());
		assertFalse(focusRequested);

		triggerUpArrow();
		focusRequested = runSwing(() -> filterPartnerComponent.wasFocusRequested());
		assertTrue(focusRequested);

		filterPartnerComponent.reset();

		triggerDownArrow();
		focusRequested = runSwing(() -> filterPartnerComponent.wasFocusRequested());
		assertTrue(focusRequested);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void triggerDownArrow() {
		triggerKey(filter.getTextField(), 0, KeyEvent.VK_DOWN, KeyEvent.CHAR_UNDEFINED);
	}

	private void triggerUpArrow() {
		triggerKey(filter.getTextField(), 0, KeyEvent.VK_UP, KeyEvent.CHAR_UNDEFINED);
	}

	private void assertFilterListenerCalled(String expected) {

		assertEquals(expected, filterListener.getFilterText());
	}

	private void assertFilterListenerNotCalled() {

		assertNull(filterListener.getFilterText());
	}

	private void assertEnterTriggered(int expectedCount) {
		assertEquals(expectedCount, enterListener.getCallCount());
	}

	private void assertEnterNotTriggered() {
		assertEquals(0, enterListener.getCallCount());
	}

	private void assertBackgroundChanged() {
		waitForTimer();
		assertTrue("Background color has not changed", spy.hasChanges());
	}

	private void assertNoBackgroundFlashing() {
		waitForTimer();
		assertFalse(spy.hasChanges());
	}

	private void assertFilterText(String expectedText) {
		String actualText = runSwing(() -> filter.getText());
		assertEquals(expectedText, actualText);
	}

	private void clickClearFilterIcon() {
		JLabel clearLabel = filter.getClearLabel();
		AbstractGenericTest.clickMouse(clearLabel, MouseEvent.BUTTON1, 0, 0, 1, 0);
	}

	private void setFilter(String text) {
		runSwing(() -> filter.setText(text));
	}

	private void assertClearIconVisible(boolean visible) {
		JLabel clearLabel = filter.getClearLabel();
		boolean isVisible = runSwing(() -> clearLabel.isVisible());
		assertEquals(visible, isVisible);
	}

	private void waitForTimer() {
		Timer timer = filter.getFlashTimer();
		AbstractGenericTest.waitForCondition(() -> {
			boolean running = runSwing(() -> timer.isRunning());
			return !running;
		}, "Timed-out waiting for flash timer to finish");
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class BackgroundColorSpy {
		List<Color> bgColorChanges = new ArrayList<>();

		void reset() {
			runSwing(() -> bgColorChanges.clear());
		}

		void colorChagned(Color c) {
			bgColorChanges.add(c);
		}

		boolean hasChanges() {

			return runSwing(() -> bgColorChanges.size() > 0);
		}

		boolean allColorsMatch(Color expected) {
			return runSwing(() -> bgColorChanges.stream().allMatch(c -> c.equals(expected)));
		}
	}

	private class EnterListener implements Callback {

		private int callCount;

		@Override
		public void call() {
			callCount++;
		}

		int getCallCount() {
			return runSwing(() -> callCount);
		}
	}

	private class TestFilterListener implements FilterListener {

		private String filterText;

		@Override
		public void filterChanged(String text) {
			filterText = text;
		}

		String getFilterText() {
			return runSwing(() -> filterText);
		}
	}

	private class TestJTextArea extends JTextArea {

		private boolean focusRequested;

		TestJTextArea() {
			super(10, 20);
		}

		@Override
		public void requestFocus() {
			super.requestFocus();
			focusRequested = true;
		}

		boolean wasFocusRequested() {
			return runSwing(() -> focusRequested);
		}

		void reset() {
			runSwing(() -> focusRequested = false);
		}

		void simulateFocusGained() {
			FocusListener[] listeners = getFocusListeners();
			runSwing(() -> {
				for (FocusListener l : listeners) {
					FocusEvent e =
						new FocusEvent(TestJTextArea.this, (int) System.currentTimeMillis());
					l.focusGained(e);
				}
			});
		}
	}
}
