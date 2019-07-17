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
package docking.event.mouse;

import static java.awt.event.MouseEvent.*;
import static org.junit.Assert.*;

import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;

import org.junit.Test;

import generic.test.AbstractGenericTest;

public class GMouseListenerAdapterTest extends AbstractGenericTest {

	private static int RIGHT = MouseEvent.BUTTON3;
	private static int LEFT = MouseEvent.BUTTON1;
	private static final int X = 0;
	private static final int Y = 0;
	private JComponent source = new JPanel();

	private List<MouseEvent> eventsSent = new ArrayList<>();
	private TestGMouseListener listener = new TestGMouseListener();
	private boolean sendAlreadyConsumed;

	@Test
	public void testSingleClick_NoDoubleClickTriggered() {
		singleClick(RIGHT);

		assertNoDoubleClickTriggered();
	}

	@Test
	public void testDoubleClick_Right_NoDoubleClickTriggered() {
		doubleClick(RIGHT);

		assertNoDoubleClickTriggered();
	}

	@Test
	public void testDoubleClick_Left_DoubleClickTriggered() {
		doubleClick(LEFT);

		assertNoPopupTriggered();
		assertDoubleClick();
	}

	@Test
	public void testDoubleClick_MultipleMouseButtons_RightThenLeft_NoDoubleClickTriggered() {
		press(RIGHT, 1, true);
		release(RIGHT, 1, false);
		click(RIGHT, 1, false);

		assertPopupOn(MOUSE_PRESSED);

		listener.reset();

		press(LEFT, 2, false);
		release(LEFT, 2, false);
		click(LEFT, 2, false);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testDoubleClick_MultipleMouseButtons_LeftThenRight_NoDoubleClickTriggered() {
		press(LEFT, 1, false);
		release(LEFT, 1, false);
		click(LEFT, 1, false);

		press(RIGHT, 2, false);
		release(RIGHT, 2, false);
		click(RIGHT, 2, false);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTriggered_Pressed_PopupTriggered() {
		press(RIGHT, 1, true);
		release(RIGHT, 1, false);
		click(RIGHT, 1, false);

		assertPopupOn(MOUSE_PRESSED);
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTriggered_Released_PopupTriggered() {
		press(RIGHT, 1, false);
		release(RIGHT, 1, true);
		click(RIGHT, 1, false);

		assertPopupOn(MOUSE_RELEASED);
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTriggered_Clicked_PopupTriggered() {
		press(RIGHT, 1, false);
		release(RIGHT, 1, false);
		click(RIGHT, 1, true);

		assertPopupOnClicked();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTriggered_WithDoubleClick_NoDoubleClickTriggered() {
		press(LEFT, 1, false);
		release(LEFT, 1, false);
		click(LEFT, 1, false);

		press(RIGHT, 2, false);
		release(RIGHT, 2, false);
		click(RIGHT, 2, true); // popup here

		assertPopupOnClicked();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTriggered_WithConsume_Pressed_NoPopupTriggered() {

		listener.setShouldConsume(true);

		press(RIGHT, 1, true);
		release(RIGHT, 1, false);
		click(RIGHT, 1, false);

		assertEventsConsumed();
		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTriggered_WithConsume_Released_NoPopupTriggered() {

		listener.setShouldConsume(true);

		press(RIGHT, 1, true);
		release(RIGHT, 1, false);
		click(RIGHT, 1, false);

		assertEventsConsumed();
		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTriggered_WithConsume_Clicked_NoPopupTriggered() {

		listener.setShouldConsume(true);

		press(RIGHT, 1, true);
		release(RIGHT, 1, false);
		click(RIGHT, 1, false);

		assertEventsConsumed();
		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testPopupTheDoubleClick() {

		press(LEFT, 1, false);
		release(LEFT, 1, false);
		click(LEFT, 1, true);

		assertPopupOnClicked();

		listener.reset();

		doubleClick(LEFT);

		assertNoPopupTriggered();
		assertDoubleClick();
	}

	@Test
	public void testListenerIgnoresConsumedEvents_Pressed() {

		sendAlreadyConsumed = true;

		press(RIGHT, 1, true);
		release(RIGHT, 1, false);
		click(RIGHT, 1, false);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();

		press(LEFT, 2, false);
		release(LEFT, 2, false);
		click(LEFT, 2, false);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testListenerIgnoresConsumedEvents_Released() {

		sendAlreadyConsumed = true;

		press(RIGHT, 1, false);
		release(RIGHT, 1, true);
		click(RIGHT, 1, false);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();

		press(LEFT, 2, false);
		release(LEFT, 2, false);
		click(LEFT, 2, false);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

	@Test
	public void testListenerIgnoresConsumedEvents_Typed() {

		sendAlreadyConsumed = true;

		press(RIGHT, 1, false);
		release(RIGHT, 1, false);
		click(RIGHT, 1, true);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();

		press(LEFT, 2, false);
		release(LEFT, 2, false);
		click(LEFT, 2, false);

		assertNoPopupTriggered();
		assertNoDoubleClickTriggered();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertEventsConsumed() {
		eventsSent.forEach(e -> assertTrue("Event not consumed: " + e, e.isConsumed()));
	}

	private MouseEvent event(int type, int button, int clickCount, boolean isPopup) {
		int when = (int) System.currentTimeMillis();
		MouseEvent e = new MouseEvent(source, type, 0, when, X, Y, clickCount, isPopup, button);

		if (sendAlreadyConsumed) {
			e.consume();
		}

		return e;
	}

	private void singleClick(int button) {
		press(button, 1, false);
		release(button, 1, false);
		click(button, 1, false);
	}

	private void doubleClick(int button) {
		press(button, 1, false);
		release(button, 1, false);
		click(button, 1, false);

		press(button, 2, false);
		release(button, 2, false);
		click(button, 2, false);
	}

	private void press(int button, int clickCount, boolean isPopup) {
		MouseEvent e = event(MOUSE_PRESSED, button, clickCount, isPopup);
		listener.mousePressed(e);
		eventsSent.add(e);
	}

	private void release(int button, int clickCount, boolean isPopup) {
		MouseEvent e = event(MOUSE_RELEASED, button, clickCount, isPopup);
		listener.mouseReleased(e);
		eventsSent.add(e);
	}

	private void click(int button, int clickCount, boolean isPopup) {
		MouseEvent e = event(MOUSE_CLICKED, button, clickCount, isPopup);
		listener.mouseClicked(e);
		eventsSent.add(e);
	}

	private void assertNoDoubleClickTriggered() {
		assertTrue("Double-click should not have been triggered", listener.doubleClicks.isEmpty());
	}

	private void assertNoPopupTriggered() {
		assertTrue("Popup should not have been triggered", listener.popups.isEmpty());
	}

	private void assertPopupOnClicked() {
		assertPopupOn(MOUSE_CLICKED);
	}

	private void assertPopupOn(int type) {

		String typeString = toString(type);

		assertEquals("Should have popup triggered for " + typeString, 1, listener.popups.size());
		MouseEvent e = listener.popups.get(0);
		assertEquals("Mouse event should have triggered on " + typeString + ", but was " +
			toString(e.getID()), type, e.getID());
	}

	private void assertDoubleClick() {
		assertEquals("Should have had 1 double-click", 1, listener.doubleClicks.size());
	}

	private String toString(int eventId) {
		switch (eventId) {
			case MOUSE_PRESSED:
				return "'pressed'";
			case MOUSE_RELEASED:
				return "'released'";
			case MOUSE_CLICKED:
				return "'clicked'";
			default:
				fail("Wrong mouse type: " + eventId);
		}
		return null; // can't get here
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestGMouseListener extends GMouseListenerAdapter {

		private List<MouseEvent> doubleClicks = new ArrayList<>();
		private List<MouseEvent> popups = new ArrayList<>();
		private boolean shouldConsume = false;

		@Override
		public boolean shouldConsume(MouseEvent e) {
			return shouldConsume;
		}

		@Override
		public void doubleClickTriggered(MouseEvent e) {
			doubleClicks.add(e);
		}

		@Override
		public void popupTriggered(MouseEvent e) {
			popups.add(e);
		}

		void setShouldConsume(boolean shouldConsume) {
			this.shouldConsume = shouldConsume;
		}

		void reset() {
			doubleClicks.clear();
			popups.clear();
		}
	}
}
