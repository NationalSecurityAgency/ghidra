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

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

import ghidra.util.Msg;

/**
 * A mouse listener implementation designed to provide consistent handling of triggers for
 * popups and double-clicking.
 * <P>
 * <U>Notes:</U>
 * <UL>
 * 		<LI>Popup triggers always supersedes double-click actions.</LI>
 *  		<LI>The stage an action triggers (pressed/released/clicked) is platform dependent.</LI>
 *  		<LI>Each of the methods mentioned below will be called as appropriate.</LI>
 *  		<LI>You can override any of these methods to be called for each trigger.</LI>
 *  		<LI>Normally popups are handled by the framework via custom actions.  But, for custom
 *          widgets it is sometimes simpler to handle your own popups.  This class makes that 
 *          easier</LI>
 * </UL>
 * 
 * @see #popupTriggered(MouseEvent)
 * @see #doubleClickTriggered(MouseEvent)
 * @see #shouldConsume(MouseEvent)
 */
public class GMouseListenerAdapter extends MouseAdapter {

	private static final int LEFT = MouseEvent.BUTTON1;

	private int lastMouseButton = -1;
	private boolean didConsume;
	private boolean didPopup;

//==================================================================================================
// Client Methods
//==================================================================================================	

	/**
	 * This method is called to ask the client if they wish to consume the given event.  This
	 * allows clients to keep events from propagating to other listeners. 
	 * 
	 * @param e the event to potentially consume
	 * @return true if the event should be consumed
	 */
	public boolean shouldConsume(MouseEvent e) {
		return false;
	}

	/**
	 * Called when a double-click event is discovered.
	 * 
	 * @param e the event that triggered the double-click
	 */
	public void doubleClickTriggered(MouseEvent e) {
		// for users to override
	}

	/**
	 * Called when a popup event is discovered.
	 * 
	 * @param e the event that triggered the popup
	 */
	public void popupTriggered(MouseEvent e) {
		// for users to override
	}

//==================================================================================================
// MouseListener Interface Methods and Implementation
//==================================================================================================	

	@Override
	public void mousePressed(MouseEvent e) {

		trace("'pressed'");

		if (e.isConsumed()) {
			return;
		}

		reset(); // always reset on pressed in case we never got the clicked event

		if (consume(e)) {
			trace("\tevent consumed");
			return;
		}

		if (popup(e)) {
			trace("\tpopup triggered");
			return;
		}
	}

	@Override
	public void mouseReleased(MouseEvent e) {

		trace("'released'");

		if (e.isConsumed()) {
			return;
		}

		if (consume(e)) {
			trace("\tevent consumed");
			return;
		}

		if (popup(e)) {
			trace("\tpopup triggered");
			return;
		}
	}

	@Override
	public void mouseClicked(MouseEvent e) {

		try {
			doMouseClicked(e);
		}
		finally {
			reset();
		}
	}

	private void doMouseClicked(MouseEvent e) {

		trace("'clicked'");

		int previousButton = lastMouseButton;
		int currentButton = e.getButton();
		lastMouseButton = currentButton;

		if (e.isConsumed()) {
			return;
		}

		if (consume(e) || didConsume) {
			trace("\tevent consumed on or before 'clicked'");
			return;
		}

		if (popup(e) || didPopup) {
			trace("\t popup triggered on or before 'clicked'");
			return;
		}

		if (e.getClickCount() % 2 == 0) { // this allows double-click repeatedly without pause 
			trace("\tdouble-click");
			if (bothClicksFromLeftButton(previousButton, currentButton)) {
				trace("\tdouble-click from left");
				doubleClickTriggered(e);
			}
		}
	}

	private boolean popup(MouseEvent e) {
		if (e.isPopupTrigger()) {
			didPopup = true;
			popupTriggered(e);
			return true;
		}
		return false;
	}

	private boolean consume(MouseEvent e) {
		if (shouldConsume(e)) {
			didConsume = true;
			e.consume();
			return true;
		}
		return false;
	}

	private boolean bothClicksFromLeftButton(int previousButton, int currentButton) {
		if (previousButton != LEFT) {
			return false;
		}

		boolean isLeft = currentButton == LEFT;
		return isLeft;
	}

	private void reset() {
		didConsume = false;
		didPopup = false;
	}

	private void trace(String message) {
		Msg.trace(GMouseListenerAdapter.class, message);
	}
}
