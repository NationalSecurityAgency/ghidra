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
package ghidra.framework.main.logviewer.event;

import java.awt.event.MouseWheelEvent;
import java.awt.event.MouseWheelListener;

import ghidra.framework.main.logviewer.event.FVEvent.EventType;

/**
 * Invoked when the user scrolls the mouse wheel either up or down. In this case we need to 
 * fire off an event telling the viewport (or any other subscribers) that a scroll needs to 
 * happen.
 *
 */
public class MouseWheelAction implements MouseWheelListener {

	private FVEventListener eventListener;

	public MouseWheelAction(FVEventListener eventListener) {
		this.eventListener = eventListener;
	}

	@Override
	public void mouseWheelMoved(MouseWheelEvent e) {

		// First things first - turn on scroll locking. If the user is moving the view, don't
		// have it snap back to the bottom every time new data comes in.
		FVEvent scrollLockEvt = new FVEvent(EventType.SCROLL_LOCK_ON, null);
		eventListener.send(scrollLockEvt);

		// A notch is defined as a single row in the table.  So scrolling one notch will
		// move the viewport by one row.
		int notches = e.getWheelRotation();
		if (notches < 0) {
			FVEvent moveUpEvt = new FVEvent(EventType.VIEWPORT_UP, -notches);
			eventListener.send(moveUpEvt);
		}
		else {
			FVEvent moveDownEvt = new FVEvent(EventType.VIEWPORT_DOWN, notches);
			eventListener.send(moveDownEvt);
		}
	}
}
