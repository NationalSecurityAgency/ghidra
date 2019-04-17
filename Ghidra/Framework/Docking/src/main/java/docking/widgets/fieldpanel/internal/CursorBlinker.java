/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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
package docking.widgets.fieldpanel.internal;

import java.awt.Rectangle;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.Timer;

import docking.widgets.fieldpanel.FieldPanel;
import docking.widgets.fieldpanel.support.AnchoredLayout;
import docking.widgets.fieldpanel.support.FieldLocation;

public class CursorBlinker {
	private Timer timer;
	private FieldPanel fieldPanel;
	private Rectangle paintBounds;
	private boolean showCursor;
	private FieldLocation cursor = new FieldLocation();
	private AnchoredLayout layout;
	int layoutYpos = 0;

	public CursorBlinker(FieldPanel panel) {
		this.fieldPanel = panel;

		timer = new Timer(500, new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				if (paintBounds != null) {
					showCursor = !showCursor;
					fieldPanel.paintImmediately(paintBounds);
				}
				else {
					timer.stop();
				}
			}
		});

		// the initial painting is laggy for some reason, so shorten the delay
		timer.setInitialDelay(100);
		timer.start();

	}

	public void stop() {
		if (timer != null) {
			timer.stop();
		}
	}

	public void restart() {
		timer.restart();
	}

	public void dispose() {
		if (timer == null) {
			return; // not sure if dispose is being called twice
		}

		timer.stop();
		timer = null;

		fieldPanel = null;
	}

	public void updatePaintArea(AnchoredLayout cursorLayout, FieldLocation cursorPosition) {
		if (cursorLayout != layout || layout.getYPos() != layoutYpos ||
			!cursor.equals(cursorPosition)) {
			layout = cursorLayout;
			cursor.set(cursorPosition);
			showCursor = true;
			if (layout != null) {
				layoutYpos = layout.getYPos();
				timer.restart();
				paintBounds = layout.getFieldBounds(cursorPosition.fieldNum);
			}
			else {
				timer.stop();
				paintBounds = null;
			}
		}

	}

	public boolean showCursor() {
		return showCursor;
	}

}
