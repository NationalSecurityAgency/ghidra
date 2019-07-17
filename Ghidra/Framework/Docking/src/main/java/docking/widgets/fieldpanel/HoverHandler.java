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
package docking.widgets.fieldpanel;

import java.awt.Rectangle;
import java.awt.event.*;

import javax.swing.Timer;
import javax.swing.ToolTipManager;

import docking.widgets.fieldpanel.field.Field;
import docking.widgets.fieldpanel.support.FieldLocation;
import docking.widgets.fieldpanel.support.HoverProvider;

public class HoverHandler implements ActionListener {
	private Timer hoverTimer;
	private MouseEvent lastMouseMovedEvent;
	private HoverProvider hoverProvider;
	private FieldPanel fieldPanel;

	HoverHandler(FieldPanel fieldPanel) {
		this.fieldPanel = fieldPanel;
	}

	/** Call this when the mouse is no longer over the hover source */
	public void hoverExited() {
		stopTimer();
	}

	public void startHover(MouseEvent e) {
		lastMouseMovedEvent = e;
		if (hoverTimer != null) {
			hoverTimer.restart();
		}
	}

	public void stopHover() {
		stopTimer();
		if (hoverProvider != null) {
			hoverProvider.closeHover();
		}
	}

	private void stopTimer() {
		if (hoverTimer != null) {
			hoverTimer.stop();
		}
	}

	public void setHoverProvider(HoverProvider hoverProvider) {
		this.hoverProvider = hoverProvider;
		if (hoverProvider != null && hoverTimer == null) {
			int timeout = ToolTipManager.sharedInstance().getInitialDelay();
			hoverTimer = new Timer(timeout, this);
			hoverTimer.setRepeats(false);
			hoverTimer.stop();
		}
		else if (hoverProvider == null && hoverTimer != null) {
			hoverTimer.stop();
			hoverTimer = null;
		}
	}

	public void scroll(int scrollAmount) {
		if (hoverProvider != null) {
			hoverProvider.scroll(scrollAmount);
		}
	}

	public boolean isHoverShowing() {
		if (hoverProvider != null) {
			return hoverProvider.isShowing();
		}
		return false;
	}

	public boolean isEnabled() {
		return hoverProvider != null;
	}

	@Override
	public void actionPerformed(ActionEvent evt) {
		mouseHovered(lastMouseMovedEvent);
	}

	public void mouseHovered(MouseEvent e) {
		stopTimer();
		Layout layout = fieldPanel.findLayoutAt(e.getY());
		if (layout != null) {
			int x = e.getX();
			int y = e.getY();

			FieldLocation newLoc = new FieldLocation();
			layout.setCursor(newLoc, x, y);
			Field mouseField = layout.getField(newLoc.fieldNum);

			if (x < mouseField.getStartX()) {
				return;
			}
			Rectangle rect = layout.getCursorRect(newLoc.fieldNum, newLoc.row, newLoc.col);
			if (x < rect.x - 10 || x > rect.x + 10) {
				return;
			}
			rect.x = mouseField.getStartX();
			rect.width = mouseField.getWidth();
			hoverProvider.mouseHovered(newLoc, mouseField, rect, e);
		}
	}
}
