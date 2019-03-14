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
package docking.widgets.table;

import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;

import java.awt.*;
import java.awt.dnd.Autoscroll;

import javax.swing.JComponent;
import javax.swing.SwingUtilities;

/**
 * Helper class for autoscrolling on a component.
 * 
 */
public class AutoscrollAdapter implements Autoscroll {

	private final static int MARGIN = 30;
	private JComponent component;
	private int scrollIncrement;

	/**
	 * Constructor
	 * @param component component that is scrollable
	 * @param scrollIncrement value to use to calculate the new
	 * visible rectangle for scrolling
	 */
	public AutoscrollAdapter(JComponent component, int scrollIncrement) {
		this.component = component;
		this.scrollIncrement = scrollIncrement;
	}

	@Override
	public Insets getAutoscrollInsets() {
		Rectangle outer = component.getBounds();
		return new Insets(outer.y + MARGIN, outer.x + MARGIN, outer.height - MARGIN, outer.width -
			MARGIN);
	}

	@Override
	public void autoscroll(Point p) {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() != OperatingSystem.WINDOWS) {
			autoscrollNonWindows();
			return;
		}

		Rectangle visRect = component.getVisibleRect();
		int scrollAmount = 0;
		if (p.y < visRect.y + MARGIN) {
			scrollAmount = -((visRect.y + MARGIN - p.y) * scrollIncrement) / 2;
		}
		else if (p.y > visRect.y + visRect.height - MARGIN) {
			scrollAmount = ((p.y - (visRect.y + visRect.height - MARGIN)) * scrollIncrement) / 2;
		}
		visRect.y += scrollAmount;
		int compHeight = component.getSize().height;
		if (visRect.y < 0) {
			visRect.y = 0;
		}
		else if (visRect.y >= compHeight - visRect.height) {
			visRect.y = compHeight - visRect.height - 1;
		}
		component.scrollRectToVisible(visRect);
	}

	private void autoscrollNonWindows() {
		//
		// On non-Windows components, we will just calculate ourselves when the cursor is over
		// an auto scroll area.
		//		
		Component releativeToComponent = component.getParent().getParent();

		PointerInfo pointerInfo = MouseInfo.getPointerInfo();
		// TODO: Not sure why this is blowing out on Java 1.7 on Mac, fixes blowup and lockup for now.
		if (pointerInfo == null) {
			return;
		}
		Point mouseLocation = pointerInfo.getLocation();
		SwingUtilities.convertPointFromScreen(mouseLocation, releativeToComponent);

		Rectangle bounds = releativeToComponent.getBounds();

		// make sure we are within the bounds horizontally
		int componentEndX = bounds.x + bounds.width;
		boolean withinHorizontally =
			mouseLocation.x >= bounds.x && mouseLocation.x <= componentEndX;
		if (!withinHorizontally) {
			return; // the user dragged out of the component to the side--do nothing
		}

		int scrollAmount = 0;

		int upperAutoScrollEndY = bounds.y + MARGIN;
		boolean overUpperAutoScrollArea = mouseLocation.y < upperAutoScrollEndY;
		int lowerScrollAreaStartY = (bounds.y + bounds.height) - MARGIN;
		boolean overLowerAutoScrollArea = mouseLocation.y > lowerScrollAreaStartY;
		if (overUpperAutoScrollArea) {

			int midUpperScrollArea = upperAutoScrollEndY - (MARGIN >> 1);
			if (mouseLocation.y < midUpperScrollArea) {
				scrollAmount = -(scrollIncrement * 3);
			}
			else {
				scrollAmount = -scrollIncrement;
			}
		}
		else if (overLowerAutoScrollArea) {
			int midLowerScrollArea = lowerScrollAreaStartY + (MARGIN >> 1);
			if (mouseLocation.y > midLowerScrollArea) {
				scrollAmount = scrollIncrement * 3;
			}
			else {
				scrollAmount = scrollIncrement;
			}
		}

		Rectangle visRect = component.getVisibleRect();
		visRect.y += scrollAmount;
		int compHeight = component.getSize().height;
		if (visRect.y < 0) {
			visRect.y = 0;
		}
		else if (visRect.y >= compHeight - visRect.height) {
			visRect.y = compHeight - visRect.height - 1;
		}

		component.scrollRectToVisible(visRect);
	}
}
