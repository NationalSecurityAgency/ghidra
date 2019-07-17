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
package ghidra.framework.task.gui.taskview;

import ghidra.util.layout.VerticalLayout;

import java.awt.*;

import javax.swing.*;

// This component is basically a JPanel that implements the Scrollable interface needed for the 
// TaskViewer.
public class TaskViewerComponent extends JPanel implements Scrollable {
	private static final int PREFERRED_WIDTH = 400;
	private static final int PREFERRED_HEIGHT = 500;
	private static final int UNIT_SCROLL = 30;

	public TaskViewerComponent() {
		super(new VerticalLayout(0));
		setBackground(Color.WHITE);
		setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
	}

	@Override
	public Dimension getPreferredScrollableViewportSize() {
		return new Dimension(PREFERRED_WIDTH, PREFERRED_HEIGHT);
	}

	@Override
	public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
		return UNIT_SCROLL;
	}

	@Override
	public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
		return UNIT_SCROLL * 5;
	}

	@Override
	public boolean getScrollableTracksViewportWidth() {
		return true;
	}

	@Override
	public boolean getScrollableTracksViewportHeight() {
		return false;
	}

}
