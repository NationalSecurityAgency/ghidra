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
package ghidra.app.plugin.core.flowarrow;

import java.awt.*;
import java.awt.event.*;
import java.util.Iterator;

import javax.swing.JPanel;
import javax.swing.ToolTipManager;

import org.jdesktop.animation.timing.Animator;

import docking.DockingWindowManager;
import docking.util.AnimationUtils;
import docking.util.SwingAnimationCallback;
import ghidra.program.model.address.*;
import ghidra.util.HelpLocation;
import ghidra.util.task.SwingUpdateManager;

class FlowArrowPanel extends JPanel {

	private Cursor clickCursor;
	private Cursor defaultCursor;

	private FlowArrowPlugin plugin;
	private Color foregroundColor;
	private Color highlightColor;
	private Color selectedColor;

	private SwingUpdateManager mouseClickUpdater;
	private Point pendingMouseClickPoint;

	FlowArrowPanel(FlowArrowPlugin p) {
		super();
		this.plugin = p;
		setMinimumSize(new Dimension(0, 0));
		setPreferredSize(new Dimension(32, 1));

		defaultCursor = getCursor();
		clickCursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);

		ToolTipManager.sharedInstance().registerComponent(this);
		DockingWindowManager.setHelpLocation(this,
			new HelpLocation("CodeBrowserPlugin", "CBFlowArrows"));

		int min = 350;
		mouseClickUpdater = new SwingUpdateManager(min, () -> {
			if (pendingMouseClickPoint == null) {
				return;
			}

			processSingleClick(pendingMouseClickPoint);
			pendingMouseClickPoint = null;
		});

		addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2) {
					pendingMouseClickPoint = null; // don't change the selection
					processDoubleClick(e);
					return;
				}

				if (e.getClickCount() == 1) {
					pendingMouseClickPoint = e.getPoint();
					mouseClickUpdater.updateLater();
				}
			}

		});

		addMouseWheelListener(new FlowArrowPanelMouseWheelListener());
		FlowArrowCursorMouseListener cursorListener = new FlowArrowCursorMouseListener();
		addMouseMotionListener(cursorListener);
		addMouseListener(cursorListener);
	}

	public void updateCursor(Point point) {
		FlowArrow arrow = getArrow(point);
		if (arrow != null) {
			setCursor(clickCursor);
		}
		else {
			setCursor(defaultCursor);
		}
	}

	public void resetCursor() {
		setCursor(defaultCursor);
	}

	private void processDoubleClick(MouseEvent e) {
		Point point = e.getPoint();
		FlowArrow arrow = getArrow(point);
		navigateArrow(arrow);
	}

	private FlowArrow getArrow(Point p) {
		FlowArrow arrow = getArrow(p, plugin.getFlowArrowIterator());
		if (arrow != null) {
			return arrow;
		}

		// try the arrows that hang around a bit
		arrow = getArrow(p, plugin.getSelectedFlowArrows());
		if (arrow != null) {
			return arrow;
		}

		return getArrow(p, plugin.getActiveArrows());
	}

	private FlowArrow getArrow(Point p, Iterator<FlowArrow> it) {
		while (it.hasNext()) {
			FlowArrow arrow = it.next();
			if (arrow.intersects(p)) {
				return arrow;
			}
		}
		return null;
	}

	private void navigateArrow(FlowArrow arrow) {
		if (arrow == null) {
			return;
		}

// TODO to do this, we should probably have another concept of 'navigated'/'current' as to not
// confuse the concept of selecting arrows				
		// select any arrow we double-click
		arrow.selected = true;
		plugin.setArrowSelected(arrow, true);

		Address end = arrow.end;
		if (end.equals(plugin.getCurrentAddress())) {
			// go back the other direction
			end = arrow.start;
		}

		if (plugin.isOnScreen(end)) {
			// don't animate arrows completely on screen
			plugin.goTo(end);
			return;
		}

		// Start the animation at the edge of the screen
		Address start = plugin.getLastAddressOnScreen(end, arrow.isUp());

		ScrollingCallback callback = new ScrollingCallback(start, end);
		Animator animator = AnimationUtils.executeSwingAnimationCallback(callback);
		callback.setAnimator(animator);

	}

	private void processSingleClick(Point point) {
		FlowArrow arrow = getArrow(point);
		if (arrow != null) {
			arrow.selected = !arrow.selected; // toggle
			plugin.setArrowSelected(arrow, arrow.selected);
			repaint();
			return; // only select one line at a time
		}
	}

	@Override
	public void setBounds(int x, int y, int width, int height) {
		// note: this gets called as the user drags the divider pane
		super.setBounds(x, y, width, height);
		plugin.updateAndRepaint();
	}

	@Override
	public String getToolTipText(MouseEvent e) {
		Point point = e.getPoint();
		Iterator<FlowArrow> it = plugin.getFlowArrowIterator();
		while (it.hasNext()) {
			FlowArrow arrow = it.next();
			if (arrow.intersects(point)) {
				return arrow.getDisplayString();
			}
		}
		return super.getToolTipText(e);
	}

	@Override
	public void setForeground(Color c) {
		super.setForeground(c);
		foregroundColor = c;
		repaint();
	}

	@Override
	public void setBackground(Color c) {
		super.setBackground(c);
		repaint();
	}

	void setHighlightColor(Color c) {
		highlightColor = c;
		repaint();
	}

	void setSelectedColor(Color c) {
		selectedColor = c;
		repaint();
	}

	@Override
	protected void paintComponent(Graphics g) {

		super.paintComponent(g);

		Address currentAddress = plugin.getCurrentAddress();
		if (currentAddress == null) {
			return;
		}

		Graphics2D g2 = (Graphics2D) g;

		Color fgColor = foregroundColor;

		//
		// Non-selected arrows
		//
		Iterator<FlowArrow> it = plugin.getFlowArrowIterator();
		while (it.hasNext()) {
			FlowArrow arrow = it.next();
			if (arrow.active || arrow.selected) {
				// painted below
				continue;
			}

			paintJump(g2, arrow, fgColor);
		}

		fgColor = highlightColor;

		//
		// Active arrows--those at the selected address; paint on top of normal arrows
		//
		it = plugin.getActiveArrows();
		while (it.hasNext()) {
			FlowArrow arrow = it.next();
			if (arrow.selected) {
				// painted below
				continue;
			}

			paintJump(g2, arrow, fgColor);
		}

		//
		// Selected arrows
		//
		fgColor = selectedColor;
		it = plugin.getSelectedFlowArrows();
		while (it.hasNext()) {
			FlowArrow arrow = it.next();
			paintJump(g2, arrow, fgColor);
		}
	}

	private void paintJump(Graphics2D g2, FlowArrow arrow, Color fgColor) {
		if (plugin.isOffscreen(arrow)) {
			return; // don't paint linger arrows, such as selected or active arrows
		}

		Color bgColor = getBackground();
		arrow.paint(g2, fgColor, bgColor);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ScrollingCallback implements SwingAnimationCallback {

		private Address start;
		private Address end;
		private AddressRange range;
		private Address lastAddress;
		private Animator animator;

		ScrollingCallback(Address start, Address end) {
			this.start = start;
			this.end = end;
			this.range = new AddressRangeImpl(start, end);
		}

		@Override
		public void progress(double percentComplete) {

			long length = range.getLength();
			long offset = Math.round(length * percentComplete);
			Address current = null;
			if (start.compareTo(end) > 0) {
				// backwards
				current = start.subtract(offset);
			}
			else {
				current = start.add(offset);
			}

			if (current.equals(lastAddress)) {
				return;
			}

			if (current.equals(end)) {
				// we are done!
				animator.stop();
				return;
			}

			// System.err.printf("%1.3f%%\t", (percentComplete * 100));
			// System.err.println("scrolling to: " + current);

			plugin.scrollTo(current);
			lastAddress = current; // let's us avoid multiple duplicate requests
		}

		@Override
		public void done() {
			// set the final position
// TODO This happens after the animation is finished, which is jarring.  If we want this centered, 
//		then we need an entirely different way of animating the transition so that the centering
//	    is part of the animation.
//			plugin.scrollToCenter(end);

			plugin.goTo(end);
		}

		void setAnimator(Animator animator) {
			this.animator = animator;
		}

	}

	private class FlowArrowCursorMouseListener implements MouseMotionListener, MouseListener {

		@Override
		public void mouseDragged(MouseEvent e) {
			// updateCursor(e.getPoint());
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			updateCursor(e.getPoint());
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			// resetCursor();
		}

		@Override
		public void mousePressed(MouseEvent e) {
			// resetCursor();
		}

		@Override
		public void mouseReleased(MouseEvent e) {
			// resetCursor();
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			resetCursor();
		}

		@Override
		public void mouseExited(MouseEvent e) {
			resetCursor();
		}

	}

	private class FlowArrowPanelMouseWheelListener implements MouseWheelListener {
		@Override
		public void mouseWheelMoved(MouseWheelEvent e) {
			plugin.forwardMouseEventToListing(e);
		}
	}

	void dispose() {
		mouseClickUpdater.dispose();
	}

}
