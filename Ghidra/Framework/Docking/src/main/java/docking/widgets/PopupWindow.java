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

import java.awt.*;
import java.awt.event.*;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.swing.*;
import javax.swing.Timer;

import generic.util.WindowUtilities;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;

public class PopupWindow {
	private static final int X_PADDING = 20;
	private static final int Y_PADDING = 20;
	private static final List<WeakReference<PopupWindow>> VISIBLE_POPUPS = new ArrayList<>();

	public static void hideAllWindows() {
		for (WeakReference<PopupWindow> weakReference : VISIBLE_POPUPS) {
			PopupWindow popupWindow = weakReference.get();
			if (popupWindow != null) {
				popupWindow.hide();
			}
		}
	}

	private JWindow popup;

	private Component sourceComponent;
	/** Area where user can mouse without hiding the window (in screen coordinates) */
	private Rectangle neutralMotionZone;

	private MouseMotionListener sourceMouseMotionListener;
	private MouseListener sourceMouseListener;
	private Timer closeTimer;
	private JComponent displayComponent;

	public PopupWindow(JComponent displayComponent) {
		this(getDefaultParentWindow(), displayComponent);
	}

	public PopupWindow(Component sourceComponent, JComponent displayComponent) {
		this(getParentWindow(sourceComponent), displayComponent);
	}

	private static Window getParentWindow(Component sourceComponent) {
		if (sourceComponent == null) {
			return getDefaultParentWindow();
		}
		Window window = WindowUtilities.windowForComponent(sourceComponent);
		if (window != null) {
			return window;
		}
		return getDefaultParentWindow();
	}

	private static Window getDefaultParentWindow() {
		KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		Window activeWindow = kfm.getActiveWindow();
		if (activeWindow == null) {
			activeWindow = JOptionPane.getRootFrame();
		}
		return activeWindow;
	}

	public PopupWindow(Window parentWindow, JComponent displayComponent) {
		this.displayComponent = displayComponent;

		popup = new JWindow(parentWindow);
		popup.setFocusableWindowState(false);
// this is bad, as it keeps tooltips above all apps and they don't go away, as normal tooltips do        
//        popup.setAlwaysOnTop( true );

		popup.getContentPane().add(displayComponent);
		popup.pack();

		closeTimer = new Timer(750, event -> hide());
		closeTimer.setRepeats(false);

		MouseListener closeWindowListener = new MouseAdapter() {
			@Override
			public void mouseEntered(MouseEvent e) {
				closeTimer.stop();
			}

			@Override
			public void mouseExited(MouseEvent e) {
				closeTimer.start();
			}
		};
		addMouseListener(popup, closeWindowListener);

		sourceMouseMotionListener = new MouseMotionAdapter() {
			@Override
			public void mouseMoved(MouseEvent e) {
				Point localPoint = e.getPoint();

				SwingUtilities.convertPointToScreen(localPoint, e.getComponent());
				if (!neutralMotionZone.contains(localPoint)) {
					hide();
				}
				else {
					// If the user mouses around the neutral zone, then start the close timer.  The
					// timer will be reset if the user enters the popup.
					closeTimer.start();
				}
				e.consume(); // consume the event so that the source component doesn't processes it
			}
		};

		sourceMouseListener = new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent e) {
				hide();
			}
		};
	}

	private void addMouseListener(Container c, MouseListener listener) {
		c.addMouseListener(listener);
		Component[] children = c.getComponents();
		for (Component element : children) {
			if (element instanceof Container) {
				addMouseListener((Container) element, listener);
			}
			else {
				element.addMouseListener(listener);
			}
		}
	}

	public JComponent getDisplayComponent() {
		return displayComponent;
	}

	public void setWindowName(String name) {
		popup.setName(name);
	}

	public void addComponentListener(ComponentListener listener) {
		popup.addComponentListener(listener);
	}

	public boolean isShowing() {
		return popup.isShowing();
	}

	public void hide() {

		popup.setVisible(false);

		if (sourceComponent != null) {
			sourceComponent.removeMouseMotionListener(sourceMouseMotionListener);
			sourceComponent.removeMouseListener(sourceMouseListener);
		}

		sourceComponent = null;
	}

	public void dispose() {
		hide();
		popup.dispose();
		removeOldPopupReferences();
	}

	private void removeOldPopupReferences() {
		for (Iterator<WeakReference<PopupWindow>> iterator =
			VISIBLE_POPUPS.iterator(); iterator.hasNext();) {
			WeakReference<PopupWindow> reference = iterator.next();
			PopupWindow window = reference.get();
			if (window == this) {
				reference.clear();
				iterator.remove();
				return;
			}
		}
	}

	public void pack() {
		popup.pack();
	}

	/**
	 * Sets the amount of time that will pass before the popup window is closed <b>after</b> the
	 * user moves away from the popup window and out of the neutral zone
	 * 
	 * @param delayInMillis the timer delay
	 */
	public void setCloseWindowDelay(int delayInMillis) {
		closeTimer = new Timer(delayInMillis, event -> hide());
		closeTimer.setRepeats(false);
	}

	public void showOffsetPopup(MouseEvent e, Dimension keepVisibleArea) {
		doShowPopup(e, keepVisibleArea);
	}

	public void showPopup(MouseEvent e) {
		doShowPopup(e, null);
	}

	private void doShowPopup(MouseEvent e, Dimension keepVisibleArea) {
		hideAllWindows();

		sourceComponent = e.getComponent();
		sourceComponent.addMouseListener(sourceMouseListener);
		sourceComponent.addMouseMotionListener(sourceMouseMotionListener);

		Point point = e.getPoint();
		SwingUtilities.convertPointToScreen(point, sourceComponent);
		if (keepVisibleArea == null) {
			keepVisibleArea = new Dimension(0, 0);
		}

		Rectangle popupBounds = popup.getBounds();

		int x = point.x + keepVisibleArea.width + X_PADDING;
		int y = point.y + keepVisibleArea.height + Y_PADDING;
		popupBounds.setLocation(x, y);

		WindowUtilities.ensureOnScreen(sourceComponent, popupBounds);

		Rectangle hoverArea = new Rectangle(point, keepVisibleArea);
		adjustBoundsForCursorLocation(popupBounds, hoverArea);

		neutralMotionZone = createNeutralMotionZone(popupBounds, hoverArea);

		installDebugPainter(e);

		popup.setBounds(popupBounds);
		popup.setVisible(true);

		removeOldPopupReferences();

		VISIBLE_POPUPS.add(new WeakReference<>(this));
	}

	private void installDebugPainter(MouseEvent e) {
		// GGlassPane glassPane = GGlassPane.getGlassPane(sourceComponent);		
		// ShapeDebugPainter painter = new ShapeDebugPainter(e, neutralMotionZone);
		// glassPane.addPainter(painter);
	}

	/**
	 * Adjusts the given bounds to make sure that they do not cover the given location.
	 * <p>
	 * When the <tt>hoverArea</tt> is obscured, this method will first attempt to move the 
	 * bounds up if possible.  If moving up is not possible due to space constraints, then this
	 * method will try to shift the bounds to the right of the hover area.  If this is not 
	 * possible, then the bounds will not be changed.
	 * 
	 * @param bounds The bounds to move as necessary.
	 * @param hoverArea The area that should not be covered by the given bounds
	 * @return the original bounds adjusted so that they do not cover the given <tt>hoverArea</tt>,
	 *         if possible.
	 */
	private Rectangle adjustBoundsForCursorLocation(Rectangle bounds, Rectangle hoverArea) {
		if (!bounds.intersects(hoverArea)) {
			return bounds;
		}

		// first attempt to move the window--try to go up
		int movedY = hoverArea.y - bounds.height;
		boolean canMoveUp = movedY >= 0;
		if (canMoveUp) {
			// move the given bounds above the current point
			bounds.y = movedY;
			return bounds;
		}

		// We couldn't move up, so we try to go left, since by default the popup is placed 
		// to the right of the hover area.
		int movedX = hoverArea.x - bounds.width;
		boolean canMoveLeft = movedX >= 0;
		if (canMoveLeft) {
			bounds.x = movedX;
		}

		return bounds;
	}

	/**
	 * Creates a rectangle that contains both given rectangles entirely.
	 */
	private Rectangle createNeutralMotionZone(Rectangle popupBounds, Rectangle hoverRectangle) {
		int newX = Math.min(hoverRectangle.x, popupBounds.x);
		int newY = Math.min(hoverRectangle.y, popupBounds.y);

		double hoverLowestCornerX = hoverRectangle.x + hoverRectangle.getWidth();
		double popupLowestCornerX = popupBounds.x + popupBounds.getWidth();
		int lowestCornerX = (int) Math.max(hoverLowestCornerX, popupLowestCornerX);

		double hoverLowestCornerY = hoverRectangle.y + hoverRectangle.getHeight();
		double popupLowestCornerY = popupBounds.y + popupBounds.getHeight();
		int lowestCornerY = (int) Math.max(hoverLowestCornerY, popupLowestCornerY);

		int width = difference(newX, lowestCornerX);
		int height = difference(newY, lowestCornerY);

		// add in some padding around the edges of the area, so that moving just over the edge
		// of the popup will not close it (this can happen when the user sloppy-scrolls)
		int padding = 25;
		newX -= padding;
		newY -= padding;
		width += (padding * 2); // * 2 to give the padding and to compensate for the shifted x
		height += (padding * 2); // * 2 to give the padding and to compensate for the shifted y

		return new Rectangle(newX, newY, width, height);
	}

	private int difference(int value1, int value2) {
		int abs1 = Math.abs(value1);
		int abs2 = Math.abs(value2);
		if (abs1 > abs2) {
			return abs1 - abs2;
		}
		return abs2 - abs1;
	}

	/** Paints shapes used by this class (useful for debugging) */
	@SuppressWarnings("unused")
	// enabled as needed
	private class ShapeDebugPainter implements GGlassPanePainter {

		private MouseEvent sourceEvent;
		private Rectangle bounds;

		ShapeDebugPainter(MouseEvent sourceEvent, Rectangle bounds) {
			this.sourceEvent = sourceEvent;
			this.bounds = bounds;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics) {

			// bounds of the popup and the mouse neutral zone
			Rectangle r = bounds;
			Point p = new Point(r.getLocation());
			SwingUtilities.convertPointFromScreen(p, glassPane);

			Color c = new Color(50, 50, 200, 125);
			graphics.setColor(c);
			graphics.fillRect(p.x, p.y, r.width, r.height);

			// show where the user hovered
			p = sourceEvent.getPoint();
			p = SwingUtilities.convertPoint(sourceEvent.getComponent(), p.x, p.y, glassPane);
			graphics.setColor(Color.RED);
			int offset = 10;
			graphics.fillRect(p.x - offset, p.y - offset, (offset * 2), (offset * 2));
		}
	}
}
