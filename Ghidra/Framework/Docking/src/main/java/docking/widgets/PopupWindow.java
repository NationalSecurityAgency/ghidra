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

import docking.widgets.shapes.*;
import generic.util.WindowUtilities;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;

/**
 * A generic window intended to be used as a temporary window to show information.  This window is
 * designed to stay open as long as the user mouses over the window.   Once the user mouses away,
 * the window will be closed. 
 */
public class PopupWindow {
	private static final int X_PADDING = 25;
	private static final int Y_PADDING = 25;
	private static final List<WeakReference<PopupWindow>> VISIBLE_POPUPS = new ArrayList<>();

	public static void hideAllWindows() {
		for (WeakReference<PopupWindow> weakReference : VISIBLE_POPUPS) {
			PopupWindow popupWindow = weakReference.get();
			if (popupWindow != null) {
				popupWindow.hide();
			}
		}
	}

	private static final PopupWindowPlacer DEFAULT_WINDOW_PLACER =
		new PopupWindowPlacerBuilder()
				.rightEdge(Location.BOTTOM)
				.leftEdge(Location.BOTTOM)
				.bottomEdge(Location.RIGHT)
				.topEdge(Location.CENTER)
				.leastOverlapCorner()
				.throwsAssertException()
				.build();

	/** Area where user can mouse without hiding the window (in screen coordinates) */
	private Rectangle mouseMovementArea;
	private JWindow popup;
	private Component sourceComponent;

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
				if (!mouseMovementArea.contains(localPoint)) {
					hide();
				}
				else {
					// If the user mouses around the neutral zone, then start the close timer.  The
					// timer will be reset if the user enters the popup.
					closeTimer.restart();
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
		for (Iterator<WeakReference<PopupWindow>> iterator = VISIBLE_POPUPS.iterator(); iterator
				.hasNext();) {
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

	public void showOffsetPopup(MouseEvent e, Rectangle keepVisibleSize) {
		doShowPopup(e, keepVisibleSize, DEFAULT_WINDOW_PLACER);
	}

	public void showPopup(MouseEvent e) {
		doShowPopup(e, null, DEFAULT_WINDOW_PLACER);
	}

	private void doShowPopup(MouseEvent e, Rectangle keepVisibleSize, PopupWindowPlacer placer) {
		hideAllWindows();

		sourceComponent = e.getComponent();
		sourceComponent.addMouseListener(sourceMouseListener);
		sourceComponent.addMouseMotionListener(sourceMouseMotionListener);

		Dimension popupDimension = popup.getSize();
		ensureSize(popupDimension);

		Rectangle keepVisibleArea = createKeepVisibleArea(e, keepVisibleSize);
		Rectangle screenBounds = WindowUtilities.getVisibleScreenBounds().getBounds();
		Rectangle placement = placer.getPlacement(popupDimension, keepVisibleArea, screenBounds);
		mouseMovementArea = createMovementArea(placement, keepVisibleArea);

		installDebugPainter(e);

		popup.setBounds(placement);
		popup.setVisible(true);

		removeOldPopupReferences();

		VISIBLE_POPUPS.add(new WeakReference<>(this));
	}

	private Rectangle createKeepVisibleArea(MouseEvent e, Rectangle keepVisibleAea) {

		Rectangle newArea;
		if (keepVisibleAea == null) {
			Point point = new Point(e.getPoint());
			newArea = new Rectangle(point);
			newArea.grow(X_PADDING, Y_PADDING); // pad to avoid placing the popup too close 
		}
		else {
			newArea = new Rectangle(keepVisibleAea);
		}

		Point point = newArea.getLocation();
		SwingUtilities.convertPointToScreen(point, sourceComponent);
		newArea.setLocation(point);

		return newArea;
	}

	private void ensureSize(Dimension popupDimension) {
		Dimension screenDimension = WindowUtilities.getVisibleScreenBounds().getBounds().getSize();

		if (screenDimension.width < popupDimension.width) {
			popupDimension.width = screenDimension.width / 2;
		}

		if (screenDimension.height < popupDimension.height) {
			popupDimension.height = screenDimension.height / 2;
		}
	}

	/**
	 * Creates a rectangle that contains both given rectangles entirely and includes padding.
	 * The padding allows users to mouse over the edge of the hovered area without triggering the
	 * popup to close.
	 */
	private Rectangle createMovementArea(Rectangle popupBounds, Rectangle hoverRectangle) {
		Rectangle result = popupBounds.union(hoverRectangle);
		return result;
	}

	private void installDebugPainter(MouseEvent e) {
//		GGlassPane glassPane = GGlassPane.getGlassPane(sourceComponent);
//		ShapeDebugPainter painter = new ShapeDebugPainter(e, null, neutralMotionZone);
//		painters.forEach(p -> glassPane.removePainter(p));
//
//		glassPane.addPainter(painter);
//		painters.add(painter);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	// for debug
//	private static List<GGlassPanePainter> painters = new ArrayList<>();

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
		public void paint(GGlassPane glassPane, Graphics g) {

			// bounds of the popup and the mouse neutral zone
			if (bounds != null) {
				Rectangle r = bounds;
				Point p = new Point(r.getLocation());
				SwingUtilities.convertPointFromScreen(p, glassPane);

				Color c = new Color(50, 50, 200, 125);
				g.setColor(c);
				g.fillRect(p.x, p.y, r.width, r.height);
			}

			// show where the user hovered
			if (sourceEvent != null) {
				Point p = sourceEvent.getPoint();
				p = SwingUtilities.convertPoint(sourceEvent.getComponent(), p.x, p.y, glassPane);
				g.setColor(Color.RED);
				int offset = 10;
				g.fillRect(p.x - offset, p.y - offset, (offset * 2), (offset * 2));
			}
		}
	}
}
