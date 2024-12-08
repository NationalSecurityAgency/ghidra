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
import java.util.*;
import java.util.List;

import javax.swing.*;
import javax.swing.Timer;

import docking.DockingUtils;
import docking.widgets.shapes.*;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.util.WindowUtilities;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;
import util.CollectionUtils;

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
		new PopupWindowPlacerBuilder().rightEdge(Location.BOTTOM)
				.leftEdge(Location.BOTTOM)
				.bottomEdge(Location.RIGHT)
				.topEdge(Location.CENTER)
				.leastOverlapCorner()
				.throwsAssertException()
				.build();

	/** 
	 * Area where user can mouse without hiding the window (in screen coordinates).  A.K.A., the
	 * mouse neutral zone.
	 */
	private Rectangle mouseMovementArea;
	private JWindow popup;
	private Component sourceComponent;
	private PopupWindowPlacer popupWindowPlacer = DEFAULT_WINDOW_PLACER;

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

	/**
	 * Sets the object that decides where to place the popup window. 
	 * @param popupWindowPlacer the placer
	 */
	public void setPopupPlacer(PopupWindowPlacer popupWindowPlacer) {
		this.popupWindowPlacer =
			popupWindowPlacer == null ? DEFAULT_WINDOW_PLACER : popupWindowPlacer;
	}

	public void showOffsetPopup(MouseEvent e, Rectangle keepVisibleArea, boolean forceShow) {
		if (forceShow || DockingUtils.isTipWindowEnabled()) {
			PopupSource popupSource = new PopupSource(e, keepVisibleArea);
			doShowPopup(popupSource);
		}
	}

	/**
	 * Shows this popup window unless popups are disabled as reported by 
	 * {@link DockingUtils#isTipWindowEnabled()}.  If {@code forceShow} is true, then the popup 
	 * will be shown regardless of the state returned by {@link DockingUtils#isTipWindowEnabled()}.
	 * @param e the event
	 * @param forceShow true to show the popup even popups are disabled application-wide
	 */
	public void showPopup(MouseEvent e, boolean forceShow) {
		if (forceShow || DockingUtils.isTipWindowEnabled()) {
			PopupSource popupSource = new PopupSource(e);
			doShowPopup(popupSource);
		}
	}

	/**
	 * Shows this popup window unless popups are disabled as reported by 
	 * {@link DockingUtils#isTipWindowEnabled()}.  If {@code forceShow} is true, then the popup 
	 * will be shown regardless of the state returned by {@link DockingUtils#isTipWindowEnabled()}.
	 * <P>
	 * Note: the component passed in is the component to which the {@code location} the location 
	 * belongs.   In the example below, the component used to get the location is to the component
	 * passed to this method.  This is because the location is relative to the parent's coordinate
	 * space.  Thus, when calling this method, make sure to use the correct component.
	 * <PRE>
	 * Point location = textField.getLocation(); // this is relative to the text field's parent
	 * Component parent = textField.getParent();
	 * PopupWindow.showPopup(parent, location, true);
	 * </PRE>
	 * 
	 * @param component the component whose coordinate space the location belongs
	 * @param location the location to show the popup
	 * @param forceShow true to show the popup even popups are disabled application-wide
	 */
	public void showPopup(Component component, Point location, boolean forceShow) {
		if (forceShow || DockingUtils.isTipWindowEnabled()) {
			PopupSource popupSource = new PopupSource(component, location, null);
			doShowPopup(popupSource);
		}
	}

	/**
	 * Shows this popup window unless popups are disabled as reported by 
	 * {@link DockingUtils#isTipWindowEnabled()}.
	 * @param e the event
	 */
	public void showPopup(MouseEvent e) {
		showPopup(e, false);
	}

	/**
	 * Shows the popup window.  This will hide any existing popup windows, adjusts the new popup
	 * to avoid covering the keep visible area and then shows the popup.
	 * 
	 * @param popupSource the popup source that contains info about the source of the popup, such
	 * as the component, a mouse event and any area to keep visible.
	 */
	private void doShowPopup(PopupSource popupSource) {

		hideAllWindows();

		sourceComponent = popupSource.getSource();
		sourceComponent.addMouseListener(sourceMouseListener);
		sourceComponent.addMouseMotionListener(sourceMouseMotionListener);

		Dimension popupSize = popup.getSize();
		ensureSize(popupSize);

		//
		// Creates a rectangle that contains both given rectangles entirely and includes padding.
		// The padding allows users to mouse over the edge of the hovered area without triggering 
		// the popup to close.
		//
		Rectangle visibleArea = popupSource.getScreenKeepVisibleArea();
		Rectangle screenBounds = WindowUtilities.getVisibleScreenBounds().getBounds();
		Rectangle placement = popupWindowPlacer.getPlacement(popupSize, visibleArea, screenBounds);
		mouseMovementArea = placement.union(visibleArea);

		popup.setBounds(placement);
		popup.setVisible(true);

		removeOldPopupReferences();

		VISIBLE_POPUPS.add(new WeakReference<>(this));
	}

	private static void ensureSize(Dimension popupDimension) {
		Dimension screenDimension = WindowUtilities.getVisibleScreenBounds().getBounds().getSize();

		if (screenDimension.width < popupDimension.width) {
			popupDimension.width = screenDimension.width / 2;
		}

		if (screenDimension.height < popupDimension.height) {
			popupDimension.height = screenDimension.height / 2;
		}
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A class that holds info related to the source of a hover request.  This is used to position
	 * the popup window that will be shown.
	 */
	private class PopupSource {

		private Component source;
		private Rectangle screenKeepVisibleArea;
		private Point location;

		PopupSource(MouseEvent e) {
			this(e, null);
		}

		PopupSource(MouseEvent e, Rectangle keepVisibleArea) {
			this(e.getComponent(), e.getPoint(), keepVisibleArea);
		}

		PopupSource(Component source, Point location, Rectangle keepVisibleArea) {

			if (CollectionUtils.isAllNull(location, keepVisibleArea)) {
				throw new NullPointerException("Both location and keepVisibleArea cannot be null");
			}
			if (keepVisibleArea == null) {
				keepVisibleArea = new Rectangle(location, new Dimension(0, 0));
			}
			this.location = location;
			this.source = source;
			this.screenKeepVisibleArea = createScreenKeepVisibleArea(location, keepVisibleArea);

			installDebugPainter(keepVisibleArea);
		}

		Component getSource() {
			return source;
		}

		Rectangle getScreenKeepVisibleArea() {
			return screenKeepVisibleArea;
		}

		private Rectangle createScreenKeepVisibleArea(Point p, Rectangle keepVisibleAea) {

			Rectangle newArea = keepVisibleAea;
			if (keepVisibleAea == null) {
				Point point = new Point(p);
				newArea = new Rectangle(point);
				newArea.grow(X_PADDING, Y_PADDING); // pad to avoid placing the popup too close 
			}

			return createScreenKeepVisibleArea(newArea);
		}

		private Rectangle createScreenKeepVisibleArea(Rectangle keepVisibleAea) {

			Objects.requireNonNull(keepVisibleAea);

			Rectangle newArea = new Rectangle(keepVisibleAea);
			Point point = newArea.getLocation();
			SwingUtilities.convertPointToScreen(point, source);
			newArea.setLocation(point);
			return newArea;
		}

		// for debug
		private void installDebugPainter(Rectangle keepVisibleArea) {

//			GGlassPane glassPane = GGlassPane.getGlassPane(source);
//			for (GGlassPanePainter p : painters) {
//				glassPane.removePainter(p);
//			}
//			ShapeDebugPainter painter = new ShapeDebugPainter();
//
//			glassPane.addPainter(painter);
//			painters.add(painter);
		}

		@SuppressWarnings("unused")
		private static List<GGlassPanePainter> painters = new ArrayList<>();

		/** Paints shapes used by this class (useful for debugging) */
		@SuppressWarnings("unused") // enabled as needed
		private class ShapeDebugPainter implements GGlassPanePainter {

			@Override
			public void paint(GGlassPane glassPane, Graphics g) {

				int alpha = 150;

				// bounds of the popup and the mouse neutral zone
				if (mouseMovementArea != null) {
					Rectangle r = mouseMovementArea;
					Point p = new Point(r.getLocation());
					SwingUtilities.convertPointFromScreen(p, glassPane);

					Color c = Palette.LAVENDER.withAlpha(alpha);
					g.setColor(c);
					g.fillRect(p.x, p.y, r.width, r.height);
				}

				// show where the user hovered
				if (location != null) {
					Point p = new Point(location);
					p = SwingUtilities.convertPoint(source, p.x, p.y, glassPane);

					g.setColor(Palette.RED.withAlpha(alpha));
					int offset = 10;
					g.fillRect(p.x - offset, p.y - offset, (offset * 2), (offset * 2));
				}
			}
		}
	}

}
