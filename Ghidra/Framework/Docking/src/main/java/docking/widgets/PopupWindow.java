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
import java.awt.geom.Rectangle2D;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.swing.*;
import javax.swing.Timer;

import generic.json.Json;
import generic.util.WindowUtilities;
import ghidra.util.Msg;
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

		ensureSize(popupBounds);

		Rectangle hoverArea = new Rectangle(point, keepVisibleArea);
		Rectangle adjustedBounds = adjustBoundsForCursorLocation(popupBounds, hoverArea);
		neutralMotionZone = createNeutralMotionZone(adjustedBounds, hoverArea);

		installDebugPainter(e);

		popup.setBounds(adjustedBounds);
		popup.setVisible(true);

		removeOldPopupReferences();

		VISIBLE_POPUPS.add(new WeakReference<>(this));
	}

	private void ensureSize(Rectangle popupBounds) {
		Shape screenShape = WindowUtilities.getVisibleScreenBounds();
		Rectangle screenBounds = screenShape.getBounds();
		if (screenBounds.width < popupBounds.width) {
			popupBounds.width = screenBounds.width / 2;
		}

		if (screenBounds.height < popupBounds.height) {
			popupBounds.height = screenBounds.height / 2;
		}
	}

	private void installDebugPainter(List<GridCell> grid) {
//		GGlassPane glassPane = GGlassPane.getGlassPane(sourceComponent);
//		ShapeDebugPainter painter = new ShapeDebugPainter(null, grid, neutralMotionZone);
//		glassPane.addPainter(painter);
//		painters.add(painter);
	}

	private void installDebugPainter(MouseEvent e) {
//		GGlassPane glassPane = GGlassPane.getGlassPane(sourceComponent);
//		ShapeDebugPainter painter = new ShapeDebugPainter(e, null, neutralMotionZone);
//		glassPane.addPainter(painter);
//		painters.add(painter);
	}

	/**
	 * Adjusts the given bounds to make sure that they do not cover the given location.
	 * <p>
	 * When the <tt>hoverArea</tt> is obscured, this method will create a grid of possible locations
	 * in which to place the given bounds.   The grid will be searched for the location that is
	 * closest to the hover area without touching it.
	 * 
	 * @param bounds The bounds to move as necessary.
	 * @param hoverArea The area that should not be covered by the given bounds
	 * @return the original bounds adjusted so that they do not cover the given <tt>hoverArea</tt>,
	 *         if possible.
	 */
	private Rectangle adjustBoundsForCursorLocation(Rectangle bounds, Rectangle hoverArea) {
		Shape screenShape = WindowUtilities.getVisibleScreenBounds();
		Rectangle screenBounds = screenShape.getBounds();
		if (!bounds.intersects(hoverArea) && screenBounds.contains(bounds)) {
			return bounds;
		}

		// center bounds over hover area; we intend not to block the hover area
		int dx = (hoverArea.width / 2) - (bounds.width / 2);
		int dy = (hoverArea.height / 2) - (bounds.height / 2);
		Point hoverCenter = bounds.getLocation();
		hoverCenter.x += dx;
		hoverCenter.y += dy;

		List<GridCell> grid = createSortedGrid(screenBounds, hoverCenter, bounds.getSize());

		installDebugPainter(grid);

		// try placing the bounds in each grid cell in order until no clipping
		Rectangle match = null;
		for (GridCell cell : grid) {
			Rectangle r = cell.getRectangle();
			if (!hoverArea.intersects(r) &&
				screenBounds.contains(r)) {
				match = r;
				break;
			}
		}

		if (match == null) {
			Msg.debug(null, "Could not find a place to put the rectangle" + bounds);
			return bounds;
		}

		return match;
	}

	private List<GridCell> createSortedGrid(Rectangle screen, Point targetCenter, Dimension size) {

		List<GridCell> grid = new ArrayList<>();

		//
		// Rather than just a simple grid of rows and columns of the given size, this loop will
		// create twice as many rows and columns, each half the size, resulting in 4 time the 
		// number of potential locations.   This allows for potential closer placement to the 
		// target center.
		//
		int row = 0;
		Rectangle r = new Rectangle(new Point(0, 0), size);
		while (screen.contains(r)) {

			int x = r.x;
			int y = r.y;

			int col = 0;
			while (screen.contains(r)) {
				grid.add(new GridCell(r, targetCenter, row, col));

				// add another cell halfway over
				col++;
				int half = size.width / 2;
				x += half;
				r = new Rectangle(x, r.y, r.width, r.height);

				if (screen.contains(r)) {
					grid.add(new GridCell(r, targetCenter, row, col));
				}

				col++;
				x += half;
				r = new Rectangle(x, r.y, r.width, r.height);
			}

			row++;
			x = 0;
			int halfHeight = r.height / 2;
			y += halfHeight;
			r = new Rectangle(x, y, r.width, r.height);

			// loop again for another row halfway down
			col = 0;
			while (screen.contains(r)) {
				grid.add(new GridCell(r, targetCenter, row, col));

				// add another cell halfway over
				col++;
				int half = size.width / 2;
				x += half;
				r = new Rectangle(x, r.y, r.width, r.height);

				if (screen.contains(r)) {
					grid.add(new GridCell(r, targetCenter, row, col));
				}

				col++;
				x += half;
				r = new Rectangle(x, r.y, r.width, r.height);
			}

			row++;
			x = 0;
			y += halfHeight;
			r = new Rectangle(x, y, r.width, r.height);
		}

		grid.sort(null);

		return grid;
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

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A cell of a grid.   This cell is given the target center point of the screen space, which
	 * is used to determine how close this cell is to the target. 
	 */
	private class GridCell implements Comparable<GridCell> {
		private Rectangle rectangle;
		private int distanceFromCenter;
		private boolean isRight;
		private boolean isBelow;
		private int row;
		private int col;

		GridCell(Rectangle rectangle, Point targetCenter, int row, int col) {
			this.rectangle = rectangle;
			this.row = row;
			this.col = col;

			double cx = rectangle.getCenterX();
			double cy = rectangle.getCenterY();
			double scx = targetCenter.getX();
			double scy = targetCenter.getY();
			double dx = cx - scx;
			double dy = cy - scy;
			distanceFromCenter = (int) Math.sqrt(dx * dx + dy * dy);
			isRight = cx > scx;
			isBelow = cy > scy;
		}

		public Rectangle getRectangle() {
			return rectangle;
		}

		@Override
		public int compareTo(GridCell other) {
			// smaller distances come first
			int delta = distanceFromCenter - other.distanceFromCenter;
			if (delta != 0) {
				return delta;
			}

			if (isRight != other.isRight) {
				return isRight ? -1 : 1;  // prefer right side
			}

			if (isBelow != other.isBelow) {
				return isBelow ? -1 : 1; // prefer below
			}

			return 0;
		}

		@Override
		public String toString() {
			return Json.toString(this);
		}
	}

	// for debug
	//private static List<GGlassPanePainter> painters = new ArrayList<>();

	/** Paints shapes used by this class (useful for debugging) */
	@SuppressWarnings("unused")
	// enabled as needed
	private class ShapeDebugPainter implements GGlassPanePainter {

		private MouseEvent sourceEvent;
		private Rectangle bounds;
		private List<GridCell> grid;

		ShapeDebugPainter(MouseEvent sourceEvent, List<GridCell> grid, Rectangle bounds) {
			this.sourceEvent = sourceEvent;
			this.grid = grid;
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

			if (grid != null) {

				Graphics2D g2d = (Graphics2D) g;
				Font font = g2d.getFont().deriveFont(12).deriveFont(Font.BOLD);
				g2d.setFont(font);

				g.setColor(new Color(55, 0, 0, 100));
				for (GridCell cell : grid) {

					Rectangle r = cell.getRectangle();
					Point p = r.getLocation();
					int oldY = p.y;
					SwingUtilities.convertPointFromScreen(p, glassPane);
					int x = p.x;
					int y = p.y;
					int w = r.width;
					int h = r.height;
					g2d.fillRect(x, y, w, h);
				}

				g2d.setColor(Color.PINK);
				for (GridCell cell : grid) {
					String coord = "(" + cell.row + "," + cell.col + ")";
					Rectangle r = cell.getRectangle();

					int cx = r.x + r.width;
					int cy = r.y + r.height;
					Point p = new Point(cx, cy);
					SwingUtilities.convertPointFromScreen(p, glassPane);
					FontMetrics fm = g2d.getFontMetrics();
					Rectangle2D sbounds = fm.getStringBounds(coord, g2d);
					int textWidth = (int) sbounds.getWidth();
					int textHeight = (int) sbounds.getHeight();
					int scx = (int) sbounds.getCenterX();
					int scy = (int) sbounds.getCenterY();
					int textx = p.x - textWidth;
					int texty = p.y - textHeight;
					g2d.drawString(coord, p.x, p.y);
				}
			}
		}
	}
}
