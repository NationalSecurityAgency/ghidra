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
package generic.util;

import java.awt.*;
import java.awt.geom.Area;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.swing.SwingUtilities;

import ghidra.util.SystemUtilities;

/**
 * A collection of window related utility methods
 */
public class WindowUtilities {

	/**
	 * Returns the title for the given window
	 * @param w the window
	 * @return the title
	 */
	public static String getTitle(Window w) {
		if (w == null) {
			return null;
		}

		if (w instanceof Frame) {
			return ((Frame) w).getTitle();
		}
		else if (w instanceof Dialog) {
			return ((Dialog) w).getTitle();
		}
		return null;
	}

	/**
	 * Returns the window parent of c.  If c is a window, then c is returned.
	 *
	 * <P>Warning: this differs from {@link SwingUtilities#windowForComponent(Component)} in
	 * that the latter method will not return the given component if it is a window.
	 *
	 * @param c the component
	 * @return the window
	 */
	public static Window windowForComponent(Component c) {
		if (c == null) {
			return null;
		}

		if (c instanceof Window) {
			return (Window) c;
		}

		return SwingUtilities.getWindowAncestor(c);
	}

	/**
	 * Returns the a rectangle representing the screen bounds for the entire screen space for 
	 * all screens in use.  The result will include virtual space that may not be rendered on 
	 * any physical hardware.   Said differently, the rectangle returned from this method will 
	 * contain all visible display coordinates, as well as potentially coordinates that are 
	 * virtual and not displayed on any physical screen.  The OS's window manager is responsible 
	 * for controlling how the virtual space is created.
	 * 
	 * @return the virtual screen bounds
	 */
	public static Rectangle getVirtualScreenBounds() {

		Rectangle virtualBounds = new Rectangle();
		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();

		GraphicsDevice[] gs = ge.getScreenDevices();
		for (GraphicsDevice gd : gs) {
			GraphicsConfiguration gc = gd.getDefaultConfiguration();
			Rectangle gcBounds = gc.getBounds();
			virtualBounds = virtualBounds.union(gcBounds);
		}
		return virtualBounds;
	}

	/**
	 * Returns a shape that represents the visible portion of the virtual screen bounds
	 * returned from {@link #getVirtualScreenBounds()}
	 * 
	 * @return the visible shape of all screen devices
	 */
	public static Shape getVisibleScreenBounds() {

		Area area = new Area();
		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
		GraphicsDevice[] gs = ge.getScreenDevices();
		for (GraphicsDevice gd : gs) {
			GraphicsConfiguration gc = gd.getDefaultConfiguration();
			Rectangle gcBounds = gc.getBounds();
			area.add(new Area(gcBounds));
		}

		return area;
	}

	/**
	 * Gets the <b>usable</b> screen bounds for the screen in which the given component is 
	 * showing.  Returns null if the given component is not showing.   Usable bounds are the 
	 * screen bounds after subtracting insets (for things like menu bars and task bars).
	 * 
	 * @param c the component
	 * @return the screen bounds; null if the component is not showing
	 */
	public static Rectangle getScreenBounds(Component c) {

		Point p = getScreenLocation(c);
		if (p == null) {
			return null; // component is not showing/realized
		}

		ScreenBounds screenBounds = doGetScreenBounds(p);
		return screenBounds.getUsableBounds();
	}

	private static Point getScreenLocation(Component c) {
		if (c instanceof Window) {
			return c.getLocation(); // window's coordinates are screen coordinates
		}

		if (!c.isShowing()) {
			return null; // not on screen
		}

		Window w = windowForComponent(c);
		if (w == null) {
			return null; // not on screen (don't think this can happen)
		}

		Point p = c.getLocationOnScreen();
		return p;
	}

	/**
	 * Computes the point such that a rectangle with the given size would be centered on the
	 * screen.   The chosen screen in this case is the screen defined by
	 * <pre>  
	 *	GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
	 * </pre>
	 * 
	 * <p>If the given size is too big to fit on the screen in either dimension, 
	 * then it will be placed at the 0 position for that dimension.
	 * 
	 * @param d the size of the rectangle to center
	 * @return the upper-left point of the given centered dimension
	 * @see #centerOnScreen(Component, Dimension)
	 */
	public static Point centerOnScreen(Dimension d) {

		GraphicsDevice defaultDevice =
			GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
		GraphicsConfiguration config = defaultDevice.getDefaultConfiguration();

		// note: the bounds may be an offset location, such as (0, 512), which would imply that
		//       the x is 0 and the y is offset 512 pixels from the top of a virtual screen bounds
		Rectangle bounds = config.getBounds();
		return center(bounds, d);
	}

	/**
	 * Computes the point such that a rectangle with the given size would be centered on the
	 * screen.   The chosen screen in this case is the screen defined by using the given 
	 * component.  If the given size is too big to fit on the screen in either dimension, 
	 * then it will be placed at the 0 position for that dimension. 
	 * 
	 * @param c the component that should be used to find the current screen
	 * @param d the size of the rectangle to center
	 * @return the upper-left point of the given centered dimension
	 * @see #centerOnScreen(Dimension)
	 */
	public static Point centerOnScreen(Component c, Dimension d) {

		Rectangle bounds = getScreenBounds(c);
		if (bounds == null) {
			throw new IllegalArgumentException("Component is not on screen: " + c);
		}

		return center(bounds, d);
	}

	private static Point center(Rectangle area, Dimension d) {

		// restrict to bounds size
		Rectangle b = area;
		int userWidth = Math.min(b.width, d.width);
		int userHeigh = Math.min(b.height, d.height);

		int halfScreenWidth = b.width / 2;
		int halfUserWidth = userWidth / 2;
		int halfScreenHeight = b.height / 2;
		int halfUserHeight = userHeigh / 2;
		int widthOffset = halfScreenWidth - halfUserWidth;
		int heightOffset = halfScreenHeight - halfUserHeight;
		int x = b.x + widthOffset;
		int y = b.y + heightOffset;
		return new Point(x, y);
	}

	/**
	 * Creates a point that is centered over the given <code>parent</code> component, based upon
	 * the size of the given <code>child</code>.
	 * @param parent The component over which to center the child.
	 * @param child The component which will be centered over the parent
	 * @return a point that is centered over the given <code>parent</code> component, based upon
	 * the size of the given <code>child</code>.
	 */
	public static Point centerOnComponent(Component parent, Component child) {
		Dimension parentSize = parent.getSize();
		Dimension childSize = child.getSize();
		int x = (parentSize.width >> 1) - (childSize.width >> 1);
		int y = (parentSize.height >> 1) - (childSize.height >> 1);
		Point point = new Point(x, y);
		if (child instanceof Window) {
			// windows are in screen coordinates, so convert to the parent coordinates, which
			// SwingUtilities does not do
			SwingUtilities.convertPointToScreen(point, parent);
		}
		else {
			// this handles negative values
			point = SwingUtilities.convertPoint(parent, point, child.getParent());
		}
		return point;
	}

	/**
	 * Update the component to be within visible bounds of the screen
	 * 
	 * <P>This method differs from {@link #ensureOnScreen(Component, Rectangle)} in that 
	 * the other method does not adjust the component's bounds like this method does.
	 * 
	 * @param c the component to move on screen as necessary
	 * @throws IllegalArgumentException if the given component is not yet realized (see 
	 *         {@link Component#isShowing()}
	 */
	public static void ensureOnScreen(Component c) {

		Rectangle bounds = c.getBounds();
		ensureOnScreen(c, bounds);
		c.setBounds(bounds);
	}

	/**
	 * Update the bounds to be within visible bounds of the screen.  The given component is 
	 * used to determine which screen to use for updating the bounds.
	 * 
	 * <P>Note: the given comonent's bounds will not be adjusted by this method
	 * 
	 * @param c the on screen component, used to determine which screen to check against the given 
	 *        bounds
	 * @param bounds the bounds to adjust
	 * @throws IllegalArgumentException if the given component is not yet realized (see 
	 *         {@link Component#isShowing()}
	 */
	public static void ensureOnScreen(Component c, Rectangle bounds) {

		Shape visibleScreenBounds = getVisibleScreenBounds();
		if (visibleScreenBounds.contains(bounds)) {
			return; // the given shape is completely on the screen 
		}

		Rectangle screen = getScreenBounds(c);
		if (screen == null) {
			throw new IllegalArgumentException("Component is not on screen: " + c);
		}

		Point newPoint = center(screen, bounds.getSize());
		bounds.setLocation(newPoint);
	}

	private static ScreenBounds doGetScreenBounds(Point p) {
		GraphicsConfiguration gc = getGraphicsConfigurationForPoint(p);
		Toolkit toolkit = Toolkit.getDefaultToolkit();
		Rectangle bounds = gc.getBounds();
		Insets insets = toolkit.getScreenInsets(gc);
		return new ScreenBounds(bounds, insets);
	}

	private static GraphicsConfiguration getGraphicsConfigurationForPoint(Point p) {
		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
		GraphicsDevice[] devices = ge.getScreenDevices();
		for (GraphicsDevice device : devices) {
			if (device.getType() == GraphicsDevice.TYPE_RASTER_SCREEN) {
				GraphicsConfiguration config = device.getDefaultConfiguration();
				if (config.getBounds().contains(p)) {
					return config;
				}
			}
		}

		GraphicsDevice defaultDevice = ge.getDefaultScreenDevice();
		return defaultDevice.getDefaultConfiguration();
	}

	/**
	 * Returns true if there are one or more modal dialogs displayed in the current JVM.
	 * @return true if there are one or more modal dialogs displayed in the current JVM.
	 */
	public static boolean areModalDialogsVisible() {
		return getOpenModalDialogs().size() > 0;
	}

	public static Dialog findModalestDialog() {
		List<Dialog> openModalDialogs = getOpenModalDialogs();
		if (openModalDialogs.size() == 0) {
			return null;
		}

		final KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		final Component permanentFocusOwner = kfm.getPermanentFocusOwner();
		if (permanentFocusOwner == null) {
			// no focus owner; any dialog should do
			return pickAModalDialog(openModalDialogs);
		}

		// check first for modal dialogs in the focused hierarchy
		Dialog theModalest = findParentModalDialog(permanentFocusOwner, openModalDialogs);
		theModalest = findYoungestChildDialogOfParentDialog(theModalest, openModalDialogs);
		theModalest = checkForActiveModalDialog(theModalest);
		if (theModalest != null) {
			return theModalest;
		}

		// Now, pick one of the open modal dialogs
		return pickAModalDialog(openModalDialogs);
	}

	private static Dialog checkForActiveModalDialog(Dialog theModalest) {
		final KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
		final Window activeWindow = kfm.getActiveWindow();
		if (!(activeWindow instanceof Dialog)) {
			return theModalest;
		}
		Dialog dialog = (Dialog) activeWindow;
		if (dialog.isModal()) {
			return dialog;
		}
		return theModalest;
	}

	private static void getOpenModalDialogChildren(Frame frame, List<Dialog> openModalDialogs) {
		Window[] ownedWindows = frame.getOwnedWindows();
		for (Window window : ownedWindows) {
			getOpenModalDialogChidrenForWindow(window, openModalDialogs);
		}
	}

	private static void getOpenModalDialogChidrenForWindow(Window window,
			List<Dialog> openModalDialogs) {

		// add the window before its children, if it is a modal dialog
		if ((window instanceof Dialog)) {
			Dialog dialog = (Dialog) window;
			if (dialog.isVisible() && dialog.isModal()) {
				openModalDialogs.add(dialog);
			}
		}

		// grab any modal children
		Window[] childWindows = window.getOwnedWindows();
		for (Window childWindow : childWindows) {
			getOpenModalDialogChidrenForWindow(childWindow, openModalDialogs);
		}
	}

	/**
	 * Returns a list of all <code>parent</code>'s descendant modal dialogs.
	 *
	 * @param parent the parent for which to find modal dialogs
	 * @return a list of all <code>parent</code>'s descendant modal dialogs.
	 */
	public static List<Dialog> getOpenModalDialogsFor(Frame parent) {
		Objects.requireNonNull(parent);
		List<Dialog> openModalDialogs = new ArrayList<>();
		getOpenModalDialogChildren(parent, openModalDialogs);
		return openModalDialogs;
	}

	private static List<Dialog> getOpenModalDialogs() {
		Frame[] frames = Frame.getFrames();
		List<Dialog> openModalDialogs = new ArrayList<>();
		for (Frame nextFrame : frames) {
			getOpenModalDialogChildren(nextFrame, openModalDialogs);
		}

		return openModalDialogs;
	}

	private static Dialog findParentModalDialog(Component permanentFocusOwner,
			List<Dialog> openModalDialogs) {

		for (Dialog dialog : openModalDialogs) {
			if (SwingUtilities.isDescendingFrom(permanentFocusOwner, dialog)) {
				return dialog;
			}
		}

		return null;
	}

	private static Dialog findYoungestChildDialogOfParentDialog(Dialog parentDialog,
			List<Dialog> openModalDialogs) {

		if (parentDialog == null) {
			return null;
		}

		for (Dialog potentialChildDialog : openModalDialogs) {
			if (parentDialog == potentialChildDialog) {
				continue;
			}
			if (SwingUtilities.isDescendingFrom(potentialChildDialog, parentDialog)) {
				return findYoungestChildDialogOfParentDialog(potentialChildDialog,
					openModalDialogs);
			}
		}
		return parentDialog;
	}

	private static Dialog pickAModalDialog(List<Dialog> openModalDialogs) {
		// We can just guess here.  We shall use the last one in the list, as usually the most
		// recent dialogs are at the end of Window's owned window list (this can be bad if
		// modal dialogs are reused).
		Dialog dialog = openModalDialogs.get(openModalDialogs.size() - 1);
		return findYoungestChildDialogOfParentDialog(dialog, openModalDialogs);
	}

	/**
	 * Attempts to locate the topmost modal dialog and then bring that dialog to the front of
	 * the window hierarchy
	 * 
	 * @param activeWindow the system's active window 
	 */
	public static void bringModalestDialogToFront(final Window activeWindow) {
		// NOTE: we do an invokeLater here, as some of our clients are calling us in a
		// WindowListener.windowActivated() callback.  During this callback, it is possible that
		// the focus owner is not correct, as it will be changed to the window under activation.
		// If we invoke later, the the call will happen when focus has been transitioned.
		SystemUtilities.runSwingLater(() -> doBringModalestDialogToFront(activeWindow));
	}

	private static void doBringModalestDialogToFront(Window activeWindow) {
		final Dialog modalestDialog = findModalestDialog();
		if (modalestDialog == null) {
			return;
		}

		SystemUtilities.runSwingLater(() -> modalestDialog.toFront());
	}

	/** Class that knows the screen bounds, insets and bounds without the insets */
	private static class ScreenBounds {

		private Rectangle fullBounds;
		private Rectangle usableBounds;

		public ScreenBounds(Rectangle bounds, Insets insets) {
			this.fullBounds = bounds;

			int x = fullBounds.x + insets.left;
			int y = fullBounds.y + insets.top;
			int width = fullBounds.width - Math.abs(insets.left + insets.right);
			int height = fullBounds.height - Math.abs(insets.top + insets.bottom);
			this.usableBounds = new Rectangle(x, y, width, height);
		}

		/**
		 * Gets the full size of this bounds object, including the insets
		 * @return the full size of this bounds object, including the insets
		 */
		Rectangle getFullBounds() {
			return fullBounds;
		}

		/**
		 * Returns the size not including the insets
		 * @return the size not including the insets
		 */
		Rectangle getUsableBounds() {
			return usableBounds;
		}
	}
}
