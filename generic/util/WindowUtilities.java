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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.swing.SwingUtilities;

import ghidra.util.SystemUtilities;

/**
 * A collection of window related utility methods
 */
public class WindowUtilities {

	private static Rectangle fullScreenBounds;

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
		return SwingUtilities.windowForComponent(c);
	}

	/**
	 * Returns the a rectangle representing the entire screen bounds.
	 */
	public static Rectangle getScreenBounds() {
		if (fullScreenBounds == null) {
			Rectangle virtualBounds = new Rectangle();
			GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();

			// this accounts for the native widgets, such as taskbars
			Rectangle maxBounds = ge.getMaximumWindowBounds();
			int clipWidth = 0;
			int clipHeight = 0;

			GraphicsDevice[] gs = ge.getScreenDevices();
			for (GraphicsDevice gd : gs) {
				GraphicsConfiguration gc = gd.getDefaultConfiguration();
				Rectangle gcBounds = gc.getBounds();
				virtualBounds = virtualBounds.union(gc.getBounds());

				// calculate the offset of the native widgets, like the Windows taskbar
				//
				// Assumption: the size of GraphicsEnvironment.getMaximumWindowBounds() is always
				// the same as or smaller than the bounds of each graphics component.  The idea
				// is the the GraphicsEnvironment's max bounds will take into account the area
				// occupied by the native widgets, such as the Windows taskbar.
				if (clipWidth == 0) {
					Dimension maxSize = maxBounds.getSize();
					clipWidth = Math.max(clipWidth, gcBounds.width - maxSize.width);
					clipHeight = Math.max(clipHeight, gcBounds.height - maxSize.height);
				}
			}
			fullScreenBounds = virtualBounds;

			// subtract the native widget space
			fullScreenBounds.width -= clipWidth;
			fullScreenBounds.height -= clipHeight;
		}
		return fullScreenBounds;
	}

	/**
	 * Computes the point such that a rectangle with the given size would be centered on the
	 * screen.
	 * @param d the size of the rectangle to center.
	 * @return the point at which the if the given rectangle were drawn with its upper left
	 * corner at that point, it would be centered on the screen.
	 */
	public static Point centerOnScreen(Dimension d) {
		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
		GraphicsDevice[] gs = ge.getScreenDevices();
		Dimension screenSize = getScreenBounds().getSize();
		if (gs.length % 2 == 0) {
			// on an odd number of screens we don't want to center across two screens, so
			// just use the primary device bounds
			screenSize = Toolkit.getDefaultToolkit().getScreenSize();
		}
		int x = screenSize.width / 2 - d.width / 2;
		int y = screenSize.height / 2 - d.height / 2;
		return new Point(x, y);
	}

	/**
	 * Creates a point that is centered over the given <tt>parent</tt> component, based upon
	 * the size of the given <tt>child</tt>.
	 * @param parent The component over which to center the child.
	 * @param child The component which will be centered over the parent
	 * @return a point that is centered over the given <tt>parent</tt> component, based upon
	 * the size of the given <tt>child</tt>.
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
			point = SwingUtilities.convertPoint(parent, point, child.getParent()); // this handles negative values
		}
		return point;
	}

	/**
	 * Makes sure the window is within visible bounds of the screen.
	 * @param window the window to move onscreen as necessary.
	 */
	public static void ensureWindowOnScreen(Window window) {
		Rectangle windowRect = window.getBounds();
		Rectangle screenRect = getScreenBounds();
		windowRect.width = Math.min(windowRect.width, screenRect.width - 2);
		windowRect.height = Math.min(windowRect.height, screenRect.height - 2);

		windowRect.x =
			Math.min(windowRect.x, screenRect.x + screenRect.width - windowRect.width - 1);
		windowRect.x = Math.max(windowRect.x, screenRect.x + 1);
		windowRect.y =
			Math.min(windowRect.y, screenRect.y + screenRect.height - windowRect.height - 1);
		windowRect.y = Math.max(windowRect.y, screenRect.y + 1);

		window.setBounds(windowRect);
	}

	/**
	 * Updates the given dimension as necessary to fit it on the screen.
	 *
	 * @param size the size that may get updated
	 */
	public static void ensureSizeFitsScreen(Dimension size) {
		Rectangle screenRect = getScreenBounds();
		size.width = Math.min(size.width, screenRect.width);
		size.height = Math.min(size.height, screenRect.height);
	}

	/**
	 * Returns an point which has been adjusted to take into account of the
	 * desktop bounds, taskbar and multi-monitor configuration.
	 * <p>
	 * This adjustment may be cancelled by invoking the application with
	 * -Djavax.swing.adjustPopupLocationToFit=false
	 *
	 * @param bounds the bounds that must fit onscreen
	 */
	public static Point adjustBoundsToFitScreen(Rectangle bounds) {
		Point p = new Point(bounds.x, bounds.y);

		if (GraphicsEnvironment.isHeadless()) {
			return p;
		}

		// Try to find GraphicsConfiguration, that includes mouse pointer position
		GraphicsConfiguration gc = getGraphicsConfigurationForPoint(p);

		Toolkit toolkit = Toolkit.getDefaultToolkit();
		Rectangle screenBounds;
		Insets screenInsets;
		if (gc != null) {
			// If we have GraphicsConfiguration use it to get
			// screen bounds and insets
			screenInsets = toolkit.getScreenInsets(gc);
			screenBounds = gc.getBounds();
		}
		else {
			// If we don't have GraphicsConfiguration use primary screen
			// and empty insets
			screenInsets = new Insets(0, 0, 0, 0);
			screenBounds = new Rectangle(toolkit.getScreenSize());
		}

		int scrWidth = screenBounds.width - Math.abs(screenInsets.left + screenInsets.right);
		int scrHeight = screenBounds.height - Math.abs(screenInsets.top + screenInsets.bottom);

		if ((p.x + bounds.width) > screenBounds.x + scrWidth) {
			p.x = screenBounds.x + scrWidth - bounds.width;
		}
		if ((p.y + bounds.height) > screenBounds.y + scrHeight) {
			p.y = screenBounds.y + scrHeight - bounds.height;
		}

		/* Change is made to the desired (X,Y) values, when the
		   bounds are too tall OR too wide for the screen
		*/
		if (p.x < screenBounds.x) {
			p.x = screenBounds.x;
		}
		if (p.y < screenBounds.y) {
			p.y = screenBounds.y;
		}

		return p;
	}

	private static GraphicsConfiguration getGraphicsConfigurationForPoint(Point p) {
		GraphicsEnvironment ge = GraphicsEnvironment.getLocalGraphicsEnvironment();
		GraphicsDevice[] gd = ge.getScreenDevices();
		GraphicsConfiguration gc = null;
		for (GraphicsDevice element : gd) {
			if (element.getType() == GraphicsDevice.TYPE_RASTER_SCREEN) {
				GraphicsConfiguration dgc = element.getDefaultConfiguration();
				if (dgc.getBounds().contains(p)) {
					return dgc;
				}
			}
		}
		return gc;
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
	 * the window hierarchy.
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

}
