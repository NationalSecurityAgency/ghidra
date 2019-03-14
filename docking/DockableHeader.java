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
package docking;

import java.awt.*;
import java.awt.dnd.*;
import java.awt.event.InputEvent;
import java.awt.event.MouseListener;
import java.awt.image.BufferedImage;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JFrame;
import javax.swing.SwingUtilities;

import org.jdesktop.animation.timing.Animator;

import docking.help.Help;
import docking.help.HelpService;
import docking.util.AnimationUtils;
import generic.util.WindowUtilities;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;

/**
 * Component for providing component titles and toolbar. Also provides Drag
 * source functionality.
 */
public class DockableHeader extends GenericHeader
		implements DragGestureListener, DragSourceListener {

	private DockableComponent dockComp;
	private static Cursor leftCursor;
	private static Cursor rightCursor;
	private static Cursor topCursor;
	private static Cursor bottomCursor;
	private static Cursor stackCursor;
	private static Cursor newWindowCursor;
	private static Cursor noDropCursor = DragSource.DefaultMoveNoDrop;

	static {
		Toolkit tk = Toolkit.getDefaultToolkit();

		BufferedImage image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		drawLeftArrow(image);
		leftCursor = tk.createCustomCursor(image, new Point(0, 6), "LEFT");

		image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		drawRightArrow(image);
		rightCursor = tk.createCustomCursor(image, new Point(31, 6), "RIGHT");

		image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		drawTopArrow(image);
		topCursor = tk.createCustomCursor(image, new Point(6, 0), "TOP");

		image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		drawBottomArrow(image);
		bottomCursor = tk.createCustomCursor(image, new Point(6, 31), "BOTTOM");

		image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		drawStack(image);
		stackCursor = tk.createCustomCursor(image, new Point(8, 8), "STACK");

		image = new BufferedImage(32, 32, BufferedImage.TYPE_INT_ARGB);
		drawNewWindow(image);
		newWindowCursor = tk.createCustomCursor(image, new Point(0, 0), "NEW_WINDOW");
	}

	private DragCursorManager dragCursorManager = createDragCursorManager();
	private DragSource dragSource = null;
	private boolean isDocking;

	private Animator focusAnimator;
	private int focusToggle = -1;

	/**
	 * Constructs a new DockableHeader for the given dockableComponent.
	 * 
	 * @param dockableComp
	 *            the dockableComponent that this header is for.
	 */
	DockableHeader(DockableComponent dockableComp, boolean isDocking) {
		this.dockComp = dockableComp;
		this.isDocking = isDocking;

		setComponent(dockableComp);

		dragSource = new DragSource();

		ComponentPlaceholder info = dockableComp.getComponentWindowingPlaceholder();

		setTitle(info.getFullTitle());
		setIcon(info.getIcon());

		toolBarMgr = new DockableToolBarManager(dockableComp, this);

		dragSource.createDefaultDragGestureRecognizer(titlePanel.getDragComponent(),
			DnDConstants.ACTION_MOVE, DockableHeader.this);

		resetComponents();
	}

	@Override
	// overridden to use our DockableComponent
	public void requestFocus() {
		validateFocusability();
		dockComp.requestFocus();
	}

	@Override
	public void setSelected(boolean hasFocus) {
		if (!hasFocus) {
			if (focusAnimator != null) {
				focusAnimator.stop();
				focusAnimator = null;
			}
		}

		super.setSelected(hasFocus);
	}

	void installRenameAction(MouseListener listener) {
		titlePanel.installRenameAction(listener);
	}

	void setHelp(HelpLocation location) {
		HelpService service = Help.getHelpService();
		if (location == null) {
			service.clearHelp(titlePanel);
		}
		else {
			service.registerHelp(titlePanel, location);
		}
	}

	/**
	 * Signals to use the GUI to make this header (and its provider) stand out from the rest.
	 */
	void emphasize() {
		DockingWindowManager manager = DockingWindowManager.getInstance(this);
		if (manager == null) {
			return;
		}

		JFrame toolFrame = manager.getRootFrame();
		Component glassPane = toolFrame.getGlassPane();
		if (!(glassPane instanceof GGlassPane)) {
			return;
		}

		if (focusAnimator != null && focusAnimator.isRunning()) {
			// prevent multiple animation
			return;
		}

		focusAnimator = createEmphasizingAnimator(toolFrame);
	}

	protected Animator createEmphasizingAnimator(JFrame parentFrame) {
		focusToggle += 1;
		switch (focusToggle) {
			case 0:
				return AnimationUtils.shakeComponent(component);
			case 1:
				return AnimationUtils.rotateComponent(component);
			case 2:
				return raiseComponent(parentFrame);
			default:
				focusToggle = -1;
				return AnimationUtils.pulseComponent(component);
		}
	}

	private Animator raiseComponent(JFrame parent) {
		if (isOnlyComponentInParent(parent)) {
			return super.createEmphasizingAnimator();
		}
		return AnimationUtils.focusComponent(component);
	}

	private boolean isOnlyComponentInParent(JFrame parentFrame) {
		return !isInSplitPanel(); // no split parent means a single component in the window
	}

	private boolean isInSplitPanel() {
		Container parent = component.getParent();
		while (parent != null && !(parent instanceof SplitPanel)) {
			parent = parent.getParent();
		}

		return (parent instanceof SplitPanel);
	}

	private void validateFocusability() {
		Container focusCycleRootAncestor = dockComp.getFocusCycleRootAncestor();
		FocusTraversalPolicy policy = focusCycleRootAncestor.getFocusTraversalPolicy();
		Component firstComponent = policy.getFirstComponent(dockComp);
		if (firstComponent == null) {
			ComponentPlaceholder info = dockComp.getComponentWindowingPlaceholder();
			Msg.debug(this,
				"Found a ComponentProvider that does not contain a " + "focusable component: " +
					info.getTitle() + ".  ComponentProviders are " +
					"required to have at least one focusable component!");
			setSelected(false); // can't select it can't take focus
		}
	}

	@Override
	public void dragGestureRecognized(DragGestureEvent event) {
		if (!isDocking) {
			return;
		}
		// check input event: if any button other than MB1 is pressed,
		// don't attempt to process the drag and drop event.
		InputEvent ie = event.getTriggerEvent();
		int modifiers = ie.getModifiers();
		if ((modifiers & InputEvent.BUTTON2_MASK) != 0 ||
			(modifiers & InputEvent.BUTTON3_MASK) != 0) {
			return;
		}
		DockableComponent.DROP_CODE = DockableComponent.DropCode.WINDOW;
		DockableComponent.DROP_CODE_SET = true;
		DockableComponent.SOURCE_INFO = dockComp.getComponentWindowingPlaceholder();

		dragCursorManager.dragStarted();

		dragSource.startDrag(event, DragSource.DefaultMoveNoDrop,
			new ComponentTransferable(new ComponentTransferableData(dockComp)), this);
	}

	@Override
	public void dragDropEnd(DragSourceDropEvent event) {
		dragCursorManager.restoreCursorOnPreviousDraggedOverComponent();
		dragCursorManager.dragEnded();

		ComponentPlaceholder info = dockComp.getComponentWindowingPlaceholder();
		DockingWindowManager winMgr = info.getNode().winMgr;
		if (DockableComponent.DROP_CODE == DockableComponent.DropCode.INVALID) {
			return;
		}

// TODO	- Mac doesn't get the drop success correct when undocking a component (dragging out of
//		  the Java app
//		else if ( !event.getDropSuccess() ) {
//		    return;
//		}
//		else
		if (DockableComponent.DROP_CODE == DockableComponent.DropCode.WINDOW) {
			winMgr.movePlaceholder(info, event.getLocation());
		}
		else {
			winMgr.movePlaceholder(info, DockableComponent.TARGET_INFO, getWindowPosition());
		}
	}

	private WindowPosition getWindowPosition() {
		switch (DockableComponent.DROP_CODE) {
			case BOTTOM:
				return WindowPosition.BOTTOM;
			case LEFT:
				return WindowPosition.LEFT;
			case RIGHT:
				return WindowPosition.RIGHT;
			case STACK:
				return WindowPosition.STACK;
			case TOP:
				return WindowPosition.TOP;
			default:
				return WindowPosition.STACK;
		}
	}

	@Override
	public void dragEnter(DragSourceDragEvent event) {
		setCursor(event);
	}

	@Override
	public void dragExit(DragSourceEvent event) {
		setCursor(event);
	}

	@Override
	public void dragOver(DragSourceDragEvent event) {
		setCursor(event);
	}

	/**
	 * Sets the drag/drop cursor based on the current drop code.
	 * 
	 * @param event the event containing the drag source context on which to set the cursor.
	 */
	private void setCursor(DragSourceEvent event) {
		// TODO not sure why we needed this mechanic.  It is wrong on the Mac.  What is the use case?		
//		if (!DockableComponent.DROP_CODE_SET) {
//			return;
//		}

		DockableComponent.DROP_CODE_SET = false;
		Cursor c = noDropCursor;
		switch (DockableComponent.DROP_CODE) {
			case LEFT:
				c = leftCursor;
				break;
			case RIGHT:
				c = rightCursor;
				break;
			case TOP:
				c = topCursor;
				break;
			case BOTTOM:
				c = bottomCursor;
				break;
			case STACK:
				c = stackCursor;
				break;
			case ROOT:
				c = stackCursor;
				break;
			case WINDOW:
				c = newWindowCursor;
				break;
			case INVALID:
				break;

		}

		dragCursorManager.setCursor(event, c);
	}

	@Override
	public void dropActionChanged(DragSourceDragEvent event) {
		// don't care
	}

	private DragCursorManager createDragCursorManager() {
		if (Platform.CURRENT_PLATFORM.getOperatingSystem() == OperatingSystem.MAC_OS_X) {
			return new MacDragCursorManager();
		}
		return new DragCursorManager();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class DragCursorManager {

		void setCursor(DragSourceEvent event, Cursor dragCursor) {
			DragSourceContext context = event.getDragSourceContext();
			context.setCursor(dragCursor); // use Java's normal mechanism
		}

		void dragStarted() {
			// no-op; dummy implementation
		}

		void dragEnded() {
			// no-op; dummy implementation
		}

		void restoreCursorOnPreviousDraggedOverComponent() {
			// no-op; dummy implementation
		}
	}

	private class MacDragCursorManager extends DragCursorManager {

		private Map<Component, Cursor> defaultCursors = new HashMap<>();
		private Component componentUnderDrag;

		@Override
		void setCursor(DragSourceEvent event, Cursor dragCursor) {
			ComponentPlaceholder placeholder = DockableComponent.DRAGGED_OVER_INFO;

			Component mousedComponent = null;
			if (placeholder == null) {
				// Must not be over any component; This can happen when over a split pane 
				// resize area or outside of the window
				super.setCursor(event, dragCursor);
				return;
			}

			int x = event.getX();
			int y = event.getY();
			Point screenPoint = new Point(x, y);

			DockableComponent draggedOverComponent = placeholder.getComponent();
			SwingUtilities.convertPointFromScreen(screenPoint, draggedOverComponent);
			Component hoveredComponent = SwingUtilities.getDeepestComponentAt(draggedOverComponent,
				screenPoint.x, screenPoint.y);

			mousedComponent = hoveredComponent;
			if (mousedComponent == null) {
				mousedComponent = placeholder.getComponent();
			}

			if (componentUnderDrag != mousedComponent) {
				restoreCursorOnPreviousDraggedOverComponent();
			}

			componentUnderDrag = mousedComponent;
			mousedComponent.setCursor(dragCursor);

			// also do the preferred thing, in case they ever fix this on the Mac
			super.setCursor(event, dragCursor);
		}

		@Override
		void restoreCursorOnPreviousDraggedOverComponent() {
			if (componentUnderDrag == null) {
				return;
			}

			Cursor restoreCursor = defaultCursors.get(componentUnderDrag);
			Window window = WindowUtilities.windowForComponent(componentUnderDrag);
			if (window != null) { // We've seen this happen when docking/undocking windows
				Cursor windowCursor = defaultCursors.get(window);
				window.setCursor(windowCursor);
			}

			componentUnderDrag.setCursor(restoreCursor);
			componentUnderDrag = null;
		}

		@Override
		void dragStarted() {

			defaultCursors.clear();

			Window[] windows = Window.getWindows();
			for (Window window : windows) {
				storeCursors(window);
			}
		}

		private void storeCursors(Container c) {
			defaultCursors.put(c, c.getCursor());
			Component[] children = c.getComponents();
			for (Component child : children) {
				if (child instanceof Container) {
					storeCursors((Container) child);
				}
			}
		}

		@Override
		void dragEnded() {
			defaultCursors.clear();
		}
	}

//==================================================================================================
// Static Methods
//==================================================================================================

	/**
	 * Draws the left arrow cursor image.
	 * 
	 * @param image the image object to draw into.
	 */
	private static void drawLeftArrow(BufferedImage image) {
		int v = 0xff000000;
		int y = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(i, y - i + j, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(i, y - 1 + j, v);
			}
		}
	}

	/**
	 * Draws the right arrow cursor image.
	 * 
	 * @param image the image object to draw into.
	 */
	private static void drawRightArrow(BufferedImage image) {
		int v = 0xff000000;
		int y = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(31 - i, y - i + j, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(31 - i, y - 1 + j, v);
			}
		}
	}

	/**
	 * Draws the up arrow cursor image.
	 * 
	 * @param image the image object to draw into.
	 */
	private static void drawTopArrow(BufferedImage image) {
		int v = 0xff000000;
		int x = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(x - i + j, i, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(x - 1 + j, i, v);
			}
		}
	}

	/**
	 * Draws the down arrow cursor image.
	 * 
	 * @param image the image object to draw into.
	 */
	private static void drawBottomArrow(BufferedImage image) {
		int v = 0xff000000;
		int x = 6;
		for (int i = 0; i < 6; i++) {
			for (int j = 0; j < 2 * i + 1; j++) {
				image.setRGB(x - i + j, 31 - i, v);
			}
		}
		for (int i = 6; i < 12; i++) {
			for (int j = 0; j < 3; j++) {
				image.setRGB(x - 1 + j, 31 - i, v);
			}
		}
	}

	/**
	 * Draws the stack cursor image.
	 * 
	 * @param image the image object to draw into.
	 */
	private static void drawStack(BufferedImage image) {
		int v = 0xff000000;
		for (int i = 0; i < 3; i++) {
			int x = i * 3;
			int y = 6 - i * 3;
			for (int j = 0; j < 10; j++) {
				image.setRGB(x, y + j, v);
				image.setRGB(x + 10, y + j, v);
				image.setRGB(x + j, y, v);
				image.setRGB(x + j, y + 10, v);
			}

		}
	}

	/**
	 * Draws the "new window" cursor image.
	 * 
	 * @param image the image object to draw into.
	 */
	private static void drawNewWindow(BufferedImage image) {
		int v = 0xff000000;
		for (int i = 0; i < 5; i++) {
			for (int j = 0; j < 14; j++) {
				image.setRGB(j, i, 0xff0000ff);
			}
		}
		for (int i = 0; i < 14; i++) {
			image.setRGB(i, 0, v);
			image.setRGB(i, 10, v);
		}
		for (int i = 0; i < 10; i++) {
			image.setRGB(0, i, v);
			image.setRGB(14, i, v);
		}
	}
}
