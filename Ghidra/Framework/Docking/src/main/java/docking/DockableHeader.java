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
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

import org.jdesktop.animation.timing.Animator;
import org.jdesktop.animation.timing.Animator.RepeatBehavior;
import org.jdesktop.animation.timing.TimingTargetAdapter;
import org.jdesktop.animation.timing.interpolation.PropertySetter;

import docking.util.AnimationUtils;
import generic.theme.GIcon;
import generic.theme.GThemeDefaults.Colors.Palette;
import generic.util.WindowUtilities;
import generic.util.image.ImageUtils;
import ghidra.framework.OperatingSystem;
import ghidra.framework.Platform;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.bean.GGlassPane;
import ghidra.util.bean.GGlassPanePainter;
import help.Help;
import help.HelpService;

/**
 * Component for providing component titles and toolbar. Also provides Drag
 * source functionality.
 */
public class DockableHeader extends GenericHeader
		implements DragGestureListener, DragSourceListener, DragSourceMotionListener {

	private DockableComponent dockComp;

	private DragCursorManager dragCursorManager = createDragCursorManager();
	private DragSource dragSource = null;
	private boolean isDocking;

	private Animator focusAnimator;

	// drag-N-drop key modifiers flags
	private static boolean ALT_DOWN = false;
	private static boolean CTRL_DOWN = false;
	private static boolean SHIFT_DOWN = false;

	// FIXME: This is a WORKAROUND to guess if a drag-N-drop operation was
	// interrupted, by either a key press (ESC) or by another mouse button
	// clicked.  It will work only while over a drop zone.
	private static boolean confirmedDragExit = false;

	// This is to tell when a drag-N-drop was started by pulling a header.
	private static boolean draggingByHeader = false;

	/**
	 * Constructs a new DockableHeader for the given dockableComponent.
	 * 
	 * @param dockableComp the dockableComponent that this header is for.
	 * @param isDocking true means this widget can be dragged and docked by the user
	 */
	DockableHeader(DockableComponent dockableComp, boolean isDocking) {
		this.dockComp = dockableComp;
		this.isDocking = isDocking;

		setComponent(dockableComp);

		dragSource = new DragSource();

		ComponentPlaceholder info = dockableComp.getComponentWindowingPlaceholder();

		setTitle(info.getFullTitle());
		setIcon(info.getIcon());

		toolBarMgr.dispose(); // reset the default manager before we create our own
		toolBarMgr = new DockableToolBarManager(dockableComp, this);

		// A drag-N-drop operation can be directed with key modifiers.
		//
		// ACTION_MOVE: pressing CTRL triggers dragExit while over a drop zone,
		// but not pressing SHIFT (CTRL means "copy").
		//
		// ACTION_COPY: pressing SHIFT triggers dragExit while over a drop zone,
		// but not pressing CTRL (SHIFT means "move").
		//
		// ACTION_LINK: either CTRL or SHIFT trigger dragExit while over a drop
		// zone, but not pressing them together.  This helps to detect a toggle
		// switch kept pressed, while over a drop zone.
		//
		// With any of the above, pressing ALT shouldn't trigger dragExit while
		// over a drop zone.
		dragSource.createDefaultDragGestureRecognizer(titlePanel.getDragComponent(),
			DnDConstants.ACTION_MOVE, DockableHeader.this);

		dragSource.addDragSourceMotionListener(DockableHeader.this);

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

	@Override
	public void dispose() {
		if (focusAnimator != null) {
			focusAnimator.stop();
			focusAnimator = null;
		}
		super.dispose();
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

		double random = Math.random();
		int choices = 7;
		int value = (int) (choices * random);

		switch (value) {
			case 0:
				return AnimationUtils.shakeComponent(component);
			case 1:
				return AnimationUtils.rotateComponent(component);
			case 2:
				return AnimationUtils.pulseComponent(component);
			case 3:
				return AnimationUtils.showTheDragonOverComponent(component);
			case 4:
				return AnimationUtils.focusComponent(component);
			case 5:
				return emphasizeDockableComponent();
			default:
				return raiseComponent(parentFrame);
		}
	}

	private Animator emphasizeDockableComponent() {

		if (!AnimationUtils.isAnimationEnabled()) {
			return null;
		}

		ComponentPlaceholder placeholder = dockComp.getComponentWindowingPlaceholder();
		ComponentNode node = placeholder.getNode();
		WindowNode windowNode = node.getTopLevelNode();
		Set<ComponentNode> componentNodes = new HashSet<>();
		getComponents(windowNode, componentNodes);

		//@formatter:off
		Set<Component> components = componentNodes.stream()
			  .map(cn -> cn.getComponent())
			  .filter(c -> c != null)
			  .filter(c -> !SwingUtilities.isDescendingFrom(component, c))
			  .collect(Collectors.toSet())
			  ;
		//@formatter:on

		components.remove(component);

		EmphasizeDockableComponentAnimationDriver driver =
			new EmphasizeDockableComponentAnimationDriver(component, components);
		return driver.animator;
	}

	private void getComponents(Node node, Set<ComponentNode> results) {

		List<Node> children = node.getChildren();
		for (Node child : children) {
			if (child instanceof ComponentNode) {
				results.add((ComponentNode) child);
			}
			else {
				getComponents(child, results);
			}
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
			String title = "";
			if (info != null) {
				title = ": Title: " + info.getTitle() + "";
			}
			Msg.debug(this,
				"Found a Component Provider that does not contain a focusable component" +
					title +
					". Component Providers are required to have at least one focusable component!");
			setSelected(false); // can't select it can't take focus
		}
	}

	@Override
	public void dragGestureRecognized(DragGestureEvent event) {
		if (!isDocking) {
			return;
		}

		// if any button other than MB1 is pressed, don't attempt to process the drag and drop event
		InputEvent ie = event.getTriggerEvent();
		int modifiers = ie.getModifiersEx();
		if ((modifiers & InputEvent.BUTTON2_DOWN_MASK) != 0 ||
			(modifiers & InputEvent.BUTTON3_DOWN_MASK) != 0) {
			return;
		}

		confirmedDragExit = false;
		DockableComponent.triggeredDragExit = false;

		ALT_DOWN = SHIFT_DOWN = CTRL_DOWN = false;

		// NOTE: When the drag-N-drop operation was started by pulling
		// a header, pressing ALT should mark the whole stack as group
		// of selected placeholders to be moved.
		draggingByHeader = this.isAncestorOf(event.getComponent());

		// NOTE: This is a remainder to assume an invalid drop action,
		// to prevent unexpected effects when voluntarily interrupting
		// a drag-N-drop operation while outside of a drop zone.
		DockableComponent.DROP_CODE = DropCode.INVALID;
		DockableComponent.DROP_CODE_SET = true;
		DockableComponent.DRAGGED_OVER_INFO = null;
		DockableComponent.SOURCE_SECTION_INFO = null;
		DockableComponent.SOURCE_INFO = dockComp.getComponentWindowingPlaceholder();

		// NOTE: Get the title from the source placeholder, and not of
		// the header.  This is to be consistent with tool tip updates
		// which use titles of placeholders.
		TransientWindow.showTransientWindow(DockableComponent.SOURCE_INFO.getTitle());

		dragCursorManager.dragStarted();

		dragSource.startDrag(event, DragSource.DefaultMoveNoDrop,
			new ComponentTransferable(new ComponentTransferableData(dockComp)), this);
	}

	@Override
	public void dragDropEnd(DragSourceDropEvent event) {
		dragCursorManager.restoreCursorOnPreviousDraggedOverComponent();
		dragCursorManager.dragEnded();

		TransientWindow.hideTransientWindow();

		// NOTE: This guesses a drag-N-drop voluntary interruption, by
		// either a key press (ESC) or by another mouse button clicked
		// while over a drop zone.  Only dragExit from DropTargetEvent
		// should had been triggered in this context.
		if (DockableComponent.triggeredDragExit != confirmedDragExit) {
			resetStackSection();
			return;
		}

		ComponentPlaceholder info = dockComp.getComponentWindowingPlaceholder();
		DockingWindowManager winMgr = info.getNode().winMgr;
		if (DockableComponent.DROP_CODE == DropCode.INVALID) {
			resetStackSection();
			return;
		}

// TODO	- Mac doesn't get the drop success correct when undocking a component (dragging out of
//		  the Java app
//		else if ( !event.getDropSuccess() ) {
//		    return;
//		}
//		else
		if (DockableComponent.DROP_CODE == DropCode.WINDOW) {
			if (ALT_DOWN) {
				winMgr.moveStackSection(DockableComponent.SOURCE_SECTION_INFO,
					info, event.getLocation());
			}
			else {
				winMgr.movePlaceholder(info, event.getLocation());
			}
		}
		else {
			if (ALT_DOWN) {
				winMgr.moveStackSection(DockableComponent.SOURCE_SECTION_INFO,
					info, DockableComponent.TARGET_INFO,
					DockableComponent.DROP_CODE.getWindowPosition());
			}
			else {
				winMgr.movePlaceholder(info, DockableComponent.TARGET_INFO,
					DockableComponent.DROP_CODE.getWindowPosition());
			}
		}

		resetStackSection();
	}

	@Override
	public void dragEnter(DragSourceDragEvent event) {
		setCursor(event);
		confirmedDragExit = false;
	}

	@Override
	public void dragExit(DragSourceEvent event) {
		setCursor(event);
		confirmedDragExit = true;
		if (ALT_DOWN) {
			if (isDraggingByHeader()) {
				setStackSection(DockableComponent.SOURCE_INFO.getNode(),
						DockableComponent.DRAGGED_OVER_INFO, SHIFT_DOWN);
			}
			else {
				setStackSection(DockableComponent.SOURCE_INFO,
					DockableComponent.DRAGGED_OVER_INFO, SHIFT_DOWN);
			}
		}
		else {
			setStackSection(DockableComponent.SOURCE_INFO);
		}
		highlightStackSection();
	}

	@Override
	public void dragOver(DragSourceDragEvent event) {
		setCursor(event);
		confirmedDragExit = false;
		if (ALT_DOWN) {
			if (isDraggingByHeader()) {
				setStackSection(DockableComponent.SOURCE_INFO.getNode(),
						DockableComponent.DRAGGED_OVER_INFO, SHIFT_DOWN);
			}
			else {
				setStackSection(DockableComponent.SOURCE_INFO,
					 DockableComponent.DRAGGED_OVER_INFO, SHIFT_DOWN);
			}
		}
		else {
			setStackSection(DockableComponent.SOURCE_INFO);
		}
		highlightStackSection();
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
		Cursor c = DockableComponent.DROP_CODE.getCursor();
		dragCursorManager.setCursor(event, c);
	}

	/**
	 * drag-N-drop ALT key modifier flag.
	 *
	 * @return TRUE is the key modifier is pressed, otherwise FALSE
	 */
	public static boolean isAltModifierDown() {
		return ALT_DOWN;
	}

	/**
	 * drag-N-drop CTRL key modifier flag.
	 *
	 * @return TRUE is the key modifier is pressed, otherwise FALSE
	 */
	public static boolean isCtrlModifierDown() {
		return CTRL_DOWN;
	}

	/**
	 * drag-N-drop SHIFT key modifier flag.
	 *
	 * @return TRUE is the key modifier is pressed, otherwise FALSE
	 */
	public static boolean isShiftModifierDown() {
		return SHIFT_DOWN;
	}

	/**
	 * Returns if the drag-N-drop was started by pulling a header.
	 *
	 * @return TRUE if the drag-n-drop was started by pulling a header
	 */
	public static boolean isDraggingByHeader() {
		return draggingByHeader;
	}

	/**
	 * Resets the current state of the stack section which was dragged
	 * around, removing the highlights from tabs.
	 */
	private static void resetStackSection() {
		DockableComponent.SOURCE_SECTION_INFO = null;
		highlightStackSection();
	}

	/**
	 * Repaints each tab to apply/remove highlights depending upon the
	 * current state of the stack section dragged around.
	 */
	private static void highlightStackSection() {

		// Get the source component.
		DockableComponent comp = DockableComponent.SOURCE_INFO.getComponent();

		// Loop over each tab of the tabbed pane associated
		// with the source component to process highlights.
		if (comp.getParent() instanceof JTabbedPane) {
			JTabbedPane tabbedPane = (JTabbedPane) comp.getParent();
			synchronized(tabbedPane.getTreeLock()) {
				for (Component c : tabbedPane.getComponents()) {
					if (c instanceof DockableComponent) {
						int tabIndex = tabbedPane.indexOfComponent(c);
						if (tabIndex != -1) {
							tabbedPane.getTabComponentAt(tabIndex).repaint();
						}
					}
				}
			}
		}
	}

	/**
	 * Updates the information about a multiple component selection as
	 * a stack section is dragged around.
	 *
	 * The selection starts from a source placeholder, and ends either
	 * with the first or last placeholder in the same window space, or
	 * before the destination placeholder if it's in the same stack of
	 * the source.
	 *
	 * @param source the placeholder from where the selection starts
	 * @param destination the placeholder with the mouse cursor over
	 * @param selectLeftSide if TRUE, select from the left of source
	 */
	private static void setStackSection(ComponentPlaceholder source,
			ComponentPlaceholder destination, boolean selectLeftSide) {

		// Collect the active placeholders found in
		// the source's stack.
		List<ComponentPlaceholder> placeholders = source.getNode().getActivePlaceholders();

		// Pre-process the stack's selection range.
		int infoIndex = placeholders.indexOf(source);

		// The hovered placeholder has index -1, if
		// in another window space than the source.
		// Otherwise, it could also be the index of
		// the currently focused placeholder, while
		// hovering the header or content space.
		int overIndex = placeholders.indexOf(destination);

		if (selectLeftSide) {
			// If the hovered placeholder is on the
			// same window space of the source, and
			// it's before it, the selection starts
			// after it.
			overIndex = overIndex < infoIndex ? overIndex + 1 : 0;

			// Section of placeholders found on the
			// left of the source placeholder.
			DockableComponent.SOURCE_SECTION_INFO = placeholders.subList(overIndex, infoIndex + 1);
		}
		else {
			// If the hovered placeholder is on the
			// same window space of the source, and
			// it is after it, the selection should
			// end before it.
			overIndex = overIndex > infoIndex ? overIndex : placeholders.size();

			// Section of placeholders found on the
			// right of the source placeholder.
			DockableComponent.SOURCE_SECTION_INFO = placeholders.subList(infoIndex, overIndex);
		}

		// Join each selected placeholder title, to
		// represent the stack section being moved.
		String infoText = DockableComponent.SOURCE_SECTION_INFO.stream()
				.map(p -> p.getTitle())
				.collect(Collectors.joining(" | "));

		// Update the transient tool tip text.
		TransientWindow.updateTransientWindow(infoText);
	}

	/**
	 * Updates the information about a multiple component selection as
	 * a whole stack is dragged around.
	 *
	 * While in the same window space, the selection should either end
	 * before the destination placeholder, if selecting from the first
	 * placeholder to the last on the right, or after it, if selecting
	 * from the last placeholder to the first on the left.
	 *
	 * @param sourceNode the source node, as a stack of placeholders
	 * @param destination the placeholder with the mouse cursor over
	 * @param invertDirection invert sorting, or selection direction
	 */
	private static void setStackSection(ComponentNode sourceNode,
			ComponentPlaceholder destination, boolean invertDirection) {

		// Collect the active placeholders found in
		// the source node.
		List<ComponentPlaceholder> placeholders = sourceNode.getActivePlaceholders();

		// Pre-process the stack's selection range.
		int infoIndex = (int) placeholders.stream()
			.takeWhile(p -> !p.getComponent().isVisible()).count();

		// The hovered placeholder has index -1, if
		// in another window space than the source.
		// Otherwise, it could also be the index of
		// the currently focused placeholder, while
		// hovering the header or content space.
		int overIndex = placeholders.indexOf(destination);

		// The hovered placeholder is in the source
		// window space, and it's not the currently
		// focused placeholder.
		if (overIndex != -1 && overIndex != infoIndex) {

			if (invertDirection) {
				// Section of placeholders from the
				// end to the placeholder after the
				// hovered placeholder, or just the
				// last placeholder.
				int end = placeholders.size();
				overIndex = (end - overIndex) > 1 ? overIndex : overIndex - 1;
				DockableComponent.SOURCE_SECTION_INFO = placeholders.subList(overIndex + 1, end);
			}
			else {
				// Section of placeholders from the
				// start, to the placeholder before
				// the hovered placeholder, or just
				// the first placeholder.
				overIndex = overIndex > 0 ? overIndex : overIndex + 1;
				DockableComponent.SOURCE_SECTION_INFO = placeholders.subList(0, overIndex);
			}
		}
		// The hovered placeholder has focus, or it
		// is from another window space.
		else if (invertDirection) {
			// Include all the source placeholders,
			// inverting the stack section sorting.
			DockableComponent.SOURCE_SECTION_INFO = placeholders.reversed();
		}
		else {
			// Include all the source placeholders.
			DockableComponent.SOURCE_SECTION_INFO = placeholders;
		}

		// Join each selected placeholder title, to
		// represent the stack section being moved.
		String infoText = DockableComponent.SOURCE_SECTION_INFO.stream()
				.map(p -> p.getTitle())
				.collect(Collectors.joining(" | "));

		// Update the transient tool tip text.
		TransientWindow.updateTransientWindow(infoText);
	}

	/**
	 * Updates the information about a multiple component selection as
	 * a single placeholder, part of a stack, is dragged around.
	 *
	 * @param source the placeholder dragged around, part of a stack
	 */
	private static void setStackSection(ComponentPlaceholder source) {
		DockableComponent.SOURCE_SECTION_INFO = new ArrayList<>(Arrays.asList(source));
		TransientWindow.updateTransientWindow(source.getTitle());
	}

	/**
	 * This is executed after a modifier is pressed or released.
	 */
	@Override
	public void dropActionChanged(DragSourceDragEvent event) {

		// Before determining the current state, reset all
		// key modifiers, and the default drop action too.
		ALT_DOWN = SHIFT_DOWN = CTRL_DOWN = false;
		DockableComponent.DROP_CODE = DropCode.INVALID;

		// Clear the stack section dragged around, and
		// reset all tabs highlights, while outside of
		// any drop zone.
		if (confirmedDragExit) {
			setStackSection(DockableComponent.SOURCE_INFO);
			highlightStackSection();
		}

		// Check if any key modifier is being pressed.
		int modifiers = event.getGestureModifiersEx();

		ALT_DOWN = ((modifiers & InputEvent.ALT_DOWN_MASK) != 0);
		CTRL_DOWN = ((modifiers & InputEvent.CTRL_DOWN_MASK) != 0);
		SHIFT_DOWN = ((modifiers & InputEvent.SHIFT_DOWN_MASK) != 0);

		if (ALT_DOWN && confirmedDragExit) {
			// Temporarily mark a stack section, of which a
			// placeholder is part of, as to be moved.
			if (draggingByHeader) {
				setStackSection(DockableComponent.SOURCE_INFO.getNode(),
						DockableComponent.DRAGGED_OVER_INFO, SHIFT_DOWN);
			}
			else {
				setStackSection(DockableComponent.SOURCE_INFO,
					DockableComponent.DRAGGED_OVER_INFO, SHIFT_DOWN);
			}
			// Highlight all tabs part of the stack section
			// and turn off the unselected.
			highlightStackSection();
		}
		// NOTE: While the ALT key is pressed, SHIFT should
		// indicate a right-to-left stack selection, from a
		// source placeholder.  In this context, it's not a
		// toggle to mark the drag-N-drop as invalid.
		else if (SHIFT_DOWN) {
			// Temporarily mark the drag-N-drop as invalid,
			// as an alternative to a sudden interruption.
			DockableComponent.DROP_CODE = DropCode.INVALID;
		}
		if (CTRL_DOWN) {
			// Temporarily mark the dragged component as to
			// be moved in a new window.  Releasing the key
			// press should revert to the default state.
			DockableComponent.DROP_CODE = DropCode.WINDOW;
		}

		// Force a mouse cursor update, needed while outside of
		// any drop zone, since no dragExit, Enter, Over should
		// take place.
		setCursor(event);
	}

	@Override
	public void dragMouseMoved(DragSourceDragEvent event) {
		TransientWindow.positionTransientWindow();
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

	public static class EmphasizeDockableComponentAnimationDriver {

		private Animator animator;
		private GGlassPane glassPane;
		private EmphasizeDockableComponentPainter rotatePainter;

		EmphasizeDockableComponentAnimationDriver(Component component, Set<Component> others) {

			glassPane = AnimationUtils.getGlassPane(component);
			rotatePainter = new EmphasizeDockableComponentPainter(component, others);

			double start = 0;
			double max = 1;
			int duration = 1000;
			animator = PropertySetter.createAnimator(duration, this, "percentComplete", start, max);

			animator.setAcceleration(0.2f);
			animator.setDeceleration(0.8f);

			animator.setRepeatCount(2);
			animator.setRepeatBehavior(RepeatBehavior.REVERSE);

			animator.addTarget(new TimingTargetAdapter() {
				@Override
				public void end() {
					done();
				}
			});

			glassPane.addPainter(rotatePainter);

			animator.start();
		}

		public void setPercentComplete(double percentComplete) {
			rotatePainter.setPercentComplete(percentComplete);
			glassPane.repaint();
		}

		void done() {
			glassPane.repaint();
			glassPane.removePainter(rotatePainter);
		}
	}

	private static class EmphasizeDockableComponentPainter implements GGlassPanePainter {

		private static final GIcon DRAGON_ICON = new GIcon("icon.dragon.256");
		private Set<ComponentPaintInfo> otherComponentInfos = new HashSet<>();
		private Image image;

		private Component component;
		private Rectangle cBounds;
		private double percentComplete = 0.0;

		EmphasizeDockableComponentPainter(Component component, Set<Component> otherComponents) {
			this.component = component;
			this.image = ImageUtils.createImage(component);

			for (Component otherComponent : otherComponents) {
				ComponentPaintInfo info = new ComponentPaintInfo(otherComponent);
				otherComponentInfos.add(info);
			}
		}

		private class ComponentPaintInfo {

			private Component myComponent;
			private Image myImage;

			ComponentPaintInfo(Component component) {
				this.myComponent = component;
				this.myImage = ImageUtils.createImage(component);
			}

			Image getImage() {
				return myImage;
			}

			Rectangle getRelativeBounds(Component other) {
				Rectangle r = myComponent.getBounds();
				return SwingUtilities.convertRectangle(myComponent.getParent(), r, other);
			}
		}

		void setPercentComplete(double percent) {
			percentComplete = percent;
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics g) {

			Graphics2D g2d = (Graphics2D) g;
			g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION,
				RenderingHints.VALUE_INTERPOLATION_BILINEAR);

			Color background = Palette.getColor("aliceblue");
			g.setColor(background);

			Rectangle othersBounds = null;
			for (ComponentPaintInfo info : otherComponentInfos) {

				Rectangle b = info.getRelativeBounds(glassPane);
				if (othersBounds == null) {
					othersBounds = b;
				}
				else {
					othersBounds.add(b);
				}
			}

			if (othersBounds == null) {
				// No other components in this window.  In this case, use the bounds of the 
				// active component.  This has the effect of showing the image behind the 
				// active component.
				Rectangle componentBounds = component.getBounds();
				componentBounds = SwingUtilities.convertRectangle(component.getParent(),
					componentBounds, glassPane);
				othersBounds = componentBounds;

				othersBounds = new Rectangle();
			}

			g2d.fillRect(othersBounds.x, othersBounds.y, othersBounds.width, othersBounds.height);

			Image ghidraImage = DRAGON_ICON.getImageIcon().getImage();

			double scale = percentComplete * 7;
			int gw = ghidraImage.getWidth(null);
			int gh = ghidraImage.getHeight(null);
			int w = (int) (gw * scale);
			int h = (int) (gh * scale);

			Rectangle gpBounds = glassPane.getBounds();
			double cx = gpBounds.getCenterX();
			double cy = gpBounds.getCenterY();
			int offsetX = (int) (cx - (w >> 1));
			int offsetY = (int) (cy - (h >> 1));

			Shape originalClip = g2d.getClip();
			if (!othersBounds.isEmpty()) {
				// restrict the icon to the 'others' area; otherwise, place it behind the provider
				g2d.setClip(othersBounds);
			}
			g2d.drawImage(ghidraImage, offsetX, offsetY, w, h, null);
			g2d.setClip(originalClip);

			paintOthers(glassPane, (Graphics2D) g, background);

			Rectangle b = component.getBounds();
			Point p = new Point(b.getLocation());
			p = SwingUtilities.convertPoint(component.getParent(), p, glassPane);

			g2d.setRenderingHints(new RenderingHints(null));
			g2d.drawImage(image, p.x, p.y, b.width, b.height, null);
		}

		private void paintOthers(GGlassPane glassPane, Graphics2D g2d, Color background) {

			if (cBounds == null) {
				cBounds = component.getBounds();
				cBounds =
					SwingUtilities.convertRectangle(component.getParent(), cBounds, glassPane);
			}

			double destinationX = cBounds.getCenterX();
			double destinationY = cBounds.getCenterY();

			g2d.setColor(background);
			for (ComponentPaintInfo info : otherComponentInfos) {

				Rectangle b = info.getRelativeBounds(glassPane);
				double scale = 1 - percentComplete;
				int w = (int) (b.width * scale);
				int h = (int) (b.height * scale);

				int offsetX = b.x - ((w - b.width) >> 1);
				int offsetY = b.y - ((h - b.height) >> 1);

				double deltaX = destinationX - offsetX;
				double deltaY = destinationY - offsetY;

				double moveX = percentComplete * deltaX;
				double moveY = percentComplete * deltaY;
				offsetX += moveX;
				offsetY += moveY;

				g2d.drawImage(info.getImage(), offsetX, offsetY, w, h, null);
			}
		}
	}

}
