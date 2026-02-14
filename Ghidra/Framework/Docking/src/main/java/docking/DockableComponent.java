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
import java.awt.event.*;
import java.util.List;

import javax.swing.*;

import org.apache.commons.lang3.ArrayUtils;

import docking.action.DockingActionIf;
import docking.widgets.tabbedpane.DockingTabRenderer;
import ghidra.util.*;
import help.HelpService;

/**
 * Wrapper class for user components. Adds the title, local toolbar and provides the drag target
 * functionality.
 */
public class DockableComponent extends JPanel implements ContainerListener {
	private static final int DROP_EDGE_OFFSET = 20;

	private static final Dimension MIN_DIM = new Dimension(100, 50);

	public static DropCode DROP_CODE;
	public static ComponentPlaceholder TARGET_INFO;
	public static ComponentPlaceholder DRAGGED_OVER_INFO;
	public static ComponentPlaceholder SOURCE_INFO;
	public static List<ComponentPlaceholder> SOURCE_SECTION_INFO;
	public static boolean DROP_CODE_SET;

	// FIXME: This is a WORKAROUND to guess if a drag-N-drop operation was
	// interrupted, by either a key press (ESC) or by another mouse button
	// clicked.  The caveat is its limit.  A voluntary interruption, while
	// the cursor is over a drop zone, would generate an uncommon dragExit
	// triggered by DropTargetEvent alone.  The catch is to confirm that a
	// DragSourceEvent did not trigger any dragExit counterpart, as it has
	// to happen when the cursor is moved outside of any drop zone.
	//
	// The motive of this workaround is that while a drag-N-drop operation
	// is in progress, its implementation might silence listening to other
	// events, except pressing the modifiers ALT, CTRL, and SHIFT, so that
	// pressing ESC isn't registered, and has to be determined indirectly,
	// to gracefully cancel the action in progress.
	public static boolean triggeredDragExit = false;

	private DockableHeader header;
	private MouseListener popupListener;
	private ComponentPlaceholder placeholder;
	private JComponent providerComp;
	private Component lastFocusedComponent;
	private DockingWindowManager winMgr;
	private ActionToGuiMapper actionMgr;
	private DropTarget dockableDropTarget;

	/**
	 * Constructs a new DockableComponent for the given info object.
	 * @param placeholder the info object that has the component to be shown.
	 * @param isDocking if true allows components to be dragged and docked.
	 */
	DockableComponent(ComponentPlaceholder placeholder, boolean isDocking) {
		if (placeholder != null) {
			this.placeholder = placeholder;

			winMgr = placeholder.getNode().winMgr;
			actionMgr = winMgr.getActionToGuiMapper();

			popupListener = new MouseAdapter() {
				@Override
				public void mousePressed(MouseEvent e) {
					componentSelected((Component) e.getSource());
					showContextMenu(e);
				}

				@Override
				public void mouseReleased(MouseEvent e) {
					showContextMenu(e);
				}

				@Override
				public void mouseClicked(MouseEvent e) {
					showContextMenu(e);
				}
			};

			dockableDropTarget = new DockableComponentDropTarget(this);
			initializeComponents(this);

			setLayout(new BorderLayout());
			header = new DockableHeader(this, isDocking);
			if (placeholder.isHeaderShowing()) {
				add(header, BorderLayout.NORTH);
			}

			// This is to register headers as drag-N-drop targets.
			// So that a DockableComponent could be dropped over a
			// header, in place of a placeholder's window surface.
			installDragDropTarget(header);

			providerComp = initializeComponentPlaceholder(placeholder);

			JPanel contentPanel = new JPanel(new BorderLayout());
			setFocusable(false); // this should never be focusable

			setFocusCycleRoot(false);
			contentPanel.add(providerComp, BorderLayout.CENTER);
			add(contentPanel, BorderLayout.CENTER);
		}
		else {
			dockableDropTarget = new DockableComponentDropTarget(this);
		}
	}

	private JComponent initializeComponentPlaceholder(ComponentPlaceholder newPlaceholder) {
		JComponent providerComponent = newPlaceholder.getProviderComponent();

		// Ensure that every provider component has a registered help location
		ComponentProvider provider = newPlaceholder.getProvider();
		HelpLocation helpLocation = provider.getHelpLocation();
		HelpLocation location = registerHelpLocation(provider, helpLocation);

		header.setHelp(location);

		return providerComponent;
	}

	public DockableHeader getHeader() {
		return header;
	}

	private HelpLocation registerHelpLocation(ComponentProvider provider,
			HelpLocation helpLocation) {
		HelpService helpService = DockingWindowManager.getHelpService();
		if (helpService.isExcludedFromHelp(provider)) {
			return null;
		}

		HelpLocation registeredHelpLocation = helpService.getHelpLocation(provider);
		if (registeredHelpLocation != null) {
			return registeredHelpLocation; // nothing to do; location already registered
		}

		if (helpLocation == null) {
			// this shouldn't happen, but just in case
			helpLocation = new HelpLocation(provider.getOwner(), provider.getName());
		}

		helpService.registerHelp(provider, helpLocation);
		return helpLocation;
	}

	void showContextMenu(PopupMenuContext popupContext) {
		actionMgr.showPopupMenu(placeholder, popupContext);
	}

	private void showContextMenu(MouseEvent e) {

		if (e.isConsumed()) {
			return;
		}

		if (!e.isPopupTrigger()) {
			return;
		}

		Component component = e.getComponent();
		if (component == null) {
			return; // not sure this can happen
		}

		// get the bounds to see if the clicked point is over the component
		Rectangle bounds = component.getBounds();
		if (component instanceof JComponent) {
			((JComponent) component).computeVisibleRect(bounds);
		}

		Point point = e.getPoint();
		if (!bounds.contains(point)) {
			return;
		}

		//
		// Consume the event so that Java UI listeners do not process it.  This fixes issues with
		// UI classes (e.g., listeners change table selection).   We want to run this code later to
		// allow trailing application mouse listeners to have a chance to update the context.  If
		// the delayed nature causes any timing issues, then we will need a more robust way of 
		// registering mouse listeners to work around this issue.
		//
		e.consume();
		Swing.runLater(() -> {

			MenuSelectionManager msm = MenuSelectionManager.defaultManager();
			MenuElement[] selectedPath = msm.getSelectedPath();
			if (!ArrayUtils.isEmpty(selectedPath)) {
				// This means that a menu is open.  This can happen if a mouse listener further down
				// the listener list has shown a popup.  In that case, do not show the context menu.
				return;
			}

			PopupMenuContext popupContext = new PopupMenuContext(e);
			actionMgr.showPopupMenu(placeholder, popupContext);
		});
	}

	@Override
	public Dimension getMinimumSize() {
		return MIN_DIM;
	}

	JComponent getProviderComponent() {
		return providerComp;
	}

	/**
	 * Returns the placeholder object associated with this DockableComponent
	 * @return the placeholder object associated with this DockableComponent
	 */
	public ComponentPlaceholder getComponentWindowingPlaceholder() {
		return placeholder;
	}

	/**
	 * Returns the component provider attached to this dockable component; null if this object
	 * has been disposed
	 *
	 * @return the provider
	 */
	public ComponentProvider getComponentProvider() {
		if (placeholder == null) {
			return null;
		}
		return placeholder.getProvider();
	}

	/**
	 * Returns the docking window manager that owns this component
	 * @return the manager
	 */
	public DockingWindowManager getDockingWindowManager() {
		if (placeholder == null) {
			return null;
		}
		return placeholder.getNode().getDockingWindowManager();
	}

	@Override
	public String toString() {
		if (placeholder == null) {
			return "";
		}
		return placeholder.getFullTitle();
	}

	private class DockableComponentDropTarget extends DropTarget {

		DockableComponentDropTarget(Component comp) {
			super(comp, null);
		}

		@Override
		public synchronized void drop(DropTargetDropEvent dtde) {
			clearAutoscroll();

			if (!dtde.isDataFlavorSupported(ComponentTransferable.localComponentProviderFlavor)) {
				dtde.rejectDrop();
				return;
			}

			Component dropTarget = ((DropTarget) dtde.getSource()).getComponent();
			setDropCode(dtde.getLocation(), dropTarget);

			if (DROP_CODE_SET) {
				TARGET_INFO = placeholder;
				dtde.acceptDrop(dtde.getDropAction());
				dtde.dropComplete(true);
				return;
			}

			dtde.rejectDrop();
		}

		@Override
		public synchronized void dragEnter(DropTargetDragEvent dtde) {
			super.dragEnter(dtde);

			triggeredDragExit = false;

			if (!dtde.isDataFlavorSupported(ComponentTransferable.localComponentProviderFlavor)) {
				dtde.rejectDrag();
				return;
			}

			Component dropTarget = ((DropTarget) dtde.getSource()).getComponent();
			setDropCode(dtde.getLocation(), dropTarget);

			if (DROP_CODE_SET) {
				DRAGGED_OVER_INFO = placeholder;
				dtde.acceptDrag(dtde.getDropAction());
				return;
			}

			dtde.rejectDrag();
		}

		@Override
		public synchronized void dragOver(DropTargetDragEvent dtde) {
			super.dragOver(dtde);

			triggeredDragExit = false;

			if (!dtde.isDataFlavorSupported(ComponentTransferable.localComponentProviderFlavor)) {
				dtde.rejectDrag();
				return;
			}

			Component dropTarget = ((DropTarget) dtde.getSource()).getComponent();
			setDropCode(dtde.getLocation(), dropTarget);

			if (DROP_CODE_SET) {
				DRAGGED_OVER_INFO = placeholder;
				dtde.acceptDrag(dtde.getDropAction());
				return;
			}

			dtde.rejectDrag();
		}

		@Override
		public synchronized void dragExit(DropTargetEvent dte) {
			super.dragExit(dte);
			triggeredDragExit = true;
			// FIXME: This is a WORKAROUND to allow the interruption of a drag-N-drop
			// operation while outside of a drop zone.  The drop should be considered
			// invalid, unless the CTRL key modifier is kept pressed.
			DROP_CODE = DockableHeader.isCtrlModifierDown() ? DropCode.WINDOW : DropCode.INVALID;
			DROP_CODE_SET = true;
			DRAGGED_OVER_INFO = null;
		}

	}

	public void installDragDropTarget(Component component) {
		new DockableComponentDropTarget(component);
	}

	private void initializeComponents(Component comp) {
		if (comp instanceof CellRendererPane) {
			return;
		}
		if (comp instanceof Container) {
			Container c = (Container) comp;
			c.addContainerListener(this);
			Component comps[] = c.getComponents();
			for (Component comp2 : comps) {
				initializeComponents(comp2);
			}
		}
		DropTarget dt = comp.getDropTarget();
		if (dt != null) {
			new CascadedDropTarget(comp, dockableDropTarget, dt);
		}

		if (comp.isFocusable()) {
			installPopupListenerFirst(comp);
		}
	}

	/**
	 * Remove and re-add all mouse listeners so our popup listener can go first.  This allows our
	 * popup listener to consume the event, preventing Java UI listeners from changing the table 
	 * selection when the user is performing a Ctrl-Mouse click on the Mac.
	 * 
	 * @param comp the component
	 */
	private void installPopupListenerFirst(Component comp) {
		comp.removeMouseListener(popupListener);
		MouseListener[] listeners = comp.getMouseListeners();
		for (MouseListener l : listeners) {
			comp.removeMouseListener(l);
		}

		comp.addMouseListener(popupListener);
		for (MouseListener l : listeners) {
			comp.addMouseListener(l);
		}
	}

	private void deinitializeComponents(Component comp) {
		if (comp instanceof CellRendererPane) {
			return;
		}
		if (comp instanceof Container) {
			Container c = (Container) comp;
			c.removeContainerListener(this);
			Component comps[] = c.getComponents();
			for (Component comp2 : comps) {
				deinitializeComponents(comp2);
			}
		}
		DropTarget dt = comp.getDropTarget();
		if (dt instanceof CascadedDropTarget) {
			CascadedDropTarget cascadedDropTarget = (CascadedDropTarget) dt;
			DropTarget newDropTarget = cascadedDropTarget.removeDropTarget(dockableDropTarget);
			comp.setDropTarget(newDropTarget);
		}
		comp.removeMouseListener(popupListener);
	}

	/**
	 * Translates the given point so that it is relative to the given component
	 */
	private void translate(Point p, Component c) {
		Point cLoc = c.getLocationOnScreen();
		Point myLoc = getLocationOnScreen();
		p.x = p.x + cLoc.x - myLoc.x;
		p.y = p.y + cLoc.y - myLoc.y;
	}

	/**
	 * Sets the drop code base on the cursor location.
	 * @param p the cursor location.
	 * @param c the drop target.
	 */
	private void setDropCode(Point p, Component c) {
		DROP_CODE_SET = true;

		// Pressing the CTRL key modifier takes precedence.  It is an override
		// to enable moving a dragged component in a new window.  This mode is
		// togglable and disabled by default as a prevention to an involuntary
		// action when a drag-N-drop operation is interrupted, by either a key
		// press (ESC), or by another mouse button clicked.
		if (DockableHeader.isCtrlModifierDown()) {
			DROP_CODE = DropCode.WINDOW;
			return;
		}

		// Pressing the SHIFT key modifier, temporarily invalidates the action
		// expected by a drag-N-drop operation in progress, unless the ALT key
		// is pressed.  Releasing the key should resume the normal processing.
		if (DockableHeader.isShiftModifierDown() && !DockableHeader.isAltModifierDown()) {
			DROP_CODE = DropCode.INVALID;
			return;
		}

		// Tabs of components that aren't currently showing, are valid targets
		// to drop a component on another which isn't showing its own content.
		if (c instanceof DockingTabRenderer) {
			if (SOURCE_INFO == placeholder) {
				// the cursor is over the same tab, just ignore this action
				DROP_CODE = DropCode.INVALID;
			}
			else if (SOURCE_INFO.getNode() != placeholder.getNode()	) {
				// push the component between others, in another window space
				DROP_CODE = DropCode.PUSH;
			}
			// After a drag had been started by pulling a header, and while in
			// the same window space, holding ALT would select all components,
			// either from the beginning or from the end of the stack.
			else if (DockableHeader.isDraggingByHeader() && DockableHeader.isAltModifierDown()) {
				// Holding SHIFT is to start the selection going from the last
				// to the first placeholder.  A group would be shifted left.
				if (DockableHeader.isShiftModifierDown()) {
					DROP_CODE = DropCode.SHIFT_LEFT;
				}
				// The selection starts with the first placeholder and goes to
				// the last.  A group would be shifted right.
				else {
					DROP_CODE = DropCode.SHIFT_RIGHT;
				}
				return;
			}
			else {
				// FIXME: assume that there is a tabbed pane
				JTabbedPane tabbedPane = (JTabbedPane) getParent();
				int target_index = tabbedPane.indexOfTabComponent(c);
				int source_index = tabbedPane.indexOfComponent(SOURCE_INFO.getComponent());
				if (target_index < source_index) {
					// shift the component to the left, in the same window space
					DROP_CODE = DropCode.SHIFT_LEFT;
				}
				else {
					// shift the component to the right, in the same window space
					DROP_CODE = DropCode.SHIFT_RIGHT;
				}
			}
			return;
		}

		// On Mac, sometimes this component is not showing,
		// which causes exception in the translate method.
		if (!isShowing()) {
			DROP_CODE_SET = false;
			return;
		}
		translate(p, c);

		if (placeholder == null) {
			DROP_CODE = DropCode.ROOT;
			return;
		}
		if (SOURCE_INFO == null) {
			DROP_CODE = DropCode.WINDOW;
			return;
		}
		if (SOURCE_INFO.getNode().winMgr != placeholder.getNode().winMgr) {
			DROP_CODE = DropCode.INVALID;
			return;
		}
		if (SOURCE_INFO == placeholder && !placeholder.isStacked()) {
			DROP_CODE = DropCode.INVALID;
			return;
		}
		else if (p.x < DROP_EDGE_OFFSET) {
			DROP_CODE = DropCode.LEFT;
		}
		else if (p.x > getWidth() - DROP_EDGE_OFFSET) {
			DROP_CODE = DropCode.RIGHT;
		}
		// Leave some space to drop over a header.  The TOP drop zone should be
		// just below the title bar (header).
		else if (p.y > DROP_EDGE_OFFSET && p.y < DROP_EDGE_OFFSET * 2) {
			DROP_CODE = DropCode.TOP;
		}
		else if (p.y > getHeight() - DROP_EDGE_OFFSET) {
			DROP_CODE = DropCode.BOTTOM;
		}
		// Dragging a component over a header, is a shortcut to prepend it as a
		// fist tab in the windows space that the mouse cursor is over.
		else if (c instanceof DockableHeader) {
			// place the component at the beginning of the target stack
			DROP_CODE = DropCode.PREPEND;
		}
		// Dragging a component over its own content space, in the same window,
		// is a shortcut to append it as a last tab.
		else if (SOURCE_INFO == placeholder) {
			// place the component at the end of the target stack
			DROP_CODE = DropCode.STACK;
		}
		else {
			DROP_CODE = DropCode.STACK;
		}
	}

	void setSelected(boolean selected) {
		header.setSelected(selected);
	}

	/**
	 * Signals to use the GUI to make this component stand out from the rest.
	 */
	void emphasize() {
		header.emphasize();
	}

	void setTitle(String title) {
		header.setTitle(title);
	}

	void setIcon(Icon icon) {
		header.setIcon(icon);
	}

	void dispose() {
		header.dispose();
		header = null;
		placeholder = null;
		providerComp = null;
		actionMgr = null;
	}

	/**
	 * Notifies the header that an action was added.
	 * @param action the action that was added.
	 */
	void actionAdded(DockingActionIf action) {
		header.actionAdded(action);
	}

	/**
	 * Notifies the header that an action was removed.
	 * @param action the action that was removed.
	 */
	void actionRemoved(DockingActionIf action) {
		header.actionRemoved(action);
	}

	@Override
	public void requestFocus() {
		if (lastFocusedComponent != null && lastFocusedComponent.isShowing()) {
			lastFocusedComponent.requestFocus();
			return;
		}

		if (placeholder == null) {
			return;	// this implies we have been disposed
		}
		placeholder.getProvider().requestFocus();
	}

	void setFocusedComponent(Component newFocusedComponet) {
		// remember it so we can restore it later when necessary
		lastFocusedComponent = newFocusedComponet;
	}

	private void componentSelected(Component component) {
		if (!component.isFocusable()) {
			// In this case, Java will not change focus for us, so we need to tell the DWM to
			// change the active DockableComponent
			requestFocus();
		}
	}

	@Override
	public void componentAdded(ContainerEvent e) {
		initializeComponents(e.getChild());
	}

	@Override
	public void componentRemoved(ContainerEvent e) {
		deinitializeComponents(e.getChild());
	}
}
