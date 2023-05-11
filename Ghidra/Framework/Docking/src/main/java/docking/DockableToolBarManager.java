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
import java.util.Collections;
import java.util.Iterator;

import javax.swing.*;

import docking.action.*;
import docking.menu.*;
import generic.theme.GColor;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;

/**
 * Manages to toolbar for the dockable components.
 */
class DockableToolBarManager {
	private static final Color BUTTON_COLOR = new GColor("color.fg.button");
	private static final Icon CLOSE_ICON = new CloseIcon(false, BUTTON_COLOR);
	private Icon MENU_ICON = new DropDownMenuIcon(BUTTON_COLOR);
	private GenericHeader dockableHeader;
	private ToolBarManager toolBarManager;

	private MenuGroupMap menuGroupMap;
	private MenuManager menuManager;
	private ToolBarItemManager menuButtonManager;
	private ToolBarItemManager closeButtonManager;

	private SwingUpdateManager headerUpdater =
		new SwingUpdateManager(() -> dockableHeader.update());
	private DockableComponent dockableComponent;

	DockableToolBarManager(GenericHeader header) {
		this.dockableHeader = header;
		menuButtonManager = new ToolBarItemManager(new ToolBarMenuAction(), null);
		initialize(null, null, Collections.emptyIterator());
	}

	/**
	 * Constructs a new DockableToolBarManger for the given ComponentInfo
	 * 
	 * @param dockableComponent the component to which this toolbar belongs
	 * @param header the header to which this toolbar belongs
	 */
	DockableToolBarManager(DockableComponent dockableComponent, DockableHeader header) {
		this.dockableComponent = dockableComponent;
		this.dockableHeader = header;
		ComponentPlaceholder placeholder = dockableComponent.getComponentWindowingPlaceholder();
		DockingWindowManager winMgr = dockableComponent.getDockingWindowManager();
		ActionToGuiMapper actionManager = winMgr.getActionToGuiMapper();
		menuGroupMap = actionManager.getMenuGroupMap();

		MenuHandler menuHandler = actionManager.getMenuHandler();
		Iterator<DockingActionIf> iter = placeholder.getActions();
		initialize(winMgr, menuHandler, iter);

		ComponentProvider provider = placeholder.getProvider();
		String owner = provider.getOwner();
		ToolBarCloseAction closeAction = new ToolBarCloseAction(owner);
		closeButtonManager = new ToolBarItemManager(closeAction, winMgr);

		ToolBarMenuAction dropDownAction = new ToolBarMenuAction(owner);
		menuButtonManager = new ToolBarItemManager(dropDownAction, winMgr);

		// we need to add this action to the tool in order to use key bindings
		Tool tool = winMgr.getTool();
		tool.addLocalAction(provider, closeAction);
		tool.addLocalAction(provider, dropDownAction);
	}

	private void initialize(DockingWindowManager winMgr, MenuHandler menuHandler,
			Iterator<DockingActionIf> actions) {
		toolBarManager = new ToolBarManager(winMgr);
		menuManager = new MenuManager(null, '\0', null, false, menuHandler, menuGroupMap);

		while (actions.hasNext()) {
			DockingActionIf action = actions.next();
			addAction(action);
		}
		updateToolBar();
	}

	/**
	 * Returns a new Panel populated with buttons.
	 * @return a component with toolbar buttons.
	 */
	JComponent getToolBar() {
		return toolBarManager.getToolBar();
	}

	JComponent getMenuCloseToolBar() {
		JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
		if (closeButtonManager == null) {
			return panel;
		}

		if (!toolBarManager.isEmpty()) {
			panel.add(DockingUtils.createToolbarSeparator());
		}
		if (!menuManager.isEmpty()) {
			panel.add(menuButtonManager.getButton());
		}

		panel.add(closeButtonManager.getButton());
		return panel;
	}

	/**
	 * Adds a new action to be added to the toolbar and/or drop-down menu.
	 * @param action the action to be added.
	 */
	void addAction(DockingActionIf action) {
		if (!SwingUtilities.isEventDispatchThread()) {
			throw new AssertException("Actions must be added from Swing thread");
		}
		if (action.getMenuBarData() != null) {
			menuManager.addAction(action);
		}
		if (action.getToolBarData() != null) {
			toolBarManager.addAction(action);
		}
		updateToolBar();
	}

	synchronized DockingActionIf getAction(String name) {
		DockingActionIf action = menuManager.getAction(name);
		if (action != null) {
			return action;
		}
		return toolBarManager.getAction(name);
	}

	/**
	 * Removes an action from the toolbar and/or drop-down menu.
	 * @param action the action to be removed.
	 */
	void removeAction(DockingActionIf action) {
		if (!SwingUtilities.isEventDispatchThread()) {
			throw new AssertException("Actions must be removed from Swing thread");
		}

		menuManager.removeAction(action);
		toolBarManager.removeAction(action);
		updateToolBar();
	}

	private void updateToolBar() {
		headerUpdater.update();
	}

	void dispose() {

		// this will be null for non-standard use cases
		if (dockableComponent != null) {
			DockingWindowManager dwm = dockableComponent.getDockingWindowManager();
			Tool tool = dwm.getTool();
			ComponentProvider provider = dockableComponent.getComponentProvider();
			tool.removeLocalAction(provider, closeButtonManager.getAction());
			tool.removeLocalAction(provider, menuButtonManager.getAction());
		}

		headerUpdater.dispose();
		menuManager.dispose();
		toolBarManager.dispose();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * Action added to toolbar for "hiding" the component.
	 */
	private class ToolBarCloseAction extends DockingAction {

		ToolBarCloseAction(String owner) {
			super("Close Window", owner, KeyBindingType.SHARED);
			setDescription("Close Window");
			setToolBarData(new ToolBarData(CLOSE_ICON, null));
			markHelpUnnecessary();
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ComponentPlaceholder placeholder = dockableComponent.getComponentWindowingPlaceholder();
			if (placeholder != null) {
				placeholder.close();
			}
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			ComponentProvider provider = context.getComponentProvider();
			return provider == dockableComponent.getComponentProvider();
		}
	}

	/**
	 * Actions added to toolbar for displaying the drop-down menu.
	 */
	private class ToolBarMenuAction extends DockingAction {

		private JButton myButton;

		/**
		 * Constructor for tool bars that are not part of standard component providers, such as
		 * those used when direct rendering.
		 */
		ToolBarMenuAction() {
			super("Local Menu", DockingWindowManager.DOCKING_WINDOWS_OWNER);
			setDescription("Menu");
			setToolBarData(new ToolBarData(MENU_ICON, null));
			markHelpUnnecessary();
		}

		/**
		 * Constructor for component providers
		 * @param owner the action owner, typically a plugin
		 */
		ToolBarMenuAction(String owner) {
			super("Local Menu", owner, KeyBindingType.SHARED);
			setDescription("Menu");
			setToolBarData(new ToolBarData(MENU_ICON, null));
			markHelpUnnecessary();
		}

		@Override
		protected JButton doCreateButton() {
			myButton = super.doCreateButton();
			return myButton;
		}

		@Override
		public void actionPerformed(ActionContext context) {
			Dimension d = myButton.getSize();
			JPopupMenu popupMenu = menuManager.getPopupMenu();
			popupMenu.addPopupMenuListener(menuManager.getMenuHandler());
			popupMenu.show(myButton, 0, d.height);
		}

		@Override
		public boolean isEnabledForContext(ActionContext context) {
			if (myButton == null) {
				return false; // no menu items; no drop-down menu
			}
			ComponentProvider provider = context.getComponentProvider();
			return provider == dockableComponent.getComponentProvider();
		}
	}
}
