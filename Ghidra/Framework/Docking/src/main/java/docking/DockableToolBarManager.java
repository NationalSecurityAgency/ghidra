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

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.util.ArrayList;
import java.util.Iterator;

import javax.swing.*;

import docking.action.*;
import docking.menu.*;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;
import resources.ResourceManager;

/**
 * Manages to toolbar for the dockable components.
 */
class DockableToolBarManager {
	private static final ImageIcon closeIcon = ResourceManager.loadImage("images/close16.gif");
	private static final ImageIcon menuIcon = ResourceManager.loadImage("images/menu16.gif");

	private GenericHeader dockableHeader;
	private ToolBarManager toolBarManager;

	private MenuGroupMap menuGroupMap;
	private MenuManager menuManager;
	private ToolBarItemManager menuButtonManager;
	private ToolBarItemManager closeButtonManager;

	private SwingUpdateManager headerUpdater =
		new SwingUpdateManager(() -> dockableHeader.update());

	DockableToolBarManager(GenericHeader header) {
		this.dockableHeader = header;
		initialize(null, null, new ArrayList<DockingActionIf>().iterator());
	}

	/**
	 * Constructs a new DockableToolBarManger for the given ComponentInfo.
	 * @param info the componentInfo object containing the component.
	 */
	DockableToolBarManager(DockableComponent dockableComp, DockableHeader header) {
		this.dockableHeader = header;
		ComponentPlaceholder placeholder = dockableComp.getComponentWindowingPlaceholder();
		DockingWindowManager winMgr =
			dockableComp.getComponentWindowingPlaceholder().getNode().winMgr;
		DockingActionManager actionManager = winMgr.getActionManager();
		menuGroupMap = actionManager.getMenuGroupMap();

		MenuHandler menuHandler = actionManager.getMenuHandler();
		Iterator<DockingActionIf> iter = placeholder.getActions();
		initialize(winMgr, menuHandler, iter);

		closeButtonManager = new ToolBarItemManager(new ToolBarCloseAction(dockableComp), winMgr);
	}

	private void initialize(DockingWindowManager winMgr, MenuHandler menuHandler,
			Iterator<DockingActionIf> actions) {
		toolBarManager = new ToolBarManager(winMgr);
		menuManager = new MenuManager(null, '\0', null, false, menuHandler, menuGroupMap);
		menuButtonManager = new ToolBarItemManager(new ToolBarMenuAction(), winMgr);

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
		private DockableComponent dockableComponent;

		ToolBarCloseAction(DockableComponent dockableComponent) {
			super("Close Window", DockingWindowManager.DOCKING_WINDOWS_OWNER);
			this.dockableComponent = dockableComponent;
			setDescription("Close Window");
			setToolBarData(new ToolBarData(closeIcon, null));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			ComponentPlaceholder placeholder = dockableComponent.getComponentWindowingPlaceholder();
			if (placeholder != null) {
				placeholder.close();
			}
		}
	}

	/**
	 * Actions added to toolbar for displaying the drop-down menu.
	 */
	private class ToolBarMenuAction extends DockingAction {

		ToolBarMenuAction() {
			super("Local Menu", DockingWindowManager.DOCKING_WINDOWS_OWNER);
			setDescription("Menu");
			setToolBarData(new ToolBarData(menuIcon, null));
		}

		@Override
		public void actionPerformed(ActionContext context) {
			JComponent src = (JComponent) context.getSourceObject();
			Dimension d = src.getSize();
			JPopupMenu popupMenu = menuManager.getPopupMenu();
			popupMenu.addPopupMenuListener(menuManager.getMenuHandler());
			popupMenu.show(src, 0, d.height);
		}
	}
}
