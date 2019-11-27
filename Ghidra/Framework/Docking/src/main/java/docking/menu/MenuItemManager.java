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
package docking.menu;

import java.awt.Component;
import java.awt.event.*;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;

import javax.swing.ButtonModel;
import javax.swing.JMenuItem;
import javax.swing.event.ChangeListener;

import docking.ActionContext;
import docking.action.*;
import ghidra.util.Msg;
import ghidra.util.StringUtilities;

/**
 * Class to manage a JMenuItem for an action.  Handles property changes in the action
 * and makes the corresponding change in the menuItem.
 */
class MenuItemManager implements ManagedMenuItem, PropertyChangeListener, ActionListener {

	private MenuHandler menuHandler;
	private DockingActionIf action;
	private boolean isPopup;
	private JMenuItem menuItem;

	// listeners to handle help activation
	// -this listener covers activation by keyboard and by mouse *when enabled*
	private ChangeListener buttonModelChangeListener;

	// -this listener covers activation by mouse *when the action is disabled*
	private MouseAdapter menuHoverListener;

	MenuItemManager(MenuHandler actionHandler, DockingActionIf dockingAction,
			boolean usePopupPath) {
		this.menuHandler = actionHandler;
		this.action = dockingAction;
		this.isPopup = usePopupPath;
		action.addPropertyChangeListener(this);

		buttonModelChangeListener = getButtonModelChangeListener();

		menuHoverListener = getMenuHoverListener();
	}

	private MouseAdapter getMenuHoverListener() {
		if (menuHandler == null) {
			return new MouseAdapter() {
				// dummy
			};
		}
		return new MouseAdapter() {
			@Override
			public void mouseEntered(MouseEvent e) {
				Component component = e.getComponent();
				if (!component.isEnabled()) {
					menuHandler.menuItemEntered(action);
				}
			}

			@Override
			public void mouseExited(MouseEvent e) {
				Component component = e.getComponent();
				if (!component.isEnabled()) {
					menuHandler.menuItemExited(action);
				}
			}
		};
	}

	private ChangeListener getButtonModelChangeListener() {
		if (menuHandler == null) {
			return e -> {
				// dummy
			};
		}
		return e -> {
			boolean isArmed = menuItem.isArmed();
			if (isArmed) {
				menuHandler.menuItemEntered(action);
			}
			else {
				menuHandler.menuItemExited(action);
			}
		};
	}

	@Override
	public String getGroup() {
		MenuData menuData = isPopup ? action.getPopupMenuData() : action.getMenuBarData();
		return menuData == null ? null : menuData.getMenuGroup();
	}

	@Override
	public String getSubGroup() {
		MenuData menuData = isPopup ? action.getPopupMenuData() : action.getMenuBarData();
		return menuData == null ? null : menuData.getMenuSubGroup();
	}

	@Override
	public void dispose() {
		if (action != null) {
			action.removePropertyChangeListener(this);
		}

		if (menuItem != null) {
			ButtonModel buttonModel = menuItem.getModel();
			buttonModel.removeChangeListener(buttonModelChangeListener);
			menuItem = null;
		}

		action = null;
	}

	@Override
	public JMenuItem getMenuItem() {
		if (menuItem != null) {
			return menuItem;
		}
		menuItem = action.createMenuItem(isPopup);
		menuItem.setEnabled(action.isEnabled());
		menuItem.addActionListener(this);

		// help activation listeners
		ButtonModel buttonModel = menuItem.getModel();
		buttonModel.addChangeListener(buttonModelChangeListener);
		menuItem.addMouseListener(menuHoverListener);

		return menuItem;
	}

	public String getOwner() {
		return action.getOwner();
	}

	@Override
	public void propertyChange(PropertyChangeEvent e) {
		if (menuItem == null) {
			return;
		}

		String name = e.getPropertyName();
		if (isPopup && name.equals(DockingActionIf.POPUP_MENU_DATA_PROPERTY)) {
			updateMenuItem();
		}
		else if (!isPopup && name.equals(DockingActionIf.MENUBAR_DATA_PROPERTY)) {
			updateMenuItem();
		}
		else if (name.equals(DockingActionIf.ENABLEMENT_PROPERTY)) {
			menuItem.setEnabled(((Boolean) e.getNewValue()).booleanValue());
			menuItem.repaint();
		}
		else if (name.equals(DockingActionIf.KEYBINDING_DATA_PROPERTY)) {
			KeyBindingData newData = (KeyBindingData) e.getNewValue();
			menuItem.setAccelerator(newData == null ? null : newData.getKeyBinding());
			menuItem.revalidate();
		}
		else if (name.equals(ToggleDockingActionIf.SELECTED_STATE_PROPERTY)) {
			menuItem.setSelected(((Boolean) e.getNewValue()).booleanValue());
			menuItem.revalidate();
		}
	}

	private void updateMenuItem() {
		MenuData menuData = isPopup ? action.getPopupMenuData() : action.getMenuBarData();
		if (menuData != null) {
			String text = menuData.getMenuItemName();
			String trimmed = StringUtilities.trimMiddle(text, 50);
			menuItem.setText(trimmed);
			menuItem.setIcon(menuData.getMenuIcon());
			menuItem.setMnemonic(menuData.getMnemonic());
			menuItem.revalidate();
		}
	}

	public DockingActionIf getAction() {
		return action;
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (menuHandler != null) {
			menuHandler.processMenuAction(action, e);
			return;
		}

		try {
			ActionContext context = new ActionContext();
			context.setSourceObject(e.getSource());
			if (action.isEnabledForContext(context)) {
				if (action instanceof ToggleDockingActionIf) {
					ToggleDockingActionIf toggleAction = ((ToggleDockingActionIf) action);
					toggleAction.setSelected(!toggleAction.isSelected());
				}
				action.actionPerformed(context);
			}
		}
		catch (Throwable t) {
			Msg.error(this, "Unexpected Exception: " + t.getMessage(), t);
		}
	}

	@Override
	public String toString() {
		return action.getName();
	}

	@Override
	public String getMenuItemText() {
		MenuData menuData = isPopup ? action.getPopupMenuData() : action.getMenuBarData();
		return menuData.getMenuItemName();
	}

	@Override
	public boolean isEmpty() {
		return action == null;
	}

	@Override
	public boolean removeAction(DockingActionIf actionToRemove) {
		if (actionToRemove == action) {
			dispose();
			return true;
		}
		return false;
	}
}
