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

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.JPopupMenu;

import docking.action.*;
import docking.menu.*;

public class PopupActionManager implements PropertyChangeListener {
	private List<DockingActionIf> popupActions = new ArrayList<DockingActionIf>();
	private DockingWindowManager windowManager;
	private MenuGroupMap menuGroupMap;

	public PopupActionManager(DockingWindowManager windowManager, MenuGroupMap menuGroupMap) {
		this.windowManager = windowManager;
		this.menuGroupMap = menuGroupMap;
	}

	public void addAction(DockingActionIf action) {
		action.addPropertyChangeListener(this);
		if (action.getPopupMenuData() != null) {
			popupActions.add(action);
		}
	}

	public void removeAction(DockingActionIf action) {
		action.removePropertyChangeListener(this);
		popupActions.remove(action);
	}

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		String propertyName = evt.getPropertyName();
		if (DockingActionIf.POPUP_MENU_DATA_PROPERTY.equals(propertyName)) {
			MenuData oldData = (MenuData) evt.getOldValue();
			MenuData newData = (MenuData) evt.getNewValue();
			if (isAddingToPopup(oldData, newData)) {
				popupActions.add((DockingActionIf) evt.getSource());
			}

			if (isRemovingFromPopup(oldData, newData)) {
				popupActions.remove(evt.getSource());
			}

		}
	}

	void popupMenu(ComponentPlaceholder info, MouseEvent e) {
		if (e.isConsumed()) {
			return;
		}
		ComponentProvider popupProvider = info.getProvider();
		ActionContext actionContext = popupProvider.getActionContext(e);
		if (actionContext == null) {
			actionContext = new ActionContext();
		}

		actionContext.setSource(e.getSource());
		actionContext.setMouseEvent(e);

		MenuHandler popupMenuHandler = new PopupMenuHandler(windowManager, actionContext);

		MenuManager menuMgr =
			new MenuManager("Popup", '\0', null, true, popupMenuHandler, menuGroupMap);
		populatePopupMenuActions(info, actionContext, menuMgr);
		if (menuMgr.isEmpty()) {
			return;
		}

		// Popup menu if items are available
		JPopupMenu popupMenu = menuMgr.getPopupMenu();
		Component c = (Component) e.getSource();
		popupMenu.addPopupMenuListener(popupMenuHandler);
		popupMenu.show(c, e.getX(), e.getY());
	}

	private void populatePopupMenuActions(ComponentPlaceholder info,
			ActionContext actionContext, MenuManager menuMgr) {

		// Include unregistered actions 
		Object source = actionContext.getSourceObject();
		if (source instanceof DockingActionProviderIf) {
			DockingActionProviderIf actionProvider = (DockingActionProviderIf) source;
			List<DockingActionIf> dockingActions = actionProvider.getDockingActions(actionContext);
			for (DockingActionIf action : dockingActions) {
				MenuData popupMenuData = action.getPopupMenuData();
				if (popupMenuData != null && action.isValidContext(actionContext) &&
					action.isAddToPopup(actionContext)) {
					action.setEnabled(action.isEnabledForContext(actionContext));
					menuMgr.addAction(action);
				}
			}
		}

		// Include temporary actions
		List<DockingActionIf> tempActions = windowManager.getTemporaryPopupActions(actionContext);
		if (tempActions != null) {
			for (DockingActionIf action : tempActions) {
				MenuData popupMenuData = action.getPopupMenuData();
				if (popupMenuData != null && action.isValidContext(actionContext) &&
					action.isAddToPopup(actionContext)) {
					action.setEnabled(action.isEnabledForContext(actionContext));
					menuMgr.addAction(action);
				}
			}
		}

		// Include global actions
		Iterator<DockingActionIf> iter = popupActions.iterator();
		while (iter.hasNext()) {
			DockingActionIf action = iter.next();

			MenuData popupMenuData = action.getPopupMenuData();
			if (popupMenuData != null && action.isValidContext(actionContext) &&
				action.isAddToPopup(actionContext)) {
				
				boolean isEnabled = action.isEnabledForContext(actionContext);
				action.setEnabled(isEnabled);
				menuMgr.addAction(action);
			}
		}

		// Include local actions for focused component
		iter = info.getActions();
		while (iter.hasNext()) {
			DockingActionIf action = iter.next();
			if (action.getPopupMenuData() != null && action.isValidContext(actionContext) &&
				action.isAddToPopup(actionContext)) {
				action.setEnabled(action.isEnabledForContext(actionContext));
				menuMgr.addAction(action);
			}
		}
	}

	private boolean isRemovingFromPopup(MenuData oldData, MenuData newData) {
		return oldData != null && newData == null;
	}

	private boolean isAddingToPopup(MenuData oldData, MenuData newData) {
		return oldData == null && newData != null;
	}

	public void dispose() {
		popupActions.clear();
		windowManager = null;
	}
}
