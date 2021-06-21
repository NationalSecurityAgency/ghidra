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
import java.awt.Point;
import java.awt.event.MouseEvent;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.JPopupMenu;

import org.apache.commons.collections4.IteratorUtils;

import docking.action.*;
import docking.menu.*;

public class PopupActionManager implements PropertyChangeListener {
	private List<DockingActionIf> popupActions = new ArrayList<>();
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

	void popupMenu(ComponentPlaceholder placeholder, PopupMenuContext popupContext) {

		MouseEvent event = popupContext.getEvent();
		ComponentProvider popupProvider = placeholder.getProvider();
		ActionContext actionContext = popupProvider.getActionContext(event);
		if (actionContext == null) {
			actionContext = new ActionContext();
		}

		actionContext.setSourceObject(popupContext.getSource());
		actionContext.setMouseEvent(event);

		Iterator<DockingActionIf> localActions = placeholder.getActions();
		JPopupMenu popupMenu = createPopupMenu(localActions, actionContext);
		if (popupMenu == null) {
			return; // no matching actions
		}

		Component c = popupContext.getComponent();
		Point p = popupContext.getPoint();
		popupMenu.show(c, p.x, p.y);
	}

	protected JPopupMenu createPopupMenu(Iterator<DockingActionIf> localActions,
			ActionContext context) {

		if (localActions == null) {
			localActions = IteratorUtils.emptyIterator();
		}

		MenuHandler popupMenuHandler = new PopupMenuHandler(windowManager, context);
		MenuManager menuMgr =
			new MenuManager("Popup", '\0', null, true, popupMenuHandler, menuGroupMap);
		populatePopupMenuActions(localActions, context, menuMgr);
		if (menuMgr.isEmpty()) {
			return null;
		}

		// Popup menu if items are available
		JPopupMenu popupMenu = menuMgr.getPopupMenu();
		popupMenu.addPopupMenuListener(popupMenuHandler);
		return popupMenu;
	}

	void populatePopupMenuActions(Iterator<DockingActionIf> localActions,
			ActionContext actionContext, MenuManager menuMgr) {

		// Unregistered actions are those used by special-needs components, on-the-fly
		addUnregisteredActions(actionContext, menuMgr);

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
		while (localActions.hasNext()) {
			DockingActionIf action = localActions.next();
			if (action.getPopupMenuData() != null && action.isValidContext(actionContext) &&
				action.isAddToPopup(actionContext)) {
				action.setEnabled(action.isEnabledForContext(actionContext));
				menuMgr.addAction(action);
			}
		}
	}

	private void addUnregisteredActions(ActionContext actionContext, MenuManager menuMgr) {

		Object source = actionContext.getSourceObject();

		// this interface is deprecated in favor the code that calls this method; this will be deleted
		if (source instanceof DockingActionProviderIf) {
			DockingActionProviderIf actionProvider = (DockingActionProviderIf) source;
			List<DockingActionIf> dockingActions = actionProvider.getDockingActions();
			for (DockingActionIf action : dockingActions) {
				MenuData popupMenuData = action.getPopupMenuData();
				if (popupMenuData != null && action.isValidContext(actionContext) &&
					action.isAddToPopup(actionContext)) {
					action.setEnabled(action.isEnabledForContext(actionContext));
					menuMgr.addAction(action);
				}
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
