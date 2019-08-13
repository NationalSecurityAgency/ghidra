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
import java.awt.event.ActionEvent;
import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.JPopupMenu;
import javax.swing.SwingUtilities;

import docking.action.*;
import docking.menu.*;

public class DialogComponentProviderPopupActionManager {

	private List<DockingActionIf> popupActions = new ArrayList<>();
	private DialogComponentProvider provider;

	public DialogComponentProviderPopupActionManager(DialogComponentProvider provider) {
		this.provider = provider;
	}

	void addAction(DockingActionIf action) {
		MenuData popupMenuData = action.getPopupMenuData();
		if (popupMenuData == null) {
			return;
		}

		popupActions.add(action);
	}

	void popupMenu(ActionContext actionContext, MouseEvent e) {
		if (e.isConsumed()) {
			return;
		}

		if (actionContext == null) {
			actionContext = new ActionContext();
		}

		// If the source is null, must set it or we won't have 
		// any popups shown.
		if (actionContext.getSourceObject() == null) {
			actionContext.setSourceObject(e.getSource());
		}

		MenuHandler popupMenuHandler = new PopupMenuHandler(actionContext);

		DockingWindowManager dwm = DockingWindowManager.getInstance(provider.getComponent());
		if (dwm == null) {
			// This is rare, but can happen if there is no initialized application, which would 
			// happen if client code triggers the showing of a DialogComponentProvider before
			// any tools are shown.
			return;
		}

		ActionToGuiMapper actionManager = dwm.getActionToGuiMapper();
		MenuGroupMap menuGroupMap = actionManager.getMenuGroupMap();
		MenuManager menuMgr =
			new MenuManager("Popup", '\0', null, true, popupMenuHandler, menuGroupMap);
		populatePopupMenuActions(dwm, menuMgr, actionContext);
		if (menuMgr.isEmpty()) {
			return;
		}

		// Popup menu if items are available
		JPopupMenu popupMenu = menuMgr.getPopupMenu();
		Component c = (Component) e.getSource();
		popupMenu.addPopupMenuListener(popupMenuHandler);
		popupMenu.show(c, e.getX(), e.getY());
	}

	private void populatePopupMenuActions(DockingWindowManager dwm, MenuManager menuMgr,
			ActionContext actionContext) {

		// This is a bit of a kludge, but allows us to get generic actions, like 'copy' for
		// tables.  This can go away if we ever convert DialogComponentProviders to use the
		// primary action system (this was something we were going to do once).  If that happens, 
		// then this entire class goes away.
		ActionToGuiMapper actionManager = dwm.getActionToGuiMapper();
		PopupActionManager toolPopupManager = actionManager.getPopupActionManager();
		Iterator<DockingActionIf> localActions = popupActions.iterator();
		toolPopupManager.populatePopupMenuActions(localActions, actionContext, menuMgr);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class PopupMenuHandler extends MenuHandler {
		private final ActionContext actionContext;

		public PopupMenuHandler(ActionContext context) {
			this.actionContext = context;
		}

		@Override
		public void menuItemEntered(DockingActionIf action) {
			DockingWindowManager.setMouseOverAction(action);
		}

		@Override
		public void menuItemExited(DockingActionIf action) {
			DockingWindowManager.clearMouseOverHelp();
		}

		@Override
		public void processMenuAction(final DockingActionIf action, final ActionEvent event) {

			DockingWindowManager.clearMouseOverHelp();
			actionContext.setSourceObject(event.getSource());

			// this gives the UI some time to repaint before executing the action
			SwingUtilities.invokeLater(() -> {
				if (action.isEnabledForContext(actionContext)) {
					if (action instanceof ToggleDockingActionIf) {
						ToggleDockingActionIf toggleAction = ((ToggleDockingActionIf) action);
						toggleAction.setSelected(!toggleAction.isSelected());
					}
					action.actionPerformed(actionContext);
				}
			});
		}
	}
}
