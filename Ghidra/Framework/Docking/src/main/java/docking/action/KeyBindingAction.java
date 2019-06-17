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
package docking.action;

import java.awt.Component;
import java.util.Set;

import docking.*;
import docking.actions.KeyBindingUtils;
import ghidra.util.Msg;
import ghidra.util.ReservedKeyBindings;

public class KeyBindingAction extends DockingAction {
	private final ActionToGuiMapper dockingActionManager;

	public KeyBindingAction(ActionToGuiMapper dockingActionManager) {
		super("Set KeyBinding", DockingWindowManager.DOCKING_WINDOWS_OWNER);
		this.dockingActionManager = dockingActionManager;
		createReservedKeyBinding(ReservedKeyBindings.UPDATE_KEY_BINDINGS_KEY);
		setEnabled(true);

		// Help actions don't have help
		DockingWindowManager.getHelpService().excludeFromHelp(this);
	}

	@Override
	public void actionPerformed(ActionContext context) {
		DockingWindowManager windowManager = DockingWindowManager.getActiveInstance();
		if (windowManager == null) {
			return;
		}

		DockingActionIf action = DockingWindowManager.getMouseOverAction();
		if (action == null) {
			return;
		}

		action = maybeGetToolLevelAction(action);

		if (!action.isKeyBindingManaged()) {
			Component parent = windowManager.getActiveComponent();
			Msg.showInfo(getClass(), parent, "Unable to Set Keybinding",
				"Action \"" + getActionName(action) + "\" is not keybinding managed and thus a " +
					"keybinding cannot be set.");
			return;
		}

		KeyEntryDialog d = new KeyEntryDialog(action, dockingActionManager);
		DockingWindowManager.showDialog(d);
	}

	/**
	 * Checks to see if the given action is key binding-managed by another action at the  
	 * tool-level and returns that tool-level action if found.
	 * @param dockingAction The action for which to check for tool-level actions
	 * @return A tool-level action if one is found; otherwise, the original action
	 */
	private DockingActionIf maybeGetToolLevelAction(DockingActionIf dockingAction) {
		if (dockingAction.isKeyBindingManaged()) {
			return dockingAction;
		}

		// It is not key binding managed, which means that it may be a shared key binding
		String actionName = dockingAction.getName();
		Set<DockingActionIf> allActions = dockingActionManager.getAllActions();
		DockingActionIf sharedAction =
			KeyBindingUtils.getSharedKeyBindingAction(allActions, actionName);
		if (sharedAction != null) {
			return sharedAction;
		}

		return dockingAction;
	}

	private String getActionName(DockingActionIf action) {
		MenuData popupMenuData = action.getPopupMenuData();
		if (popupMenuData != null) {
			return popupMenuData.getMenuItemName();
		}

		MenuData menuBarData = action.getMenuBarData();
		if (menuBarData != null) {
			return menuBarData.getMenuItemName();
		}

		return action.getName();
	}

	@Override
	public boolean isEnabledForContext(ActionContext context) {
		return true;
	}

}
