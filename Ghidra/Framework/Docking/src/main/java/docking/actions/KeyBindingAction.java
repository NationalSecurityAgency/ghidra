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
package docking.actions;

import java.awt.Component;

import docking.ActionContext;
import docking.DockingWindowManager;
import docking.action.*;
import ghidra.util.Msg;

public class KeyBindingAction extends DockingAction {

	public static String NAME = "Set KeyBinding";
	private ToolActions toolActions;

	public KeyBindingAction(ToolActions toolActions) {
		super(NAME, DockingWindowManager.DOCKING_WINDOWS_OWNER);
		this.toolActions = toolActions;

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

		if (!action.getKeyBindingType().supportsKeyBindings()) {
			Component parent = windowManager.getActiveComponent();
			Msg.showInfo(getClass(), parent, "Unable to Set Keybinding",
				"Action \"" + getActionName(action) + "\" does not support key bindings");
			return;
		}

		KeyEntryDialog d = new KeyEntryDialog(action, toolActions);
		DockingWindowManager.showDialog(d);
	}

	/**
	 * Checks to see if the given action is key binding-managed by another action at the  
	 * tool-level and returns that tool-level action if found.
	 * @param dockingAction The action for which to check for tool-level actions
	 * @return A tool-level action if one is found; otherwise, the original action
	 */
	private DockingActionIf maybeGetToolLevelAction(DockingActionIf dockingAction) {

		if (dockingAction.getKeyBindingType().isShared()) {

			// It is not key binding managed, which means that it may be a shared key binding
			String actionName = dockingAction.getName();
			DockingActionIf sharedAction = toolActions.getSharedStubKeyBindingAction(actionName);
			if (sharedAction != null) {
				return sharedAction;
			}
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
