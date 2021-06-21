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

import java.util.LinkedHashSet;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.MenuSelectionManager;

import docking.action.DockingActionIf;
import docking.menu.MenuGroupMap;
import docking.menu.MenuHandler;
import ghidra.util.HelpLocation;

/**
 * Manages the global actions for the menu and toolbar.
 */
public class ActionToGuiMapper {

	private Set<DockingActionIf> globalActions = new LinkedHashSet<>();

	private MenuHandler menuBarMenuHandler;
	private MenuGroupMap menuGroupMap;

	private GlobalMenuAndToolBarManager menuAndToolBarManager;
	private PopupActionManager popupActionManager;

	ActionToGuiMapper(DockingWindowManager winMgr) {
		menuGroupMap = new MenuGroupMap();
		menuBarMenuHandler = new MenuBarMenuHandler(winMgr);
		menuAndToolBarManager =
			new GlobalMenuAndToolBarManager(winMgr, menuBarMenuHandler, menuGroupMap);
		popupActionManager = new PopupActionManager(winMgr, menuGroupMap);

		DockingWindowsContextSensitiveHelpListener.install();
	}

	/**
	 * Register a specific Help content location for a component.
	 * The DocWinListener will be notified with the help location if the specified
	 * component 'c' has focus and the help key is pressed.
	 *  
	 * @param c component
	 * @param helpLocation the help location
	 */
	static void setHelpLocation(JComponent c, HelpLocation helpLocation) {
		DockingWindowManager.getHelpService().registerHelp(c, helpLocation);
	}

	/**
	 * Adds the given Global action to the menu and/or toolbar.
	 * @param action the action to be added.
	 */
	void addToolAction(DockingActionIf action) {
		if (globalActions.add(action)) {
			popupActionManager.addAction(action);
			menuAndToolBarManager.addAction(action);
		}
	}

	/**
	 * Removes the Global action from the menu and/or toolbar.
	 * @param action the action to be removed.
	 */
	void removeToolAction(DockingActionIf action) {
		popupActionManager.removeAction(action);
		menuAndToolBarManager.removeAction(action);
		globalActions.remove(action);
	}

	Set<DockingActionIf> getGlobalActions() {
		return globalActions;
	}

	void setActive(boolean active) {
		if (!active) {
			dismissMenus();

			DockingWindowManager.clearMouseOverHelp();
		}
	}

	private void dismissMenus() {
		MenuSelectionManager.defaultManager().clearSelectedPath();
	}

	void update() {
		menuAndToolBarManager.update();
		contextChangedAll();
	}

	void dispose() {
		popupActionManager.dispose();
		menuAndToolBarManager.dispose();
		globalActions.clear();
	}

	void setMenuGroup(String[] menuPath, String group, String menuSubGroup) {
		menuGroupMap.setMenuGroup(menuPath, group, menuSubGroup);
	}

	MenuHandler getMenuHandler() {
		return menuBarMenuHandler;
	}

	void contextChangedAll() {
		menuAndToolBarManager.contextChangedAll();
	}

	void contextChanged(ComponentPlaceholder placeHolder) {
		menuAndToolBarManager.contextChanged(placeHolder);
	}

	PopupActionManager getPopupActionManager() {
		return popupActionManager;
	}

	public MenuGroupMap getMenuGroupMap() {
		return menuGroupMap;
	}

	public void showPopupMenu(ComponentPlaceholder componentInfo, PopupMenuContext popupContext) {
		popupActionManager.popupMenu(componentInfo, popupContext);
	}
}
