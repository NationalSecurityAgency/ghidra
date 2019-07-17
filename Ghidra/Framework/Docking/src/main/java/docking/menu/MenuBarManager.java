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

import java.util.*;

import javax.swing.JMenuBar;

import docking.action.DockingActionIf;
import docking.action.MenuData;

/**
 * Manages the main menu bar on the main frame
 */
public class MenuBarManager implements MenuGroupListener {

	private MenuHandler menuHandler;
	private Map<String, MenuManager> menuManagers;
	private final MenuGroupMap menuGroupMap;

	public MenuBarManager(MenuHandler actionHandler, MenuGroupMap menuGroupMap) {
		this.menuGroupMap = menuGroupMap;
		menuManagers = new TreeMap<>();
		this.menuHandler = actionHandler;
	}

	public void clearActions() {
		menuManagers = new TreeMap<>();
	}

	/**
	 * Adds an action to the menu
	 * @param action the action to be added
	 */
	public void addAction(DockingActionIf action) {
		MenuManager menuManager = getMenuManager(action);
		if (menuManager == null) {
			return;
		}

		menuManager.addAction(action);
	}

	private MenuManager getMenuManager(DockingActionIf action) {
		MenuData menuBarData = action.getMenuBarData();
		if (menuBarData == null) {
			return null;
		}

		String[] menuPath = menuBarData.getMenuPath();
		if (menuPath == null || menuPath.length <= 1) {
			return null;
		}

		return getMenuManager(menuPath[0]);
	}

	/**
	 * Removes an action from the menu.
	 * @param action the action to be removed.
	 */
	public void removeAction(DockingActionIf action) {
		Iterator<MenuManager> it = menuManagers.values().iterator();
		while (it.hasNext()) {
			MenuManager mgr = it.next();
			mgr.removeAction(action);
			if (mgr.isEmpty()) {
				it.remove();
			}
		}
	}

	/**
	 * Releases all resources and makes this object unusable.
	 *
	 */
	public void dispose() {
		Iterator<MenuManager> it = menuManagers.values().iterator();
		while (it.hasNext()) {
			MenuManager mgr = it.next();
			mgr.dispose();
		}
		menuManagers.clear();
	}

	/**
	 * Returns the menu manager for the given menu name.
	 * @param menuName the name of the menu the be retrieved.
	 * @return the MenuManager for the named menu.
	 */
	private MenuManager getMenuManager(String menuName) {

		char mk = MenuManager.getMnemonicKey(menuName);
		menuName = MenuManager.stripMnemonicAmp(menuName);

		MenuManager mgr = menuManagers.get(menuName);
		if (mgr == null) {
			mgr = new MenuManager(menuName, new String[] { menuName }, mk, 1, null, false,
				menuHandler, menuGroupMap);
			menuManagers.put(menuName, mgr);
		}
		return mgr;
	}

	public JMenuBar getMenuBar() {
		MenuManager fileMenu = menuManagers.get("File");
		MenuManager editMenu = menuManagers.get("Edit");
		MenuManager windowMenu = menuManagers.get("Window");
		MenuManager helpMenu = menuManagers.get("Help");

		JMenuBar menuBar = new JMenuBar();
		if (fileMenu != null) {
			menuBar.add(fileMenu.getMenu());
		}
		if (editMenu != null) {
			menuBar.add(editMenu.getMenu());
		}

		Iterator<MenuManager> it = menuManagers.values().iterator();
		while (it.hasNext()) {
			MenuManager mgr = it.next();
			if (mgr != fileMenu && mgr != editMenu && mgr != windowMenu && mgr != helpMenu) {

				menuBar.add(mgr.getMenu());
			}
		}

		if (windowMenu != null) {
			menuBar.add(windowMenu.getMenu());
		}
		if (helpMenu != null) {
			menuBar.add(helpMenu.getMenu());
		}

		return menuBar;
	}

	/**
	 * Handles changes to the Menu Group
	 * @param menuPath the menu path whose group changed.
	 * @param group the new group for the given menuPath.
	 */
	@Override
	public void menuGroupChanged(String[] menuPath, String group) {
		if (menuPath != null && menuPath.length > 1) {
			MenuManager mgr = getMenuManager(menuPath[0]);
			if (mgr != null) {
				mgr.menuGroupChanged(menuPath, 1, group);
			}
		}
	}

}
