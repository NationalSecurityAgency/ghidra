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

import java.awt.event.MouseEvent;
import java.util.*;

import javax.swing.*;

import docking.action.*;
import docking.menu.MenuGroupMap;
import docking.menu.MenuHandler;
import ghidra.util.*;

/**
 * Manages the global actions for the menu and toolbar.
 */
public class DockingActionManager {

	private HashSet<DockingActionIf> globalActions = new LinkedHashSet<>();

	private MenuHandler menuBarMenuHandler;
	private MenuGroupMap menuGroupMap;

	private static boolean enableDiagnosticActions;

	private KeyBindingsManager keyBindingsManager;

	private GlobalMenuAndToolBarManager menuAndToolBarManager;

	private PopupActionManager popupActionManager;
	private DockingAction keyBindingsAction;

	/**
	 * Constructs a new ActionManager
	 * @param frame the frame to contain the menu and toolbar.
	 * @param enableDiagnosticActions if true additional diagnostic actions will enabled
	 */
	DockingActionManager(DockingWindowManager winMgr) {
		menuGroupMap = new MenuGroupMap();

		menuBarMenuHandler = new MenuBarMenuHandler(winMgr);

		keyBindingsManager = new KeyBindingsManager(winMgr);
		menuAndToolBarManager =
			new GlobalMenuAndToolBarManager(winMgr, menuBarMenuHandler, menuGroupMap);
		popupActionManager = new PopupActionManager(winMgr, menuGroupMap);

		initializeHelpActions();
	}

	private void initializeHelpActions() {
		DockingWindowsContextSensitiveHelpListener.install();

		keyBindingsAction = new KeyBindingAction(this);
		keyBindingsManager.addReservedAction(new HelpAction(false, ReservedKeyBindings.HELP_KEY1));
		keyBindingsManager.addReservedAction(new HelpAction(false, ReservedKeyBindings.HELP_KEY2));
		keyBindingsManager.addReservedAction(
			new HelpAction(true, ReservedKeyBindings.HELP_INFO_KEY));
		keyBindingsManager.addReservedAction(keyBindingsAction);

		if (enableDiagnosticActions) {
			keyBindingsManager.addReservedAction(new ShowFocusInfoAction());
			keyBindingsManager.addReservedAction(new ShowFocusCycleAction());
		}
	}

	/**
	 * A static initializer allowing additional diagnostic actions
	 * to be added to all frame and dialog windows.
	 * @param enable
	 */
	static void enableDiagnosticActions(boolean enable) {
		enableDiagnosticActions = enable;
	}

	/**
	 * Register a specific Help content location for a component.
	 * The DocWinListener will be notified with the help location if the specified
	 * component 'c' has focus and the help key is pressed. 
	 * @param c component
	 * @param helpURL help content URL
	 */
	static void setHelpLocation(JComponent c, HelpLocation helpLocation) {
		DockingWindowManager.getHelpService().registerHelp(c, helpLocation);
	}

	/**
	 * Removes all actions associated with the given owner
	 * @param owner the owner of all actions to be removed.
	 */
	void removeAll(String owner) {
		Iterator<DockingActionIf> iter = new ArrayList<>(globalActions).iterator();
		List<DockingActionIf> removedList = new ArrayList<>();
		while (iter.hasNext()) {
			DockingActionIf action = iter.next();
			if (owner.equals(action.getOwner())) {
				keyBindingsManager.removeAction(action);
				menuAndToolBarManager.removeAction(action);
				popupActionManager.removeAction(action);
				removedList.add(action);
			}
		}

		globalActions.removeAll(removedList);
	}

	void addLocalAction(DockingActionIf action, ComponentProvider provider) {
		keyBindingsManager.addAction(action, provider);
	}

	void removeLocalAction(DockingActionIf action) {
		keyBindingsManager.removeAction(action);
	}

	/**
	 * Adds the given Global action to the menu and/or toolbar.
	 * @param action the action to be added.
	 */
	void addToolAction(DockingActionIf action) {
		if (globalActions.add(action)) {
			keyBindingsManager.addAction(action, null);
			popupActionManager.addAction(action);
			menuAndToolBarManager.addAction(action);
		}
	}

	/**
	 * Removes the Global action from the menu and/or toolbar.
	 * @param action the action to be removed.
	 */
	void removeToolAction(DockingActionIf action) {
		keyBindingsManager.removeAction(action);
		popupActionManager.removeAction(action);
		menuAndToolBarManager.removeAction(action);
		globalActions.remove(action);
	}

	public List<DockingActionIf> getAllDockingActionsByFullActionName(String fullActionName) {

		// Note: this method is called by non-Swing test code.  Synchronize access to the 
		//       data structures in this class in order to prevent concurrent mod exceptions.
		List<DockingActionIf> actions = new ArrayList<>();
		SystemUtilities.runSwingNow(() -> {
			actions.addAll(getGlobalDockingActionsByFullActionName(fullActionName));
			actions.addAll(getLocalDockingActionsByFullActionName(fullActionName));
		});
		return actions;
	}

	private List<DockingActionIf> getGlobalDockingActionsByFullActionName(String fullActionName) {
		List<DockingActionIf> matchingActions = new ArrayList<>();
		ArrayList<DockingActionIf> existingAction = new ArrayList<>(globalActions);
		for (DockingActionIf action : existingAction) {
			if (fullActionName.equals(action.getFullName())) {
				matchingActions.add(action);
			}
		}
		return matchingActions;
	}

	private List<DockingActionIf> getLocalDockingActionsByFullActionName(String fullActionName) {
		List<DockingActionIf> matchingActions = new ArrayList<>();
		ArrayList<DockingActionIf> existingAction =
			new ArrayList<>(keyBindingsManager.getLocalActions());
		for (DockingActionIf action : existingAction) {
			if (fullActionName.equals(action.getFullName())) {
				matchingActions.add(action);
			}
		}
		return matchingActions;
	}

	public Action getDockingKeyAction(KeyStroke keyStroke) {
		return keyBindingsManager.getDockingKeyAction(keyStroke);
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

	/**
	 * Close all menus (includes popup menus)
	 */
	static void dismissMenus() {
		MenuSelectionManager.defaultManager().clearSelectedPath();
	}

	/**
	 * Updates the menu and toolbar to reflect any changes in the set of actions.
	 *
	 */
	void update() {
		menuAndToolBarManager.update();
		contextChangedAll();
	}

	/**
	 * Releases all resources and makes this object unavailable for future use.
	 *
	 */
	void dispose() {
		keyBindingsManager.dispose();
		popupActionManager.dispose();
		menuAndToolBarManager.dispose();
		globalActions.clear();
	}

	void setMenuGroup(String[] menuPath, String group) {
		menuGroupMap.setMenuGroup(menuPath, group);
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

	public MenuGroupMap getMenuGroupMap() {
		return menuGroupMap;
	}

	public void showPopupMenu(ComponentPlaceholder componentInfo, MouseEvent e) {
		popupActionManager.popupMenu(componentInfo, e);
	}
}
