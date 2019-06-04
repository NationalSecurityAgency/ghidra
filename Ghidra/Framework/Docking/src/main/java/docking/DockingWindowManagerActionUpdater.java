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

import java.util.Set;

import docking.action.DockingActionIf;

/**
 * A class that exists primarily to provide access to action-related package-level methods of the
 * {@link DockingWindowManager}.  This allows the manager's interface to hide methods that 
 * don't make sense for public consumption.
 */
public class DockingWindowManagerActionUpdater {

	private DockingWindowManager windowManager;

	public DockingWindowManagerActionUpdater(DockingWindowManager windowManager) {
		this.windowManager = windowManager;
	}

	/**
	 * Adds an action to the global menu or toolbar which appear in the main frame. If the action 
	 * has a menu path, it will be in the menu.  If it has an icon, it will appear in the toolbar.
	 * @param action the action to be added
	 */
	public void addToolAction(DockingActionIf action) {
		windowManager.addToolAction(action);
	}

	/**
	 * Removes the given action from the global menu and toolbar
	 * @param action the action to be removed
	 */
	public void removeToolAction(DockingActionIf action) {
		windowManager.removeToolAction(action);
	}

	/**
	 * Returns all actions registered with this manager
	 * @return the actions
	 */
	public Set<DockingActionIf> getAllActions() {
		return windowManager.getAllActions();
	}

	/**
	 * Adds an action that will be associated with the given provider.  These actions will
	 * appear in the local header for the component as a toolbar button or a drop-down menu
	 * item if it has an icon and menu path respectively.
	 * 
	 * @param provider the provider whose header on which the action is to be placed
	 * @param action the action to add to the providers header bar
	 */
	public void addLocalAction(ComponentProvider provider, DockingActionIf action) {
		windowManager.addLocalAction(provider, action);
	}

}
