/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import javax.swing.JMenuItem;

import docking.action.DockingActionIf;

/**
 * Common interface for MenuItemManager and MenuMangers that are sub-menus.
 */
interface ManagedMenuItem {

	/**
	 * Returns the group for this menu or menuItem.
	 */
	String getGroup();

	/**
	 * Returns a sub group string that species how this item should be grouped within its 
	 * primary group, as defined by {@link #getGroup()}.
	 */
	String getSubGroup();

	/**
	 * Returns the text of the menu item.
	 * @return  the text of the menu item.
	 */
	String getMenuItemText();

	/**
	 * Returns the MenuItem if this is a MenuItemManager or the Menu if this is a MenuManger.
	 * (Menus are MenuItems)
	 */
	JMenuItem getMenuItem();

	/**
	 * Releases all resources used by this object.
	 */
	void dispose();

	boolean removeAction(DockingActionIf action);

	boolean isEmpty();

}
