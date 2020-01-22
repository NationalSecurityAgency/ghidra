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

import java.util.HashMap;
import java.util.Map;

import docking.action.MenuData;

/**
 * Maps menuPaths to groups
 */
public class MenuGroupMap {
	private Map<String, String> preferredMenuGroups = new HashMap<>();
	private Map<String, String> preferredMenuSubGroups = new HashMap<>();

	/**
	 * Sets the group for the given menuPath
	 * @param menuPath the menuPath for which to assign a group
	 * @param group the name of the group for the action with the given menu path
	 * @param menuSubGroup the name used for sorting items in the same <code>group</code>.  If this 
	 *        value is {@link MenuData#NO_SUBGROUP}, then sorting is based upon the name of the
	 *        menu item.
	 */
	public void setMenuGroup(String[] menuPath, String group, String menuSubGroup) {
		if (menuSubGroup == null) {
			menuSubGroup = MenuData.NO_SUBGROUP;
		}

		String key = getMenuPathKey(menuPath);
		if (group == null) {
			preferredMenuGroups.remove(key);
		}
		else {
			preferredMenuGroups.put(key, group);
		}

		preferredMenuSubGroups.put(key, menuSubGroup);
	}

	/**
	 * Returns the group for the given menu path
	 * @param menuPath the menu path for which to find its group
	 * @return the menu group
	 */
	public String getMenuGroup(String[] menuPath) {
		return preferredMenuGroups.get(getMenuPathKey(menuPath));
	}

	/**
	 * Returns the menu subgroup string for the given menu path.  This string is used to perform
	 * sorting of menu items that exist in the same group.
	 * 
	 * @param menuPath the menu path for which to find its group
	 * @return the menu sub-group
	 */
	public String getMenuSubGroup(String[] menuPath) {
		return preferredMenuSubGroups.get(getMenuPathKey(menuPath));
	}

	private static String getMenuPathKey(String[] menuPath) {
		StringBuffer buf = new StringBuffer();
		for (String element : menuPath) {
			buf.append("/");
			buf.append(element);
		}
		return buf.toString();
	}

}
