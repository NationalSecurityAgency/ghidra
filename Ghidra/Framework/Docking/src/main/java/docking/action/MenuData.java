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

import javax.swing.Icon;

import docking.DockingUtils;
import ghidra.util.SystemUtilities;

public class MenuData {
	public static final int NO_MNEMONIC = -1;

	public static final String NO_SUBGROUP = Character.toString('\uffff');

	private String[] menuPath;
	private Icon icon;
	private int mnemonic = NO_MNEMONIC;
	private String menuGroup;

	/**
	 * The subgroup string.  This string is used to sort items within a 
	 * {@link #getMenuGroup() toolbar group}.  This value is not required.  If not specified, 
	 * then the value will effectively place this item at the end of its specified group.
	 */
	private String menuSubGroup;

	public MenuData(String[] menuPath) {
		this(menuPath, null, null);
	}

	public MenuData(String[] menuPath, String group) {
		this(menuPath, null, group);
	}

	public MenuData(String[] menuPath, Icon icon) {
		this(menuPath, icon, null);
	}

	public MenuData(String[] menuPath, Icon icon, String menuGroup) {
		this(processMenuPath(menuPath), icon, menuGroup, getMnemonic(menuPath), null);
	}

	public MenuData(String[] menuPath, Icon icon, String menuGroup, int mnemonic,
			String menuSubGroup) {

		if (menuPath == null || menuPath.length == 0) {
			throw new IllegalArgumentException("Menu path cannot be null or empty");
		}
		this.menuPath = menuPath;
		this.menuGroup = menuGroup;
		this.menuSubGroup = menuSubGroup == null ? NO_SUBGROUP : menuSubGroup;
		this.mnemonic = mnemonic;
		this.icon = DockingUtils.scaleIconAsNeeded(icon);
	}

	public MenuData(MenuData menuData) {
		this.menuPath = menuData.menuPath;
		this.icon = menuData.icon;
		this.menuGroup = menuData.menuGroup;
		this.menuSubGroup = menuData.menuSubGroup;
		this.mnemonic = menuData.mnemonic;
	}

	public MenuData cloneData() {
		return new MenuData(menuPath, icon, menuGroup, mnemonic, menuSubGroup);
	}

	protected void firePropertyChanged(MenuData oldData) {
		// for subclasses to define (should make this abstract)
	}

	/**
	 * Returns the menu path.
	 * @return an array of strings where each string is an element of a higher level menu.
	 */
	public String[] getMenuPath() {
		return menuPath;
	}

	public String getMenuPathAsString() {
		if (menuPath == null || menuPath.length == 0) {
			return null;
		}
		StringBuilder buildy = new StringBuilder();
		for (int i = 0; i < menuPath.length; i++) {
			buildy.append(menuPath[i]);
			if (i != (menuPath.length - 1)) {
				buildy.append("->");
			}
		}
		return buildy.toString();
	}

	public int getMnemonic() {
		return mnemonic;
	}

	/**
	 * Returns the icon assigned to this action's menu. Null indicates that this action does not 
	 * have a menu icon
	 */
	public Icon getMenuIcon() {
		return icon;
	}

	public String getMenuGroup() {
		return menuGroup;
	}

	/**
	 * Returns the subgroup string.  This string is used to sort items within a 
	 * {@link #getMenuGroup() toolbar group}.  This value is not required.  If not specified, 
	 * then the value will effectively place this item at the end of its specified group.
	 */
	public String getMenuSubGroup() {
		return menuSubGroup;
	}

	public void setIcon(Icon newIcon) {
		if (icon == newIcon) {
			return;
		}
		MenuData oldData = cloneData();
		icon = DockingUtils.scaleIconAsNeeded(newIcon);

		firePropertyChanged(oldData);
	}

	public void setMenuGroup(String newGroup) {
		if (SystemUtilities.isEqual(menuGroup, newGroup)) {
			return;
		}
		MenuData oldData = cloneData();
		menuGroup = newGroup;
		firePropertyChanged(oldData);
	}

	public void setMenuSubGroup(String newSubGroup) {
		if (SystemUtilities.isEqual(menuSubGroup, newSubGroup)) {
			return;
		}
		MenuData oldData = cloneData();
		menuSubGroup = newSubGroup;
		firePropertyChanged(oldData);
	}

	public void setMenuPath(String[] newPath) {
		MenuData oldData = cloneData();
		menuPath = processMenuPath(newPath);
		int newMnemonic = getMnemonic(newPath);
		if (newMnemonic != NO_MNEMONIC) {
			mnemonic = newMnemonic;
		}
		firePropertyChanged(oldData);
	}

	public void setMnemonic(Character newMnemonic) {
		MenuData oldData = cloneData();
		mnemonic = newMnemonic;
		firePropertyChanged(oldData);
	}

	public void setMenuItemName(String newMenuItemName) {
		String processedMenuItemName = processMenuItemName(newMenuItemName);
		if (processedMenuItemName.equals(menuPath[menuPath.length - 1])) {
			return;
		}
		MenuData oldData = cloneData();
		menuPath = menuPath.clone();
		menuPath[menuPath.length - 1] = processedMenuItemName;
		int newMnemonic = getMnemonic(newMenuItemName);
		if (newMnemonic != NO_MNEMONIC) {
			mnemonic = newMnemonic;
		}
		firePropertyChanged(oldData);
	}

	private static int getMnemonic(String[] menuPath) {
		if (menuPath == null || menuPath.length == 0) {
			return NO_MNEMONIC;
		}
		return getMnemonic(menuPath[menuPath.length - 1]);
	}

	private static int getMnemonic(String string) {
		int indexOf = string.indexOf('&');
		if (indexOf >= 0 && indexOf < string.length() - 1) {
			return string.charAt(indexOf + 1);
		}
		return NO_MNEMONIC;
	}

	private static String[] processMenuPath(String[] menuPath) {
		if (menuPath != null && menuPath.length > 0) {
			menuPath[menuPath.length - 1] = processMenuItemName(menuPath[menuPath.length - 1]);
		}
		return menuPath;
	}

	private static String processMenuItemName(String string) {
		int indexOf = string.indexOf('&');
		if (indexOf >= 0 && indexOf < string.length() - 1) {
			return string.substring(0, indexOf) + string.substring(indexOf + 1);

		}
		return string;

	}

	public String getMenuItemName() {
		if (menuPath == null) {
			return "Missing Menu Path!";
		}
		return menuPath[menuPath.length - 1];
	}
}
