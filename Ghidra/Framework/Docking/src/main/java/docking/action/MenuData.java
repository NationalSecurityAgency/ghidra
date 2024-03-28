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

import java.awt.event.KeyEvent;
import java.util.Arrays;

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
	private String parentMenuGroup;

	/**
	 * The subgroup string.  This string is used to sort items within a 
	 * {@link #getMenuGroup() toolbar group}.  This value is not required.  If not specified, 
	 * then the value will effectively place this item at the end of its specified group.
	 */
	private String menuSubGroup;

	public MenuData(String[] menuPath) {
		this(menuPath, null, null, NO_MNEMONIC, null);
	}

	public MenuData(String[] menuPath, String group) {
		this(menuPath, null, group, NO_MNEMONIC, null);
	}

	public MenuData(String[] menuPath, Icon icon) {
		this(menuPath, icon, null, NO_MNEMONIC, null);
	}

	public MenuData(String[] menuPath, Icon icon, String menuGroup) {
		this(menuPath, icon, menuGroup, NO_MNEMONIC, null);
	}

	public MenuData(String[] menuPath, Icon icon, String menuGroup, int mnemonic,
			String menuSubGroup) {

		if (menuPath == null || menuPath.length == 0) {
			throw new IllegalArgumentException("Menu path cannot be null or empty");
		}
		this.menuPath = processMenuPath(menuPath);
		this.menuGroup = menuGroup;
		this.menuSubGroup = menuSubGroup == null ? NO_SUBGROUP : menuSubGroup;
		this.mnemonic = mnemonic == NO_MNEMONIC ? getMnemonic(menuPath) : mnemonic;
		this.icon = DockingUtils.scaleIconAsNeeded(icon);
	}

	public MenuData(MenuData menuData) {
		this.menuPath = menuData.menuPath;
		this.icon = menuData.icon;
		this.menuGroup = menuData.menuGroup;
		this.menuSubGroup = menuData.menuSubGroup;
		this.parentMenuGroup = menuData.parentMenuGroup;
		this.mnemonic = menuData.mnemonic;
	}

	public MenuData cloneData() {
		MenuData newData = new MenuData(menuPath, icon, menuGroup, mnemonic, menuSubGroup);
		newData.parentMenuGroup = parentMenuGroup;
		return newData;
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

	/**
	 * Returns the menu path as a string. This method includes accelerator characters in the path
	 * @return the menu path as a string
	 */
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

	/**
	 * Returns the menu path as a string. This method filters accelerator chars('&') from the path.
	 * @return the menu path as a string without unescaped '&' chars
	 */
	public String getMenuPathDisplayString() {
		if (menuPath == null || menuPath.length == 0) {
			return null;
		}
		StringBuilder buildy = new StringBuilder();
		for (int i = 0; i < menuPath.length; i++) {
			if (i != (menuPath.length - 1)) {
				buildy.append(processMenuItemName(menuPath[i]));
				buildy.append("->");
			}
			else {
				// the last entry has already had processMenuItemName called on it
				buildy.append(menuPath[i]);
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
	 * @return the icon
	 */
	public Icon getMenuIcon() {
		return icon;
	}

	/**
	 * Returns the group for the menu item created by this data.   This value determines which
	 * section inside of the tool's popup menu the menu item will be placed.   If you need to
	 * control the ordering <b>within a section</b>, then provide a value for 
	 * {@link #setMenuSubGroup(String)}.
	 * 
	 * @return the group
	 */
	public String getMenuGroup() {
		return menuGroup;
	}

	/**
	 * Returns the subgroup string.  This string is used to sort items within a 
	 * {@link #getMenuGroup() toolbar group}.  This value is not required.  If not specified, 
	 * then the value will effectively place this item at the end of its specified group.
	 * @return the sub-group
	 */
	public String getMenuSubGroup() {
		return menuSubGroup;
	}

	/**
	 * Returns the group for the parent menu of the menu item created by this data.   That is, 
	 * this value is effectively the same as {@link #getMenuGroup()}, but for the parent menu
	 * item of this data's item.   Setting this value is only valid if the {@link #getMenuPath()}
	 * has a length greater than 1.
	 * 
	 * @return the parent group
	 */
	public String getParentMenuGroup() {
		return parentMenuGroup;
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

		if (newSubGroup == null) {
			newSubGroup = NO_SUBGROUP;
		}

		MenuData oldData = cloneData();
		menuSubGroup = newSubGroup;
		firePropertyChanged(oldData);
	}

	/**
	 * See the description in {@link #getParentMenuGroup()}
	 * 
	 * @param newParentMenuGroup the parent group
	 */
	public void setParentMenuGroup(String newParentMenuGroup) {
		if (menuPath.length <= 1) {
			throw new IllegalStateException(
				"Cannot set the parent menu group for a menu item " + "that has no parent");
		}

		if (SystemUtilities.isEqual(parentMenuGroup, newParentMenuGroup)) {
			return;
		}

		MenuData oldData = cloneData();
		parentMenuGroup = newParentMenuGroup;
		firePropertyChanged(oldData);

		this.parentMenuGroup = newParentMenuGroup;
	}

	public void setMenuPath(String[] newPath) {
		if (newPath == null || newPath.length == 0) {
			throw new IllegalArgumentException("Menu path cannot be null or empty");
		}
		MenuData oldData = cloneData();
		menuPath = processMenuPath(newPath);
		mnemonic = getMnemonic(newPath);
		firePropertyChanged(oldData);
	}

	public void setMnemonic(Character newMnemonic) {
		MenuData oldData = cloneData();
		mnemonic = newMnemonic;
		firePropertyChanged(oldData);
	}

	public void clearMnemonic() {
		setMnemonic((char) KeyEvent.VK_UNDEFINED /* == 0 */);
	}

	/**
	 * Sets the menu item name and the mnemonic, using the first unescaped '&amp;' found in the text
	 * as a marker ("S&amp;ave As").
	 * <p>
	 * NOTE: do NOT use this method with strings that contain user-supplied text.  Instead, use
	 * {@link #setMenuItemNamePlain(String)}, and then manually {@link #setMnemonic(Character) set}
	 * the mnemonic.
	 * 
	 * @param newMenuItemName the new name for this menu item, with an optional '&amp;' to flag one
	 * of the characters of the name as the new mnemonic of this item 
	 */
	public void setMenuItemName(String newMenuItemName) {
		String processedMenuItemName = processMenuItemName(newMenuItemName);
		if (processedMenuItemName.equals(menuPath[menuPath.length - 1])) {
			return;
		}
		MenuData oldData = cloneData();
		menuPath = menuPath.clone();
		menuPath[menuPath.length - 1] = processedMenuItemName;
		mnemonic = getMnemonic(newMenuItemName);
		firePropertyChanged(oldData);
	}

	/**
	 * Sets the menu item name, without parsing the name for mnemonics ("&amp;File").
	 * <p>
	 * Use this method instead of {@link #setMenuItemName(String)} when the name may have '&amp;'
	 * characters that need to be preserved, which is typically any user supplied strings.
	 * 
	 * @param newMenuItemName the new name for this menu item
	 */
	public void setMenuItemNamePlain(String newMenuItemName) {
		MenuData oldData = cloneData();
		menuPath = menuPath.clone();
		menuPath[menuPath.length - 1] = newMenuItemName;
		firePropertyChanged(oldData);
	}

	private static int getMnemonic(String[] menuPath) {
		if (menuPath == null || menuPath.length == 0) {
			return NO_MNEMONIC;
		}
		return getMnemonic(menuPath[menuPath.length - 1]);
	}

	private static int getMnemonic(String string) {
		int indexOf;
		int fromIndex = 0;
		do {
			indexOf = string.indexOf('&', fromIndex);
			fromIndex = indexOf + 2;
		} while (indexOf >= 0 && indexOf < string.length() - 1 && string.charAt(indexOf + 1) == '&');
		if (indexOf >= 0 && indexOf < string.length() - 1) {
			return string.charAt(indexOf + 1);
		}
		return NO_MNEMONIC;
	}

	private static String[] processMenuPath(String[] menuPath) {
		String[] copy = Arrays.copyOf(menuPath, menuPath.length);
		if (copy != null && copy.length > 0) {
			copy[copy.length - 1] = processMenuItemName(copy[copy.length - 1]);
		}
		return copy;
	}

	private static String processMenuItemName(String string) {
		int firstAmp = string.indexOf('&');
		if (firstAmp < 0) {
			return string;
		}
		StringBuilder builder = new StringBuilder(string.substring(0, firstAmp));
		for (int i = firstAmp; i < string.length(); i++) {
			char ch = string.charAt(i);
			if (ch == '&') {
				if (i < string.length() - 1 && string.charAt(i+1) == '&') {
					builder.append('&');
					i++;
				}
			} else {
				builder.append(ch);
			}
		}
		return builder.toString();
	}

	public String getMenuItemName() {
		if (menuPath == null) {
			return "Missing Menu Path!";
		}
		return menuPath[menuPath.length - 1];
	}
}
