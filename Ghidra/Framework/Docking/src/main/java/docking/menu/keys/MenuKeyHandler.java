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
package docking.menu.keys;

import java.awt.Component;

import javax.swing.*;

/**
 * The interface for work to be done on an open menu.
 */
abstract class MenuKeyHandler {

	/**
	 * The work method of this handler.  This method will only be called when a menu or popup
	 * menu is open.
	 * 
	 * @param manager the active menu selection manager
	 * @param path the active menu path
	 */
	abstract void process(MenuSelectionManager manager, MenuElement[] path);

	protected int getLeafPopupIndex(MenuElement[] path) {

		if (path != null) {
			for (int i = path.length - 1; i >= 0; i--) {
				MenuElement menuElement = path[i];
				if (menuElement instanceof JPopupMenu) {
					return i;
				}
			}
		}
		return -1;
	}

	protected JPopupMenu getLeafPopupMenu(MenuElement[] path) {

		int index = getLeafPopupIndex(path);
		if (index >= 0) {
			return (JPopupMenu) path[index];
		}
		return null;
	}

	protected int findActiveMenuItemIndex(MenuSelectionManager manager, MenuElement[] path) {

		int popupIndexdex = getLeafPopupIndex(path);
		if (popupIndexdex == -1) {
			return -1; // not sure if this can happen
		}

		if (popupIndexdex == path.length - 1) {
			// last item is the popup--no selected menu item
			return -1;
		}

		MenuElement activeItem = path[path.length - 1];
		JPopupMenu popup = (JPopupMenu) path[popupIndexdex];
		int count = 0;
		int n = popup.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component c = popup.getComponent(i);
			if (isValidItem(c)) {
				if (activeItem == c) {
					return count;
				}
				count++;
			}

		}
		return -1;
	}

	protected int findActiveMenuItemRawIndex(MenuSelectionManager manager, MenuElement[] path) {

		int popupIndexdex = getLeafPopupIndex(path);
		if (popupIndexdex == -1) {
			return -1; // not sure if this can happen
		}

		if (popupIndexdex == path.length - 1) {
			// last item is the popup--no selected menu item
			return -1;
		}

		MenuElement activeItem = path[path.length - 1];
		JPopupMenu popup = (JPopupMenu) path[popupIndexdex];
		int count = 0;
		int n = popup.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component c = popup.getComponent(i);
			if (activeItem == c) {
				return count;
			}
			count++;
		}
		return -1;
	}

	protected int findNextSeparatorIndex(JPopupMenu popup, int startIndex) {

		int n = popup.getComponentCount();
		for (int i = startIndex; i < n; i++) {
			Component c = popup.getComponent(i);
			if (c instanceof JSeparator) {
				return i;
			}
		}

		return -1;
	}

	protected int findPreviousSeparatorIndex(JPopupMenu popup, int startIndex) {

		for (int i = startIndex; i >= 0; i--) {
			Component c = popup.getComponent(i);
			if (c instanceof JSeparator) {
				return i;
			}
		}

		return -1;
	}

	protected int findNextValidIndex(JPopupMenu popup, int startIndex) {

		int n = popup.getComponentCount();
		for (int i = startIndex; i < n; i++) {
			Component c = popup.getComponent(i);
			if (isValidItem(c)) {
				return i;
			}
		}

		return -1;
	}

	protected int findPreviousValidIndex(JPopupMenu popup, int startIndex) {

		for (int i = startIndex; i >= 0; i--) {
			Component c = popup.getComponent(i);
			if (isValidItem(c)) {
				return i;
			}
		}

		return -1;
	}

	protected int moveForward(MenuSelectionManager manager, MenuElement[] path,
			int offset) {

		JPopupMenu popup = getLeafPopupMenu(path);
		if (popup == null) {
			return -1;
		}

		int itemCount = getItemCount(popup);

		// handle wrapping around to the top again
		int updatedOffset = offset >= itemCount ? offset % itemCount : offset;
		int progress = 0;
		int n = popup.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component c = popup.getComponent(i);
			if (isValidItem(c)) {
				if (progress == updatedOffset) {
					return i;
				}
				progress++;
			}
		}

		return -1;
	}

	protected void setNewMenuItemIndex(MenuSelectionManager manager, MenuElement[] path,
			int index) {

		if (index < 0) {
			return;
		}

		int popupIndex = getLeafPopupIndex(path);
		JPopupMenu popup = (JPopupMenu) path[popupIndex];

		JMenuItem newItem = (JMenuItem) popup.getComponent(index);
		int length = path.length - 1 == popupIndex ? path.length + 1 : path.length;

		MenuElement[] newPath = new MenuElement[length];
		System.arraycopy(path, 0, newPath, 0, popupIndex + 1);
		newPath[popupIndex + 1] = newItem;

		// replace last path element
		manager.setSelectedPath(newPath);
	}

	protected MenuElement getNextValidItem(JPopupMenu popup, int start) {

		int n = popup.getComponentCount();
		for (int i = 0; i < n; i++) {

			// handle wrapping
			int updated = i + start;
			int index = (updated < n) ? updated : Math.abs(i - (n - start));

			Component c = popup.getComponent(index);
			if (isValidItem(c)) {
				return (MenuElement) c;
			}
		}
		return null;
	}

	protected MenuElement getPreviousValidItem(JPopupMenu popup, int offset) {

		int n = popup.getComponentCount();
		for (int i = n - 1; i >= 0; i--) {

			// handle wrapping
			int updated = (n - (i + 1));
			int index = (updated > offset) ? updated : offset - updated;

			Component c = popup.getComponent(index);
			if (isValidItem(c)) {
				return (MenuElement) c;
			}
		}
		return null;
	}

	protected int getItemCount(JPopupMenu popup) {
		int count = 0;
		int n = popup.getComponentCount();
		for (int i = 0; i < n; i++) {
			Component c = popup.getComponent(i);
			if (isValidItem(c)) {
				count++;
			}
		}
		return count;
	}

	protected boolean isValidItem(Component c) {
		return c instanceof JMenuItem && c.isEnabled();
	}
}
