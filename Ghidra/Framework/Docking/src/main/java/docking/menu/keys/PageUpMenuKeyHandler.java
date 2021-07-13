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

import javax.swing.*;

class PageUpMenuKeyHandler extends MenuKeyHandler {

	@Override
	void process(MenuSelectionManager manager, MenuElement[] path) {
		JPopupMenu popup = getLeafPopupMenu(path);
		if (popup == null) {
			return;
		}

		int activeIndex = findActiveMenuItemRawIndex(manager, path);
		int separatorIndex = -1;
		if (activeIndex >= 0) {
			// Only search for separator with an active item.  This will trigger the search
			// to start at the bottom of the menu
			separatorIndex = findPreviousSeparatorIndex(popup, activeIndex - 1);
		}

		int nextIndex = findPreviousValidIndex(popup, separatorIndex - 1);
		if (nextIndex < 0) {
			separatorIndex = popup.getComponentCount(); // wrap the search; start at the bottom
			nextIndex = findPreviousValidIndex(popup, separatorIndex - 1);
		}

		setNewMenuItemIndex(manager, path, nextIndex);
	}

}
