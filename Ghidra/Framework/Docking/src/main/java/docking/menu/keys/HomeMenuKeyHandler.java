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

class HomeMenuKeyHandler extends MenuKeyHandler {

	@Override
	void process(MenuSelectionManager manager, MenuElement[] path) {

		int popupIndex = getLeafPopupIndex(path);
		if (popupIndex == -1) {
			return;
		}

		JPopupMenu popup = (JPopupMenu) path[popupIndex];
		MenuElement newItem = getNextValidItem(popup, 0);
		int length = path.length - 1 == popupIndex ? path.length + 1 : path.length;

		MenuElement[] newPath = new MenuElement[length];
		System.arraycopy(path, 0, newPath, 0, popupIndex + 1);
		newPath[popupIndex + 1] = newItem;

		// replace last path element
		manager.setSelectedPath(newPath);
	}

}
