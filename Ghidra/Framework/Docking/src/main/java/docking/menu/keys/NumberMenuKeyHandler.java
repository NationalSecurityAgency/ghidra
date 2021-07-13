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

import javax.swing.MenuElement;
import javax.swing.MenuSelectionManager;

class NumberMenuKeyHandler extends MenuKeyHandler {

	private int number;

	NumberMenuKeyHandler(int number) {
		this.number = number;
	}

	@Override
	public void process(MenuSelectionManager manager, MenuElement[] path) {
		int activeMenuItemIndex = findActiveMenuItemIndex(manager, path);
		int amount = activeMenuItemIndex + number;
		int nextIndex = moveForward(manager, path, amount);
		setNewMenuItemIndex(manager, path, nextIndex);
	}
}
