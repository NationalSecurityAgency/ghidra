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

import javax.swing.JPopupMenu;

/**
 * A class to help during testing to get objects otherwise restricted by package
 */
public class DockingWindowManagerTestHelper {

	/**
	 * Gets the popup menu for the given context
	 * @param dwm the window manager
	 * @param context the action context
	 * @return the popup menu; null if there are no valid actions for the given context
	 */
	public static JPopupMenu getPopupMenu(DockingWindowManager dwm, ActionContext context) {

		ActionToGuiMapper mapper = dwm.getActionToGuiMapper();
		PopupActionManager popupManager = mapper.getPopupActionManager();
		JPopupMenu popup = popupManager.createPopupMenu(null, context);
		return popup;
	}
}
