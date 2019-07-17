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
package docking;

import java.util.List;

import docking.action.DockingActionIf;

/**
 * Listener interface for the object to be notified when the user closes the 
 * docking windows manager or initiates a popup menu.
 */
public interface DockWinListener {
	/**
	 * Notification triggered when the user presses the "x" button in the main tool frame.
	 * Typical reaction is to dispose the dockingWindowManger and/or exit.
	 */
	void close();
	
	/**
	 * Provides notification when a popup menu is about to be displayed
	 * and permits a list of temporary actions to be returned.  Only 
	 * those actions which have a suitable popup menu path will be 
	 * considered.
	 * @param context the ActionContext
	 * @return list of temporary actions.
	 */
	List<DockingActionIf> getPopupActions(ActionContext context);

}
