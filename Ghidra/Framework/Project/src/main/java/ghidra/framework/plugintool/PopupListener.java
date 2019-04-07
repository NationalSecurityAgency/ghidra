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
package ghidra.framework.plugintool;

import java.util.List;

import docking.ActionContext;
import docking.action.DockingActionIf;

/**
 * <code>PopupListener</code> provides notification when the popup action
 * menu is displayed. 
 */
public interface PopupListener {
	
	/**
	 * Provides notification that the popup menu is about to be displayed
	 * and allows a set of temporary actions to be included in the popup menu.
	 * Actions returned will be included in the menu if they have a valid popup 
	 * menu path and respond true to the isValidContext method.
	 * @param context the ActionContext
	 * @return list of temporary popup actions (null may be returned)
	 */
	List<DockingActionIf> getPopupActions(ActionContext context);

}
