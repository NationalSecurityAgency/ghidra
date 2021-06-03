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
package docking.actions;

import java.util.List;

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingActionIf;

/**
 * Provides notification when the popup action menu is displayed.   This interface allows 
 * temporary/transient actions (those not registered with the tool via 
 * {@link Tool#addAction(DockingActionIf)}) to be used in the popup context menu.   
 * 
 * <p>
 * Most clients will register actions directly with the tool.   However, clients that have numerous
 * actions that vary greatly with the context can use this method to only create those actions
 * on demand as the popup is about to be shown, and only if their context is active.   This 
 * mechanism can reduce the tool's action management overhead.    Once you have created an
 * implementation of this class, you must register it with
 * {@link Tool#addPopupActionProvider(PopupActionProvider)}.
 */
public interface PopupActionProvider {

	/**
	 * Provides notification that the popup menu is about to be displayed and allows a set of 
	 * temporary actions to be included in the popup menu.  Actions returned will be 
	 * included in the menu if they have a valid popup menu path and respond true to the 
	 * {@link DockingActionIf#isValidContext(ActionContext)} call.
	 * 
	 * @param tool the tool requesting the actions
	 * @param context the ActionContext
	 * @return list of temporary popup actions; return null if there are no popup actions
	 */
	public List<DockingActionIf> getPopupActions(Tool tool, ActionContext context);
}
