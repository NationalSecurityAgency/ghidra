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

import javax.swing.KeyStroke;

import docking.tool.ToolConstants;

/**
 * A marker interface to signal that the implementing action serves as an action that should
 * not be itself used in the tool, but should only be used to register and manager keybindings.
 * 
 * 
 * <p>This action is merely a tool by which transient components can ensure that their actions
 * are correctly managed when the component is created.  Normal actions will get registered when
 * the tool first starts-up.  Alternatively, transient components only appear when called upon
 * by some event, such as a user request.  The issue heretofore was that the tool will remove
 * any options that are not longer used. Thus, if an action belonging to a transient component
 * does not get registered every time the tool is used, then the options (and key bindings) for
 * that action are removed from the too.   This interface allows a second-party to register 
 * an action on behalf of a transient provider, thus preventing the tool from removing any 
 * previously applied options.
 */
public interface SharedDockingActionPlaceholder {

	/**
	 * The action name.  This name must exactly match the name of the action represented by 
	 * this placeholder.
	 * @return the name
	 */
	public String getName();

	/**
	 * Returns an owner name to use in place of {@value ToolConstants#SHARED_OWNER}.  
	 * This should only be used when the client knows for certain that all shared actions are 
	 * shared by a single owner.  This is not typical for shared actions.  This can happen when one
	 * owner (such as a plugin) has multiple component providers that share action key  bindings.
	 * @return the owner
	 */
	public default String getOwner() {
		return ToolConstants.SHARED_OWNER;
	}

	/**
	 * The default key binding for the action represented by this placeholder
	 * @return the key binding; may be null
	 */
	public default KeyStroke getKeyBinding() {
		return null;
	}
}
