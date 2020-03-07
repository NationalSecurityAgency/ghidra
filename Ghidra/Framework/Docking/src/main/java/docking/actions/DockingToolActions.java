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

import java.util.Set;

import docking.ComponentProvider;
import docking.action.DockingActionIf;

/**
 * Represents the collection of actions registered with the tool, along with method for adding
 * and removing actions.
 */
public interface DockingToolActions {

	/**
	 * Adds the given action that enabled when the given provider is active
	 * 
	 * @param provider the provider
	 * @param action the action
	 */
	public void addLocalAction(ComponentProvider provider, DockingActionIf action);

	/**
	 * Gets the provider action by the given name
	 * 
	 * @param provider the provider
	 * @param actionName the action name
	 * @return the action
	 */
	public DockingActionIf getLocalAction(ComponentProvider provider, String actionName);

	/**
	 * Removes the given provider's local action
	 * 
	 * @param provider the provider
	 * @param action the action
	 */
	public void removeLocalAction(ComponentProvider provider, DockingActionIf action);

	/**
	 * Adds the given action that is enabled, regardless of the active provider
	 * 
	 * @param action the action
	 */
	public void addGlobalAction(DockingActionIf action);

	/**
	 * Removes the given global action 
	 * @param action the action
	 */
	public void removeGlobalAction(DockingActionIf action);

	/**
	 * Removes all global actions for the given owner 
	 * 
	 * @param owner the owner
	 */
	public void removeActions(String owner);

	/**
	 * Removes all local actions for the given provider
	 * 
	 * @param provider the provider
	 */
	public void removeActions(ComponentProvider provider);

	/**
	 * Returns all actions with the given owner
	 * 
	 * @param owner the owner
	 * @return the actions
	 */
	public Set<DockingActionIf> getActions(String owner);

	/**
	 * Returns all actions known to the tool
	 * @return the actions
	 */
	public Set<DockingActionIf> getAllActions();

	/**
	 * Allows clients to register an action by using a placeholder.  This is useful when 
	 * an API wishes to have a central object (like a plugin) register actions for transient
	 * providers, that may not be loaded until needed.
	 * 
	 * <p>This method may be called multiple times with the same conceptual placeholder--the
	 * placeholder will only be added once.
	 * 
	 * @param placeholder the placeholder containing information related to the action it represents
	 */
	public void registerSharedActionPlaceholder(SharedDockingActionPlaceholder placeholder);
}
