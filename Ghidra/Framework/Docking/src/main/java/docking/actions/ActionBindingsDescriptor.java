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

import docking.action.DockingActionIf;

/**
 * An interface that allows the {@link KeyBindingsModel} API to provide key and mouse binding information
 * to clients, without having to have a registered action to provide the information.  Action 
 * descriptions will be loaded from the saved tool options.  If no plugin has registered an action
 * for the current tool session, then the an unregistered action descriptor will get created when
 * editing key and mouse bindings via the options UI.
 */
public interface ActionBindingsDescriptor {

	/**
	 * {@return the action name without the owner} 
	 */
	public String getName();

	/**
	 * {@return the full action name in the format: 'Name (Owner)'} 
	 */
	public String getFullName();

	/**
	 * {@return the owner name(s) of the action} 
	 */
	public String getOwnerDescription();

	/**
	 * {@return the action description or a blank string} 
	 */
	public String getDescription();

	/**
	 * {@return a string that shows all key and mouse binding info for the action} 
	 */
	public String getBindingText();

	/**
	 * The action for the binding.  This will be an arbitrary action for shared bindings. 
	 * This will be null if this class represents an unregistered action.
	 * 
	 * @return an action or null
	 */
	public DockingActionIf getRepresentativeAction();

	/**
	 * {@return true if a plugin has registered an action for this descriptor; false is no action
	 * has been registered}
	 */
	public boolean isRegistered();
}
