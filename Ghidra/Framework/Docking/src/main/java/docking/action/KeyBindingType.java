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
package docking.action;

/**
 * Allows clients to signal their support for the assigning of key binding shortcut keys.  Most
 * action clients need not be concerned with this class.   The default settings of 
 * {@link DockingAction} work correctly for almost all cases, which is to have the action 
 * support individual key bindings, which are managed by the system via the UI.
 * 
 * @see DockingActionIf
 */
public enum KeyBindingType {

	//@formatter:off
	/** 
	 * Indicates the setting of key bindings through the UI is not supported	
	 */
	UNSUPPORTED, 
	
	/** 
	 * Supports the assignment of key bindings via the UI.  Setting a key binding on an action 
	 * with this type will not affect any other action.
	 */
	INDIVIDUAL,
	
	/**
	 * When the key binding is set via the UI, this action, and any action that shares a 
	 * name with this action, will be updated to the same key binding value whenever the key 
	 * binding options change.
	 * 
	 * <p>Most actions will not be shared.  If you are unsure if your action
	 * should use a shared keybinding, then do not do so.
	 */
	SHARED;
	//@formatter:on

	/**
	 * Returns true if this type supports key bindings.  This is a convenience method for 
	 * checking that this type is not {@link #UNSUPPORTED}.
	 * @return true if key bindings are supported
	 */
	public boolean supportsKeyBindings() {
		return this != UNSUPPORTED;
	}

	/**
	 * Convenience method for checking if this type is the {@link #SHARED} type
	 * @return true if shared
	 */
	public boolean isShared() {
		return this == SHARED;
	}

	/**
	 * A convenience method for clients to check whether this key binding type should be 
	 * managed directly by the system.
	 * 
	 * <p>Shared actions are not managed directly by the system, but are instead managed through
	 * a proxy action.
	 * 
	 * @return true if managed directly by the system; false if key binding are not supported 
	 *         or are managed through a proxy
	 */
	public boolean isManaged() {
		return this == INDIVIDUAL;
	}
}
