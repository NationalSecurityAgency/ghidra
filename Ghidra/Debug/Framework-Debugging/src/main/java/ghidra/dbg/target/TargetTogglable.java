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
package ghidra.dbg.target;

import java.util.concurrent.CompletableFuture;

import ghidra.dbg.DebuggerTargetObjectIface;
import ghidra.dbg.target.schema.TargetAttributeType;

/**
 * An object which can be toggled
 */
@DebuggerTargetObjectIface("Togglable")
public interface TargetTogglable extends TargetObject {

	String ENABLED_ATTRIBUTE_NAME = PREFIX_INVISIBLE + "enabled";

	/**
	 * Check if the object is enabled
	 * 
	 * @return true if enabled, false otherwise
	 */
	@TargetAttributeType(name = ENABLED_ATTRIBUTE_NAME, required = true, hidden = true)
	public default boolean isEnabled() {
		return getTypedAttributeNowByName(ENABLED_ATTRIBUTE_NAME, Boolean.class, false);
	}

	/**
	 * Disable this object
	 */
	public CompletableFuture<Void> disable();

	/**
	 * Enable this object
	 */
	public CompletableFuture<Void> enable();

	/**
	 * Enable or disable this object
	 * 
	 * @param enabled true to enable, false to disable
	 */
	public default CompletableFuture<Void> toggle(boolean enabled) {
		return enabled ? enable() : disable();
	}
}
