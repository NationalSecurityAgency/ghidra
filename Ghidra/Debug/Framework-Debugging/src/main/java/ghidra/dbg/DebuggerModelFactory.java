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
package ghidra.dbg;

import ghidra.dbg.util.ConfigurableFactory;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A factory for a debugger model
 * 
 * <p>
 * This provides a discoverable means of creating a debug model.
 */
public interface DebuggerModelFactory
		extends ExtensionPoint, ConfigurableFactory<DebuggerObjectModel> {
	/**
	 * Check if this factory is compatible with the local system.
	 * 
	 * @return true if compatible
	 */
	default boolean isCompatible() {
		return true;
	}
}
