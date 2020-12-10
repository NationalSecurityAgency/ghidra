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

import ghidra.util.classfinder.ExtensionPointProperties;

/**
 * A factory for a local debugger model
 *
 * <p>
 * These factories are searched when attempting to create a new default debug model targeting the
 * local environment.
 */
public interface LocalDebuggerModelFactory extends DebuggerModelFactory {
	/**
	 * Get the priority of this factory
	 * 
	 * <p>
	 * In the event multiple compatible factories are discovered, the one with the highest priority
	 * is selected, breaking ties arbitrarily.
	 * 
	 * <p>
	 * The default implementation returns the priority given by {@link ExtensionPointProperties}. If
	 * the priority must be determined dynamically, then override this implementation.
	 * 
	 * @return the priority, where lower values indicate higher priority.
	 */
	default int getPriority() {
		return ExtensionPointProperties.Util.getPriority(getClass());
	}
}
