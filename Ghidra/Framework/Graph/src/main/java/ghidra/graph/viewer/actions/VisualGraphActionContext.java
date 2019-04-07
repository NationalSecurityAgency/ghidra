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
package ghidra.graph.viewer.actions;

import ghidra.graph.VisualGraph;

/**
 * Action context for {@link VisualGraph}s
 */
public interface VisualGraphActionContext {

	/**
	 * Returns true actions that manipulate the satellite viewer should be enabled for this context
	 * @return true actions that manipulate the satellite viewer should be enabled for this context
	 */
	public default boolean shouldShowSatelliteActions() {
		// these actions should be available generically; subclasses may override to return false
		return true;
	}
}
