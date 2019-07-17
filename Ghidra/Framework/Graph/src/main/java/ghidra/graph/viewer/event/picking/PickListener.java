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
package ghidra.graph.viewer.event.picking;

import java.util.Set;

public interface PickListener<V> {

	public enum EventSource {
		/** Originated from outside of the graph API (e.g., an external location change) */
		EXTERNAL,

		/** Originated from the graph API (e.g., a user click, a graph grouping) */
		INTERNAL
	}

	public void verticesPicked(Set<V> vertices, EventSource source);
}
