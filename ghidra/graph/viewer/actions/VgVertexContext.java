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

import docking.ComponentProvider;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualVertex;

/**
 * Context for a {@link VisualGraph} when a vertex is selected
 *
 * @param <V> the vertex type
 */
public class VgVertexContext<V extends VisualVertex> extends VgActionContext
		implements VisualGraphVertexActionContext<V> {

	private V v;

	public VgVertexContext(ComponentProvider provider, V v) {
		super(provider);
		this.v = v;
	}

	@Override
	public V getVertex() {
		return v;
	}

	@Override
	public boolean shouldShowSatelliteActions() {
		return false; // not satellite actions when we are over a vertex
	}
}
