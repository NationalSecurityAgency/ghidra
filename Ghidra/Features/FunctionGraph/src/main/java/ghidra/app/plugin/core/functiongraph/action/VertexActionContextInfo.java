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
package ghidra.app.plugin.core.functiongraph.action;

import java.util.Collections;
import java.util.Set;

import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.program.model.address.AddressSet;

/**
 * A container object use by the graph's context system to give actions the state of the graph.
 * 
 * <P>This class has a vertex which is considered the active vertex, which may be the vertex
 * under the mouse (for mouse driven data)  or the focused vertex (for key event driven data).
 */
public class VertexActionContextInfo {

	private final FGVertex activeVertex;
	private final AddressSet hoveredVertexAddresses;
	private final AddressSet selectedVertexAddresses;
	private final Set<FGVertex> selectedVertices;

	protected VertexActionContextInfo(FGVertex activeVertex) {
		this(activeVertex, Collections.emptySet());
	}

	public VertexActionContextInfo(FGVertex activeVertex, Set<FGVertex> selectedVertices) {
		this(activeVertex, selectedVertices, new AddressSet(), new AddressSet());
	}

	public VertexActionContextInfo(FGVertex activeVertex, Set<FGVertex> selectedVertices,
			AddressSet hoveredVertexAddresses, AddressSet selectedVertexAddresses) {
		this.activeVertex = activeVertex;
		this.selectedVertices = selectedVertices;
		this.hoveredVertexAddresses = hoveredVertexAddresses;
		this.selectedVertexAddresses = selectedVertexAddresses;
	}

	public FGVertex getActiveVertex() {
		return activeVertex;
	}

	public Set<FGVertex> getSelectedVertices() {
		return selectedVertices;
	}

	public AddressSet getHoveredVertexAddresses() {
		return hoveredVertexAddresses;
	}

	public AddressSet getSelectedVertexAddresses() {
		return selectedVertexAddresses;
	}
}
