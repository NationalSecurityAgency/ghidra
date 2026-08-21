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
package datagraph;

import java.util.Set;

import datagraph.data.graph.DegEdge;
import datagraph.data.graph.DegVertex;
import docking.ActionContext;
import ghidra.graph.viewer.actions.VgVertexContext;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;

/**
 * {@link ActionContext} for the data exploration graph.
 */
public class DegContext extends VgVertexContext<DegVertex> {

	private Set<DegVertex> selectedVertices;

	public DegContext(DataGraphProvider dataGraphProvider, DegVertex targetVertex,
			Set<DegVertex> selectedVertices) {
		this(dataGraphProvider, targetVertex, selectedVertices, null);
	}

	public DegContext(DataGraphProvider dataGraphProvider,
			DegVertex targetVertex, Set<DegVertex> selectedVertices,
			VertexMouseInfo<DegVertex, DegEdge> vertexMouseInfo) {
		super(dataGraphProvider, targetVertex);
		this.selectedVertices = selectedVertices;
	}

	public Set<DegVertex> getSelectedVertices() {
		return selectedVertices;
	}

	@Override
	public boolean shouldShowSatelliteActions() {
		return getVertex() == null;
	}

}
