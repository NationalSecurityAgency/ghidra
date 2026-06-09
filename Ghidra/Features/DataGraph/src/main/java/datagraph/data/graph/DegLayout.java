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
package datagraph.data.graph;

import java.util.Comparator;

import datagraph.graph.explore.EgEdgeTransformer;
import datagraph.graph.explore.EgGraphLayout;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;

/**
 * The layout for the DataExplorationGraph. It extends the {@link EgGraphLayout} the implements
 * the basic incoming and outgoing tree structures. This basically just adds the ordering logic
 * for vertices.
 */
public class DegLayout extends EgGraphLayout<DegVertex, DegEdge> {

	protected DegLayout(DataExplorationGraph g, int verticalGap, int horizontalGap) {
		super(g, "Data Graph Layout", verticalGap, horizontalGap);
	}

	@Override
	public DataExplorationGraph getVisualGraph() {
		return (DataExplorationGraph) getGraph();
	}

	@Override
	public AbstractVisualGraphLayout<DegVertex, DegEdge> createClonedLayout(
			VisualGraph<DegVertex, DegEdge> newGraph) {
		if (!(newGraph instanceof DataExplorationGraph dataGraph)) {
			throw new IllegalArgumentException(
				"Must pass a " + DataExplorationGraph.class.getSimpleName() +
					"to clone the " + getClass().getSimpleName());
		}

		DegLayout newLayout = new DegLayout(dataGraph, verticalGap, horizontalGap);
		return newLayout;
	}

	@Override
	protected Comparator<DegVertex> getIncommingVertexComparator() {
		return (v1, v2) -> v1.getAddress().compareTo(v2.getAddress());
	}

	@Override
	protected Comparator<DegVertex> getOutgoingVertexComparator() {
		return (v1, v2) -> {
			DegVertex parent = (DegVertex) v1.getSourceVertex();
			return parent.compare(v1, v2);
		};
	}

	@Override
	protected EgEdgeTransformer<DegVertex, DegEdge> createEdgeTransformer() {
		return new EgEdgeTransformer<>();
	}
}
