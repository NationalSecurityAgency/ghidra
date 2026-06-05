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

import datagraph.graph.explore.AbstractExplorationGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;

/**
 * A graph for exploring data and its incoming and outgoing references.
 */
public class DataExplorationGraph extends AbstractExplorationGraph<DegVertex, DegEdge> {

	private VisualGraphLayout<DegVertex, DegEdge> layout;

	/**
	 * The initial vertex for the graph. All other vertices in this graph can trace back its source
	 * to this vertex.
	 * @param root the initial source vertex for this explore graph
	 */
	public DataExplorationGraph(DegVertex root) {
		super(root);
	}

	@Override
	public VisualGraphLayout<DegVertex, DegEdge> getLayout() {
		return layout;
	}

	@Override
	public DataExplorationGraph copy() {
		DataExplorationGraph newGraph = new DataExplorationGraph(getRoot());

		for (DegVertex v : vertices.keySet()) {
			newGraph.addVertex(v);
		}

		for (DegEdge e : edges.keySet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

	void setLayout(VisualGraphLayout<DegVertex, DegEdge> layout) {
		this.layout = layout;
	}

}
