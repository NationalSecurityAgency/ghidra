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
package ghidra.examples.graph;

import ghidra.graph.graphs.FilteringVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;

/**
 * A graph for the {@link SampleGraphPlugin} that allows for filtering
 */
public class SampleGraph extends FilteringVisualGraph<SampleVertex, SampleEdge> {

	private VisualGraphLayout<SampleVertex, SampleEdge> layout;

	@Override
	public VisualGraphLayout<SampleVertex, SampleEdge> getLayout() {
		return layout;
	}

	@Override
	public SampleGraph copy() {
		SampleGraph newGraph = new SampleGraph();

		for (SampleVertex v : vertices.keySet()) {
			newGraph.addVertex(v);
		}

		for (SampleEdge e : edges.keySet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

	void setLayout(VisualGraphLayout<SampleVertex, SampleEdge> layout) {
		this.layout = layout;
	}
}
