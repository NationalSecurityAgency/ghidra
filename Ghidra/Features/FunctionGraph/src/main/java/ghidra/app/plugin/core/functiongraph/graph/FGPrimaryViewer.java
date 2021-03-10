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
package ghidra.app.plugin.core.functiongraph.graph;

import java.awt.Dimension;
import java.util.Set;

import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertexTooltipProvider;
import ghidra.graph.*;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.PathHighlightListener;
import ghidra.graph.viewer.edge.VisualGraphPathHighlighter;
import ghidra.graph.viewer.layout.VisualGraphLayout;

public class FGPrimaryViewer extends GraphViewer<FGVertex, FGEdge> {

	FGPrimaryViewer(FGComponent graphComponent, VisualGraphLayout<FGVertex, FGEdge> layout,
			Dimension size) {
		super(layout, size);

		setVertexTooltipProvider(new FGVertexTooltipProvider());
	}

	@Override
	protected VisualGraphViewUpdater<FGVertex, FGEdge> createViewUpdater() {
		return new FGViewUpdater(this, getVisualGraph());
	}

	// Overridden so that we can install our own path highlighter that knows how to work around
	// source/sink vertices that have been grouped.  This allows us to use dominance algorithms
	// that require sources/sinks
	@Override
	protected VisualGraphPathHighlighter<FGVertex, FGEdge> createPathHighlighter(
			PathHighlightListener listener) {

		return new VisualGraphPathHighlighter<>(getVisualGraph(), listener) {

			@Override
			protected GDirectedGraph<FGVertex, FGEdge> getDominanceGraph(
					VisualGraph<FGVertex, FGEdge> graph, boolean forward) {

				Set<FGVertex> sources =
					forward ? GraphAlgorithms.getSources(graph) : GraphAlgorithms.getSinks(graph);
				if (!sources.isEmpty()) {
					return graph;
				}

				FunctionGraph functionGraph = (FunctionGraph) graph;
				Set<FGEdge> dummyEdges =
					forward ? functionGraph.createDummySources() : functionGraph.createDummySinks();
				MutableGDirectedGraphWrapper<FGVertex, FGEdge> modifiedGraph =
					new MutableGDirectedGraphWrapper<>(graph);
				for (FGEdge e : dummyEdges) {
					modifiedGraph.addEdge(e);
				}
				return modifiedGraph;
			}
		};
	}
}
