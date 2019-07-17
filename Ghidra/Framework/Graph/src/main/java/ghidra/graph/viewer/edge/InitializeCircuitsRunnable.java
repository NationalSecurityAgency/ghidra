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
package ghidra.graph.viewer.edge;

import java.util.*;

import ghidra.graph.*;
import ghidra.graph.viewer.*;
import ghidra.util.task.SwingRunnable;
import ghidra.util.task.TaskMonitor;

/**
 * A task to find all the loops in a graph.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 * @param <G> the graph type
 */
//@formatter:off
public class InitializeCircuitsRunnable<V extends VisualVertex, 
                                        E extends VisualEdge<V>, 
                                        G extends VisualGraph<V, E>>
		implements SwingRunnable {
//@formatter:on

	private final VisualGraph<V, E> graph;
	private final Set<E> allCircuitResults;
	private final Map<V, Set<E>> circuitFlowResults;
	private VisualGraphView<V, E, G> view;

	public InitializeCircuitsRunnable(VisualGraphView<V, E, G> view, VisualGraph<V, E> graph) {
		this.view = Objects.requireNonNull(view);
		this.graph = graph;
		this.allCircuitResults = new HashSet<>();
		this.circuitFlowResults = new HashMap<>();
	}

	@Override
	public void monitoredRun(TaskMonitor monitor) {
		monitor.setMessage("Finding all loops");

		Set<Set<V>> strongs = GraphAlgorithms.getStronglyConnectedComponents(graph);

		for (Set<V> vertices : strongs) {
			if (vertices.size() == 1) {
				continue;
			}

			GDirectedGraph<V, E> subGraph = GraphAlgorithms.createSubGraph(graph, vertices);

			Collection<E> edges = subGraph.getEdges();
			allCircuitResults.addAll(edges);

			HashSet<E> asSet = new HashSet<>(edges);
			Collection<V> subVertices = subGraph.getVertices();
			for (V v : subVertices) {
				circuitFlowResults.put(v, asSet);
			}
		}
	}

	@Override
	public void swingRun(boolean isCancelled) {
		if (isCancelled) {
			return;
		}

		// TODO delete this class...now!
//		GraphViewer<V, E> viewer = view.getPrimaryGraphViewer();
//		VisualGraphPathHighlighter<V, E> pathHighlighter = viewer.getPathHighlighter();
//		pathHighlighter.setEdgeCircuits(allCircuitResults, circuitFlowResults);
//		view.repaint();
	}
}
