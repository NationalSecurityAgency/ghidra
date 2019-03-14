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
package ghidra.graph.algo;

import java.util.Set;

import ghidra.graph.GEdge;
import ghidra.graph.MutableGDirectedGraphWrapper;
import util.CollectionUtils;

/**
 * A general base class for sharing code between graph algorithm implementations.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
abstract class AbstractDominanceAlgorithm<V, E extends GEdge<V>> {

	private static final String DUMMY_ROOT_NAME = "Dummy Root Vertex";
	private static final String DUMMY_SINK_NAME = "Dummy Sink Vertex";

	/**
	 * Converts multiple source/root nodes in a graph into a single source of which those become
	 * children.
	 * 
	 * @param graph the graph
	 * @param graphNavigator the navigator to determine graph direction
	 * @return the new single source
	 * @throws IllegalArgumentException if there is not at least one source node in the graph
	 */
	protected static <V, E extends GEdge<V>> V unifySources(
			MutableGDirectedGraphWrapper<V, E> graph, GraphNavigator<V, E> graphNavigator) {

		//
		//							Unusual Code Alert!
		// This method engages in some chicanery.  We may need to update the graph, in the case
		// where there are multiple roots.  In that case, we need to add vertices and edges to
		// our graph.  The issue is that whatever we create will not be of the same type that
		// is in the graph, since we don't know how to create a V or E.  So, just add an 
		// object of our choosing and feel confident that we are the only user of the newly
		// 'forced-in' types.
		//
		// The warnings that arise from this code are suppressed below.
		//

		Set<V> sources = graphNavigator.getSources(graph);
		if (sources.isEmpty()) {
			throw new IllegalArgumentException(
				"The graph does not contain at least one source node");
		}

		if (sources.size() == 1) {
			return CollectionUtils.any(sources);
		}

		// Turn the sources into children of a single root.
		V dummy = graph.addDummyVertex(DUMMY_ROOT_NAME);
		sources.forEach(s -> {
			if (graphNavigator.isTopDown()) {
				graph.addDummyEdge(dummy, s);
			}
			else {
				graph.addDummyEdge(s, dummy);
			}
		});
		return dummy;
	}

	/**
	 * Converts multiple sink/exit nodes in a graph into a single sink of which those become
	 * parents.
	 * 
	 * @param graph the graph
	 * @param graphNavigator the navigator to determine graph direction
	 * @return the new single sink
	 * @throws IllegalArgumentException if there is not at least one sink node in the graph
	 */
	protected static <V, E extends GEdge<V>> V unifySinks(MutableGDirectedGraphWrapper<V, E> graph,
			GraphNavigator<V, E> graphNavigator) {

		Set<V> sinks = graphNavigator.getSinks(graph);
		if (sinks.isEmpty()) {
			throw new IllegalArgumentException("The graph does not contain at least one sink node");
		}

		if (sinks.size() == 1) {
			return sinks.iterator().next();
		}

		// Turn the sinks into children of a single sink.
		V dummy = graph.addDummyVertex(DUMMY_SINK_NAME);
		sinks.forEach(s -> {

			if (graphNavigator.isTopDown()) {
				graph.addDummyEdge(s, dummy);
			}
			else {
				graph.addDummyEdge(dummy, s);
			}
		});
		return dummy;
	}

}
