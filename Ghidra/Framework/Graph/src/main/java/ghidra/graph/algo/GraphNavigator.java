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

import static util.CollectionUtils.*;

import java.util.*;

import ghidra.graph.*;

/**
 * The methods on this interface are meant to enable graph traversal in a way that allows 
 * the underlying graph to be walked from top-down or bottom-up.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class GraphNavigator<V, E extends GEdge<V>> {

	private boolean isTopDown;

	/**
	 * Creates a top-down navigator, which is one that traverses the graph from the source
	 * to the sink.
	 * 
	 * @return the navigator
	 */
	public static <V, E extends GEdge<V>> GraphNavigator<V, E> topDownNavigator() {
		return new GraphNavigator<>(true);
	}

	/**
	 * Creates a bottom-down navigator, which is one that traverses the graph from the sink 
	 * to the source.
	 * 
	 * @return the navigator
	 */
	public static <V, E extends GEdge<V>> GraphNavigator<V, E> bottomUpNavigator() {
		return new GraphNavigator<>(false);
	}

	private GraphNavigator(boolean isTopDown) {
		this.isTopDown = isTopDown;
	}

	/**
	 * Gets all edges leaving the given vertex, depending upon the direction of this navigator.
	 * 
	 * @param graph the graph
	 * @param v the vertex
	 * @return the edges
	 */
	public Collection<E> getEdges(GDirectedGraph<V, E> graph, V v) {
		if (isTopDown) {
			return asCollection(graph.getOutEdges(v));
		}
		return asCollection(graph.getInEdges(v));
	}

	/**
	 * Returns true if this navigator processes nodes from the top down; false if nodes are
	 * processed from the bottom up.
	 * 
	 * @return true if this navigator processes nodes from the top down; false if nodes are
	 * 		   processed from the bottom up.
	 */
	public boolean isTopDown() {
		return isTopDown;
	}

	/**
	 * Gets all child vertices of the given vertex, depending upon the direction of the 
	 * navigator.
	 * 
	 * @param graph the graph
	 * @param v the vertex 
	 * @return the vertices
	 */
	public Collection<V> getSuccessors(GDirectedGraph<V, E> graph, V v) {
		if (isTopDown) {
			return graph.getSuccessors(v);
		}
		return graph.getPredecessors(v);
	}

	/**
	 * Gets all parent vertices of the given vertex, depending upon the direction of the 
	 * navigator.
	 * 
	 * @param graph the graph
	 * @param v the vertex 
	 * @return the vertices
	 */
	public Collection<V> getPredecessors(GDirectedGraph<V, E> graph, V v) {
		if (isTopDown) {
			return asCollection(graph.getPredecessors(v));
		}
		return asCollection(graph.getSuccessors(v));
	}

	/**
	 * Gets the vertex at the end of the given edge, where the 'end' of the edge depends on the
	 * start vertex.
	 * 
	 * @param e the edge
	 * @return the vertex
	 */
	public V getEnd(E e) {
		if (isTopDown) {
			return e.getEnd();
		}
		return e.getStart();
	}

	/**
	 * Gets the root vertices of the given graph.  If this is a top-down navigator, then the
	 * sources are returned; otherwise, the sinks are returned.
	 * 
	 * @param graph the graph
	 * @return the roots
	 */
	public Set<V> getSources(GDirectedGraph<V, E> graph) {
		if (isTopDown) {
			return asSet(GraphAlgorithms.getSources(graph));
		}
		return asSet(GraphAlgorithms.getSinks(graph));
	}

	/**
	 * Gets the exit vertices of the given graph.  If this is a top-down navigator, then the
	 * sinks are returned; otherwise, the sources are returned.
	 * 
	 * @param graph the graph
	 * @return the exits
	 */
	public Set<V> getSinks(GDirectedGraph<V, E> graph) {
		if (isTopDown) {
			return asSet(GraphAlgorithms.getSinks(graph));
		}
		return asSet(GraphAlgorithms.getSources(graph));
	}

	/**
	 * Returns all vertices in the given graph in the depth-first order.   The order will 
	 * be post-order for a top-down navigator and pre-order for a bottom-up navigator.
	 * 
	 * @param graph the graph
	 * @return the ordered vertices
	 */
	public List<V> getVerticesInPostOrder(GDirectedGraph<V, E> graph) {
		List<V> postOrder = asList(GraphAlgorithms.getVerticesInPostOrder(graph, this));
		return postOrder;
	}
}
