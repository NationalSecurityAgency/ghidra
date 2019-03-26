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

import java.util.*;

import ghidra.graph.*;

/**
 * Processes the given graph depth first and records that order of the vertices.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class DepthFirstSorter<V, E extends GEdge<V>> {

	/**
	 * Returns the vertices of the given graph in post-order, which is the order the vertices
	 * are last visited when performing a depth-first traversal.
	 * 
	 * @param g the graph
	 * @return the vertices in post-order
	 */
	public static <V, E extends GEdge<V>> List<V> postOrder(GDirectedGraph<V, E> g) {
		return postOrder(g, GraphNavigator.topDownNavigator());
	}

	/**
	 * Returns the vertices of the given graph in post-order, which is the order the vertices
	 * are last visited when performing a depth-first traversal.
	 * 
	 * @param g the graph
	 * @param navigator the knower of the direction the graph should be traversed
	 * @return the vertices in post-order
	 */
	public static <V, E extends GEdge<V>> List<V> postOrder(GDirectedGraph<V, E> g,
			GraphNavigator<V, E> navigator) {

		DepthFirstSorter<V, E> sorter = new DepthFirstSorter<>(g, navigator);
		List<V> list = sorter.getVerticesPostOrder();
		sorter.dispose();
		return list;
	}

	/**
	 * Returns the vertices of the given graph in pre-order, which is the order the vertices
	 * are encountered when performing a depth-first traversal.
	 * 
	 * @param g the graph
	 * @return the vertices in pre-order
	 */
	public static <V, E extends GEdge<V>> List<V> preOrder(GDirectedGraph<V, E> g) {
		return preOrder(g, GraphNavigator.topDownNavigator());
	}

	/**
	 * Returns the vertices of the given graph in pre-order, which is the order the vertices
	 * are encountered when performing a depth-first traversal.
	 * 
	 * @param g the graph
	 * @param navigator the knower of the direction the graph should be traversed
	 * @return the vertices in pre-order
	 */
	public static <V, E extends GEdge<V>> List<V> preOrder(GDirectedGraph<V, E> g,
			GraphNavigator<V, E> navigator) {

		DepthFirstSorter<V, E> sorter = new DepthFirstSorter<>(g, navigator);
		List<V> list = sorter.getVerticesPreOrder();
		sorter.dispose();
		return list;
	}

//==================================================================================================
// Instance Code
//==================================================================================================	

	private GDirectedGraph<V, E> g;
	GraphNavigator<V, E> navigator;
	private LinkedHashSet<V> visited;

	private DepthFirstSorter(GDirectedGraph<V, E> g, GraphNavigator<V, E> navigator) {
		this.g = g;
		this.navigator = navigator;
		int vertexCount = g.getVertexCount();
		visited = new LinkedHashSet<>(vertexCount);
	}

	private List<V> getVerticesPostOrder() {
		Set<V> seeds = navigator.getSources(g);
		for (V v : seeds) {
			postOrderVisit(v);
		}

		for (V v : g.getVertices()) {
			if (!visited.contains(v)) {
				postOrderVisit(v);
			}
		}
		return new ArrayList<>(visited);
	}

	private List<V> getVerticesPreOrder() {
		Set<V> seeds = GraphAlgorithms.getSources(g);
		for (V v : seeds) {
			preOrderVisit(v);
		}

		for (V v : g.getVertices()) {
			if (!visited.contains(v)) {
				preOrderVisit(v);
			}
		}
		return new ArrayList<>(visited);
	}

	private void postOrderVisit(V v) {
		if (visited.contains(v)) {
			return;
		}

		visited.add(v);

		Collection<V> successors = navigator.getSuccessors(g, v);
		for (V child : successors) {
			postOrderVisit(child);
		}

		// remove/put back here to update traversal order to be post-order
		visited.remove(v);
		visited.add(v);
	}

	private void preOrderVisit(V v) {
		if (visited.contains(v)) {
			return;
		}

		visited.add(v);

		Collection<V> successors = navigator.getSuccessors(g, v);
		for (V child : successors) {
			preOrderVisit(child);
		}
	}

	private void dispose() {
		visited.clear();
	}
}
