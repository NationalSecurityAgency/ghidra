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
 * Computes a topological sorting of the vertices in a directed acyclic graph (DAG)
 * 
 * <p>
 * This produces a list of vertices in the graph s.t. for every pair (v, w) where v precedes w, it
 * can never be the case that the edge w -> v exists in the graph. Optionally, this sorter may also
 * require that the list is unique. Here are some examples:
 * 
 * <p>
 * A-->B-->C yields simply [A, B, C]
 * 
 * <p>
 * A, B-->C yields either [A, B, C], [B, A, C], or [B, C, A] If a total ordering is required, this
 * example causes the algorithm to fail, since the solution is not unique.
 * 
 * <p>
 * A-->B-->C-->A fails always, because the graph contains a cycle, i.e., not a DAG.
 * 
 * <p>
 * A-->B-->D, A-->C-->D yields either [A, B, C, D] or [A, C, B, D]
 * 
 * @see {@link https://en.wikipedia.org/wiki/Topological_sorting}
 */
public class TopologicalSorter<V, E extends GEdge<V>> {
	private final GDirectedGraph<V, E> graph;
	private boolean requireTotal;
	private final LinkedList<V> list;
	private final Deque<V> unmarked;

	/**
	 * Apply a topological sort to the given graph
	 * 
	 * @param graph the graph
	 * @param requireTotal true to require a unique solution
	 * @note if a unique solution is not requested, this algorithm will choose a solution
	 *       arbitrarily. It does not yield all possible solutions.
	 */
	public TopologicalSorter(GDirectedGraph<V, E> graph, boolean requireTotal) {
		this.graph = graph;
		this.requireTotal = requireTotal;
		this.list = new LinkedList<>();
		this.unmarked = new LinkedList<>(graph.getVertices());
	}

	/**
	 * Execute the algorithm an obtain the list of vertices, in topological order
	 * 
	 * @return the sorted list of vertices
	 * @throws SorterException if the graph is cyclic, or if {@code requireTotal} is set and the
	 *             solution is not unique.
	 */
	public List<V> sort() throws SorterException {
		if (requireTotal) {
			checkTotal();
		}
		while (true) {
			V n = unmarked.peek();
			if (n == null) { // Will also cause future calls to sort() to short-circuit :)
				return list;
			}
			visit(n);
		}
	}

	/**
	 * Check that the solution is unique
	 * 
	 * @throws SorterException if the solution is not unique
	 */
	protected void checkTotal() throws SorterException {
		// This is probably not the most efficient, but this should only be once per message type
		DijkstraShortestPathsAlgorithm<V, E> dijkstra =
			new DijkstraShortestPathsAlgorithm<>(graph, GEdgeWeightMetric.unitMetric());
		for (V v1 : graph.getVertices()) {
			for (V v2 : graph.getVertices()) { // Maybe look into spliterator? to avoid double check
				Double distF = dijkstra.getDistancesFromSource(v1).get(v2);
				Double distR = dijkstra.getDistancesFromSource(v2).get(v1);
				if (distF == null && distR == null) {
					throw new SorterException("Not a total order", v1, v2);
				}
			}
		}
	}

	/**
	 * Visit a vertex
	 * 
	 * @param n the vertex
	 * @throws SorterException if a cycle is detected
	 */
	protected void visit(V n) throws SorterException {
		visit(n, new LinkedList<>());
	}

	/**
	 * Visit a vertex, checking for a cycle
	 * 
	 * @param n the vertex
	 * @param temp a list of previously-visited vertices on this path
	 * @throws SorterException if a cycle is detected
	 */
	protected void visit(V n, Deque<V> temp) throws SorterException {
		if (temp.contains(n)) {
			throw new SorterException("Graph is cyclic", temp);
		}
		if (unmarked.contains(n)) {
			temp.push(n);
			try {
				for (V m : graph.getSuccessors(n)) {
					visit(m, temp);
				}
				unmarked.remove(n);
			}
			finally {
				temp.pop();
			}
			list.push(n);
		}
	}
}
