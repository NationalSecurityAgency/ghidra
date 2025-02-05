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
package ghidra.graph;

import java.util.*;

import org.apache.commons.collections4.map.LazyMap;

import ghidra.graph.jung.JungDirectedGraph;

/**
 * This class provides an algorithm for topological graph sorting and an algorithm for using
 * that topological sort to create a tree structure from the graph using that topological sort.
 * <P>
 * In general topological sorting and converting to a tree, require an acyclic graph. However,
 * by supplying a root vertex, the graph can be made to be acyclic by traversing the graph from 
 * that root and discarding any edges the return to a "visited" vertex. This has a side effect of
 * ignoring any nodes that are not reachable from the root node. Also, this algorithm class is 
 * constructed with an edge comparator which can also determine the order nodes are traversed,
 * thereby affecting the final ordering or tree structure. Higher priority edges will be processed
 * first, making those edges least likely to be removed as "back" edges.
 * <P>
 * To convert a general graph to a tree, some subset of the the graphs original edges are used to
 * form the tree. There are many possible different trees that can be created in this way. This
 * algorimth's goal is to create a tree such that if all the original "forward" edges are added 
 * back to the tree, they only flow down the tree. This is useful for creating a nicely organized
 * layout of vertices and edges when drawn.
 * 
 * @param <V> The vertex type
 * @param <E> The edge type
 */
public class GraphToTreeAlgorithm<V, E extends GEdge<V>> {
	private GDirectedGraph<V, E> graph;
	private Comparator<E> edgeComparator;

	/**
	 * Constructor.
	 * 
	 * @param graph the graph from with to create a tree
	 * @param edgeComparator provides a priority ordering of edges with higher priority edges 
	 * getting first shot at claiming children for its sub-tree.
	 */
	public GraphToTreeAlgorithm(GDirectedGraph<V, E> graph, Comparator<E> edgeComparator) {
		this.graph = graph;
		this.edgeComparator = edgeComparator;
	}

	/**
	 * Creates a tree graph with the given vertex as the root from this object's graph.
	 * 
	 * @param root the vertex to be used as the root
	 * getting first shot at claiming children for its sub-tree.
	 * @return a graph with edges removed such that the graph is a tree.
	 */
	public GDirectedGraph<V, E> toTree(V root) {

		// first sort the vertices topologically
		List<V> sorted = topolocigalSort(root);

		// Visit nodes in the sorted order and track the longest path to each node from the root.
		Map<V, Depth> depthMap = assignDepths(root, sorted);

		// Assign vertices to the tree in the sorted order and only using edges where the "from"
		// vertex (parent) is at a depth 1 less then the depth of "to" vertex. This will ensure
		// that the tree is ordered such that if all the original forward edges are added back in,
		// they would always flow down the tree.
		return createTree(root, sorted, depthMap);

	}

	/**
	 * Sorts the vertices in this graph topologically.
	 * 
	 * @param root the start node for traversing the graph (will always be the first node in the
	 * resulting list)
	 * @return a list of vertices reachable from the given root vertex, sorted topologically
	 */
	public List<V> topolocigalSort(V root) {

		Set<V> visited = new HashSet<>();
		List<V> ordered = new ArrayList<>();

		Deque<VertexChildIterator> stack = new ArrayDeque<>();

		stack.push(new VertexChildIterator(root));
		visited.add(root);

		while (!stack.isEmpty()) {
			VertexChildIterator childIterator = stack.getFirst();
			if (childIterator.hasNext()) {
				V child = childIterator.next();

				// only process the child if never seen before, otherwise it is a loop back
				if (!visited.contains(child)) {
					stack.push(new VertexChildIterator(child));
					visited.add(child);
				}
			}
			else {
				ordered.add(childIterator.getParent());
				stack.pop();
			}
		}
		Collections.reverse(ordered);
		return ordered;
	}

	private JungDirectedGraph<V, E> createTree(V root, List<V> sorted, Map<V, Depth> depthMap) {
		Set<V> visited = new HashSet<>();
		visited.add(root);

		JungDirectedGraph<V, E> tree = new JungDirectedGraph<V, E>();
		for (V v : sorted) {
			tree.addVertex(v);
		}

		for (V parent : sorted) {
			Depth parentDepth = depthMap.get(parent);
			Collection<E> outEdges = graph.getOutEdges(parent);
			for (E e : outEdges) {
				V child = e.getEnd();
				if (visited.contains(child)) {
					continue;  // already assigned
				}
				Depth childDepth = depthMap.get(child);
				if (childDepth.isDirectChildOf(parentDepth)) {
					tree.addEdge(e);
					visited.add(child);
				}
			}
		}
		return tree;
	}

	private Map<V, Depth> assignDepths(V root, List<V> sorted) {

		Set<V> visited = new HashSet<>();
		Map<V, Depth> depthMap = LazyMap.lazyMap(new HashMap<>(), k -> new Depth());

		depthMap.put(root, new Depth());
		for (V parent : sorted) {
			visited.add(parent);
			Depth parentDepth = depthMap.get(parent);
			List<E> edges = new ArrayList<>();
			Collection<E> out = graph.getOutEdges(parent);
			if (out != null) {
				edges.addAll(out);
			}
			edges.sort(edgeComparator);
			for (E e : edges) {
				V child = e.getEnd();
				if (visited.contains(child)) {
					continue;		// loop backs are ignored
				}
				Depth childDepth = depthMap.get(child);
				childDepth.adjustDepth(parentDepth);
			}
		}
		return depthMap;
	}

	// traces the distance from the root of the tree
	private static class Depth {
		private int depth = 0;

		private void adjustDepth(Depth parentDepth) {
			depth = Math.max(depth, parentDepth.depth + 1);
		}

		private boolean isDirectChildOf(Depth parentDepth) {
			return depth == parentDepth.depth + 1;
		}
	}

	private class VertexChildIterator {
		private V parent;
		private Iterator<E> it;

		VertexChildIterator(V parent) {
			this.parent = parent;
			Collection<E> out = graph.getOutEdges(parent);
			List<E> outEdges = new ArrayList<>();
			if (out != null) {
				outEdges.addAll(out);
			}
			outEdges.sort(edgeComparator);
			it = outEdges.reversed().iterator();
		}

		V getParent() {
			return parent;
		}

		public boolean hasNext() {
			return it.hasNext();
		}

		public V next() {
			return it.next().getEnd();
		}
	}

}
