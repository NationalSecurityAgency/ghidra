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

import java.io.PrintStream;
import java.util.*;
import java.util.stream.Collectors;

import ghidra.graph.algo.*;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.TimeoutException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import util.CollectionUtils;

/**
 * A set of convenience methods for performing graph algorithms on a graph.
 * 
 * <P>Some definitions:
 * <OL>
 * 	   <LI>
 * 		<B>dominance:</B> 
 * 					a node 'a' dominates node 'b' if all paths from start to 'b' contain 'a';
 *		            a node always dominates itself (except in 'strict dominance', which is all
 *		            dominators except for itself)
 *
 *	   <LI>
 *		<B>post-dominance:</B> 
 *					 A node 'b' is said to post-dominate node 'a' if all paths from 'a'
 *		             to END contain 'b'
 *
 *	   <LI>
 *		<B>immediate dominator:</B> 
 *					the closest dominator of a node
 *
 *	   <LI>
 *		<B>dominance tree:</B>  
 *					A dominator tree is a tree where each node's children are those nodes 
 *					it *immediately* dominates (a idom b)
 *
 *     <LI>
 *     	<B>dominance frontier:</B> 
 *     				the immediate successors of the nodes dominated by 'a'; it is the set of 
 *     				nodes where d's dominance stops.
 *     
 *     <LI>
 *     	<B>strongly connected components:</B> 
 *     				a graph is said to be strongly connected if every vertex is reachable 
 *     				from every other vertex. The strongly connected components 
 *     				of an arbitrary directed graph form a partition into 
 *     				subgraphs that are themselves strongly connected.
 *     <LI>
 *     	<B>graph density:</B>
 *     <PRE>
 *                        E
 *          Density =  --------
 *                      V(V-1)
 *		</PRE>
 * </OL>
 */
public class GraphAlgorithms {

	private GraphAlgorithms() {
		// utils; can't create
	}

	/**
	 * Returns all source vertices (those with no incoming edges) in the graph.
	 * 
	 * @param g the graph
	 * @return source vertices
	 */
	public static <V, E extends GEdge<V>> Set<V> getSources(GDirectedGraph<V, E> g) {

		Set<V> sources = new HashSet<>();
		Collection<V> vertices = g.getVertices();
		for (V v : vertices) {
			Collection<E> inEdges = g.getInEdges(v);
			if (inEdges.isEmpty()) {
				sources.add(v);
			}
		}

		return sources;
	}

	/**
	 * Returns all sink vertices (those with no outgoing edges) in the graph.
	 * 
	 * @param g the graph
	 * @return sink vertices
	 */
	public static <V, E extends GEdge<V>> Set<V> getSinks(GDirectedGraph<V, E> g) {

		Set<V> sinks = new HashSet<>();
		Collection<V> vertices = g.getVertices();
		for (V v : vertices) {
			Collection<E> outEdges = g.getOutEdges(v);
			if (outEdges.isEmpty()) {
				sinks.add(v);
			}
		}

		return sinks;
	}

	/**
	 * Returns all descendants for the given vertices in the given graph.  Descendants for a given
	 * vertex are all nodes at the outgoing side of an edge, as well as their outgoing 
	 * vertices, etc.
	 * 
	 * @param g the graph
	 * @param vertices the vertices for which to find descendants
	 * @return the descendants
	 */
	public static <V, E extends GEdge<V>> Set<V> getDescendants(GDirectedGraph<V, E> g,
			Collection<V> vertices) {

		Set<E> edges = getEdgesFrom(g, vertices, true);
		Set<V> descendants = toVertices(edges);
		return descendants;
	}

	/**
	 * Returns all ancestors for the given vertices in the given graph.  Ancestors for a given
	 * vertex are all nodes at the incoming side of an edge, as well as their incoming 
	 * vertices, etc.
	 * 
	 * @param g the graph
	 * @param vertices the vertices for which to find descendants
	 * @return the ancestors
	 */
	public static <V, E extends GEdge<V>> Set<V> getAncestors(GDirectedGraph<V, E> g,
			Collection<V> vertices) {

		Set<E> edges = getEdgesFrom(g, vertices, false);
		Set<V> ancestors = toVertices(edges);
		return ancestors;
	}

	/**
	 * Returns a set of all edges that are reachable from the given vertex.
	 * 
	 * @param g the graph
	 * @param v the vertex for which to get edges
	 * @param topDown true for outgoing edges; false for incoming edges
	 * @return the set of edges
	 */
	public static <V, E extends GEdge<V>> Set<E> getEdgesFrom(GDirectedGraph<V, E> g, V v,
			boolean topDown) {

		List<V> list = Arrays.asList(v);
		Set<E> edges = getEdgesFrom(g, list, topDown);
		return edges;
	}

	/**
	 * Returns a set of all edges that are reachable from the given collection of vertices.
	 * 
	 * @param g the graph
	 * @param vertices the vertices for which to get edges
	 * @param topDown true for outgoing edges; false for incoming edges
	 * @return the set of edges
	 */
	public static <V, E extends GEdge<V>> Set<E> getEdgesFrom(GDirectedGraph<V, E> g,
			Collection<V> vertices, boolean topDown) {

		GraphNavigator<V, E> navigator = null;
		if (topDown) {
			navigator = GraphNavigator.topDownNavigator();
		}
		else {
			navigator = GraphNavigator.bottomUpNavigator();
		}

		Set<E> edges = new HashSet<>();
		Set<V> newlyPending = new HashSet<>();

		Set<V> pending = new HashSet<>(vertices);
		while (!pending.isEmpty()) {
			for (V parent : pending) {

				Collection<E> outEdges = navigator.getEdges(g, parent);
				for (E e : outEdges) {
					V destination = navigator.getEnd(e);
					if (edges.add(e)) {
						newlyPending.add(destination);
					}
				}
			}
			pending = newlyPending;
			newlyPending = new HashSet<>();
		}
		return edges;
	}

	/**
	 * Creates a subgraph of the given graph for each edge of the given graph that is 
	 * contained in the list of vertices.
	 * 
	 * @param g the existing graph
	 * @param vertices the vertices to be in the new graph
	 * @return the new subgraph
	 */
	public static <V, E extends GEdge<V>> GDirectedGraph<V, E> createSubGraph(
			GDirectedGraph<V, E> g, Collection<V> vertices) {

		vertices = CollectionUtils.asSet(vertices); // ensure fast lookup

		GDirectedGraph<V, E> subGraph = g.emptyCopy();

		for (E e : g.getEdges()) {
			V start = e.getStart();
			V end = e.getEnd();
			if (vertices.contains(start) && vertices.contains(end)) {
				subGraph.addEdge(e);
			}
		}
		return subGraph;
	}

	/**
	 * Returns a list where each set therein is a strongly connected component of the given 
	 * graph.  Each strongly connected component is that in which each vertex is reachable from
	 * any other vertex in that set.
	 * 
	 * <P>This method can be used to determine reachability of a set of vertices.  
	 * 
	 * <P>This can also be useful for cycle detection, as a multi-vertex strong component 
	 * is by definition a cycle.  This method differs from 
	 * {@link #findCircuits(GDirectedGraph, boolean, TaskMonitor)} in that the latter will 
	 * return cycles within the strong components, or sub-cycles. 
	 * 
	 * @param g the graph
	 * @return the list of strongly connected components
	 */
	public static <V, E extends GEdge<V>> Set<Set<V>> getStronglyConnectedComponents(
			GDirectedGraph<V, E> g) {
		TarjanStronglyConnectedAlgorthm<V, E> algorithm = new TarjanStronglyConnectedAlgorthm<>(g);
		return algorithm.getConnectedComponents();
	}

	/**
	 * Returns all entry points in the given graph.  This includes sources, vertices which 
	 * have no incoming edges, as well as strongly connected sub-graphs.  The latter being a 
	 * group vertices where each vertex is reachable from every other vertex.  In the case of
	 * strongly connected components, we pick one of them arbitrarily to be the entry point.
	 * 
	 * @param g the graph
	 * @return the entry points into the graph
	 */
	public static <V, E extends GEdge<V>> Set<V> getEntryPoints(GDirectedGraph<V, E> g) {

		Set<V> sources = getSources(g);
		Set<V> descendants = getDescendants(g, sources);
		Set<V> isolatedVertices = new HashSet<>(g.getVertices());
		isolatedVertices.removeAll(sources);
		isolatedVertices.removeAll(descendants);

		Set<V> entryPoints = new HashSet<>(sources);
		if (isolatedVertices.isEmpty()) {
			// no unconnected vertices 
			return entryPoints;
		}

		GDirectedGraph<V, E> isolatedGraph = createSubGraph(g, isolatedVertices);
		Set<Set<V>> strongs = getStronglyConnectedComponents(isolatedGraph);

		for (Set<V> set : strongs) {
			if (isSelfContainedStrongComponent(g, set)) {
				// just pick one to be the entry point
				entryPoints.add(set.iterator().next());
			}
		}

		return entryPoints;
	}

	/**
	 * Returns the dominance tree of the given graph.  A dominator tree of the vertices where each 
	 * node's children are those nodes it *immediately* dominates (a idom b)
	 * 
	 * @param g the graph
	 * @param monitor the task monitor
	 * @return the tree
	 * @throws CancelledException if the monitor is cancelled
	 */
	public static <V, E extends GEdge<V>> GDirectedGraph<V, GEdge<V>> findDominanceTree(
			GDirectedGraph<V, E> g, TaskMonitor monitor) throws CancelledException {
		ChkDominanceAlgorithm<V, E> algorithm = new ChkDominanceAlgorithm<>(g, monitor);
		return algorithm.getDominanceTree();
	}

	/**
	 * Returns a set of all vertices that are dominated by the given vertex.  A node 'a' 
	 * dominates node 'b' if all paths from start to 'b' contain 'a';
	 * a node always dominates itself (except in 'strict dominance', which is all
	 * dominators except for itself)
	 * 
	 * @param g the graph
	 * @param from the vertex for which to find dominated vertices
	 * @param monitor the monitor
	 * @return the set of dominated vertices
	 * @throws CancelledException if the monitor is cancelled
	 */
	public static <V, E extends GEdge<V>> Set<V> findDominance(GDirectedGraph<V, E> g, V from,
			TaskMonitor monitor) throws CancelledException {

		ChkDominanceAlgorithm<V, E> algo = new ChkDominanceAlgorithm<>(g, monitor);
		Set<V> dominated = algo.getDominated(from);
		return dominated;
	}

	/**
	 * Returns a set of all vertices that are post-dominated by the given vertex.  A node 'b' 
	 * is said to post-dominate node 'a' if all paths from 'a' to END contain 'b'.
	 * 
	 * @param g the graph
	 * @param from the vertex for which to get post-dominated vertices
	 * @param monitor the monitor
	 * @return the post-dominated vertices
	 * @throws CancelledException if the monitor is cancelled
	 */
	public static <V, E extends GEdge<V>> Set<V> findPostDominance(GDirectedGraph<V, E> g, V from,
			TaskMonitor monitor) throws CancelledException {

		ChkPostDominanceAlgorithm<V, E> algo = new ChkPostDominanceAlgorithm<>(g, monitor);
		Set<V> postDominated = algo.getDominated(from);
		return postDominated;
	}

	/**
	 * Finds all the circuits, or cycles, in the given graph.
	 * 
	 * @param g the graph
	 * @param monitor the task monitor
	 * @return the circuits
	 * @throws CancelledException if the monitor is cancelled
	 */
	public static <V, E extends GEdge<V>> List<List<V>> findCircuits(GDirectedGraph<V, E> g,
			TaskMonitor monitor) throws CancelledException {
		return findCircuits(g, true, monitor);
	}

	/**
	 * Finds all the circuits, or cycles, in the given graph.
	 * 
	 * @param g the graph
	 * @param uniqueCircuits true signals to return only unique circuits, where no two 
	 *        circuits will contain the same vertex
	 * @param monitor the task monitor
	 * @return the circuits
	 * @throws CancelledException if the monitor is cancelled
	 */
	public static <V, E extends GEdge<V>> List<List<V>> findCircuits(GDirectedGraph<V, E> g,
			boolean uniqueCircuits, TaskMonitor monitor) throws CancelledException {

		ListAccumulator<List<V>> accumulator = new ListAccumulator<>();
		JohnsonCircuitsAlgorithm<V, E> algorithm = new JohnsonCircuitsAlgorithm<>(g, accumulator);
		algorithm.compute(uniqueCircuits, monitor);
		return accumulator.asList();
	}

	/**
	 * Finds all the circuits, or cycles, in the given graph.  <B>This version
	 * of <code>findCircuits()</code> takes a {@link TimeoutTaskMonitor}, which allows for the 
	 * client to control the duration of work.</B>   This is useful for finding paths on very
	 * large, dense graphs.
	 * 
	 * @param g the graph
	 * @param uniqueCircuits true signals to return only unique circuits, where no two 
	 *        circuits will contain the same vertex
	 * @param monitor the timeout task monitor
	 * @return the circuits
	 * @throws CancelledException if the monitor is cancelled
	 * @throws TimeoutException if the algorithm times-out, as defined by the monitor
	 */
	public static <V, E extends GEdge<V>> List<List<V>> findCircuits(GDirectedGraph<V, E> g,
			boolean uniqueCircuits, TimeoutTaskMonitor monitor)
			throws CancelledException, TimeoutException {

		ListAccumulator<List<V>> accumulator = new ListAccumulator<>();
		JohnsonCircuitsAlgorithm<V, E> algorithm = new JohnsonCircuitsAlgorithm<>(g, accumulator);
		algorithm.compute(uniqueCircuits, monitor);
		return accumulator.asList();
	}

	/**
	 * Finds all paths from <code>start</code> to <code>end</code> in the given graph.
	 * 
	 * <P><B><U>Warning:</U></B> for large, dense graphs (those with many interconnected 
	 * vertices) this algorithm could run indeterminately, possibly causing the JVM to 
	 * run out of memory.
	 * 
	 * <P>You are encouraged to call this method with a monitor that will limit the work to 
	 * be done, such as the {@link TimeoutTaskMonitor}.
	 *
	 * @param g the graph
	 * @param start the start vertex
	 * @param end the end vertex
	 * @param accumulator the accumulator into which results will be placed
	 * @param monitor the task monitor
	 * @throws CancelledException if the operation is cancelled
	 */
	public static <V, E extends GEdge<V>> void findPaths(GDirectedGraph<V, E> g, V start, V end,
			Accumulator<List<V>> accumulator, TaskMonitor monitor) throws CancelledException {

		IterativeFindPathsAlgorithm<V, E> algo = new IterativeFindPathsAlgorithm<>();
		algo.findPaths(g, start, end, accumulator, monitor);
	}

	/**
	 * Finds all paths from <code>start</code> to <code>end</code> in the given graph.  <B>This version
	 * of <code>findPaths()</code> takes a {@link TimeoutTaskMonitor}, which allows for the 
	 * client to control the duration of work.</B>   This is useful for finding paths on very
	 * large, dense graphs.
	 * 
	 * <P><B><U>Warning:</U></B> for large, dense graphs (those with many interconnected 
	 * vertices) this algorithm could run indeterminately, possibly causing the JVM to 
	 * run out of memory.
	 *
	 * @param g the graph
	 * @param start the start vertex
	 * @param end the end vertex
	 * @param accumulator the accumulator into which results will be placed
	 * @param monitor the timeout task monitor
	 * @throws CancelledException if the operation is cancelled
	 * @throws TimeoutException if the operation passes the timeout period
	 */
	public static <V, E extends GEdge<V>> void findPaths(GDirectedGraph<V, E> g, V start, V end,
			Accumulator<List<V>> accumulator, TimeoutTaskMonitor monitor)
			throws CancelledException, TimeoutException {

		FindPathsAlgorithm<V, E> algo = new IterativeFindPathsAlgorithm<>();
		algo.findPaths(g, start, end, accumulator, monitor);
	}

	/**
	 * Returns the vertices of the graph in post-order.   Pre-order is the order the vertices
	 * are last visited when performing a depth-first traversal.
	 * 
	 * @param g the graph
	 * @param navigator the knower of the direction the graph should be traversed
	 * @return the vertices
	 */
	public static <V, E extends GEdge<V>> List<V> getVerticesInPostOrder(GDirectedGraph<V, E> g,
			GraphNavigator<V, E> navigator) {
		List<V> postOrder = DepthFirstSorter.postOrder(g, navigator);
		return postOrder;
	}

	/**
	 * Returns the vertices of the graph in pre-order.   Pre-order is the order the vertices
	 * are encountered when performing a depth-first traversal.
	 * 
	 * @param g the graph
	 * @param navigator the knower of the direction the graph should be traversed
	 * @return the vertices
	 */
	public static <V, E extends GEdge<V>> List<V> getVerticesInPreOrder(GDirectedGraph<V, E> g,
			GraphNavigator<V, E> navigator) {
		List<V> preOrder = DepthFirstSorter.preOrder(g, navigator);
		return preOrder;
	}

	/**
	 * Calculates 'complexity depth', which is, for each vertex, the deepest/longest path 
	 * from that vertex for a depth-first traversal.   So, for a vertex with a single 
	 * successor that has no children, the depth would be 1.
	 * 
	 * @param g the graph
	 * @return the map of each vertex to its complexity depth
	 */
	public static <V, E extends GEdge<V>> Map<V, Integer> getComplexityDepth(
			GDirectedGraph<V, E> g) {

		Map<V, Integer> map = new HashMap<>();
		List<V> verticesInPostOrder = getVerticesInPostOrder(g, GraphNavigator.topDownNavigator());
		for (V v : verticesInPostOrder) {
			int maxChildLevel = getMaxChildLevel(g, map, v);
			map.put(v, maxChildLevel + 1);
		}

		return map;
	}

	/**
	 * Retain all edges in the graph where each edge's endpoints are in the given set of 
	 * vertices. 
	 * 
	 * @param graph the graph
	 * @param vertices the vertices of the edges to keep
	 * @return the set of edges
	 */
	public static <V, E extends GEdge<V>> Set<E> retainEdges(GDirectedGraph<V, E> graph,
			Set<V> vertices) {

		//@formatter:off
		Collection<E> edges = graph.getEdges();
		Set<E> results = 
			edges.stream()
				 .filter(e -> vertices.contains(e.getStart()))
				 .filter(e -> vertices.contains(e.getEnd()))
				 .collect(Collectors.toSet())
				 ;
		//@formatter:on

		return results;
	}

	/**
	 * Returns the set of vertices contained within the given edges.
	 * 
	 * @param edges the edges
	 * @return the vertices
	 */
	public static <V, E extends GEdge<V>> Set<V> toVertices(Collection<E> edges) {
		Set<V> result = new HashSet<>();
		for (E e : edges) {
			result.add(e.getStart());
			result.add(e.getEnd());
		}
		return result;
	}

	/**
	 * A method to debug the given graph by printing it.
	 * 
	 * @param g the graph to print
	 * @param ps the output stream
	 */
	public static <V, E extends GEdge<V>> void printGraph(GDirectedGraph<V, E> g, PrintStream ps) {
		Set<V> sources = getSources(g);
		Set<V> printedSet = new HashSet<>();
		ps.println("=================================");
		for (V v : sources) {
			recursivePrint(g, v, printedSet, 0, ps);
			ps.println("---------------------------------");
		}
		ps.println("=================================");
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	/**
	 * Returns true if the given strong component has no incoming edges that are outside of 
	 * the component.  This is useful to know, as it signals that the given strong component
	 * is reachable from outside of that component.
	 * 
	 * @param g the graph
	 * @param strongComponent the set of vertices representing a strong component
	 * @return true if the given strong component has no incoming edges that are outside of 
	 * 		   the component
	 */
	private static <V, E extends GEdge<V>> boolean isSelfContainedStrongComponent(
			GDirectedGraph<V, E> g, Set<V> strongComponent) {

		Set<V> parents = new HashSet<>();
		for (V v : strongComponent) {
			parents.addAll(g.getPredecessors(v));
		}

		// check to see if the given set of vertices has an incoming edge that is outside of 
		// the strong component
		return strongComponent.containsAll(parents);
	}

	private static <V, E extends GEdge<V>> int getMaxChildLevel(GDirectedGraph<V, E> g,
			Map<V, Integer> levelMap, V v) {
		int maxLevel = -1;
		Collection<V> successors = g.getSuccessors(v);
		for (V child : successors) {
			Integer level = levelMap.get(child);
			if (level != null && level.intValue() > maxLevel) {
				maxLevel = level;
			}
		}
		return maxLevel;
	}

	private static <V, E extends GEdge<V>> void recursivePrint(GDirectedGraph<V, E> g, V v,
			Set<V> set, int depth, PrintStream ps) {

		for (int i = 1; i <= depth; i++) {
			ps.print(".");
		}

		if (set.contains(v)) {
			ps.println(v + "^ (" + depth + ")");
			return;
		}

		ps.print(v);
		if (depth > 0) {
			ps.print(" (" + depth + ")");
		}
		ps.print('\n');

		set.add(v);
		Collection<V> successors = g.getSuccessors(v);
		for (V v2 : successors) {
			recursivePrint(g, v2, set, depth + 1, ps);
		}
	}
}
