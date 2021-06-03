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

import org.apache.commons.collections4.map.LazyMap;

import ghidra.graph.*;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This algorithm is an implementation of the Cooper, Harvey, Kennedy algorithm.  
 * 
 * <P>The algorithm processes the graph in reverse post-order.  The runtime of 
 * this algorithm is approximately <code>O(V+E*D)</code> per iteration of the loop, where 
 * D is the size of the largest dominator set.  The number of iterations is 
 * bound at <code>d(G) + 3</code>, where d(G) is the "loop 
 * connectedness" of the graph. 
 * 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class ChkDominanceAlgorithm<V, E extends GEdge<V>> extends AbstractDominanceAlgorithm<V, E> {

	private GDirectedGraph<V, E> sourceGraph;
	private MutableGDirectedGraphWrapper<V, E> mutableGraph;
	private V root;

	// Note: we track dominators and dominated for lookups after the algorithm finishes them
	// A mapping of dominated nodes to their idom
	private Map<V, V> dominatorMap = new HashMap<>();

	// A mapping of idoms to dominated nodes
	private Map<V, List<V>> dominatedMap =
		LazyMap.lazyMap(new HashMap<>(), () -> new ArrayList<>());

	private GraphNavigator<V, E> navigator;

	/**
	 * Constructor.
	 * 
	 * @param g the graph
	 * @param monitor the monitor
	 * @throws CancelledException if the algorithm is cancelled
	 * @throws IllegalArgumentException if there are no source vertices in the graph
	 */
	public ChkDominanceAlgorithm(GDirectedGraph<V, E> g, TaskMonitor monitor)
			throws CancelledException {

		this(g, GraphNavigator.topDownNavigator(), monitor);
	}

	ChkDominanceAlgorithm(GDirectedGraph<V, E> g, GraphNavigator<V, E> navigator,
			TaskMonitor monitor) throws CancelledException {

		this.navigator = navigator;
		this.sourceGraph = g;
		this.mutableGraph = new MutableGDirectedGraphWrapper<>(g);

		root = findRoot();

		dominatorMap.put(root, root);
		monitor.setMessage("Computing dominance");
		computeDominance(monitor);
	}

	private V findRoot() {
		V theRoot = unifySources(mutableGraph, navigator);
		unifySinks(mutableGraph, navigator);
		return theRoot;
	}

	private void computeDominance(TaskMonitor monitor) throws CancelledException {

		List<V> list = navigator.getVerticesInPostOrder(mutableGraph);

		Map<V, Integer> map = new HashMap<>();
		for (int i = 0; i < list.size(); i++) {
			map.put(list.get(i), i);
		}

		boolean changed = true;
		while (changed) {
			monitor.checkCanceled();
			changed = false;

			// start 1 from the end so we always have a predecessor
			for (int i = list.size() - 2; i >= 0; i--) {  // process in reverse order
				V b = list.get(i);
				Collection<V> vertices = navigator.getPredecessors(mutableGraph, b);
				Iterator<V> iterator = vertices.iterator();
				V newIdom = null;

				while (iterator.hasNext()) {
					V p = iterator.next();
					if (dominatorMap.containsKey(p)) {
						newIdom = p;
						break;
					}
				}
				if (newIdom == null) {
					throw new AssertException("No processed predecessors found for " + b);
				}
				iterator = vertices.iterator();

				while (iterator.hasNext()) {
					V p = iterator.next();
					if (newIdom.equals(p)) {
						continue;
					}
					if (dominatorMap.containsKey(p)) {
						newIdom = intersect(p, newIdom, map);
					}
				}

				V idom = dominatorMap.get(b);
				if (!newIdom.equals(idom)) {
					V last = dominatorMap.put(b, newIdom);
					dominatedMap.get(newIdom).add(b);
					if (last != null) {
						dominatedMap.get(last).remove(b);
					}
					changed = true;
				}
			}
		}
	}

	private V intersect(V v1, V v2, Map<V, Integer> map) {
		V finger1 = v1;
		V finger2 = v2;
		int finger1Index = map.get(finger1);
		int finger2Index = map.get(finger2);
		while (!finger1.equals(finger2)) {
			while (finger1Index < finger2Index) {
				finger1 = dominatorMap.get(finger1);
				finger1Index = map.get(finger1);
			}
			while (finger2Index < finger1Index) {
				if (dominatorMap.get(finger2) == null) {
					// this can happen when the dominators for 'finger2' have not 
					// yet been calculated
					return finger1;
				}

				finger2 = dominatorMap.get(finger2);
				finger2Index = map.get(finger2);
			}
		}
		return finger1;
	}

	/**
	 * Returns all nodes dominated by the given vertex.  A node 'a' dominates node 'b' if 
	 * all paths from start to 'b' contain 'a'.
	 * 
	 * @param a the vertex
	 * @return the dominated vertices
	 */
	public Set<V> getDominated(V a) {
		HashSet<V> results = new HashSet<>();
		doGetDominated(a, results);
		return results;
	}

	private void doGetDominated(V a, Set<V> results) {
		add(a, results); // a node always dominates itself
		List<V> dominated = dominatedMap.get(a);
		dominated.forEach(b -> doGetDominated(b, results));
	}

	/**
	 * Returns all nodes that dominate the given vertex.  A node 'a' dominates node 'b' if 
	 * all paths from start to 'b' contain 'a'.  
	 * 
	 * @param a the vertex
	 * @return the dominating vertices
	 */
	public Set<V> getDominators(V a) {
		Set<V> dominators = new HashSet<>();
		dominators.add(a);

		while (!root.equals(a)) {
			a = dominatorMap.get(a); // immediate dominator
			add(a, dominators);
		}
		return dominators;
	}

	private void add(V v, Collection<V> set) {
		if (!isDummy(v)) {
			set.add(v);
		}
	}

	private boolean isDummy(V v) {
		return v != null && mutableGraph.isDummy(v);
	}

	/**
	 * Returns the dominance tree for the given graph, which is tree where each 
	 * node's children are those nodes it *immediately* dominates (a idom b).
	 * 
	 * @return the dominance tree
	 */
	public GDirectedGraph<V, GEdge<V>> getDominanceTree() {
		GDirectedGraph<V, GEdge<V>> dg = GraphFactory.createDirectedGraph();

		// note: we use the source graph here and not the one we mutated for calculating dominance
		Collection<V> vertices = sourceGraph.getVertices();
		Set<V> sources = navigator.getSources(sourceGraph);
		for (V v : vertices) {
			if (sources.contains(v)) {
				continue;
			}

			V dominator = getImmediateDominator(v);
			if (!Objects.equals(dominator, v)) {
				dg.addEdge(new DefaultGEdge<>(dominator, v));
			}
		}
		return dg;
	}

	private V getImmediateDominator(V v) {
		V dom = dominatorMap.get(v);
		if (isDummy(dom)) {
			return null;
		}
		return dom;
	}

	/**
	 * Releases cached values used by internal data structures
	 */
	public void clear() {
		dominatedMap.clear();
		dominatorMap.clear();
	}

}
