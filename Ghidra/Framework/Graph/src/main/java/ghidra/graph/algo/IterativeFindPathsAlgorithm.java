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
import org.apache.commons.collections4.set.ListOrderedSet;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.algo.GraphAlgorithmStatusListener.STATUS;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds all paths between two vertices for a given graph.
 * 
 * <P>Note: this algorithm is based on the {@link JohnsonCircuitsAlgorithm}, modified to be
 * iterative instead of recursive. 
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class IterativeFindPathsAlgorithm<V, E extends GEdge<V>>
		implements FindPathsAlgorithm<V, E> {

	private GDirectedGraph<V, E> g;
	private V start;
	private V end;

	private Set<V> blockedSet = new HashSet<>();
	private Map<V, Set<V>> blockedBackEdgesMap =
		LazyMap.lazyMap(new HashMap<>(), k -> new HashSet<>());

	private GraphAlgorithmStatusListener<V> listener = new GraphAlgorithmStatusListener<>();
	private TaskMonitor monitor;
	private Accumulator<List<V>> accumulator;

	@Override
	public void setStatusListener(GraphAlgorithmStatusListener<V> listener) {
		this.listener = listener;
	}

	@SuppressWarnings("hiding") // squash warning on names of variables
	@Override
	public void findPaths(GDirectedGraph<V, E> g, V start, V end, Accumulator<List<V>> accumulator,
			TaskMonitor monitor) throws CancelledException {
		this.g = g;
		this.start = start;
		this.end = end;
		this.accumulator = accumulator;
		this.monitor = monitor;

		if (start.equals(end)) {
			// can't find the paths between a node and itself
			throw new IllegalArgumentException("Start and end vertex cannot be the same: " + start);
		}

		if (!g.containsVertex(start)) {
			throw new IllegalArgumentException("Start vertex is not in the graph: " + start);
		}

		if (!g.containsVertex(end)) {
			throw new IllegalArgumentException("End vertex is not in the graph: " + end);
		}

		find();
		listener.finished();
	}

	private void find() throws CancelledException {
		Stack<Node> path = new Stack<>();
		path.push(new Node(null, start));

		monitor.initialize(g.getEdgeCount());

		while (!path.isEmpty()) {

			monitor.checkCanceled();
			monitor.incrementProgress(1);
			Node node = path.peek();

			setStatus(node.v, STATUS.EXPLORING);

			if (node.v.equals(end)) {
				outputCircuit(path);
				node.setParentFound();
				path.pop();
			}
			else if (node.isExplored()) {
				node.setDone();
				path.pop();
			}
			else {
				node = node.getNext();
				path.push(node);
			}
		}
	}

	private void unblock(V v) {

		ListOrderedSet<V> toProcess = new ListOrderedSet<>();
		toProcess.add(v);

		while (!toProcess.isEmpty()) {
			V next = toProcess.remove(0);
			Set<V> childBlocked = doUnblock(next);
			if (childBlocked != null && !childBlocked.isEmpty()) {
				toProcess.addAll(childBlocked);
				childBlocked.clear();
			}
		}
	}

	private Set<V> doUnblock(V v) {

		blockedSet.remove(v);
		setStatus(v, STATUS.WAITING);
		Set<V> set = blockedBackEdgesMap.get(v);
		return set;
	}

	private void blockBackEdge(V u, V v) {
		Set<V> set = blockedBackEdgesMap.get(u);
		set.add(v);
	}

	private void outputCircuit(Stack<Node> stack) throws CancelledException {
		List<V> path = new ArrayList<>();
		for (Node vv : stack) {
			path.add(vv.v);
		}
		setStatus(path, STATUS.IN_PATH);
		accumulator.add(path);

		monitor.checkCanceled(); // pause for listener
	}

	private void setStatus(List<V> path, STATUS s) {
		for (V v : path) {
			listener.statusChanged(v, s);
		}
	}

	private void setStatus(V v, STATUS s) {
		if (blockedSet.contains(v) && s == STATUS.WAITING) {
			listener.statusChanged(v, STATUS.BLOCKED);
		}
		else {
			listener.statusChanged(v, s);
		}
	}

	private Collection<E> getOutEdges(V v) {
		Collection<E> outEdges = g.getOutEdges(v);
		if (outEdges == null) {
			return Collections.emptyList();
		}
		return outEdges;
	}
//==================================================================================================
// Inner Classes
//==================================================================================================	

	/**
	 * Simple class to maintain a relationship between a given node and its children that need
	 * processing.  It also knows if it has been found in a path from start to end.
	 */
	private class Node {
		private Node parent;
		private V v;
		private Deque<V> unexplored;
		private boolean found;

		Node(Node parent, V v) {
			this.parent = parent;
			this.v = v;

			blockedSet.add(v);
			setStatus(v, STATUS.SCHEDULED);

			Collection<E> outEdges = getOutEdges(v);
			unexplored = new ArrayDeque<>(outEdges.size());
			for (E e : getOutEdges(v)) {
				V u = e.getEnd();
				if (!blockedSet.contains(u)) {
					unexplored.add(u);
				}
			}
		}

		void setDone() {
			if (found) {
				setParentFound();
			}
			else {
				// block back edges
				for (E e : getOutEdges(v)) {
					V u = e.getEnd();
					blockBackEdge(u, v);
				}
				setStatus(v, STATUS.BLOCKED);
			}
		}

		void setParentFound() {
			if (parent != null) {
				parent.found = true;
			}
			unblock(v);
		}

		boolean isExplored() {
			return unexplored.isEmpty();
		}

		Node getNext() {
			if (isExplored()) {
				return null;
			}

			Node node = new Node(this, unexplored.pop());
			return node;
		}

		@Override
		public String toString() {
			return v.toString();
		}
	}
}
