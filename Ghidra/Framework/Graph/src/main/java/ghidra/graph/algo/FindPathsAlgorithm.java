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

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds all paths between two vertices for a given graph.
 * 
 * <P><B><U>Warning:</U></B> This is a recursive algorithm.  As such, it is limited in how deep 
 * it can recurse.   Any path that exceeds the {@link #JAVA_STACK_DEPTH_LIMIT} will not be found.
 * 
 * <P>Note: this algorithm is based entirely on the {@link JohnsonCircuitsAlgorithm}.
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class FindPathsAlgorithm<V, E extends GEdge<V>> {

	public static final int JAVA_STACK_DEPTH_LIMIT = 2700;
	private GDirectedGraph<V, E> g;
	private V startVertex;
	private V endVertex;

	private Stack<V> stack = new Stack<>();
	private Set<V> blockedSet = new HashSet<>();
	private Map<V, Set<V>> blockedBackEdgesMap = new HashMap<>();

	public FindPathsAlgorithm(GDirectedGraph<V, E> g, V start, V end,
			Accumulator<List<V>> accumulator, TaskMonitor monitor) throws CancelledException {
		this.g = g;
		this.startVertex = start;
		this.endVertex = end;

		monitor.initialize(g.getEdgeCount());
		find(accumulator, monitor);
	}

	private void find(Accumulator<List<V>> accumulator, TaskMonitor monitor)
			throws CancelledException {

		explore(startVertex, accumulator, 0, monitor);
	}

	private boolean explore(V v, Accumulator<List<V>> accumulator, int depth, TaskMonitor monitor)
			throws CancelledException {

		// TODO
		// Sigh.  We are greatly limited in the size of paths we can processes due to the 
		// recursive nature of this algorithm.  This should be changed to be non-recursive.
		if (depth > JAVA_STACK_DEPTH_LIMIT) {
			return false;
		}

		boolean foundPath = false;
		blockedSet.add(v);
		stack.push(v);
		Collection<E> outEdges = getOutEdges(v);
		for (E e : outEdges) {
			monitor.checkCanceled();

			V u = e.getEnd();
			if (u.equals(endVertex)) {
				outputCircuit(accumulator);
				foundPath = true;
				monitor.incrementProgress(1);
			}
			else if (!blockedSet.contains(u)) {
				foundPath |= explore(u, accumulator, depth + 1, monitor);
				monitor.incrementProgress(1);
			}
		}

		if (foundPath) {
			unblock(v);
		}
		else {
			for (E e : outEdges) {
				monitor.checkCanceled();
				V u = e.getEnd();
				addBackEdge(u, v);
			}
		}

		stack.pop();
		return foundPath;
	}

	private Collection<E> getOutEdges(V v) {
		Collection<E> outEdges = g.getOutEdges(v);
		if (outEdges == null) {
			return Collections.emptyList();
		}
		return outEdges;
	}

	private void unblock(V v) {
		blockedSet.remove(v);
		Set<V> set = blockedBackEdgesMap.get(v);
		if (set == null) {
			return;
		}
		for (V u : set) {
			if (blockedSet.contains(u)) {
				unblock(u);
			}
		}
		set.clear();
	}

	private void addBackEdge(V u, V v) {
		Set<V> set = blockedBackEdgesMap.get(u);
		if (set == null) {
			set = new HashSet<>();
			blockedBackEdgesMap.put(u, set);
		}
		set.add(v);
	}

	private void outputCircuit(Accumulator<List<V>> accumulator) {
		List<V> path = new ArrayList<>(stack);
		path.add(endVertex);
		accumulator.add(path);
	}
}
