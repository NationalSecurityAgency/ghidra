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
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Finds all circuits (loops) in the given graph.
 * 
 * <P><B><U>Warning:</U></B> This is a recursive algorithm.  As such, it is limited in how deep 
 * it can recurse.   Any path that exceeds the {@link #JAVA_STACK_DEPTH_LIMIT} will not be found.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class JohnsonCircuitsAlgorithm<V, E extends GEdge<V>> {

	public static final int JAVA_STACK_DEPTH_LIMIT = 2700;

	private GDirectedGraph<V, E> g;
	private GDirectedGraph<V, E> subGraph;
	private Stack<V> stack = new Stack<>();
	private V startVertex;
	private Set<V> blockedSet = new HashSet<>();
	private Map<V, Set<V>> blockedBackEdgesMap = new HashMap<>();
	private Accumulator<List<V>> accumulator;

	public JohnsonCircuitsAlgorithm(GDirectedGraph<V, E> g, Accumulator<List<V>> accumulator) {
		this.g = g;
		this.accumulator = accumulator;
	}

	/**
	 * Finds the circuits in the graph passed at construction time.
	 * 
	 * @param uniqueCircuits true signals to return only unique circuits, where no two 
	 *        circuits will contain the same vertex
	 * @param monitor the task monitor
	 * @throws CancelledException if the monitor is cancelled
	 */
	public void compute(boolean uniqueCircuits, TaskMonitor monitor) throws CancelledException {
		Set<Set<V>> stronglyConnected = GraphAlgorithms.getStronglyConnectedComponents(g);

		for (Set<V> set : stronglyConnected) {
			if (set.size() < 2) {
				continue;
			}

			subGraph = GraphAlgorithms.createSubGraph(g, set);
			List<V> vertices = new ArrayList<>(subGraph.getVertices());

			int size = vertices.size() - 1;
			if (uniqueCircuits) {
				size += 1;
			}

			for (int i = 0; i < size; i++) {
				startVertex = vertices.get(i);

				blockedSet.clear();
				blockedBackEdgesMap.clear();
				circuit(startVertex, 0, monitor);

				if (uniqueCircuits) {
					subGraph.removeVertex(startVertex);
				}
			}
		}
	}

	private boolean circuit(V v, int depth, TaskMonitor monitor) throws CancelledException {
		monitor.checkCanceled();

		// TODO
		// Sigh.  We are greatly limited in the size of paths we can processes due to the 
		// recursive nature of this algorithm.  This should be changed to be non-recursive.
		if (depth > JAVA_STACK_DEPTH_LIMIT) {
			return false;
		}

		boolean foundCircuit = false;
		blockedSet.add(v);
		stack.push(v);
		Collection<E> outEdges = subGraph.getOutEdges(v);
		for (E e : outEdges) {
			V u = e.getEnd();
			if (u.equals(startVertex)) {
				outputCircuit();
				foundCircuit = true;
			}
			else if (!blockedSet.contains(u)) {
				foundCircuit |= circuit(u, depth + 1, monitor);
			}
		}

		if (foundCircuit) {
			unblock(v);
		}
		else {
			for (E e : outEdges) {
				V u = e.getEnd();
				addBackEdge(u, v);
			}
		}
		stack.pop();
		return foundCircuit;
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

	private void outputCircuit() {
		List<V> circuit = new ArrayList<>(stack);
		circuit.add(startVertex);
		accumulator.add(circuit);
	}
}
