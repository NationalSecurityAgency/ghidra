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

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * This is {@link ChkDominanceAlgorithm} with reverse graph traversal, which allows the
 * algorithm to calculate post dominance.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class ChkPostDominanceAlgorithm<V, E extends GEdge<V>> extends ChkDominanceAlgorithm<V, E> {

	/**
	 * Constructor.
	 * 
	 * @param g the graph
	 * @param monitor the monitor
	 * @throws CancelledException if the algorithm is cancelled
	 */
	public ChkPostDominanceAlgorithm(GDirectedGraph<V, E> g, TaskMonitor monitor)
			throws CancelledException {
		super(g, GraphNavigator.bottomUpNavigator(), monitor);
	}
}
