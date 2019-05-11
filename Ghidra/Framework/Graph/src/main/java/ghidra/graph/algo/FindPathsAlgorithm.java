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

import java.util.List;

import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface FindPathsAlgorithm<V, E extends GEdge<V>> {

	public void findPaths(GDirectedGraph<V, E> g, V start, V end, Accumulator<List<V>> accumulator,
			TaskMonitor monitor) throws CancelledException;

	public void setStatusListener(GraphAlgorithmStatusListener<V> listener);
}
