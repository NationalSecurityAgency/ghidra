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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface FGLayoutProvider extends LayoutProvider<FGVertex, FGEdge, FunctionGraph> {

	// Suppressing warning on the return type; we know our class is the right type
	@Override
	public default FGLayout getLayout(FunctionGraph graph, TaskMonitor monitor)
			throws CancelledException {

		return getFGLayout(graph, monitor);
	}

	public FGLayout getFGLayout(FunctionGraph graph, TaskMonitor monitor) throws CancelledException;

}
