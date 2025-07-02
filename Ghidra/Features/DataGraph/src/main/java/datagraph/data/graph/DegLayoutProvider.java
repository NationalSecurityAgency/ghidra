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
package datagraph.data.graph;

import ghidra.graph.viewer.layout.AbstractLayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Provider for the DegLayout
 */
public class DegLayoutProvider
		extends AbstractLayoutProvider<DegVertex, DegEdge, DataExplorationGraph> {
	private static final String NAME = "Data Graph Layout";

	private static final int VERTICAL_GAP = 50;
	private static final int HORIZONTAL_GAP = 100;

	@Override
	public VisualGraphLayout<DegVertex, DegEdge> getLayout(DataExplorationGraph graph,
			TaskMonitor monitor)
			throws CancelledException {
		DegLayout layout = new DegLayout(graph, VERTICAL_GAP, HORIZONTAL_GAP);
		initVertexLocations(graph, layout);
		return layout;
	}

	@Override
	public String getLayoutName() {
		return NAME;
	}
}
