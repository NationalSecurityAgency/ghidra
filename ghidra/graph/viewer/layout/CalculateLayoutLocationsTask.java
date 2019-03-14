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
package ghidra.graph.viewer.layout;

import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

//@formatter:off
public class CalculateLayoutLocationsTask<V extends VisualVertex, 
										  E extends VisualEdge<V>>
		extends Task {
//@formatter:on

	private VisualGraphLayout<V, E> layout;
	private VisualGraph<V, E> graph;

	private LayoutPositions<V, E> locations;

	public CalculateLayoutLocationsTask(VisualGraph<V, E> graph, VisualGraphLayout<V, E> layout) {
		super("Calculate Layout Locations", true, false, true, true);
		this.graph = graph;
		this.layout = layout;
	}

	@Override
	public void run(TaskMonitor monitor) {
		monitor.setMessage("Calculating layout locations...");

		locations = layout.calculateLocations(graph, monitor);
	}

	public LayoutPositions<V, E> getLocations() {
		return locations;
	}
}
