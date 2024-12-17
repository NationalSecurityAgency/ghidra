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
package ghidra.app.plugin.core.functiongraph.graph.layout.flowchart;

import javax.swing.Icon;

import generic.theme.GIcon;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProviderExtensionPoint;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Makes the Flow Chart Layout available for the function graph feature.
 */
public class FlowChartLayoutProvider extends FGLayoutProviderExtensionPoint {
	private static final Icon ICON = new GIcon("icon.plugin.functiongraph.layout.flowchart");

	@Override
	public String getLayoutName() {
		return "Flow Chart";
	}

	@Override
	public Icon getActionIcon() {
		return ICON;
	}

	@Override
	public int getPriorityLevel() {
		return 140;
	}

	@Override
	public FGLayout getFGLayout(FunctionGraph graph, TaskMonitor monitor)
			throws CancelledException {
		return new FGFlowChartLayout(graph, false);
	}

}
