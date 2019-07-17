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

import javax.swing.Icon;

import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class DecompilerNestedLayoutProvider implements FGLayoutProvider {

	private static final Icon ICON =
		ResourceManager.loadImage("images/function_graph_code_flow.png");

	@Override
	public FGLayout getFGLayout(FunctionGraph graph, TaskMonitor monitor) {
		DecompilerNestedLayout layout = new DecompilerNestedLayout(graph);
		layout.setTaskMonitor(monitor);
		return layout;
	}

	@Override
	public String getLayoutName() {
		// TODO better name?...or rename classes to match
		return "Nested Code Layout";
	}

	@Override
	public Icon getActionIcon() {
		return ICON;
	}

	@Override
	public int getPriorityLevel() {
		return 200; // above the others
	}

}
