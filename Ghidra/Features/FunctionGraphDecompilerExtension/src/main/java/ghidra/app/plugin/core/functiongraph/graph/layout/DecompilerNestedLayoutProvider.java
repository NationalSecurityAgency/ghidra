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
import ghidra.framework.options.Options;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

public class DecompilerNestedLayoutProvider extends FGLayoutProviderExtensionPoint {

	private static final Icon ICON =
		ResourceManager.loadImage("images/function_graph_code_flow.png");
	static final String LAYOUT_NAME = "Nested Code Layout";

	@Override
	public FGLayout getFGLayout(FunctionGraph graph, TaskMonitor monitor) {
		DecompilerNestedLayout layout = new DecompilerNestedLayout(graph, LAYOUT_NAME);
		layout.setTaskMonitor(monitor);
		return layout;
	}

	@Override
	public FGLayoutOptions createLayoutOptions(Options options) {
		DNLayoutOptions layoutOptions = new DNLayoutOptions();
		layoutOptions.registerOptions(options);
		return layoutOptions;
	}

	@Override
	public String getLayoutName() {
		return LAYOUT_NAME;
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
