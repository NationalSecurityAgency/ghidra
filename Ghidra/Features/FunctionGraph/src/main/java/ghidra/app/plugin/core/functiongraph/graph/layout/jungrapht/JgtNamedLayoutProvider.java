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
package ghidra.app.plugin.core.functiongraph.graph.layout.jungrapht;

import javax.swing.Icon;

import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayoutProvider;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A layout provider that allows us to specify a Jung layout by name.
 */
public class JgtNamedLayoutProvider extends FGLayoutProvider {
	// layout algorithm categories
	static final String MIN_CROSS = "Hierarchical MinCross";
	static final String VERT_MIN_CROSS = "Vertical Hierarchical MinCross";

	private String layoutName;

	public JgtNamedLayoutProvider(String layoutName) {
		this.layoutName = layoutName;
	}

	@Override
	public String getLayoutName() {
		return layoutName;
	}

	@Override
	public Icon getActionIcon() {
		return null; // no good icon
	}

	@Override
	public int getPriorityLevel() {
		// low priority than other layouts; other layouts use 200, 101 and 100
		return 75;
	}

	@Override
	public FGLayout getFGLayout(FunctionGraph graph, TaskMonitor monitor)
			throws CancelledException {
		JgtNamedLayout layout = new JgtNamedLayout(graph, layoutName);
		layout.setTaskMonitor(monitor);
		return layout;
	}

	@Override
	public String toString() {
		return layoutName;
	}

	@Override
	public HelpLocation getHelpLocation() {
		// condense hierarchical action help to the top-level help description
		String anchor = layoutName;
		if (layoutName.contains(VERT_MIN_CROSS)) {
			anchor = VERT_MIN_CROSS;
		}
		else if (layoutName.contains(MIN_CROSS)) {
			anchor = MIN_CROSS;
		}
		return new HelpLocation("GraphServices", anchor);
	}
}
