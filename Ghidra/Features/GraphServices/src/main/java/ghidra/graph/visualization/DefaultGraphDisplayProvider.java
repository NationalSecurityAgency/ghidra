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
package ghidra.graph.visualization;

import java.util.HashSet;
import java.util.Set;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class DefaultGraphDisplayProvider implements GraphDisplayProvider {

	private Set<DefaultGraphDisplay> displays = new HashSet<>();
	private PluginTool pluginTool;
	private Options options;
	private int displayCounter;

	@Override
	public String getName() {
		return "Default Graph Display";
	}

	public PluginTool getPluginTool() {
		return pluginTool;
	}

	public Options getOptions() {
		return options;
	}

	@Override
	public GraphDisplay getGraphDisplay(boolean reuseGraph,
			TaskMonitor monitor) {

		if (reuseGraph && !displays.isEmpty()) {
			return getVisibleGraph();
		}

		DefaultGraphDisplay display =
			Swing.runNow(() -> new DefaultGraphDisplay(this, displayCounter++));
		displays.add(display);
		return display;
	}

	@Override
	public void initialize(PluginTool tool, Options graphOptions) {
		this.pluginTool = tool;
		this.options = graphOptions;
	}

	/**
	 * Get a {@code GraphDisplay} that is 'showing', assuming that is the one the user
	 * wishes to append to.
	 * Called only when displays is not empty. If there are no 'showing' displays,
	 * return one from the Set via its iterator
	 * @return a display that is showing
	 */
	private GraphDisplay getVisibleGraph() {
		return displays.stream().filter(d -> d.getComponent().isShowing())
				.findAny().orElse(displays.iterator().next());
	}

	@Override
	public void optionsChanged(Options graphOptions) {
		// no supported options
	}

	@Override
	public void dispose() {
		// first copy to new set to avoid concurrent modification exception
		HashSet<DefaultGraphDisplay> set = new HashSet<>(displays);
		for (DefaultGraphDisplay display : set) {
			display.close();
		}
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("GraphServices", "Default_Graph_Display");
	}

	public void remove(DefaultGraphDisplay defaultGraphDisplay) {
		displays.remove(defaultGraphDisplay);
	}
}
