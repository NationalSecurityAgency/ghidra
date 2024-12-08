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

import java.util.*;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Collectors;

import ghidra.framework.options.Options;
import ghidra.framework.options.PreferenceState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.*;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class DefaultGraphDisplayProvider implements GraphDisplayProvider {

	private static final String PREFERENCES_KEY = "GRAPH_DISPLAY_SERVICE";
	private static final String DEFAULT_SATELLITE_STATE = "DEFAULT_SATELLITE_STATE";
	private final Set<DefaultGraphDisplayWrapper> displays = new CopyOnWriteArraySet<>();
	private PluginTool pluginTool;
	private Options options;
	private int displayCounter = 1;
	private boolean defaultSatelliteState;
	private PreferenceState preferences;

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
	public GraphDisplay getGraphDisplay(boolean reuseGraph, TaskMonitor monitor) {

		return Swing.runNow(() -> {

			if (reuseGraph && !displays.isEmpty()) {
				DefaultGraphDisplayWrapper visibleGraph =
					(DefaultGraphDisplayWrapper) getActiveGraphDisplay();

				// set a temporary dummy graph; clients will set a real graph
				visibleGraph.setGraph(new AttributedGraph("Empty", null),
					new DefaultGraphDisplayOptions(), "", false, monitor);
				visibleGraph.restoreDefaultState();
				return visibleGraph;
			}

			DefaultGraphDisplayWrapper display =
				new DefaultGraphDisplayWrapper(this, displayCounter++);
			displays.add(display);
			return display;
		});
	}

	@Override
	public GraphDisplay getActiveGraphDisplay() {
		if (displays.isEmpty()) {
			return null;
		}

		// get the sorted displays in order to pick the newest graph
		return getAllGraphDisplays().get(0);
	}

	@Override
	public List<GraphDisplay> getAllGraphDisplays() {
		return displays.stream().sorted().collect(Collectors.toList());
	}

	@Override
	public void initialize(PluginTool tool, Options graphOptions) {
		this.pluginTool = tool;
		this.options = graphOptions;

		Swing.assertSwingThread("Graph preferences must be accessed on the Swing thread");
		preferences = pluginTool.getWindowManager().getPreferenceState(PREFERENCES_KEY);
		if (preferences == null) {
			preferences = new PreferenceState();
			pluginTool.getWindowManager().putPreferenceState(PREFERENCES_KEY, preferences);
		}

		defaultSatelliteState = preferences.getBoolean(DEFAULT_SATELLITE_STATE, false);
	}

	@Override
	public void optionsChanged(Options graphOptions) {
		// no supported options
	}

	@Override
	public void dispose() {

		// Calling close() will trigger the display to call back to this class's remove(). Avoid
		// unnecessary copies in the 'copy on write' set by closing after clearing the set.
		Set<GraphDisplay> set = new HashSet<>(displays);
		displays.clear();
		set.forEach(d -> d.close());
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("GraphServices", "Default_Graph_Display");
	}

	void remove(DefaultGraphDisplay defaultGraphDisplay) {
		displays.removeIf(wrapper -> wrapper.isDelegate(defaultGraphDisplay));
	}

	boolean getDefaultSatelliteState() {
		return defaultSatelliteState;
	}

	void setDefaultSatelliteState(boolean b) {
		Swing.assertSwingThread("Graph preferences must be accessed on the Swing thread");
		defaultSatelliteState = b;
		preferences.putBoolean(DEFAULT_SATELLITE_STATE, b);
	}
}
