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

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import ghidra.framework.options.Options;
import ghidra.framework.options.PreferenceState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.util.HelpLocation;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

public class DefaultGraphDisplayProvider implements GraphDisplayProvider {

	private static final String PREFERENCES_KEY = "GRAPH_DISPLAY_SERVICE";
	private static final String DEFAULT_SATELLITE_STATE = "DEFAULT_SATELLITE_STATE";
	private final Set<DefaultGraphDisplay> displays = new HashSet<>();
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
	public GraphDisplay getGraphDisplay(boolean reuseGraph,  TaskMonitor monitor) {
		return getGraphDisplay(reuseGraph, Collections.emptyMap(), monitor);
	}

		@Override
	public GraphDisplay getGraphDisplay(boolean reuseGraph, Map<String, String> properties,
			TaskMonitor monitor) {

		if (reuseGraph && !displays.isEmpty()) {
			DefaultGraphDisplay visibleGraph = getVisibleGraph();
			visibleGraph.restoreToDefaultSetOfActions();
			return visibleGraph;
		}

		DefaultGraphDisplay display =
			Swing.runNow(() -> new DefaultGraphDisplay(this, properties, displayCounter++));
		displays.add(display);
		return display;
	}

	@Override
	public void initialize(PluginTool tool, Options graphOptions) {
		this.pluginTool = tool;
		this.options = graphOptions;
		preferences = pluginTool.getWindowManager().getPreferenceState(PREFERENCES_KEY);
		if (preferences == null) {
			preferences = new PreferenceState();
			pluginTool.getWindowManager().putPreferenceState(PREFERENCES_KEY, preferences);
		}
		defaultSatelliteState = preferences.getBoolean(DEFAULT_SATELLITE_STATE, false);
	}

	/**
	 * Get a {@code GraphDisplay} that is 'showing', assuming that is the one the user
	 * wishes to append to.
	 * Called only when displays is not empty. If there are no 'showing' displays,
	 * return one from the Set via its iterator
	 * @return a display that is showing
	 */
	private DefaultGraphDisplay getVisibleGraph() {
		return displays.stream()
				.filter(d -> d.getComponent().isShowing())
				.findAny()
				.orElse(displays.iterator().next());
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

	boolean getDefaultSatelliteState() {
		return defaultSatelliteState;
	}

	void setDefaultSatelliteState(boolean b) {
		defaultSatelliteState = b;
		preferences.putBoolean(DEFAULT_SATELLITE_STATE, b);

	}

}
