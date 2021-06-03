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
package ghidra.service.graph;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.HelpLocation;
import ghidra.util.classfinder.ExtensionPoint;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

import java.util.Collections;
import java.util.Map;

/**
 * Basic interface for objects that can display or otherwise consume a generic graph
 */
public interface GraphDisplayProvider extends ExtensionPoint {

	/**
	 * The name of this provider (for displaying as menu option when graphing)
	 * @return the name of this provider.
	 */
	public String getName();

	/**
	 * Returns a GraphDisplay that can be used to "display" a graph
	 * 
	 * @param reuseGraph if true, this provider will attempt to re-use an existing GraphDisplay
	 * @param monitor the {@link TaskMonitor} that can be used to monitor and cancel the operation
	 * @return A GraphDisplay that can be used to display (or otherwise consume - e.g. export) the graph
	 * @throws GraphException thrown if there is a problem creating a GraphDisplay
	 */
	public GraphDisplay getGraphDisplay(boolean reuseGraph,	TaskMonitor monitor) throws GraphException;

	/**
	 * Returns a GraphDisplay that can be used to "display" a graph
	 *
	 * @param reuseGraph if true, this provider will attempt to re-use an existing GraphDisplay
	 * @param properties a {@code Map} of property key/values that can be used to customize the display
	 * @param monitor the {@link TaskMonitor} that can be used to monitor and cancel the operation
	 * @return A GraphDisplay that can be used to display (or otherwise consume - e.g. export) the graph
	 * @throws GraphException thrown if there is a problem creating a GraphDisplay
	 */
	default GraphDisplay getGraphDisplay(boolean reuseGraph, Map<String, String> properties,
										TaskMonitor monitor) throws GraphException {
		return getGraphDisplay(reuseGraph, monitor);
	}

	/**
	 * Provides an opportunity for this provider to register and read tool options
	 * 
	 * @param tool the tool hosting this display
	 * @param options the tool options for graphing
	 */
	public void initialize(PluginTool tool, Options options);

	/**
	 * Called if the graph options change
	 * 
	 * @param options the current tool options
	 */
	public void optionsChanged(Options options);

	/**
	 * Disposes this GraphDisplayProvider
	 */
	public void dispose();

	/**
	 * Gets the help location for this GraphDisplayProvider
	 * @return help location for this GraphDisplayProvider
	 */
	public HelpLocation getHelpLocation();
}
