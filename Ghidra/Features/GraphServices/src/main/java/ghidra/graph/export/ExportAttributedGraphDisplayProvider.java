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
package ghidra.graph.export;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.util.HelpLocation;
import ghidra.util.task.TaskMonitor;

/**
 * {@link GraphDisplayProvider} implementation for exporting graphs.  In this case, there is no
 * associated visual display, instead the graph output gets sent to a file.  The corresponding
 * {@link GraphDisplay} is mostly just a placeholder for executing the export function.  By
 * hijacking the {@link GraphDisplayProvider} and {@link GraphDisplay} interfaces for exporting,
 * all graph generating operations can be exported instead of being displayed without changing
 * the graph generation code.    
 */
public class ExportAttributedGraphDisplayProvider implements GraphDisplayProvider {

	private PluginTool pluginTool;
	private Options options;

	@Override
	public String getName() {
		return "Graph Export";
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

		return new ExportAttributedGraphDisplay(this);
	}

	@Override
	public void initialize(PluginTool tool, Options graphOptions) {
		this.pluginTool = tool;
		this.options = graphOptions;
	}

	@Override
	public void optionsChanged(Options graphOptions) {
		// no options so far graph exporting
	}

	@Override
	public void dispose() {
		// nothing to clean up
	}

	@Override
	public HelpLocation getHelpLocation() {
		return new HelpLocation("GraphServices", "Graph_Exporter");
	}
}
