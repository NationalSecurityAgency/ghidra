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
package ghidra.graph;

import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.service.graph.GraphDisplay;
import ghidra.service.graph.GraphDisplayProvider;
import ghidra.util.HelpLocation;
import ghidra.util.exception.GraphException;
import ghidra.util.task.TaskMonitor;

public class TestGraphService implements GraphDisplayProvider {
	private TestGraphDisplay testDisplay = new TestGraphDisplay();

	@Override
	public String getName() {
		return "Test Graph Service";
	}

	@Override
	public GraphDisplay getGraphDisplay(boolean reuseGraph,
			TaskMonitor monitor) throws GraphException {
		return testDisplay;
	}

	@Override
	public void initialize(PluginTool tool, Options options) {
		// nothing

	}

	@Override
	public void optionsChanged(Options options) {
		// nothing

	}

	@Override
	public void dispose() {
		// nothing
	}

	@Override
	public HelpLocation getHelpLocation() {
		return null;
	}

}
