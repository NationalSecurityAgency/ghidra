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
package ghidra.app.plugin.core.functiongraph.mvc;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.GraphPerspectiveInfo;

/**
 * A version of the view settings to hold information about the graph that is being built or is
 * awaiting to be built.  When the graph is finished loading, this settings object will be 
 * used to apply graph settings.
 * 
 * @see CurrentFunctionGraphViewSettings
 */
class PendingFunctionGraphViewSettings extends FunctionGraphViewSettings {

	PendingFunctionGraphViewSettings(FunctionGraphViewSettings copySettings,
			GraphPerspectiveInfo<FGVertex, FGEdge> perspective) {
		super(copySettings);

		if (perspective == null) {
			perspective = GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo();

		}
		setFunctionGraphPerspectiveInfo(perspective);
	}
}
