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
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

abstract class FunctionGraphViewSettings {

	private ProgramLocation location;
	private ProgramSelection selection;
	private ProgramSelection highlight;
	private GraphPerspectiveInfo<FGVertex, FGEdge> info =
		GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo();

	FunctionGraphViewSettings() {
		// used for creating settings that have no state (like when there is no function)
	}

	FunctionGraphViewSettings(FunctionGraphViewSettings copySettings) {
		location = copySettings.location;
		selection = copySettings.selection;
		highlight = copySettings.highlight;
		info = copySettings.info;
	}

	public void setLocation(ProgramLocation location) {
		this.location = location;
	}

	public void setSelection(ProgramSelection selection) {
		this.selection = selection;
	}

	public void setHighlight(ProgramSelection highlight) {
		this.highlight = highlight;
	}

	public void setFunctionGraphPerspectiveInfo(GraphPerspectiveInfo<FGVertex, FGEdge> info) {
		this.info = info;
	}

	public ProgramLocation getLocation() {
		return location;
	}

	public ProgramSelection getSelection() {
		return selection;
	}

	public ProgramSelection getHighlight() {
		return highlight;
	}

	public GraphPerspectiveInfo<FGVertex, FGEdge> getFunctionGraphPerspectiveInfo() {
		return info;
	}
}
