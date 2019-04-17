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

import java.util.Objects;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.GraphPerspectiveInfo;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * This settings object is created after a graph has been loaded.  Further, creating this object
 * will apply the perspective information, if any has been specified.
 * <p>
 * This settings object is what exists when a graph is being displayed.  Changing attributes on
 * this settings object will apply those values directly to the graph.  Contrastingly, when a 
 * graph is being built, then a different type of {@link FunctionGraphViewSettings} object is in
 * place and changing attributes of that object will apply the changed value after the graph 
 * has been loaded.
 * 
 * @see PendingFunctionGraphViewSettings
 */
class CurrentFunctionGraphViewSettings extends FunctionGraphViewSettings {

	private final FGView view;

	CurrentFunctionGraphViewSettings(FGView view, FunctionGraphViewSettings copySettings) {
		this.view = view;
		setLocation(copySettings.getLocation());
		setSelection(copySettings.getSelection());
		setHighlight(copySettings.getHighlight());
		setFunctionGraphPerspectiveInfo(copySettings.getFunctionGraphPerspectiveInfo());
	}

	@Override
	public void setLocation(ProgramLocation newLocation) {
		if (Objects.equals(newLocation, getLocation())) {
			return;
		}

		super.setLocation(newLocation);
		view.setLocation(newLocation);
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		super.setSelection(selection);
		view.setSelection(selection);
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		super.setHighlight(highlight);
		view.setHighlight(highlight);
	}

	@Override
	public void setFunctionGraphPerspectiveInfo(GraphPerspectiveInfo<FGVertex, FGEdge> info) {
		super.setFunctionGraphPerspectiveInfo(info);
		if (!info.isInvalid()) {
			view.setGraphPerspective(info);
		}
	}
}
