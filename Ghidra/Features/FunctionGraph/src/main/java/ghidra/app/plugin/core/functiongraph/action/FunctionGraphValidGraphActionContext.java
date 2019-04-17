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
package ghidra.app.plugin.core.functiongraph.action;

import java.util.Set;

import ghidra.app.context.NavigatableActionContext;
import ghidra.app.plugin.core.functiongraph.FGProvider;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.actions.VisualGraphActionContext;

public class FunctionGraphValidGraphActionContext extends NavigatableActionContext
		implements FunctionGraphValidGraphActionContextIf, VisualGraphActionContext {

	private final Set<FGVertex> selectedVertices;

	public FunctionGraphValidGraphActionContext(FGProvider functionGraphProvider,
			Set<FGVertex> selectedVertices) {
		super(functionGraphProvider, functionGraphProvider);
		this.selectedVertices = selectedVertices;
	}

	@Override
	public Set<FGVertex> getSelectedVertices() {
		return selectedVertices;
	}
}
