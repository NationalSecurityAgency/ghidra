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
package functioncalls.graph.view;

import functioncalls.graph.*;
import functioncalls.plugin.FunctionCallGraphPlugin;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.options.VisualGraphOptions;

/**
 * A graph view for the {@link FunctionCallGraphPlugin}
 */
public class FcgView extends VisualGraphView<FcgVertex, FcgEdge, FunctionCallGraph> {

	@Override
	protected void installGraphViewer() {

		FcgComponent component = createGraphComponent();
		component.setGraphOptions(new VisualGraphOptions());
		setGraphComponent(component);
	}

	private FcgComponent createGraphComponent() {

		FcgComponent component = new FcgComponent(getVisualGraph());
		return component;
	}

	@Override
	public FcgComponent getGraphComponent() {
		return (FcgComponent) super.getGraphComponent();
	}
}
