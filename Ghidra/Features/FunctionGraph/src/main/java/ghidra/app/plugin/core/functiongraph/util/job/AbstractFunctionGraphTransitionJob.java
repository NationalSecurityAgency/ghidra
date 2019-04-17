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
package ghidra.app.plugin.core.functiongraph.util.job;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.graph.job.AbstractGraphTransitionJob;

/**
 * A class to handle mapping from Function Graph needs to the more generic Graph Job API.
 */
public abstract class AbstractFunctionGraphTransitionJob
		extends AbstractGraphTransitionJob<FGVertex, FGEdge> {

	protected FGController controller;

	protected AbstractFunctionGraphTransitionJob(FGController controller, boolean useAnimation) {
		super(controller.getView().getPrimaryGraphViewer(), useAnimation);
		this.controller = controller;
	}

	FunctionGraph getFunctionGraph() {
		return controller.getFunctionGraphData().getFunctionGraph();
	}

	FGLayout getFunctionGraphLayout() {
		return getFunctionGraph().getLayout();
	}
}
