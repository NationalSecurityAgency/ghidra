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
package ghidra.app.plugin.core.functiongraph.graph.jung.renderer;

import java.awt.Color;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.graph.viewer.renderer.ArticulatedEdgeRenderer;

/**
 * A renderer used by the Function Graph API to provide additional edge coloring, as 
 * determined by the {@link FunctionGraphOptions}.
 */
public class FGEdgeRenderer extends ArticulatedEdgeRenderer<FGVertex, FGEdge> {

	@Override
	public Color getBaseColor(Graph<FGVertex, FGEdge> g, FGEdge e) {
		FunctionGraphOptions options = getOptions(g);
		return options.getColor(e.getFlowType());
	}

	@Override
	public Color getHighlightColor(Graph<FGVertex, FGEdge> g, FGEdge e) {
		FunctionGraphOptions options = getOptions(g);
		return options.getHighlightColor(e.getFlowType());
	}

	private FunctionGraphOptions getOptions(Graph<FGVertex, FGEdge> g) {
		FunctionGraph fg = (FunctionGraph) g;
		return fg.getOptions();
	}
}
