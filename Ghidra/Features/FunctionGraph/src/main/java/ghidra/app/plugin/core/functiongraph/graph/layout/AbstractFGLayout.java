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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.jung.renderer.FGEdgeRenderer;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.listing.Function;

/**
 * An abstract class that is the root for Function Graph layouts.  It changes the type of
 * the graph returned to {@link FunctionGraph} and defines a clone method that takes in a 
 * Function Graph.
 */
public abstract class AbstractFGLayout extends AbstractVisualGraphLayout<FGVertex, FGEdge>
		implements FGLayout {

	protected Function function;
	protected FunctionGraphOptions options;

	protected AbstractFGLayout(FunctionGraph graph, String layoutName) {
		super(graph, layoutName);
		this.function = graph.getFunction();
		this.options = graph.getOptions();
	}

	protected abstract AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedFGLayout(
			FunctionGraph newGraph);

	@Override
	public FunctionGraph getVisualGraph() {
		return (FunctionGraph) getGraph();
	}

	@Override
	public AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedLayout(
			VisualGraph<FGVertex, FGEdge> newGraph) {
		return createClonedFGLayout((FunctionGraph) newGraph);
	}

	@Override
	public FGLayout cloneLayout(VisualGraph<FGVertex, FGEdge> newGraph) {
		VisualGraphLayout<FGVertex, FGEdge> clone = super.cloneLayout(newGraph);
		return (FGLayout) clone;
	}

	@Override
	protected boolean isCondensedLayout() {
		return options.useCondensedLayout();
	}

	@Override
	public BasicEdgeRenderer<FGVertex, FGEdge> getEdgeRenderer() {
		return new FGEdgeRenderer();
	}
}
