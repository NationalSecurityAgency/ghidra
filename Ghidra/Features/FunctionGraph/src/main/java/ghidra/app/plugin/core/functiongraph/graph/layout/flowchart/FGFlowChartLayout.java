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
package ghidra.app.plugin.core.functiongraph.graph.layout.flowchart;

import java.util.Comparator;

import edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.jung.renderer.FGEdgeRenderer;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FunctionGraphOptions;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;

/**
 * Adapts the {@link AbstractFlowChartLayout} to work for {@link FunctionGraph}s.
 */
public class FGFlowChartLayout extends AbstractFlowChartLayout<FGVertex, FGEdge>
		implements FGLayout {

	private FunctionGraphOptions options;

	protected FGFlowChartLayout(FunctionGraph graph, boolean leftAligned) {
		super(graph, new FGEdgeComparator(), leftAligned);
		this.options = graph.getOptions();
	}

	@Override
	public FunctionGraph getVisualGraph() {
		return (FunctionGraph) super.getVisualGraph();
	}

	@Override
	public AbstractVisualGraphLayout<FGVertex, FGEdge> createClonedLayout(
			VisualGraph<FGVertex, FGEdge> newGraph) {
		return new FGFlowChartLayout((FunctionGraph) newGraph, leftAligned);
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

	private static class FGEdgeComparator implements Comparator<FGEdge> {
		@Override
		public int compare(FGEdge e1, FGEdge e2) {
			return priority(e1).compareTo(priority(e2));
		}

		private Integer priority(FGEdge e) {
			FlowType type = e.getFlowType();
			// making fall through edges a higher priority, makes it more likely that vertices
			// with fall through connections will be direct descendants (closer) when the graph is
			// converted to a tree.
			if (type == RefType.FALL_THROUGH) {
				return 1;  // lower is more preferred
			}
			return 10;
		}
	}

	@Override
	protected FGVertex getRoot(VisualGraph<FGVertex, FGEdge> g) {
		if (graph instanceof FunctionGraph fg) {
			return fg.getRootVertex();
		}
		return null;
	}
}
