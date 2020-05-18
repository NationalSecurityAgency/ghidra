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
package ghidra.graph.visualization;

import java.util.function.Function;

import org.jungrapht.visualization.layout.algorithms.*;
import org.jungrapht.visualization.layout.algorithms.sugiyama.Layering;

import org.jungrapht.visualization.layout.algorithms.repulsion.BarnesHutFRRepulsion;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

/**
 * A central location to list and provide all layout algorithms, their names, and their builders
 * Add or remove items here to change what layout algorithms are offered in the layout algorithm menu.
 * Change the String name to affect the menu's label for a specific layout algorithm.
 * This class provides LayoutAlgorithm builders instead of LayoutAlgorithms because some LayoutAlgorithms
 * accumulate state information (so are used only one time).
 */
class LayoutFunction
		implements Function<String, LayoutAlgorithm.Builder<AttributedVertex, ?, ?>> {

	static final String KAMADA_KAWAI = "Force Balanced";
	static final String FRUCTERMAN_REINGOLD = "Force Directed";
	static final String CIRCLE_MINCROSS = "Circle";
	static final String TIDIER_TREE = "Compact Hierarchical";
	static final String MIN_CROSS_TOP_DOWN = "Hierarchical MinCross Top Down";
	static final String MIN_CROSS_LONGEST_PATH = "Hierarchical MinCross Longest Path";
	static final String MIN_CROSS_NETWORK_SIMPLEX = "Hierarchical MinCross Network Simplex";
	static final String MIN_CROSS_COFFMAN_GRAHAM = "Hierarchical MinCross Coffman Graham";
	static final String MULTI_ROW_EDGE_AWARE_TREE = "Hierarchical MultiRow";
	static final String EDGE_AWARE_TREE = "Hierarchical";
	static final String EDGE_AWARE_RADIAL = "Radial";

	public String[] getNames() {
		return new String[] { EDGE_AWARE_TREE, MULTI_ROW_EDGE_AWARE_TREE, TIDIER_TREE,
				MIN_CROSS_TOP_DOWN, MIN_CROSS_LONGEST_PATH, MIN_CROSS_NETWORK_SIMPLEX,
				MIN_CROSS_COFFMAN_GRAHAM, CIRCLE_MINCROSS, KAMADA_KAWAI, FRUCTERMAN_REINGOLD,
				EDGE_AWARE_RADIAL };
	}

	@Override
	public LayoutAlgorithm.Builder<AttributedVertex, ?, ?> apply(String name) {
		switch(name) {
			case KAMADA_KAWAI:
				return KKLayoutAlgorithm.<AttributedVertex> builder().preRelaxDuration(1000);
			case FRUCTERMAN_REINGOLD:
				return FRLayoutAlgorithm.<AttributedVertex> builder()
					.repulsionContractBuilder(BarnesHutFRRepulsion.barnesHutBuilder());
			case CIRCLE_MINCROSS:
				return CircleLayoutAlgorithm.<AttributedVertex> builder()
					.reduceEdgeCrossing(true);
			case TIDIER_TREE:
				return TidierTreeLayoutAlgorithm.<AttributedVertex, AttributedEdge> edgeAwareBuilder();
			case MIN_CROSS_TOP_DOWN:
				return HierarchicalMinCrossLayoutAlgorithm
					.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.layering(Layering.TOP_DOWN);
			case MIN_CROSS_LONGEST_PATH:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.layering(Layering.LONGEST_PATH);
			case MIN_CROSS_NETWORK_SIMPLEX:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.layering(Layering.NETWORK_SIMPLEX);
			case MIN_CROSS_COFFMAN_GRAHAM:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.layering(Layering.COFFMAN_GRAHAM);
			case MULTI_ROW_EDGE_AWARE_TREE:
				return MultiRowEdgeAwareTreeLayoutAlgorithm
					.<AttributedVertex, AttributedEdge> edgeAwareBuilder();
			case EDGE_AWARE_RADIAL:
				return RadialEdgeAwareTreeLayoutAlgorithm
					.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
					.verticalVertexSpacing(300);
			case EDGE_AWARE_TREE:
			default:
				return EdgeAwareTreeLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder();
		}
	}
}
