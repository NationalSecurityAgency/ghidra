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
import org.jungrapht.visualization.layout.algorithms.repulsion.BarnesHutFRRepulsion;
import org.jungrapht.visualization.layout.algorithms.sugiyama.Layering;

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
	static final String TIDIER_RADIAL_TREE = "Compact Radial";
	static final String MIN_CROSS_TOP_DOWN = "Hierarchical MinCross Top Down";
	static final String MIN_CROSS_LONGEST_PATH = "Hierarchical MinCross Longest Path";
	static final String MIN_CROSS_NETWORK_SIMPLEX = "Hierarchical MinCross Network Simplex";
	static final String MIN_CROSS_COFFMAN_GRAHAM = "Hierarchical MinCross Coffman Graham";
	static final String TREE = "Hierarchical";
	static final String RADIAL = "Radial";
	static final String BALLOON = "Balloon";
	static final String GEM = "Gem (Graph Embedder)";

	public String[] getNames() {
		return new String[] { TIDIER_TREE, TREE,
				TIDIER_RADIAL_TREE, MIN_CROSS_TOP_DOWN, MIN_CROSS_LONGEST_PATH,
				MIN_CROSS_NETWORK_SIMPLEX, MIN_CROSS_COFFMAN_GRAHAM, CIRCLE_MINCROSS,
				KAMADA_KAWAI, FRUCTERMAN_REINGOLD, RADIAL, BALLOON, GEM
		};
	}

	@Override
	public LayoutAlgorithm.Builder<AttributedVertex, ?, ?> apply(String name) {
		switch(name) {
			case GEM:
				return GEMLayoutAlgorithm.edgeAwareBuilder();
			case KAMADA_KAWAI:
				return KKLayoutAlgorithm.<AttributedVertex> builder()
						.preRelaxDuration(1000);
			case FRUCTERMAN_REINGOLD:
				return FRLayoutAlgorithm.<AttributedVertex> builder()
					.repulsionContractBuilder(BarnesHutFRRepulsion.builder());
			case CIRCLE_MINCROSS:
				return CircleLayoutAlgorithm.<AttributedVertex> builder()
					.reduceEdgeCrossing(true);
			case TIDIER_RADIAL_TREE:
				return TidierRadialTreeLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder();
			case MIN_CROSS_TOP_DOWN:
				return EiglspergerLayoutAlgorithm
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
			case RADIAL:
				return RadialTreeLayoutAlgorithm
						.<AttributedVertex> builder()
					.verticalVertexSpacing(300);
			case BALLOON:
				return BalloonLayoutAlgorithm
						.<AttributedVertex> builder()
						.verticalVertexSpacing(300);
			case TREE:
				return TreeLayoutAlgorithm
						.builder();
			case TIDIER_TREE:
			default:
				return TidierTreeLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder();
		}
	}
}
