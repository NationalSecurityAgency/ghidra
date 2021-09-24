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

import static ghidra.service.graph.LayoutAlgorithmNames.*;

import java.util.Comparator;
import java.util.function.Function;
import java.util.function.Predicate;

import org.jungrapht.visualization.layout.algorithms.*;
import org.jungrapht.visualization.layout.algorithms.repulsion.BarnesHutFRRepulsion;
import org.jungrapht.visualization.layout.algorithms.sugiyama.Layering;

import com.google.common.base.Objects;

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

	Predicate<AttributedEdge> favoredEdgePredicate;
	Comparator<AttributedEdge> edgeTypeComparator;

	LayoutFunction(GraphRenderer renderer) {
		this.edgeTypeComparator = new EdgeComparator(renderer);
		this.favoredEdgePredicate =
			edge -> Objects.equal(edge.getEdgeType(), renderer.getFavoredEdgeType());
	}



	@Override
	public LayoutAlgorithm.Builder<AttributedVertex, ?, ?> apply(String name) {
		switch(name) {
			case GEM:
				return GEMLayoutAlgorithm.edgeAwareBuilder();
			case FORCED_BALANCED:
				return KKLayoutAlgorithm.<AttributedVertex> builder()
						.preRelaxDuration(1000);
			case FORCE_DIRECTED:
				return FRLayoutAlgorithm.<AttributedVertex> builder()
					.repulsionContractBuilder(BarnesHutFRRepulsion.builder());
			case CIRCLE:
				return CircleLayoutAlgorithm.<AttributedVertex> builder()
					.reduceEdgeCrossing(false);
			case COMPACT_RADIAL:
				return TidierRadialTreeLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator);
			case MIN_CROSS_TOP_DOWN:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.TOP_DOWN);
			case MIN_CROSS_LONGEST_PATH:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.LONGEST_PATH);
			case MIN_CROSS_NETWORK_SIMPLEX:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.NETWORK_SIMPLEX);
			case MIN_CROSS_COFFMAN_GRAHAM:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.COFFMAN_GRAHAM);
			case VERT_MIN_CROSS_TOP_DOWN:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.TOP_DOWN);
			case VERT_MIN_CROSS_LONGEST_PATH:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.LONGEST_PATH);
			case VERT_MIN_CROSS_NETWORK_SIMPLEX:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.NETWORK_SIMPLEX);
			case VERT_MIN_CROSS_COFFMAN_GRAHAM:
				return EiglspergerLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.COFFMAN_GRAHAM);
			case RADIAL:
				return RadialTreeLayoutAlgorithm
						.<AttributedVertex> builder()
					.verticalVertexSpacing(300);
			case BALLOON:
				return BalloonLayoutAlgorithm
						.<AttributedVertex> builder()
						.verticalVertexSpacing(300);
			case HIERACHICAL:
				return EdgeAwareTreeLayoutAlgorithm
						.<AttributedVertex, AttributedEdge>edgeAwareBuilder();
			case COMPACT_HIERARCHICAL:
			default:
				return TidierTreeLayoutAlgorithm
						.<AttributedVertex, AttributedEdge> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator);

		}
	}
}
