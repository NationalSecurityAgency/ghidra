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
package ghidra.app.plugin.core.functiongraph.graph.layout.jungrapht;

import static ghidra.service.graph.LayoutAlgorithmNames.*;

import java.awt.Shape;
import java.util.Comparator;
import java.util.List;
import java.util.function.Function;
import java.util.function.Predicate;

import org.jungrapht.visualization.layout.algorithms.*;
import org.jungrapht.visualization.layout.algorithms.LayoutAlgorithm.Builder;
import org.jungrapht.visualization.layout.algorithms.sugiyama.Layering;
import org.jungrapht.visualization.layout.algorithms.util.VertexBoundsFunctionConsumer;
import org.jungrapht.visualization.layout.model.Rectangle;

import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.util.Msg;

/**
 * A class that supplies Jung graph layouts to the Function Graph API.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class JgtLayoutFactory<V extends FGVertex, E extends FGEdge> {

	private static List<String> layoutNames = List.of(
		COMPACT_HIERARCHICAL,
		HIERACHICAL,
		MIN_CROSS_TOP_DOWN,
		MIN_CROSS_LONGEST_PATH,
		MIN_CROSS_NETWORK_SIMPLEX,
		MIN_CROSS_COFFMAN_GRAHAM,
		VERT_MIN_CROSS_TOP_DOWN,
		VERT_MIN_CROSS_LONGEST_PATH,
		VERT_MIN_CROSS_NETWORK_SIMPLEX,
		VERT_MIN_CROSS_COFFMAN_GRAHAM);

	private Predicate<E> favoredEdgePredicate;
	private Comparator<E> edgeTypeComparator;
	private Predicate<V> rootPredicate;

	public JgtLayoutFactory(Comparator<E> comparator, Predicate<E> favoredEdgePredicate,
			Predicate<V> rootPredicate) {
		this.edgeTypeComparator = comparator;
		this.favoredEdgePredicate = favoredEdgePredicate;
		this.rootPredicate = rootPredicate;
	}

	public static List<String> getSupportedLayoutNames() {
		return layoutNames;
	}

	public LayoutAlgorithm<V> getLayout(String name) {

		Builder<V, ?, ?> layoutBuilder = doGetLayout(name);
		LayoutAlgorithm<V> layout = layoutBuilder.build();

		if (layout instanceof TreeLayout) {
			((TreeLayout<V>) layout).setRootPredicate(rootPredicate);
		}

		if (layout instanceof VertexBoundsFunctionConsumer) {
			@SuppressWarnings("unchecked")
			VertexBoundsFunctionConsumer<FGVertex> boundsLayout =
				(VertexBoundsFunctionConsumer<FGVertex>) layout;
			Function<FGVertex, Rectangle> vertexBoundsFunction = new FGVertexShapeFunction();
			boundsLayout.setVertexBoundsFunction(vertexBoundsFunction);
		}

		// we should not need to set the max level, since our graphs do not get too many vertices
		// layoutAlgorithm.setMaxLevelCrossFunction(...);

		return layout;
	}

	private LayoutAlgorithm.Builder<V, ?, ?> doGetLayout(String name) {
		switch (name) {
			case COMPACT_HIERARCHICAL:
				return TidierTreeLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator);
			case HIERACHICAL:
				return EdgeAwareTreeLayoutAlgorithm
						.<V, E> edgeAwareBuilder();
			case MIN_CROSS_TOP_DOWN:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.TOP_DOWN)
						.threaded(false);
			case MIN_CROSS_LONGEST_PATH:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.LONGEST_PATH)
						.threaded(false);
			case MIN_CROSS_NETWORK_SIMPLEX:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.NETWORK_SIMPLEX)
						.threaded(false);
			case MIN_CROSS_COFFMAN_GRAHAM:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.layering(Layering.COFFMAN_GRAHAM)
						.threaded(false);
			case VERT_MIN_CROSS_TOP_DOWN:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.TOP_DOWN)
						.threaded(false);
			case VERT_MIN_CROSS_LONGEST_PATH:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.LONGEST_PATH)
						.threaded(false);
			case VERT_MIN_CROSS_NETWORK_SIMPLEX:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.NETWORK_SIMPLEX)
						.threaded(false);
			case VERT_MIN_CROSS_COFFMAN_GRAHAM:
				return EiglspergerLayoutAlgorithm
						.<V, E> edgeAwareBuilder()
						.edgeComparator(edgeTypeComparator)
						.favoredEdgePredicate(favoredEdgePredicate)
						.layering(Layering.COFFMAN_GRAHAM)
						.threaded(false);
			default:
				Msg.error(this, "Unknown graph layout type: '" + name + "'");
				return null;
		}
	}

	private class FGVertexShapeFunction implements Function<FGVertex, Rectangle> {

		private VisualGraphVertexShapeTransformer<FGVertex> vgShaper =
			new VisualGraphVertexShapeTransformer<>();

		@Override
		public Rectangle apply(FGVertex v) {

			Shape shape = vgShaper.apply(v);
			java.awt.Rectangle r = shape.getBounds();
			return Rectangle.of(r.x, r.y, r.width, r.height);
		}
	}
}
