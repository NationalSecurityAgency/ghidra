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

import static ghidra.graph.visualization.LayoutFunction.*;

import java.util.Comparator;
import java.util.function.Function;
import java.util.function.Predicate;

import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.layout.algorithms.*;
import org.jungrapht.visualization.layout.algorithms.util.VertexBoundsFunctionConsumer;
import org.jungrapht.visualization.layout.model.Rectangle;
import org.jungrapht.visualization.util.LayoutAlgorithmTransition;
import org.jungrapht.visualization.util.LayoutPaintable;

import ghidra.service.graph.AttributedEdge;
import ghidra.service.graph.AttributedVertex;

/**
 * Manages the selection and transition from one {@link LayoutAlgorithm} to another
 */
class LayoutTransitionManager {

	LayoutFunction layoutFunction = new LayoutFunction();
	/**
	 * the {@link VisualizationServer} used to display graphs using the requested {@link LayoutAlgorithm}
	 */
	VisualizationServer<AttributedVertex, AttributedEdge> visualizationServer;

	/**
	 * a {@link Predicate} to assist in determining which vertices are root vertices (for Tree layouts)
	 */
	Predicate<AttributedVertex> rootPredicate;

	/**
	 * a {@link Comparator} to sort edges during layout graph traversal
	 */
	Comparator<AttributedEdge> edgeComparator = (e1, e2) -> 0;

	/**
	 * a {@link Function} to provide {@link Rectangle} (and thus bounds} for vertices
	 */
	Function<AttributedVertex, Rectangle> vertexBoundsFunction;

	/**
	 * the {@link RenderContext} used to draw the graph
	 */
	RenderContext<AttributedVertex, AttributedEdge> renderContext;

	LayoutPaintable.BalloonRings<AttributedVertex, AttributedEdge> balloonLayoutRings;

	LayoutPaintable.RadialRings<AttributedVertex> radialLayoutRings;


	/**
	 * Create an instance with passed parameters
	 * @param visualizationServer displays the graph
	 * @param rootPredicate selects root vertices
	 */
	public LayoutTransitionManager(
			VisualizationServer<AttributedVertex, AttributedEdge> visualizationServer,
			Predicate<AttributedVertex> rootPredicate) {
		this.visualizationServer = visualizationServer;
		this.rootPredicate = rootPredicate;

		this.renderContext = visualizationServer.getRenderContext();
		this.vertexBoundsFunction = visualizationServer.getRenderContext().getVertexBoundsFunction();
	}

	public void setEdgeComparator(Comparator<AttributedEdge> edgeComparator) {
		this.edgeComparator = edgeComparator;
	}

	/**
	 * set the layout in order to configure the requested {@link LayoutAlgorithm}
	 * @param layoutName the name of the layout algorithm to use
	 */
	@SuppressWarnings("unchecked")
	public void setLayout(String layoutName) {
		LayoutAlgorithm.Builder<AttributedVertex, ?, ?> builder = layoutFunction.apply(layoutName);
		LayoutAlgorithm<AttributedVertex> layoutAlgorithm = builder.build();
		if (layoutAlgorithm instanceof VertexBoundsFunctionConsumer) {
			((VertexBoundsFunctionConsumer<AttributedVertex>) layoutAlgorithm)
				.setVertexBoundsFunction(vertexBoundsFunction);
		}
		if (layoutAlgorithm instanceof Layered) {
			((Layered<AttributedVertex, AttributedEdge>) layoutAlgorithm)
					.setMaxLevelCrossFunction(g ->
							Math.max(1, Math.min(10, 500 / g.vertexSet().size())));
		}
		if (layoutAlgorithm instanceof TreeLayout) {
			((TreeLayout<AttributedVertex>) layoutAlgorithm).setRootPredicate(rootPredicate);
		}
		// remove any previously added layout paintables
		removePaintable(radialLayoutRings);
		removePaintable(balloonLayoutRings);
		if (layoutAlgorithm instanceof BalloonLayoutAlgorithm) {
			balloonLayoutRings =
					new LayoutPaintable.BalloonRings<>(
					visualizationServer,
					(BalloonLayoutAlgorithm<AttributedVertex>) layoutAlgorithm);
			visualizationServer.addPreRenderPaintable(balloonLayoutRings);
		}
		if (layoutAlgorithm instanceof RadialTreeLayout) {
			radialLayoutRings =
					new LayoutPaintable.RadialRings<>(
					visualizationServer, (RadialTreeLayout<AttributedVertex>) layoutAlgorithm);
			visualizationServer.addPreRenderPaintable(radialLayoutRings);
		}

		if (layoutAlgorithm instanceof EdgeSorting) {
			((EdgeSorting<AttributedEdge>) layoutAlgorithm).setEdgeComparator(edgeComparator);
		}
		LayoutAlgorithmTransition.apply(visualizationServer, layoutAlgorithm);
	}

	private void removePaintable(VisualizationServer.Paintable paintable) {
		if (paintable != null) {
			visualizationServer.removePreRenderPaintable(paintable);
		}
	}

	@SuppressWarnings("unchecked")
	public LayoutAlgorithm<AttributedVertex> getInitialLayoutAlgorithm() {
		LayoutAlgorithm<AttributedVertex> initialLayoutAlgorithm =
			layoutFunction.apply(TIDIER_TREE).build();

		if (initialLayoutAlgorithm instanceof TreeLayout) {
			((TreeLayout<AttributedVertex>) initialLayoutAlgorithm)
					.setRootPredicate(rootPredicate);
			((TreeLayout<AttributedVertex>) initialLayoutAlgorithm)
					.setVertexBoundsFunction(vertexBoundsFunction);
		}
		if (initialLayoutAlgorithm instanceof EdgeSorting) {
			((EdgeSorting<AttributedEdge>) initialLayoutAlgorithm)
					.setEdgeComparator(edgeComparator);
		}
		if (initialLayoutAlgorithm instanceof VertexBoundsFunctionConsumer) {
			((VertexBoundsFunctionConsumer<AttributedVertex>) initialLayoutAlgorithm)
					.setVertexBoundsFunction(vertexBoundsFunction);
		}
		return initialLayoutAlgorithm;
	}

	public String[] getLayoutNames() {
		return layoutFunction.getNames();
	}
}
