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
import java.util.function.Predicate;

import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.layout.algorithms.*;
import org.jungrapht.visualization.layout.algorithms.util.VertexBoundsFunctionConsumer;
import org.jungrapht.visualization.layout.model.Rectangle;
import org.jungrapht.visualization.util.LayoutAlgorithmTransition;
import org.jungrapht.visualization.util.LayoutPaintable;

import ghidra.service.graph.*;

/**
 * Manages the selection and transition from one {@link LayoutAlgorithm} to another
 */
class LayoutTransitionManager {

	LayoutFunction layoutFunction;
	/**
	 * the {@link VisualizationServer} used to display graphs using the requested {@link LayoutAlgorithm}
	 */
	VisualizationServer<AttributedVertex, AttributedEdge> visualizationServer;

	/**
	 * a {@link Predicate} to assist in determining which vertices are root vertices (for Tree layouts)
	 */
	Predicate<AttributedVertex> rootPredicate;

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
	 * @param renderer the graph renderer
	 */
	public LayoutTransitionManager(
			VisualizationServer<AttributedVertex, AttributedEdge> visualizationServer,
			Predicate<AttributedVertex> rootPredicate, GraphRenderer renderer) {

		this.visualizationServer = visualizationServer;
		this.rootPredicate = rootPredicate;
		this.renderContext = visualizationServer.getRenderContext();
		this.vertexBoundsFunction =
			visualizationServer.getRenderContext().getVertexBoundsFunction();
		this.layoutFunction = new LayoutFunction(renderer);
	}

	/**
	 * set the layout in order to configure the requested {@link LayoutAlgorithm}
	 * @param layoutName the name of the layout algorithm to use
	 */
	@SuppressWarnings("unchecked")
	public void setLayout(String layoutName) {
		LayoutAlgorithm.Builder<AttributedVertex, ?, ?> builder = layoutFunction.apply(layoutName);
		LayoutAlgorithm<AttributedVertex> layoutAlgorithm = builder.build();
		// layout algorithm considers the size of vertices
		if (layoutAlgorithm instanceof VertexBoundsFunctionConsumer) {
			((VertexBoundsFunctionConsumer<AttributedVertex>) layoutAlgorithm)
					.setVertexBoundsFunction(vertexBoundsFunction);
		}
		// mincross layouts are 'layered'. put some bounds on the number of
		// iterations of the level cross function based on the size of the graph
		// very large graphs do not improve enough to out-weigh the cost of
		// repeated iterations
		if (layoutAlgorithm instanceof Layered) {
			((Layered<AttributedVertex, AttributedEdge>) layoutAlgorithm).setMaxLevelCrossFunction(
				g -> Math.max(1, Math.min(10, 500 / g.vertexSet().size())));
		}
		// tree layouts need a way to determine which vertices are roots
		// especially when the graph is not a DAG
		if (layoutAlgorithm instanceof TreeLayout) {
			((TreeLayout<AttributedVertex>) layoutAlgorithm).setRootPredicate(rootPredicate);
		}
		// remove any previously added layout paintables
		// and apply paintables to these 2 algorithms
		removePaintable(radialLayoutRings);
		removePaintable(balloonLayoutRings);
		if (layoutAlgorithm instanceof BalloonLayoutAlgorithm) {
			balloonLayoutRings = new LayoutPaintable.BalloonRings<>(visualizationServer,
				(BalloonLayoutAlgorithm<AttributedVertex>) layoutAlgorithm);
			visualizationServer.addPreRenderPaintable(balloonLayoutRings);
		}
		if (layoutAlgorithm instanceof RadialTreeLayout) {
			radialLayoutRings = new LayoutPaintable.RadialRings<>(visualizationServer,
				(RadialTreeLayout<AttributedVertex>) layoutAlgorithm);
			visualizationServer.addPreRenderPaintable(radialLayoutRings);
		}

		// apply the layout algorithm
		LayoutAlgorithmTransition.apply(visualizationServer, layoutAlgorithm);
	}

	private void removePaintable(VisualizationServer.Paintable paintable) {
		if (paintable != null) {
			visualizationServer.removePreRenderPaintable(paintable);
		}
	}

	/**
	 * Supplies the {@code LayoutAlgorithm} to be used for the initial @{code Graph} visualization
	 * @return the algorithm
	 */
	@SuppressWarnings("unchecked")
	public LayoutAlgorithm<AttributedVertex> getInitialLayoutAlgorithm() {
		LayoutAlgorithm<AttributedVertex> initialLayoutAlgorithm =
			layoutFunction.apply(LayoutAlgorithmNames.COMPACT_HIERARCHICAL).build();

		if (initialLayoutAlgorithm instanceof TreeLayout) {
			((TreeLayout<AttributedVertex>) initialLayoutAlgorithm).setRootPredicate(rootPredicate);
		}
		if (initialLayoutAlgorithm instanceof VertexBoundsFunctionConsumer) {
			((VertexBoundsFunctionConsumer<AttributedVertex>) initialLayoutAlgorithm)
					.setVertexBoundsFunction(vertexBoundsFunction);
		}
		return initialLayoutAlgorithm;
	}

}
