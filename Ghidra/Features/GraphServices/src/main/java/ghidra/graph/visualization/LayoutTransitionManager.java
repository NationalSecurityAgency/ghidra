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

import java.awt.Shape;
import java.util.*;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.jgrapht.Graph;
import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationServer;
import org.jungrapht.visualization.layout.algorithms.*;
import org.jungrapht.visualization.layout.algorithms.util.*;
import org.jungrapht.visualization.layout.model.LayoutModel;
import org.jungrapht.visualization.util.Context;

import docking.menu.MultiActionDockingAction;
import ghidra.service.graph.*;

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
	 * a {@link Predicate} to allow different handling of specific edge types
	 */
	Predicate<AttributedEdge> edgePredicate;

	/**
	 * a {@link Comparator} to sort edges during layout graph traversal
	 */
	Comparator<AttributedEdge> edgeComparator = (e1, e2) -> 0;

	/**
	 * a {@link MultiActionDockingAction} to allow the user to select a layout algorithm
	 */
	MultiActionDockingAction multiActionDockingAction;

	/**
	 * the currently active {@code LayoutAlgorithm.Builder}
	 */
	LayoutAlgorithm.Builder<AttributedVertex, ?, ?> activeBuilder;

	/**
	 * a {@link Function} to provide {@link Shape} (and thus bounds} for vertices
	 */
	Function<AttributedVertex, Shape> vertexShapeFunction;

	/**
	 * the {@link RenderContext} used to draw the graph
	 */
	RenderContext<AttributedVertex, AttributedEdge> renderContext;

	/**
	 * a LayoutAlgorithm may change the edge shape function (Sugiyama for articulated edges)
	 * This is a reference to the original edge shape function so that it can be returned to
	 * the original edge shape function for subsequent LayoutAlgorithm requests
	 */
	private Function<Context<Graph<AttributedVertex, AttributedEdge>, AttributedEdge>, Shape> originalEdgeShapeFunction;


	/**
	 * Create an instance with passed parameters
	 * @param visualizationServer displays the graph
	 * @param rootPredicate selects root vertices
	 * @param edgePredicate differentiates edges
	 */
	public LayoutTransitionManager(
			VisualizationServer<AttributedVertex, AttributedEdge> visualizationServer,
			Predicate<AttributedVertex> rootPredicate, Predicate<AttributedEdge> edgePredicate) {
		this.visualizationServer = visualizationServer;
		this.rootPredicate = rootPredicate;
		this.edgePredicate = edgePredicate;

		this.renderContext = visualizationServer.getRenderContext();
		this.vertexShapeFunction = visualizationServer.getRenderContext().getVertexShapeFunction();
		this.originalEdgeShapeFunction =
			visualizationServer.getRenderContext().getEdgeShapeFunction();

	}

	public void setGraph(AttributedGraph graph) {
		edgeComparator = new EdgeComparator(graph, "EdgeType", DefaultGraphDisplay.FAVORED_EDGE);
	}

	/**
	 * set the layout in order to configure the requested {@link LayoutAlgorithm}
	 * @param layoutName the name of the layout algorithm to use
	 */
	@SuppressWarnings("unchecked")
	public void setLayout(String layoutName) {
		LayoutAlgorithm.Builder<AttributedVertex, ?, ?> builder = layoutFunction.apply(layoutName);
		visualizationServer.getRenderContext().getMultiLayerTransformer().setToIdentity();
		LayoutAlgorithm<AttributedVertex> layoutAlgorithm = builder.build();

		if (layoutAlgorithm instanceof RenderContextAware) {
			((RenderContextAware<AttributedVertex, AttributedEdge>) layoutAlgorithm)
				.setRenderContext(visualizationServer.getRenderContext());
		}
		else {
			visualizationServer.getRenderContext().setEdgeShapeFunction(originalEdgeShapeFunction);
		}
		if (layoutAlgorithm instanceof VertexShapeAware) {
			((VertexShapeAware<AttributedVertex>) layoutAlgorithm)
				.setVertexShapeFunction(vertexShapeFunction);
		}
		if (layoutAlgorithm instanceof TreeLayout) {
			((TreeLayout<AttributedVertex>) layoutAlgorithm).setRootPredicate(rootPredicate);
		}
		if (layoutAlgorithm instanceof EdgeSorting) {
			((EdgeSorting<AttributedEdge>) layoutAlgorithm).setEdgeComparator(edgeComparator);
		}
		if (layoutAlgorithm instanceof EdgePredicated) {
			((EdgePredicated<AttributedEdge>) layoutAlgorithm).setEdgePredicate(edgePredicate);
		}
		if (!(layoutAlgorithm instanceof TreeLayout)) {
			LayoutModel<AttributedVertex> layoutModel =
				visualizationServer.getVisualizationModel().getLayoutModel();
			int preferredWidth = layoutModel.getPreferredWidth();
			int preferredHeight = layoutModel.getPreferredHeight();
			layoutModel.setSize(preferredWidth, preferredHeight);
		}
		if (layoutAlgorithm instanceof RenderContextAware) {
			((RenderContextAware<AttributedVertex, AttributedEdge>) layoutAlgorithm)
				.setRenderContext(renderContext);
		}
		if (layoutAlgorithm instanceof AfterRunnable) {
			((AfterRunnable) layoutAlgorithm).setAfter(visualizationServer::scaleToLayout);
		}
		LayoutAlgorithmTransition.apply(visualizationServer, layoutAlgorithm,
			visualizationServer::scaleToLayout);
	}

	@SuppressWarnings("unchecked")
	public LayoutAlgorithm<AttributedVertex> getInitialLayoutAlgorithm(
			AttributedGraph graph) {
		Set<AttributedVertex> roots = getRoots(graph);

		// if there are no roots, don't attempt to create a Tree layout
		if (roots.size() == 0) {
			return layoutFunction.apply(FRUCTERMAN_REINGOLD).build();
		}

		LayoutAlgorithm<AttributedVertex> initialLayoutAlgorithm =
			layoutFunction.apply(EDGE_AWARE_TREE).build();

		if (initialLayoutAlgorithm instanceof TreeLayout) {
			((TreeLayout<AttributedVertex>) initialLayoutAlgorithm)
					.setRootPredicate(rootPredicate);
			((TreeLayout<AttributedVertex>) initialLayoutAlgorithm)
					.setVertexShapeFunction(vertexShapeFunction);
		}
		if (initialLayoutAlgorithm instanceof EdgeSorting) {
			((EdgeSorting<AttributedEdge>) initialLayoutAlgorithm)
					.setEdgeComparator(edgeComparator);
		}
		if (initialLayoutAlgorithm instanceof EdgePredicated) {
			((EdgePredicated<AttributedEdge>) initialLayoutAlgorithm)
					.setEdgePredicate(edgePredicate);
		}
		if (initialLayoutAlgorithm instanceof ShapeFunctionAware) {
			((ShapeFunctionAware<AttributedVertex>) initialLayoutAlgorithm)
					.setVertexShapeFunction(vertexShapeFunction);
		}
		return initialLayoutAlgorithm;
	}

	private Set<AttributedVertex> getRoots(AttributedGraph graph) {
		return graph.edgeSet()
				.stream()
				.sorted(edgeComparator)
				.map(graph::getEdgeSource)
				.filter(rootPredicate)
				.collect(Collectors.toCollection(LinkedHashSet::new));
	}

	public String[] getLayoutNames() {
		return layoutFunction.getNames();
	}

}
