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
package ghidra.graph.job;

import static ghidra.graph.viewer.GraphViewerUtils.*;

import java.awt.*;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.HashSet;
import java.util.Set;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import util.CollectionUtils;

/**
 * A job to scale one or more viewers such that the contained graph will fit entirely inside the
 * viewing area.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class FitGraphToViewJob<V extends VisualVertex, E extends VisualEdge<V>>
		implements GraphJob {

	private final Set<VisualizationViewer<V, E>> viewers = new HashSet<>();
	private boolean isFinished;
	private final boolean onlyResizeWhenTooBig;

	@SafeVarargs
	public FitGraphToViewJob(VisualizationServer<V, E>... viewers) {
		for (VisualizationServer<V, E> viewer : viewers) {
			if (!(viewer instanceof VisualizationViewer)) {
				throw new IllegalArgumentException("VisualizationServer is not an instance of " +
					"VisualizationViewer.  We currently need this for bounds information.");
			}
			this.viewers.add((VisualizationViewer<V, E>) viewer);
		}

		this.onlyResizeWhenTooBig = false;
	}

	public FitGraphToViewJob(VisualizationServer<V, E> viewer, boolean onlyResizeWhenTooBig) {
		if (!(viewer instanceof VisualizationViewer)) {
			throw new IllegalArgumentException("VisualizationServer is not an instance of " +
				"VisualizationViewer.  We currently need this for bounds information.");
		}
		this.viewers.add((VisualizationViewer<V, E>) viewer);
		this.onlyResizeWhenTooBig = onlyResizeWhenTooBig;
	}

	@Override
	public boolean canShortcut() {
		return true;
	}

	@Override
	public void execute(GraphJobListener listener) {
		doExecute();
		listener.jobFinished(this);
	}

	private void doExecute() {
		if (isFinished) {
			return;
		}

		if (graphIsEmpty()) {
			return;
		}

		for (VisualizationViewer<V, E> viewer : viewers) {
			Rectangle graphBounds = getTotalGraphSizeInLayoutSpace(viewer);
			boolean resized = scaleToFitViewer(viewer, graphBounds);
			if (resized) {
				centerGraph(viewer, graphBounds);
			}
		}

		isFinished = true;
	}

	private boolean graphIsEmpty() {
		VisualizationViewer<V, E> viewer = CollectionUtils.any(viewers);
		Graph<V, E> graph = viewer.getGraphLayout().getGraph();
		return graph.getVertexCount() == 0;
	}

	@Override
	public boolean isFinished() {
		return isFinished;
	}

	@Override
	public void shortcut() {
		// just mark as finished and skip the work; this allows this job to be run many times, 
		// with only the last one performing any work
		isFinished = true;
	}

	@Override
	public void dispose() {
		isFinished = true;
	}

	private boolean scaleToFitViewer(VisualizationViewer<V, E> visualizationViewer,
			Rectangle2D graphBounds) {

		Dimension windowSize = visualizationViewer.getSize();
		Rectangle bounds = graphBounds.getBounds();

		Shape viewShape = translateShapeFromLayoutSpaceToViewSpace(bounds, visualizationViewer);
		Rectangle viewBounds = viewShape.getBounds();
		boolean fitsInView =
			viewBounds.width < windowSize.width && viewBounds.height < windowSize.height;
		if (onlyResizeWhenTooBig && fitsInView) {
			return false;
		}

		Double scaleRatio = getScaleRatioToFitInDimension(bounds.getSize(), windowSize);
		if (scaleRatio == null) {
			return true;
		}
		if (scaleRatio > 1.0) {
			scaleRatio = 1.0;
		}

		// add some padding and make it relative to the new scale
		int unscaledPaddingSize = 10;
		addPaddingToRectangle((int) (unscaledPaddingSize / scaleRatio), bounds);
		scaleRatio = getScaleRatioToFitInDimension(bounds.getSize(), windowSize);
		if (scaleRatio == null) {
			return true;
		}

		RenderContext<V, E> renderContext = visualizationViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		MutableTransformer viewTransformer = multiLayerTransformer.getTransformer(Layer.VIEW);

		viewTransformer.setScale(scaleRatio, scaleRatio, new Point(0, 0));
		return true;
	}

	private void centerGraph(VisualizationViewer<V, E> visualizationViewer, Rectangle graphBounds) {

		RenderContext<?, ?> context = visualizationViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = context.getMultiLayerTransformer();

		// ...get the offset we need to revert the view translation back to zero
		MutableTransformer viewTransformer = multiLayerTransformer.getTransformer(Layer.VIEW);
		viewTransformer.setTranslate(0, 0);

		// ...get the offset we need to revert the layout translation back to zero
		MutableTransformer layoutTransformer = multiLayerTransformer.getTransformer(Layer.LAYOUT);
		layoutTransformer.setTranslate(0, 0);

		// ...get the center of the graph and center the viewer over that point
		Point2D viewCenter = visualizationViewer.getCenter();

		viewCenter = translatePointFromViewSpaceToLayoutSpace(viewCenter, visualizationViewer);

		Point2D.Double graphCenter =
			new Point2D.Double(graphBounds.getCenterX(), graphBounds.getCenterY());
		double centerX = graphCenter.getX() - viewCenter.getX();
		double centerY = graphCenter.getY() - viewCenter.getY();

		layoutTransformer.setTranslate(-centerX, -centerY);
	}

	@Override
	public String toString() {
		return "Fit Graph to View Job";
	}
}
