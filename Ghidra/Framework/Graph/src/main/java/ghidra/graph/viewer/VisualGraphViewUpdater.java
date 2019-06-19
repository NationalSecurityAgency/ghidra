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
package ghidra.graph.viewer;

import static ghidra.graph.viewer.GraphViewerUtils.*;

import java.awt.*;
import java.awt.geom.Point2D;
import java.util.Collection;
import java.util.Objects;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.*;
import ghidra.graph.VisualGraph;
import ghidra.graph.job.*;
import ghidra.graph.viewer.edge.routing.BasicEdgeRouter;
import ghidra.util.Msg;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import ghidra.util.task.BusyListener;
import utility.function.Callback;

/**
 * This is the class through which operations travel that manipulate the view and graph <b>while
 * plugged-in to the UI</b>.   (Setup and tear down operations performed before the view 
 * or graph are visible need not pass through this class.)  This class is responsible for 
 * controlling how to display view and graph changes, including whether to animate.
 * 
 * <P>The animations are categorized into those that mutate the graph and those that are just
 * display animations (like hover animations).
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphViewUpdater<V extends VisualVertex, E extends VisualEdge<V>> {

	@SuppressWarnings("unused") // may be useful in the future
	private VisualGraph<V, E> graph;

	private GraphJobRunner jobRunner = new GraphJobRunner();

	// TODO merge the two animators into a 'non-mutating, concurrent' job runner
	private static AbstractAnimator edgeHoverAnimator;
	private static TwinkleVertexAnimator<?, ?> vertexTwinkleAnimator;

	private GraphViewer<V, E> primaryViewer;

	// may be null if a graph does not use a satellite
	private SatelliteGraphViewer<V, E> satelliteViewer;

	private WeakSet<Callback> jobStartedListeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	public VisualGraphViewUpdater(GraphViewer<V, E> primaryViewer, VisualGraph<V, E> graph) {
		this.primaryViewer = Objects.requireNonNull(primaryViewer);
		this.graph = Objects.requireNonNull(graph);
	}

	protected void setSatelliteViewer(SatelliteGraphViewer<V, E> satelliteViewer) {
		this.satelliteViewer = satelliteViewer;
	}

	/**
	 * Add a listener to be notified when a job is started.  Jobs often, but not always, mutate
	 * the underlying graph.  For this reason, other tasks that use the graph may want to not 
	 * do their work while a job is running. 
	 * 
	 * @param c the listener
	 */
	public void addJobScheduledListener(Callback c) {
		jobStartedListeners.add(c);
	}

	public boolean isAnimationEnabled() {
		return primaryViewer.getOptions().useAnimation();
	}

	public void dispose() {
		// stop all mutations and animations
		jobRunner.dispose();
	}

	/**
	 * Fits the graph into both the primary and satellite views
	 */
	public void fitAllGraphsToViewsNow() {
		scheduleViewChangeJob(new FitGraphToViewJob<>(primaryViewer, satelliteViewer));
	}

	public void fitGraphToViewerNow() {
		fitGraphToViewerNow(primaryViewer);
	}

	public void fitGraphToViewerNow(VisualizationServer<V, E> theViewer) {
		scheduleViewChangeJob(new FitGraphToViewJob<>(theViewer));
	}

	/**
	 * Will schedule the fitting work to happen now if now work is being done, or later otherwis
	 */
	public void fitGraphToViewerLater() {
		jobRunner.setFinalJob(new FitGraphToViewJob<>(primaryViewer));
	}

	public void fitGraphToViewerLater(VisualizationServer<V, E> theViewer) {
		jobRunner.setFinalJob(new FitGraphToViewJob<>(theViewer));
	}

	public void zoomInCompletely() {
		zoomInCompletely(null);
	}

	public void zoomInCompletely(V centerOnVertex) {

		setGraphScale(1.0);
		if (centerOnVertex == null) {
			return;
		}
		moveVertexToCenterWithoutAnimation(centerOnVertex);
	}

	public void moveVertexToCenterTopWithoutAnimation(V vertex) {

		// Note: it is implied that any move *without* animation is a signal to cancel
		// all animation, as it is usually in response to a major structural change in the graph
		stopAllAnimation();

		Point2D.Double desiredOffsetPoint =
			getVertexOffsetFromLayoutCenterTop(primaryViewer, vertex);
		double dx = desiredOffsetPoint.getX();
		double dy = desiredOffsetPoint.getY();

		RenderContext<V, E> renderContext = primaryViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		multiLayerTransformer.getTransformer(Layer.LAYOUT).translate(dx, dy);
		primaryViewer.repaint();
	}

	public void moveVertexToCenterWithoutAnimation(V vertex) {

		// Note: it is implied that any move *without* animation is a signal to cancel
		// all animation, as it is usually in response to a major structural change in the graph
		stopAllAnimation();

		Point2D.Double desiredOffsetPoint = getVertexOffsetFromLayoutCenter(primaryViewer, vertex);
		double dx = desiredOffsetPoint.getX();
		double dy = desiredOffsetPoint.getY();

		RenderContext<V, E> renderContext = primaryViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		multiLayerTransformer.getTransformer(Layer.LAYOUT).translate(dx, dy);
		primaryViewer.repaint();
	}

	/*
	 
	 	moveVertexToCenterLater(vertex);
	 	
	 	moveVertexToCenterAnimated(vertex);
	 
	 */

	public void moveVertexToCenterWithAnimation(V vertex) {
		moveVertexToCenterWithAnimation(vertex, null);
	}

	public void moveVertexToCenterWithAnimation(V vertex, BusyListener callbackListener) {

		MoveVertexToCenterAnimatorFunctionGraphJob<V, E> job =
			new MoveVertexToCenterAnimatorFunctionGraphJob<>(primaryViewer, vertex,
				isAnimationEnabled());
		job.setBusyListener(callbackListener);
		scheduleViewChangeJob(job);
	}

	public void moveVertexToCenterTopWithAnimation(V vertex) {
		moveVertexToCenterTopWithAnimation(vertex, null);
	}

	public void moveVertexToCenterTopWithAnimation(V vertex, BusyListener callbackListener) {

		MoveVertexToCenterTopAnimatorFunctionGraphJob<V, E> job =
			new MoveVertexToCenterTopAnimatorFunctionGraphJob<>(primaryViewer, vertex,
				isAnimationEnabled());
		job.setBusyListener(callbackListener);
		scheduleViewChangeJob(job);
	}

	public void moveViewerLocationWithoutAnimation(Point translation) {

		// Note: it is implied that any move *without* animation is a signal to cancel
		// all animation, as it is usually in response to a major structural change in the graph
		stopAllAnimation();

		double dx = translation.x;
		double dy = translation.y;

		RenderContext<V, E> renderContext = primaryViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		multiLayerTransformer.getTransformer(Layer.LAYOUT).translate(dx, dy);
		primaryViewer.repaint();
	}

	public void centerViewSpacePointWithAnimation(Point point) {

		scheduleViewChangeJob(new MoveViewToViewSpacePointAnimatorFunctionGraphJob<>(primaryViewer,
			point, isAnimationEnabled()));
	}

	public void centerViewSpacePointWithoutAnimation(Point point) {
		Point pointInLayoutSpace = translatePointFromViewSpaceToLayoutSpace(point, primaryViewer);
		centerLayoutSpacePointWithoutAnimation(pointInLayoutSpace);
	}

	public void centerLayoutSpacePointWithoutAnimation(Point point) {

		// Note: it is implied that any move *without* animation is a signal to cancel
		// all animation, as it is usually in response to a major structural change in the graph
		stopAllAnimation();

		Point2D.Double translationOffset = getOffsetFromCenterInLayoutSpace(primaryViewer, point);
		double dx = translationOffset.getX();
		double dy = translationOffset.getY();

		RenderContext<V, E> renderContext = primaryViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		multiLayerTransformer.getTransformer(Layer.LAYOUT).translate(dx, dy);
		primaryViewer.repaint();
	}

	public void setLayoutSpacePointWithoutAnimation(Point2D point) {

		// Note: it is implied that any move *without* animation is a signal to cancel
		// all animation, as it is usually in response to a major structural change in the graph
		stopAllAnimation();

		double dx = point.getX();
		double dy = point.getY();

		RenderContext<V, E> renderContext = primaryViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		multiLayerTransformer.getTransformer(Layer.LAYOUT).translate(dx, dy);
		primaryViewer.repaint();
	}

	public void setLayoutSpacePointWithAnimation(Point point) {

		scheduleViewChangeJob(new MoveViewToLayoutSpacePointAnimatorFunctionGraphJob<>(
			primaryViewer, point, isAnimationEnabled()));
	}

	public void ensureVertexVisible(V vertex, Rectangle area) {

		RenderContext<V, E> renderContext = primaryViewer.getRenderContext();
		Function<? super V, Shape> transformer = renderContext.getVertexShapeTransformer();
		Shape shape = transformer.apply(vertex);
		Rectangle bounds = shape.getBounds();
		ensureVertexAreaVisible(vertex, bounds, null);
	}

	/*
	 * Makes sure that the given rectangle is not outside of the primary viewer's view and that
	 * the area is not occluded by the satellite viewer.
	 */
	public void ensureVertexAreaVisible(V vertex, Rectangle area, BusyListener callbackListener) {

		Objects.requireNonNull(vertex, "Vertex cannot be null");
		Objects.requireNonNull(area, "Area rectangle cannot be null");
		EnsureAreaVisibleAnimatorFunctionGraphJob<V, E> job =
			new EnsureAreaVisibleAnimatorFunctionGraphJob<>(primaryViewer, satelliteViewer, vertex,
				area, isAnimationEnabled());

		job.setBusyListener(callbackListener);
		scheduleViewChangeJob(job);
	}

	public void updateEdgeShapes(Collection<E> edges) {

		if (!layoutUsesEdgeArticulations(primaryViewer.getGraphLayout())) {
			return;
		}

		// ArticulatedEdgeRouter<V, E> edgeRouter = new ArticulatedEdgeRouter<V, E>(viewer, edges);
		BasicEdgeRouter<V, E> edgeRouter = new BasicEdgeRouter<>(primaryViewer, edges);
		edgeRouter.route();
	}

	public void setGraphPerspective(GraphPerspectiveInfo<V, E> graphInfo) {

		/*
			Current Issues (see SCR 9208):
			-the given data is not created correctly--the memento is using location information
			 from when the navigation takes place, which may be after the user has moved the
			 graph (panned it by hand).  So, we really need to record the info at the point when
			 the user first clicks or when the location is first set.
		
			-How to handle the case where the user moves vertices that are on the navigation stack?
			--Use this algorithm and then ensure that the cursor is on the screen.
		
		*/

		if (graphInfo == null) {
			return;
		}

		// Note: Using this method implies a major structural change in the graph
		stopAllAnimation();

		if (!graphInfo.isRestoreZoom()) {
			// note: if we want to support this, then we will have to adjust the translate
			//       coordinates based upon the differences in zoom.
			Msg.error(this, "Restoring the view coordinates without " +
				"restoring the zoom is currently not supported.", new AssertException());
		}

		RenderContext<V, E> renderContext = primaryViewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();

		// restore the current transform before we
		setGraphScale(graphInfo.getZoom());

		Point layoutPoint = graphInfo.getLayoutTranslateCoordinates();
		multiLayerTransformer.getTransformer(Layer.LAYOUT).setTranslate(layoutPoint.x,
			layoutPoint.y);

		Point viewPoint = graphInfo.getViewTranslateCoordinates();
		multiLayerTransformer.getTransformer(Layer.VIEW).setTranslate(viewPoint.x, viewPoint.y);
	}

	public void twinkeVertex(V vertex) {

		if (!isScaledPastVertexInteractionThreshold(primaryViewer)) {
			return;
		}

		if (vertexTwinkleAnimator != null) {
			if (vertexTwinkleAnimator.getVertex() == vertex) {
				return; // let the current twinkle just finish
			}
			vertexTwinkleAnimator.stop();
		}

		vertexTwinkleAnimator =
			new TwinkleVertexAnimator<>(primaryViewer, vertex, isAnimationEnabled());
		vertexTwinkleAnimator.start();
	}

	public void setGraphScale(double scale) {
		stopAllAnimation();
		GraphViewerUtils.setGraphScale(primaryViewer, scale);
	}

	public void animateEdgeHover() {

		if (edgeHoverAnimator != null) {
			edgeHoverAnimator.stop();
		}

		edgeHoverAnimator =
			new EdgeHoverAnimator<>(primaryViewer, satelliteViewer, isAnimationEnabled());
		edgeHoverAnimator.start();
	}

	/**
	 * Returns true if this updater is performing any animations or running any jobs that can
	 * mutate the graph or view
	 * 
	 * @return true if busy
	 */
	public boolean isBusy() {
		if (edgeHoverAnimator != null) {
			if (!edgeHoverAnimator.hasFinished()) {
				return true;
			}
		}

		if (vertexTwinkleAnimator != null) {
			if (!vertexTwinkleAnimator.hasFinished()) {
				return true;
			}
		}

		boolean busy = jobRunner.isBusy();
		return busy;
	}

	/**
	 * Returns true if this updater is running any jobs that can mutate the graph or view
	 * 
	 * @return true if busy
	 */
	public boolean isMutatingGraph() {
		boolean busy = jobRunner.isBusy();
		return busy;
	}

//==================================================================================================
// Animation Methods
//==================================================================================================

	public void scheduleViewChangeJob(GraphJob job) {
		jobStartedListeners.forEach(l -> l.call());
		stopAllNonMutativeAnimation();
		jobRunner.schedule(job);
	}

	public void stopEdgeHoverAnimation() {
		if (edgeHoverAnimator != null) {
			edgeHoverAnimator.stop();
			edgeHoverAnimator = null;
		}
	}

	private void stopVertexTwinkleAnimation() {
		if (vertexTwinkleAnimator != null) {
			vertexTwinkleAnimator.stop();
			vertexTwinkleAnimator = null;
		}
	}

	public void stopAllAnimation() {
		stopAllNonMutativeAnimation();
		jobRunner.finishAllJobs();
	}

	protected void stopAllNonMutativeAnimation() {
		stopEdgeHoverAnimation();
		stopVertexTwinkleAnimation();
	}

}
