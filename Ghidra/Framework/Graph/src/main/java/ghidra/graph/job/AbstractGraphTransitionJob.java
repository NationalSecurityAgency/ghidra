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

import java.awt.geom.Point2D;
import java.util.*;
import java.util.Map.Entry;

import org.jdesktop.animation.timing.Animator;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.util.Caching;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.layout.*;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskLauncher;

/**
 * A job to transition vertices in a graph for location and visibility.  The parent class 
 * handled the opacity callback.  The progress of the job is used by this class to move 
 * vertices from the the start location to the final destination, where the progress is the
 * percentage of the total move to display.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public abstract class AbstractGraphTransitionJob<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractGraphVisibilityTransitionJob<V, E> {

	protected final VisualGraphLayout<V, E> graphLayout;

	/** A start and end point for each vertex */
	protected Map<V, TransitionPoints> vertexLocations = new HashMap<>();

	/** A start and end point for each edge articulation */
	protected Map<E, List<ArticulationTransitionPoints>> edgeArticulationLocations =
		new HashMap<>();

	// not sure why we need these, as opposed to just using the 'edgeArticulationLocations', but
	// these points are different--I would like a better description of how these are different
	protected Map<E, List<Point2D>> finalEdgeArticulations = new HashMap<>();

	protected AbstractGraphTransitionJob(GraphViewer<V, E> viewer, boolean useAnimation) {

		super(viewer, useAnimation);

		this.graphLayout = viewer.getVisualGraphLayout();
	}

	/**
	 * Create the vertex locations that will be transitioned over the life of this animator. 
	 * The locations are in <code>layout space</code>.   This method is expected to update
	 * {@link #vertexLocations} (and optionally {@link #edgeArticulationLocations}).
	 */
	protected abstract void initializeVertexLocations();

	@Override
	public boolean canShortcut() {
		// for now we've decided to always allow the animation to play out
		return false;
	}

	@Override
	public void shortcut() {
		throw new UnsupportedOperationException("Cannot shortcut this job: " + this);
	}

	@Override
	protected Animator createAnimator() {
		initializeVertexLocations();
		clearLocationCache();
		return super.createAnimator();
	}

	@Override
	protected void finished() {
		clearLocationCache();
		installFinalEdgeArticulations();
		super.finished();
	}

	/**
	 * Callback from our animator.
	 */
	@Override
	public void setPercentComplete(double percentComplete) {
		updateNewVertexPositions(percentComplete);
		super.setPercentComplete(percentComplete);
	}

	protected void updatePointFromPercentComplete(TransitionPoints transitionPoints,
			double percentComplete, Point2D updatePoint) {
		double startX = transitionPoints.startPoint.getX();
		double destinationX = transitionPoints.destinationPoint.getX();
		double deltaX = (destinationX - startX) * percentComplete;

		double startY = transitionPoints.startPoint.getY();
		double destinationY = transitionPoints.destinationPoint.getY();
		double deltaY = (destinationY - startY) * percentComplete;

		double newX = transitionPoints.startPoint.getX() + deltaX;
		double newY = transitionPoints.startPoint.getY() + deltaY;

		updatePoint.setLocation(newX, newY);
	}

	protected void installFinalEdgeArticulations() {
		Collection<E> edges = graph.getEdges();
		for (E edge : edges) {
			List<Point2D> articulations = finalEdgeArticulations.get(edge);
			if (articulations == null) {
				// Depending upon the value of 'relayout', we may have removed articulations
				articulations = Collections.emptyList();
			}

			edge.setArticulationPoints(articulations);
		}
	}

	private void updateNewVertexPositions(double percentComplete) {
		//
		// The new position is some percentage of the distance between the start 
		// positions and the destination positions.  The grouped vertex does not change positions.
		//
		Set<Entry<V, TransitionPoints>> entrySet = vertexLocations.entrySet();
		for (Entry<V, TransitionPoints> entry : entrySet) {
			Point2D newVertexLocation = new Point2D.Double();
			updatePointFromPercentComplete(entry.getValue(), percentComplete, newVertexLocation);

			// the new values won't be read if we don't clear the cache 
			clearLocationCache();
			V newVertex = entry.getKey();
			graphLayout.setLocation(newVertex, newVertexLocation, ChangeType.TRANSIENT);
		}

		Set<Entry<E, List<ArticulationTransitionPoints>>> edgeEntries =
			edgeArticulationLocations.entrySet();
		for (Entry<E, List<ArticulationTransitionPoints>> entry : edgeEntries) {
			List<ArticulationTransitionPoints> transitions = entry.getValue();
			for (ArticulationTransitionPoints transitionPoint : transitions) {
				// manipulate the edges locations directly, as not to incur excess object creation
				// (the start point is copied from the edge during initialization)
				Point2D updatePoint = transitionPoint.pointToUpdate;
				updatePointFromPercentComplete(transitionPoint, percentComplete, updatePoint);
			}
		}
	}

	protected LayoutPositions<V, E> calculateDefaultLayoutLocations() {
		LayoutPositions<V, E> positions = calculateDefaultLayoutLocations(Collections.emptySet());
		return positions;
	}

	protected LayoutPositions<V, E> getCurrentLayoutLocations() {
		return LayoutPositions.getCurrentPositions(graph, graphLayout);
	}

	protected Point2D toLocation(V v) {
		return graphLayout.apply(v);
	}

	// note: due to the caching nature of some layouts, if we don't reset this, then 
	// some of our GUI calculations will be incorrect (like when we try to fit the 
	// satellite in it's window).  So, we always have to clear the cache when we set locations
	protected void clearLocationCache() {
		Layout<V, E> jungLayout = viewer.getGraphLayout();
		((Caching) jungLayout).clear();
	}

//==================================================================================================
// Utility Methods
//==================================================================================================

	/**
	 * Calculates default vertex locations for the current graph by using the current layout, 
	 * excluding those vertices in the given <i>ignore</i> set.  The graph, 
	 * layout and vertices will be unaltered.
	 *
	 * @param verticesToIgnore The set of vertices which should be excluded from the layout process
	 * @return The mapping of all arranged vertices to their respective locations
	 */
	public LayoutPositions<V, E> calculateDefaultLayoutLocations(Set<V> verticesToIgnore) {

		VisualGraphLayout<V, E> layout = graph.getLayout();
		VisualGraph<V, E> newGraph = graph.copy();
		newGraph.removeVertices(verticesToIgnore);

		//
		// A bit of kludge.  The layout in the task will fail if the vertices' components are not
		// realized, which must happen on the Swing thread.
		//
		ensureVerticesComponentsCreated(newGraph);

		CalculateLayoutLocationsTask<V, E> task =
			new CalculateLayoutLocationsTask<>(newGraph, layout);
		new TaskLauncher(task, null, 2000); // this call will block

		return task.getLocations();
	}

	private void ensureVerticesComponentsCreated(VisualGraph<V, E> g) {
		SystemUtilities.assertThisIsTheSwingThread(
			"Cannot create vertex components off the Swing thread");
		Collection<V> vertices = g.getVertices();
		for (V v : vertices) {
			v.getComponent();
		}
	}
//==================================================================================================
// Inner Classes
//==================================================================================================

	protected class TransitionPoints {
		public Point2D startPoint;
		public Point2D destinationPoint;

		public TransitionPoints(Point2D startPoint, Point2D destinationPoint) {
			if (startPoint == null) {
				throw new IllegalArgumentException("Start point cannot be null");
			}

			if (destinationPoint == null) {
				throw new IllegalArgumentException("Destination point cannot be null");
			}

			this.startPoint = startPoint;
			this.destinationPoint = destinationPoint;
		}

		@Override
		public String toString() {
			return getClass().getSimpleName() + "[start=" + startPoint + ", dest=" +
				destinationPoint + "]";
		}
	}

	protected class ArticulationTransitionPoints extends TransitionPoints {
		public Point2D pointToUpdate;

		public ArticulationTransitionPoints(Point2D currentEdgePoint, Point2D destinationPoint) {
			super((Point2D) currentEdgePoint.clone(), destinationPoint);
			this.pointToUpdate = currentEdgePoint;
		}
	}
}
