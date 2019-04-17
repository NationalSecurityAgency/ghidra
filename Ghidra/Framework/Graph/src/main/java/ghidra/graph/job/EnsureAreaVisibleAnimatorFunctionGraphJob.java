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

import java.awt.Point;
import java.awt.Rectangle;
import java.awt.geom.Point2D;
import java.util.Objects;

import org.jdesktop.animation.timing.Animator;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import ghidra.graph.viewer.*;

// TODO doc - the area is expected to be vertex relative, where
//			  vertex relative means that the value is from inside the vertex, or the vertex's
//            coordinate space (like a component that is inside the vertex)
public class EnsureAreaVisibleAnimatorFunctionGraphJob<V extends VisualVertex, E extends VisualEdge<V>>
		extends MoveViewAnimatorFunctionGraphJob<V, E> {

	private final SatelliteGraphViewer<V, E> satelliteViewer;
	private final V vertex;
	private final Rectangle visibleArea;
	private Point2D preCreatedDestinaton;

	public EnsureAreaVisibleAnimatorFunctionGraphJob(VisualizationViewer<V, E> primaryViewer,
			SatelliteGraphViewer<V, E> satelliteViewer, V vertex, Rectangle visibleArea,
			boolean useAnimation) {

		super(primaryViewer, useAnimation);

		this.satelliteViewer = Objects.requireNonNull(satelliteViewer);
		this.vertex = Objects.requireNonNull(vertex);
		this.visibleArea = Objects.requireNonNull(visibleArea);
	}

	@Override
	protected Animator createAnimator() {

		Rectangle viewSpaceRectangle =
			GraphViewerUtils.translateRectangleFromVertexRelativeSpaceToViewSpace(viewer, vertex,
				visibleArea);

		//
		// Get the point to which we will move if any of the cursor is obscured
		// 
		Point newPoint =
			new Point((int) viewSpaceRectangle.getCenterX(), (int) viewSpaceRectangle.getCenterY());

		// get the point of the cursor, centered in the vertex (this prevents jumping from 
		// side-to-side as we move the vertex)
		Rectangle vertexBounds = GraphViewerUtils.getVertexBoundsInViewSpace(viewer, vertex);
		int vertexCenterX = vertexBounds.x + (vertexBounds.width >> 1);
		newPoint.x = vertexCenterX;

		// see if the cursor bounds are not completely in screen
		Rectangle viewerBounds = viewer.getBounds();
		if (!viewerBounds.contains(viewSpaceRectangle)) {
			preCreatedDestinaton = newPoint;
			return super.createAnimator();
		}

		if (!satelliteViewer.isDocked()) {
			return null; // cannot obscure if not docked
		}

		if (!satelliteViewer.isShowing()) {
			return null; // nothing to do
		}

		// see if the satellite is hiding the area
		Rectangle satelliteBounds = satelliteViewer.getBounds();
		if (!satelliteBounds.contains(viewSpaceRectangle)) {
			return null; // nothing to do
		}

		preCreatedDestinaton = newPoint;
		return super.createAnimator();
	}

	@Override
	protected Point2D createDestination() {
		if (preCreatedDestinaton == null) {
			return null; // we chose not to change move the view
		}
		return GraphViewerUtils.getOffsetFromCenterForPointInViewSpace(viewer,
			preCreatedDestinaton);
	}

	@Override
	public void setOffset(Point2D offsetFromOriginalPoint) {
		if (preCreatedDestinaton == null) {
			// This method gets called back after the animator is finished.  If we chose not to
			// do work, then just exit
			return;
		}
		super.setOffset(offsetFromOriginalPoint);
	}
}
