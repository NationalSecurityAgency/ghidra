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

import java.awt.Rectangle;
import java.awt.Shape;
import java.awt.geom.Point2D;

import edu.uci.ics.jung.visualization.*;
import ghidra.graph.viewer.*;

/**
 * Graph job to move the entire graph to ensure one or two vertices are fully on screen. If both
 * vertices can't be fully shown at the same time, the primary vertex gets precedence.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class RelayoutAndEnsureVisible<V extends VisualVertex, E extends VisualEdge<V>>
		extends RelayoutFunctionGraphJob<V, E> {
	private static final int VIEW_BOUNDARY_PADDING = 50;
	private V primaryVertex;
	private V secondaryVertex;
	private Distance moveDistance;
	private Distance movedSoFar = new Distance(0, 0);

	public RelayoutAndEnsureVisible(GraphViewer<V, E> viewer, V primaryVertex, V secondaryVertex,
			boolean useAnimation) {
		super(viewer, useAnimation);
		this.primaryVertex = primaryVertex;
		this.secondaryVertex = secondaryVertex;
	}

	@Override
	protected void initializeVertexLocations() {
		super.initializeVertexLocations();

		Shape layoutViewerShape =
			GraphViewerUtils.translateShapeFromViewSpaceToLayoutSpace(viewer.getBounds(), viewer);
		Rectangle layoutViewerBounds = layoutViewerShape.getBounds();

		// get layout destination position for each vertex
		Rectangle primaryLayoutVertexBounds =
			GraphViewerUtils.getVertexBoundsInLayoutSpace(viewer, primaryVertex);
		Rectangle secondaryLayoutVertexBounds =
			GraphViewerUtils.getVertexBoundsInLayoutSpace(viewer, secondaryVertex);

		setRectangleLocationToFinalDestination(primaryLayoutVertexBounds, primaryVertex);
		setRectangleLocationToFinalDestination(secondaryLayoutVertexBounds, secondaryVertex);

		padVertexBounds(primaryLayoutVertexBounds);
		padVertexBounds(secondaryLayoutVertexBounds);

		// This is the distance we need to move the view to ensure the less important vertex is
		// is fully visible in the view.
		Distance secondaryMoveDistance =
			getMoveDistanceToContainVertexInView(layoutViewerBounds, secondaryLayoutVertexBounds);

		// Assuming we already moved the layout as computed above, how much additional movement is
		// needed to bring the preferred vertex fully into view. Note that if both vertices don't
		// fit, the secondary vertex may no longer be visible after all movement is applied.
		layoutViewerBounds.x -= secondaryMoveDistance.deltaX;
		layoutViewerBounds.y -= secondaryMoveDistance.deltaY;
		Distance primaryMoveDistance =
			getMoveDistanceToContainVertexInView(layoutViewerBounds, primaryLayoutVertexBounds);

		// The total distance we need to move the view is the net effect of combining the first
		// move and the second move.
		moveDistance = secondaryMoveDistance.add(primaryMoveDistance);
	}

	private Distance getMoveDistanceToContainVertexInView(
			Rectangle layoutViewerBounds, Rectangle layoutVertexBounds) {

		// if the vertex is already fully in the view, no move needed
		if (layoutViewerBounds.contains(layoutVertexBounds)) {
			return new Distance(0, 0);
		}

		int deltaX = 0;
		int deltaY = 0;

		int view1x = layoutViewerBounds.x;
		int view1y = layoutViewerBounds.y;

		int view2x = layoutViewerBounds.x + layoutViewerBounds.width;
		int view2y = layoutViewerBounds.y + layoutViewerBounds.height;

		int vertex1x = layoutVertexBounds.x;
		int vertex1y = layoutVertexBounds.y;

		int vertex2x = layoutVertexBounds.x + layoutVertexBounds.width;
		int vertex2y = layoutVertexBounds.y + layoutVertexBounds.height;

		if (view1x > vertex1x) {
			deltaX = -(vertex1x - view1x);
		}
		else if (view2x < vertex2x) {
			deltaX = -(vertex2x - view2x);
		}

		if (view1y > vertex1y) {
			deltaY = -(vertex1y - view1y);
		}
		else if (view2y < vertex2y) {
			deltaY = -(vertex2y - view2y);

		}
		return new Distance(deltaX, deltaY);
	}

	private void padVertexBounds(Rectangle layoutVertexBounds) {
		layoutVertexBounds.x -= VIEW_BOUNDARY_PADDING;
		layoutVertexBounds.y -= VIEW_BOUNDARY_PADDING;
		layoutVertexBounds.width += 2 * VIEW_BOUNDARY_PADDING;
		layoutVertexBounds.height += 2 * VIEW_BOUNDARY_PADDING;
	}

	private void setRectangleLocationToFinalDestination(Rectangle layoutVertexBounds, V v) {
		TransitionPoints transitionPoints = vertexLocations.get(v);
		Point2D centerPoint = transitionPoints.destinationPoint;
		int upperLeftCornerX = (int) centerPoint.getX() - layoutVertexBounds.width / 2;
		int upperLeftCornerY = (int) centerPoint.getY() - layoutVertexBounds.height / 2;
		layoutVertexBounds.setLocation(upperLeftCornerX, upperLeftCornerY);
	}

	@Override
	public void setPercentComplete(double percentComplete) {
		super.setPercentComplete(percentComplete);

		Distance newMovedSoFar = moveDistance.scale(percentComplete);
		double deltaX = newMovedSoFar.deltaX - movedSoFar.deltaX;
		double deltaY = newMovedSoFar.deltaY - movedSoFar.deltaY;

		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer xform = renderContext.getMultiLayerTransformer();
		xform.getTransformer(Layer.LAYOUT).translate(deltaX, deltaY);
		viewer.repaint();

		movedSoFar = newMovedSoFar;
	}

	private record Distance(int deltaX, int deltaY) {
		Distance scale(double scale) {
			return new Distance((int) (deltaX * scale), (int) (deltaY * scale));
		}

		public Distance add(Distance other) {
			return new Distance(deltaX + other.deltaX, deltaY + other.deltaY);
		}
	}

}
