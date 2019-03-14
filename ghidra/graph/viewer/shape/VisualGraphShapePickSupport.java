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
package ghidra.graph.viewer.shape;

import java.awt.Point;
import java.awt.Shape;
import java.awt.geom.*;
import java.util.Collection;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.VisualizationServer;
import edu.uci.ics.jung.visualization.picking.ShapePickSupport;
import ghidra.graph.viewer.*;

public class VisualGraphShapePickSupport<V extends VisualVertex, E extends VisualEdge<V>>
		extends ShapePickSupport<V, E> {

	public VisualGraphShapePickSupport(VisualizationServer<V, E> viewer) {
		super(viewer);
	}

	@Override
	protected Collection<V> getFilteredVertices(Layout<V, E> layout) {
		return GraphViewerUtils.createCollectionWithZOrderBySelection(
			super.getFilteredVertices(layout));
	}

	/**
	 * Overridden to handle edge picking with our custom edge placement.  The painting and picking
	 * algorithms in Jung are all hard-coded to transform loop edges to above the vertex--there
	 * is no way to plug our own transformation into Jung :(
	 * 
	 * @param layout
	 * @param viewSpaceX The x under which to look for an edge (view coordinates)
	 * @param viewSpaceY The y under which to look for an edge (view coordinates)
	 * @return The closest edge to the given point; null if no edge near the point
	 */
	@Override
	public E getEdge(Layout<V, E> layout, double viewSpaceX, double viewSpaceY) {

		Point2D viewSpacePoint = new Point2D.Double(viewSpaceX, viewSpaceY);
		Point graphSpacePoint =
			GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(viewSpacePoint, vv);

		// create a box around the given point the size of 'pickSize'
		Rectangle2D pickArea = new Rectangle2D.Float(graphSpacePoint.x - pickSize / 2,
			graphSpacePoint.y - pickSize / 2, pickSize, pickSize);
		E closestEdge = null;
		double smallestDistance = Double.MAX_VALUE;
		for (E e : getFilteredEdges(layout)) {

			Shape edgeShape = GraphViewerUtils.getEdgeShapeInGraphSpace(vv, e);
			if (edgeShape == null) {
				continue;
			}

			// because of the transform, the edgeShape is now a GeneralPath
			// see if this edge is the closest of any that intersect
			if (edgeShape.intersects(pickArea)) {
				float[] coords = new float[6];
				GeneralPath path = new GeneralPath(edgeShape);
				PathIterator iterator = path.getPathIterator(null);
				if (iterator.isDone()) {
					// not sure how this can happen--0 length edge?
					continue;
				}

				iterator.next();
				iterator.currentSegment(coords);
				float segmentX = coords[0];
				float segmentY = coords[1];

				float deltaX = segmentX - graphSpacePoint.x;
				float deltaY = segmentY - graphSpacePoint.y;
				float currentDistance = deltaX * deltaX + deltaY * deltaY;
				if (currentDistance < smallestDistance) {
					smallestDistance = currentDistance;
					closestEdge = e;
				}
			}
		}

		return closestEdge;
	}
}
