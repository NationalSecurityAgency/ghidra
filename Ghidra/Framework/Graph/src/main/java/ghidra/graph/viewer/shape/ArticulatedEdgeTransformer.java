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

import java.awt.Shape;
import java.awt.geom.*;
import java.util.List;

import edu.uci.ics.jung.visualization.decorators.ParallelEdgeShapeTransformer;
import ghidra.graph.viewer.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * An edge shape that renders as a series of straight lines between articulation points.
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class ArticulatedEdgeTransformer<V extends VisualVertex, E extends VisualEdge<V>>
		extends ParallelEdgeShapeTransformer<V, E> {

	protected static final int OVERLAPPING_EDGE_OFFSET = 10;

	/**
	 * Returns a value by which to offset edges that overlap.  This is used to make the edges
	 * easier to see.
	 * 
	 * @param edge the edge
	 * @return the offset value
	 */
	public int getOverlapOffset(E edge) {
		// not sure what the correct default behavior is
		return OVERLAPPING_EDGE_OFFSET;
	}

	/**
	 * Get the shape for this edge, returning either the shared instance or, in
	 * the case of self-loop edges, the Loop shared instance.
	 */
	@Override
	public Shape apply(E e) {
		V start = e.getStart();
		V end = e.getEnd();

		boolean isLoop = start.equals(end);
		if (isLoop) {
			return GraphViewerUtils.createHollowEgdeLoop();
		}

		Point2D p1 = start.getLocation();
		if (p1 == null) {
			logMissingLocation(e, start);
			return null;
		}

		Point2D p2 = end.getLocation();
		if (p2 == null) {
			logMissingLocation(e, end);
			return null;
		}

		List<Point2D> articulations = e.getArticulationPoints();
		final double originX = p1.getX();
		final double originY = p1.getY();

		int offset = getOverlapOffset(e);
		GeneralPath path = new GeneralPath();
		path.moveTo(0, 0);
		for (Point2D pt : articulations) {
			float x = (float) (pt.getX() - originX) + offset;
			float y = (float) (pt.getY() - originY) + offset;
			path.lineTo(x, y);
			path.moveTo(x, y);
		}

		float p2x = (float) (p2.getX() - originX);
		float p2y = (float) (p2.getY() - originY);
		path.lineTo(p2x, p2y);
		path.moveTo(p2x, p2y);
		path.closePath();

		AffineTransform transform = new AffineTransform();
		final double deltaY = p2.getY() - originY;
		final double deltaX = p2.getX() - originX;
		if (deltaX == 0 && deltaY == 0) {
			// this implies the source and destination node are at the same location, which
			// is possible if the user drags it there or during animations
			return transform.createTransformedShape(path);
		}

		double theta = StrictMath.atan2(deltaY, deltaX);
		transform.rotate(theta);
		double scale = StrictMath.sqrt(deltaY * deltaY + deltaX * deltaX);
		transform.scale(scale, 1.0f);

		//
		// TODO
		// The current design and use of this transformer is a bit odd.   We currently have code
		// to create the edge shape here and in the ArticulatedEdgeRenderer.  Ideally, this 
		// class would be the only one that creates the edge shape.  Then, any clients of the
		// edge transformer would have to take the shape and then transform it to the desired 
		// space (the view or graph space).  The transformations could be done using the 
		// GraphViewerUtils.
		//

		try {
			// TODO it is not clear why this is using an inverse transform; why not just create
			// the transform that we want?
			AffineTransform inverse = transform.createInverse();
			Shape transformedShape = inverse.createTransformedShape(path);
			return transformedShape;
		}
		catch (NoninvertibleTransformException e1) {
			Msg.error(this, "Unexpected exception transforming an edge", e1);
		}

		return null;
	}

	private void logMissingLocation(E e, V v) {

		//
		// This can happen when an edge has a vertex that is 'equal' to a vertex that is 
		// in the graph, but is not the same instance.  The can also happen when a new or
		// copied layout does not initialize its vertices with locations.  This can happen
		// when:
		// 	-two nodes share the same name
		//  -a node is added a second time to the graph
		//
		// An example of duplicate nodes being added is when a client creates a new 
		// edge with a new start and end vertex, which are equal, but not the same, as vertices
		// already in the graph.  **Instead of creating those vertices from scratch, they should
		// be retrieved from the graph when creating the edge.  Further, if you are creating a 
		// new vertex to be added to the graph, be sure to only create one representation of 
		// that vertex that will be shared amongst any edges that are to be added to the graph.
		// 
		// The reason this happens is that the newly 'equals' vertices live in the edge, but 
		// they have not had their 'setLocation' called--the graph contains a vertex that 
		// is 'equals' that has had its 'setLocation' called.  When this transformer grabs the
		// vertex from the edge, its location was never set.
		// 
		boolean isStart = e.getStart() == v;
		String type = isStart ? "start" : "end";
		Msg.debug(this,
			"no location defined for " + type + " vertex: " + v + " " + System.identityHashCode(v));
		if (SystemUtilities.isInTestingMode()) {
			throw new IllegalStateException("Edge vertex is missing a location");
		}
	}
}
