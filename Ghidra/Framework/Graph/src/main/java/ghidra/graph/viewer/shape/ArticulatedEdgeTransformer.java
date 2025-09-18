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
import java.awt.geom.GeneralPath;
import java.awt.geom.Point2D;
import java.util.List;

import com.google.common.base.Function;

import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;

/**
 * An edge shape that renders as a series of straight lines between articulation points.
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class ArticulatedEdgeTransformer<V extends VisualVertex, E extends VisualEdge<V>>
		implements Function<E, Shape> {

	private RenderContext<V, E> renderContext;

	public void setRenderContext(RenderContext<V, E> context) {
		this.renderContext = context;
	}

	/**
	 * Get the shape for this edge
	 * 
	 * @param e the edge
	 * @return the edge shape
	 */
	@Override
	public Shape apply(E e) {
		V start = e.getStart();
		V end = e.getEnd();

		boolean isLoop = start.equals(end);
		if (isLoop) {
			//
			// Our edge loops are sized and positioned according to the shared
			// code in the utils class.  We do this so that our hit detection matches our rendering.
			//
			Function<? super V, Shape> vertexShapeTransformer =
				renderContext.getVertexShapeTransformer();
			Shape vertexShape = getVertexShapeForEdge(end, vertexShapeTransformer);
			Shape hollowEgdeLoop = GraphViewerUtils.createHollowEgdeLoop();

			// we are not actually creating this in graph space, but by passing in 0,0, we are in
			// unit space
			return GraphViewerUtils.createEgdeLoopInGraphSpace(hollowEgdeLoop, vertexShape, 0, 0);
		}

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

		// TODO pretty sure this is not needed; keeping for a bit as a reminder of how it used to be
		// int offset = getOverlapOffset(e);
		int offset = 0;
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
		return path;
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private static <V> Shape getVertexShapeForEdge(V v, Function<? super V, Shape> vertexShaper) {
		if (vertexShaper instanceof VisualGraphVertexShapeTransformer) {
			if (v instanceof VisualVertex) {
				VisualVertex vv = (VisualVertex) v;

				// Note: it is a bit odd that we 'know' to use the compact shape here for 
				//		 hit detection, but this is how the edge is painted, so we want the 
				//		 view to match the mouse.
				return ((VisualGraphVertexShapeTransformer) vertexShaper).transformToCompactShape(
					vv);
			}
		}
		return vertexShaper.apply(v);
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
