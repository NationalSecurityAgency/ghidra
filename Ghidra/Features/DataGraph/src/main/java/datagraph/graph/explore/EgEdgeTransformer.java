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
package datagraph.graph.explore;

import java.awt.Dimension;
import java.awt.Shape;
import java.awt.geom.*;

import com.google.common.base.Function;

import ghidra.graph.viewer.GraphViewerUtils;
import ghidra.graph.viewer.VisualEdge;

/**
 * An edge shape that draws edges from left side of source vertex to the right side of the
 * destination vertex. The vertical position on edges of the source vertex and destination is
 * determined by the calls to the vertex so that edges can be aligned with a vertex's internals.
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class EgEdgeTransformer<V extends EgVertex, E extends VisualEdge<V>>
		implements Function<E, Shape> {
	private static final double OVERLAP_GAP = 20;
	private static int LOOP_SIZE = 12;

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
		Dimension startSize = start.getComponent().getSize();

		Point2D location = start.getLocation();
		double originX = location.getX();
		double originY = location.getY();

		Point2D startPoint = start.getStartingEdgePoint(end);
		Point2D endPoint = end.getEndingEdgePoint(start);

		boolean isLoop = start.equals(end);

		if (isLoop) {
			Shape hollowEgdeLoop = GraphViewerUtils.createHollowEgdeLoop();
			AffineTransform xform =
				AffineTransform.getTranslateInstance(startSize.width / 2 + LOOP_SIZE / 2,
					start.getOutgoingEdgeOffsetFromCenter(end));

			xform.scale(LOOP_SIZE, LOOP_SIZE);
			return xform.createTransformedShape(hollowEgdeLoop);
		}
		GeneralPath path = new GeneralPath();

		path.moveTo(startPoint.getX() - originX, startPoint.getY() - originY);
		if (startPoint.getX() > endPoint.getX() - OVERLAP_GAP) {
			if (start.getLocation().getX() != startPoint.getX()) {
				path.lineTo(startPoint.getX() - originX + OVERLAP_GAP, startPoint.getY() - originY);
			}
			if (end.getLocation().getX() != endPoint.getX()) {
				path.lineTo(endPoint.getX() - originX - OVERLAP_GAP, endPoint.getY() - originY);
			}
		}

		path.lineTo(endPoint.getX() - originX, endPoint.getY() - originY);

		return path;

	}

}
