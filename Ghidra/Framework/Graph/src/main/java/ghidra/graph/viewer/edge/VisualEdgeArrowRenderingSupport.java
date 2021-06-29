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
package ghidra.graph.viewer.edge;

import java.awt.Shape;
import java.awt.geom.*;

import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * Basic class to calculate the position of an edge arrow
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualEdgeArrowRenderingSupport<V extends VisualVertex, E extends VisualEdge<V>> {

	public AffineTransform createArrowTransform(RenderContext<V, E> rc, Shape edgeShape,
			Shape vertexShape) {

		return doCreateArrowTransform(rc.getArrowPlacementTolerance(), edgeShape, vertexShape);
	}

	AffineTransform doCreateArrowTransform(double arrowPlacementTolerance, Shape edgeShape,
			Shape vertexShape) {

		GeneralPath path = new GeneralPath(edgeShape);
		double[] seg = new double[6];
		Point2D p1 = null;
		Point2D p2 = null;
		AffineTransform at = new AffineTransform();

		// Find the line segment whose endpoint is in the end vertex (this handles straight lines
		// and articulated lines).  Use that line's start point to for the arrow position and use
		// the line's angle to rotate the arrow head.
		for (PathIterator i = path.getPathIterator(null, 1); !i.isDone(); i.next()) {
			int type = i.currentSegment(seg);
			if (type == PathIterator.SEG_MOVETO) {
				p2 = new Point2D.Double(seg[0], seg[1]);
			}
			else if (type == PathIterator.SEG_LINETO) {
				p1 = p2;
				p2 = new Point2D.Double(seg[0], seg[1]);
				if (vertexShape.contains(p2)) {
					Line2D lineSegment = new Line2D.Double(p1, p2);
					Line2D line =
						findClosestLineSegment(arrowPlacementTolerance, lineSegment, vertexShape);
					return createArrowTransformFromLine(line);
				}
			}
		}
		return at;
	}

	Line2D findClosestLineSegment(double arrowPlacementTolerance, Line2D line, Shape vertexShape) {

		if (!vertexShape.contains(line.getP2())) {
			String errorString = "line end point: " + line.getP2() +
				" is not contained in shape: " + vertexShape.getBounds2D();
			throw new IllegalArgumentException(errorString);
		}

		Line2D left = new Line2D.Double();
		Line2D right = new Line2D.Double();

		// keep chopping the line in half until it is small enough and lands just outside of the
		// vertex shape, within the provided tolerance		
		int iterations = 0; // arbitrary limit to ensure rounding errors do not loop forever
		while (lengthSquared(line) > arrowPlacementTolerance && iterations++ < 15) {
			bisect(line, left, right);
			line = vertexShape.contains(right.getP1()) ? left : right;
		}
		return line;
	}

	private double lengthSquared(Line2D line) {
		double dx = line.getX1() - line.getX2();
		double dy = line.getY1() - line.getY2();
		return dx * dx + dy * dy;
	}

	private void bisect(Line2D src, Line2D left, Line2D right) {

		double x1 = src.getX1();
		double y1 = src.getY1();
		double x2 = src.getX2();
		double y2 = src.getY2();
		double mx = x1 + (x2 - x1) / 2.0;
		double my = y1 + (y2 - y1) / 2.0;
		left.setLine(x1, y1, mx, my);
		right.setLine(mx, my, x2, y2);
	}

	private AffineTransform createArrowTransformFromLine(Line2D line) {
		double x1 = line.getX1();
		double y1 = line.getY1();
		double dx = x1 - line.getX2();
		double dy = y1 - line.getY2();
		double atheta = Math.atan2(dx, dy) + Math.PI / 2;
		AffineTransform at = AffineTransform.getTranslateInstance(x1, y1);
		at.rotate(-atheta);
		return at;
	}

}
