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
package ghidra.graph.viewer.renderer;

import java.awt.Shape;
import java.awt.geom.GeneralPath;
import java.awt.geom.Point2D;
import java.util.List;

import com.google.common.base.Function;

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.Layer;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;
import ghidra.graph.viewer.shape.ArticulatedEdgeTransformer;

public class ArticulatedEdgeRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualEdgeRenderer<V, E> {

	@SuppressWarnings("unchecked")
	@Override
	public Shape getEdgeShape(RenderContext<V, E> rc, Graph<V, E> graph, E e, float x1, float y1,
			float x2, float y2, boolean isLoop, Shape vertexShape) {

		if (isLoop) {
			return GraphViewerUtils.createEgdeLoopInGraphSpace(vertexShape, x1, y1);
		}

		GeneralPath path = new GeneralPath();
		path.moveTo(x1, y1);

		int offset = 0;
		Function<? super E, Shape> edgeShapeTransformer = rc.getEdgeShapeTransformer();
		if (edgeShapeTransformer instanceof ArticulatedEdgeTransformer) {
			offset = ((ArticulatedEdgeTransformer<V, E>) edgeShapeTransformer).getOverlapOffset(e);
		}

		List<Point2D> articulations = e.getArticulationPoints();
		offset = updateOffsetForLeftOrRightHandSizeEdge(rc, offset, x1, articulations);
		for (Point2D point : articulations) {
			Point2D offsetPoint =
				new Point2D.Float((float) point.getX() + offset, (float) point.getY() + offset);
			point = rc.getMultiLayerTransformer().transform(Layer.LAYOUT, offsetPoint);
			path.lineTo((float) point.getX(), (float) point.getY());
			path.moveTo((float) point.getX(), (float) point.getY());
		}

		path.lineTo(x2, y2);
		path.moveTo(x2, y2);
		path.closePath();

		return path;
	}

	private int updateOffsetForLeftOrRightHandSizeEdge(RenderContext<V, E> rc, int offset, float x,
			List<Point2D> articulations) {

		int size = articulations.size();
		if (size == 0) {
			// no articulations or start to destination only, with no angles
			return offset;
		}

		Point2D start = articulations.get(0);
		start = rc.getMultiLayerTransformer().transform(Layer.LAYOUT, start);
		double delta = x - start.getX();
		if (delta == 0) {
			// don't move the edge when it is directly below the vertex (this prevents having 
			// a slightly skewed/misaligned edge) 
			return 0;
		}

		boolean isLeft = delta > 0;
		return isLeft ? -offset : offset;
	}
}
