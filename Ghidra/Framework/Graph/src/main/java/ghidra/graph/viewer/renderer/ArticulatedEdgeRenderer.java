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

import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.Layer;
import edu.uci.ics.jung.visualization.RenderContext;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.VisualEdgeRenderer;

public class ArticulatedEdgeRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualEdgeRenderer<V, E> {

	@Override
	public Shape getEdgeShape(RenderContext<V, E> rc, Graph<V, E> graph, E e, float x1, float y1,
			float x2, float y2, boolean isLoop, Shape vertexShape) {

		if (isLoop) {
			return GraphViewerUtils.createEgdeLoopInGraphSpace(vertexShape, x1, y1);
		}

		GeneralPath path = new GeneralPath();
		path.moveTo(x1, y1);

		// TODO investigate using the transformer directly
		// Function<? super E, Shape> edgeShapeTransformer = rc.getEdgeShapeTransformer();

		List<Point2D> articulations = e.getArticulationPoints();
		for (Point2D point : articulations) {
			double x = point.getX();
			double y = point.getY();
			Point2D offsetPoint = new Point2D.Double(x, y);
			point = rc.getMultiLayerTransformer().transform(Layer.LAYOUT, offsetPoint);

			x = point.getX();
			y = point.getY();
			path.lineTo(x, y);
		}

		path.lineTo(x2, y2);
		path.moveTo(x2, y2);
		path.closePath();

		return path;
	}
}
