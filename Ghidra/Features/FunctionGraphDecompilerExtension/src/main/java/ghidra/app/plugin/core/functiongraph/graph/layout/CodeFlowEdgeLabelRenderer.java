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
package ghidra.app.plugin.core.functiongraph.graph.layout;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;
import java.util.List;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.util.Context;
import edu.uci.ics.jung.graph.util.Pair;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.renderers.EdgeLabelRenderer;
import edu.uci.ics.jung.visualization.renderers.Renderer;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;

class CodeFlowEdgeLabelRenderer<V extends FGVertex, E extends FGEdge>
		implements Renderer.EdgeLabel<V, E> {

	private static final int EDGE_OFFSET = 20;

	VisualGraphVertexShapeTransformer vertexShapeTransformer =
		new VisualGraphVertexShapeTransformer();

	@Override
	public void labelEdge(RenderContext<V, E> rc, Layout<V, E> layout, E e, String text) {

		if (text == null || text.isEmpty()) {
			return;
		}

		Graph<V, E> jungGraph = layout.getGraph();
		Pair<V> endpoints = jungGraph.getEndpoints(e);
		V v1 = endpoints.getFirst();
		V v2 = endpoints.getSecond();
		if (!rc.getEdgeIncludePredicate().apply(
			Context.<Graph<V, E>, E> getInstance(jungGraph, e))) {
			return;
		}

		if (!rc.getVertexIncludePredicate().apply(
			Context.<Graph<V, E>, V> getInstance(jungGraph, v1)) ||
			!rc.getVertexIncludePredicate().apply(
				Context.<Graph<V, E>, V> getInstance(jungGraph, v2))) {
			return;
		}

		Point2D p1 = layout.apply(v1);
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		p1 = multiLayerTransformer.transform(Layer.LAYOUT, p1);

		Shape vertexShape = vertexShapeTransformer.apply(v1);
		Rectangle vertexBounds = vertexShape.getBounds();
		int xDisplacement = rc.getLabelOffset();

		Point2D labelPointOffset = new Point2D.Double();

		List<Point2D> articulationPoints = e.getArticulationPoints();
		if (articulationPoints.isEmpty()) {
			double vertexBottom = p1.getY() + (vertexBounds.height >> 1); // location is centered
			int textY = (int) (vertexBottom + EDGE_OFFSET); // below the vertex; above the bend 
			int textX = (int) (p1.getX() + xDisplacement); // right of the edge
			labelPointOffset.setLocation(textX, textY);
		}
		else if (articulationPoints.size() == 1) {
			// articulation must have been removed
			return;
		}
		else {

			Point2D bend1 = articulationPoints.get(0);
			bend1 = multiLayerTransformer.transform(Layer.LAYOUT, bend1);
			Point2D bend2 = articulationPoints.get(1);
			bend2 = multiLayerTransformer.transform(Layer.LAYOUT, bend2);

			double bx1 = bend1.getX();

			if (articulationPoints.size() == 2) {

				double vertexSide = p1.getX() + (vertexBounds.width >> 1); // location is centered
				int textX = (int) (vertexSide + EDGE_OFFSET); // right of the vertex 
				int textY = (int) (p1.getY() + EDGE_OFFSET); // above the edge 
				labelPointOffset.setLocation(textX, textY);
			}
			else if (articulationPoints.size() == 3) {
				double vertexBottom = p1.getY() + (vertexBounds.height >> 1); // location is centered
				int textY = (int) (vertexBottom + EDGE_OFFSET); // below the vertex; above the bend 
				int textX = (int) (bx1 + xDisplacement); // right of the edge
				labelPointOffset.setLocation(textX, textY);
			}
			else if (articulationPoints.size() == 4) {
				double vertexBottom = p1.getY() + (vertexBounds.height >> 1); // location is centered
				int textY = (int) (vertexBottom + EDGE_OFFSET); // below the vertex; above the bend 
				int textX = (int) (bx1 + xDisplacement); // right of the edge
				labelPointOffset.setLocation(textX, textY);
			}
		}
		EdgeLabelRenderer labelRenderer = rc.getEdgeLabelRenderer();
		Font font = rc.getEdgeFontTransformer().apply(e);
		boolean isSelected = rc.getPickedEdgeState().isPicked(e);
		Component component = labelRenderer.getEdgeLabelRendererComponent(rc.getScreenDevice(),
			text, font, isSelected, e);

		Dimension d = component.getPreferredSize();

		GraphicsDecorator g = rc.getGraphicsContext();
		AffineTransform old = g.getTransform();
		AffineTransform xform = new AffineTransform(old);
		xform.translate(labelPointOffset.getX(), labelPointOffset.getY());

		g.setTransform(xform);
		g.draw(component, rc.getRendererPane(), 0, 0, d.width, d.height, true);

		g.setTransform(old);
	}
}
