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
package ghidra.graph.viewer.vertex;

import static ghidra.graph.viewer.GraphViewerUtils.PAINT_ZOOM_THRESHOLD;

import java.awt.*;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.util.Context;
import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A renderer for the {@link VisualGraph} system.
 * 
 * <p>Rendering in the graph system is a bit different than other Java rendering systems.  For
 * example, when a JTable renders itself, it uses a single renderer to stamp the data.  The 
 * table's renderer has no state and is updated for each cell's data that is to be rendered.
 * The graph renderer system is different due to the possibility of complex vertex UIs.  Some
 * vertices have sophisticated UI elements that have state.  For these vertices, it makes sense
 * for the vertex to build and maintain that state; having that state repeatedly built by the
 * renderer would be extremely inefficient and difficult to implement.  Considering that we 
 * expect the vertex to build and maintain its UI, this renderer is really just a tool to:
 * <ol>
 *  <li>Determine if the vertex needs to be painted (by clipping or filtering)
 *  </li>
 *  <li>Setup the geometry for the vertex (convert the model's location to the view location,
 *      accounting for panning and zooming)
 *  </li>
 *  <li>Paint any added effects (such as drop-shadows or highlighting)
 *  </li>
 * </ol>
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualVertexRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractVisualVertexRenderer<V, E> {

	@Override
	public void paintVertex(RenderContext<V, E> rc, Layout<V, E> layout, V vertex) {

		Graph<V, E> graph = layout.getGraph();
		if (!rc.getVertexIncludePredicate().apply(
			Context.<Graph<V, E>, V> getInstance(graph, vertex))) {
			return;
		}

		GraphicsDecorator g = rc.getGraphicsContext();
		GraphicsDecorator gCopy = getEmphasisGraphics(g, vertex, rc, layout);

		// Note: for most graphs, the full/compact shapes are the same
		Shape fullShape = getFullShape(rc, layout, vertex);
		Shape compactShape = getCompactShape(rc, layout, vertex);
		if (!vertexHit(rc, fullShape)) {
			return;
		}

		Rectangle bounds = fullShape.getBounds();

		paintHighlight(rc, vertex, gCopy, bounds);

		paintDropShadow(rc, gCopy, compactShape, vertex);

		paintVertexOrVertexShape(rc, gCopy, layout, vertex, compactShape, fullShape);

		gCopy.dispose();
	}

	// Note: overridden to take the extra Vertex parameter, which is used by subclasses
	protected void paintDropShadow(RenderContext<V, E> rc, GraphicsDecorator g, Shape shape,
			V vertex) {

		super.paintDropShadow(rc, g, shape);
	}

	protected void paintVertexOrVertexShape(RenderContext<V, E> rc, GraphicsDecorator g,
			Layout<V, E> layout, V vertex, Shape compactShape, Shape fullShape) {

		if (isScaledPastVertexPaintingThreshold(rc)) {
			paintScaledVertex(rc, vertex, g, compactShape);
			return;
		}

		Rectangle bounds = fullShape.getBounds();
		paintVertex(rc, g, vertex, bounds, layout);

// DEBUG		
//		Paint oldPaint = g.getPaint();
//		g.setPaint(Color.RED);
//		g.draw(compactShape);
//
//		g.setPaint(Color.CYAN);
//		g.draw(fullShape);
//		g.setPaint(oldPaint);
	}

	protected void paintVertex(RenderContext<V, E> rc, GraphicsDecorator g, V vertex,
			Rectangle bounds, Layout<V, E> layout) {

		Component component = vertex.getComponent();
		g.draw(component, rc.getRendererPane(), bounds.x, bounds.y, bounds.width, bounds.height,
			true);

		// HACK: we must restore our bounds here, since the renderer pane will change them during
		// the rendering process (not sure if this is still needed; if we figure out why, then
		// update this comment)
		component.setBounds(bounds);
	}

	protected boolean isScaledPastVertexPaintingThreshold(RenderContext<V, E> rc) {
		double scale = getScale(rc);
		return scale < PAINT_ZOOM_THRESHOLD;
	}

	protected void paintScaledVertex(RenderContext<V, E> rc, V vertex, GraphicsDecorator g,
			Shape shape) {
		Function<? super V, Paint> fillXform = rc.getVertexFillPaintTransformer();
		Paint fillPaint = fillXform.apply(vertex);
		if (fillPaint == null) {
			return;
		}

		Paint oldPaint = g.getPaint();
		g.setPaint(fillPaint);
		g.fill(shape);

		// an outline
		g.setColor(Color.BLACK);
		g.draw(shape);

		g.setPaint(oldPaint);
	}
}
