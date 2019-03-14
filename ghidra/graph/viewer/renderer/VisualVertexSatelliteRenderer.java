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

import java.awt.*;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.RenderContext;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.vertex.AbstractVisualVertexRenderer;

/**
 * A renderer for vertices for the satellite view.  This is really just a basic renderer 
 * that adds emphasis capability, as seen in the primary function graph renderer.
 */
public class VisualVertexSatelliteRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractVisualVertexRenderer<V, E> {

	/**
	 * Overridden to handle painting emphasis.
	 */
	@Override
	protected void paintIconForVertex(RenderContext<V, E> rc, V v, Layout<V, E> layout) {

		GraphicsDecorator defaultGraphics = rc.getGraphicsContext();
		if (v.isSelected()) {
			Shape shape = getFullShape(rc, layout, v);
			Rectangle bounds = shape.getBounds();
			paintHighlight(rc, v, defaultGraphics, bounds);
		}

		double empahsis = v.getEmphasis();
		if (empahsis == 0) {
			super.paintIconForVertex(rc, v, layout);
			return;
		}

// POSTERITY NOTE: we used to let the satellite paint the emphasis of nodes, as a way to call
//		           attention to the selected node.  Now that we use caching, this has the odd 
//		           side-effect of painting a large vertex in the cached image.  Also, we have 
//		           changed how the satellite paints selected vertices, so the effect being 
//		           performed below is no longer necessary.
//		GraphicsDecorator emphasisGraphics = getEmphasisGraphics(defaultGraphics, v, rc, layout);
//		rc.setGraphicsContext(emphasisGraphics);
//		super.paintIconForVertex(rc, v, layout);
//		rc.setGraphicsContext(defaultGraphics);

		super.paintIconForVertex(rc, v, layout);
	}

	@Override
	protected Shape prepareFinalVertexShape(RenderContext<V, E> rc, V v, Layout<V, E> layout,
			int[] coords) {

		// DEBUG original behavior; this can show the true shape of the vertex
		// return super.prepareFinalVertexShape(rc, v, layout, coords);

		// use the compact shape in the satellite view		
		return getCompactShape(rc, layout, v);
	}

	@Override
	protected void paintHighlight(RenderContext<V, E> rc, V vertex, GraphicsDecorator g,
			Rectangle bounds) {

		if (!vertex.isSelected()) {
			return;
		}

		Paint oldPaint = g.getPaint();

		int halfishTransparency = 150;
		Color yellowWithTransparency = new Color(255, 255, 0, halfishTransparency);
		g.setPaint(yellowWithTransparency);

//		int offset = (int) adjustValueForCurrentScale(rc, 10D, .25);
		int offset = 10;

		// scale the offset with the scale of the view, but not as fast, so that as we scale down, 
		// the size of the paint area starts to get larger than the vertex
		offset = (int) adjustValueForCurrentScale(rc, offset, .9);
		g.fillOval(bounds.x - offset, bounds.y - offset, bounds.width + (offset * 2),
			bounds.height + (offset * 2));

		if (isGraphScaledEnoughToBeDifficultToSee(rc)) {
			g.setColor(Color.BLACK);
			g.drawOval(bounds.x - offset, bounds.y - offset, bounds.width + (offset * 2),
				bounds.height + (offset * 2));
			g.drawOval(bounds.x - offset - 1, bounds.y - offset - 1,
				bounds.width + (offset * 2) + 2, bounds.height + (offset * 2) + 2);
			g.drawOval(bounds.x - offset - 2, bounds.y - offset - 2,
				bounds.width + (offset * 2) + 4, bounds.height + (offset * 2) + 4);
		}

		g.setPaint(oldPaint);
	}

	private boolean isGraphScaledEnoughToBeDifficultToSee(RenderContext<V, E> rc) {
		double scale = getScale(rc);
		return scale < .05;
	}

}
