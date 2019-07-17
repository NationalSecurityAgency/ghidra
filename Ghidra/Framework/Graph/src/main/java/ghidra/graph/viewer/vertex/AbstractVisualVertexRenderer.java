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

import static ghidra.graph.viewer.GraphViewerUtils.INTERACTION_ZOOM_THRESHOLD;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;

import com.google.common.base.Function;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.renderers.BasicVertexRenderer;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import edu.uci.ics.jung.visualization.transform.MutableTransformerDecorator;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A base renderer class to define shared logic needed to render a vertex
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class AbstractVisualVertexRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends BasicVertexRenderer<V, E> {

	/**
	 * Creates a copy of the given {@link GraphicsDecorator} that may have scaling tweaked to 
	 * handle {@link VisualVertex#getEmphasis()} emphasized vertices.
	 */
	protected GraphicsDecorator getEmphasisGraphics(GraphicsDecorator g, V vertex,
			RenderContext<V, E> rc, Layout<V, E> layout) {

		Graphics2D graphicsCopy = (Graphics2D) g.create();
		GraphicsDecorator decoratorCopy = new GraphicsDecorator(graphicsCopy);

		double alpha = vertex.getAlpha();
		if (alpha < 1D) {
			decoratorCopy.setComposite(
				AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(), (float) alpha));
		}

		double emphasis = vertex.getEmphasis();
		if (emphasis == 0) {
			return decoratorCopy;
		}

		AffineTransform transform = graphicsCopy.getTransform();
		double scaleX = transform.getScaleX();
		if (((int) scaleX) == 1) {
			return decoratorCopy;
		}

		Point2D p = layout.apply(vertex);
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		p = multiLayerTransformer.transform(Layer.LAYOUT, p);

		double vertexX = p.getX();
		double vertexY = p.getY();
		AffineTransform xf = AffineTransform.getTranslateInstance(vertexX, vertexY);
		emphasis = adjustValueForCurrentScale(rc, emphasis, .5);
		double newScale = 1.0 + emphasis;
		xf.scale(newScale, newScale);
		xf.translate(-vertexX, -vertexY);

		transform.concatenate(xf);

		graphicsCopy.setTransform(transform);

		return decoratorCopy;
	}

	protected void paintHighlight(RenderContext<V, E> rc, V vertex, GraphicsDecorator g,
			Rectangle bounds) {

		if (!vertex.isSelected()) {
			return;
		}

		Paint oldPaint = g.getPaint();

		int halfishTransparency = 150;
		Color yellowWithTransparency = new Color(255, 255, 0, halfishTransparency);
		g.setPaint(yellowWithTransparency);

		int offset = 10;

		// scale the offset with the scale of the view, but not as fast, so that as we scale down, 
		// the size of the paint area starts to get larger than the vertex
		offset = (int) adjustValueForCurrentScale(rc, offset, .9);
		g.fillOval(bounds.x - offset, bounds.y - offset, bounds.width + (offset * 2),
			bounds.height + (offset * 2));

// DEBUG		
//		g.setPaint(Color.BLUE);
//		g.drawRect(bounds.x - offset, bounds.y - offset, bounds.width + (offset * 2),
//			bounds.height + (offset * 2));
//		g.setPaint(Color.BLACK);
//		g.drawRect(bounds.x, bounds.y, bounds.width, bounds.height);

		g.setPaint(oldPaint);
	}

	protected void paintDropShadow(RenderContext<V, E> rc, GraphicsDecorator g, Shape shape) {

		if (!isScaledPastVertexInteractionThreshold(rc)) {
			return;
		}

		g.setColor(Color.GRAY);
		int grayOffset = 15;
		int blackOffset = 5;

		AffineTransform xform = AffineTransform.getTranslateInstance(grayOffset, grayOffset);
		Shape xShape = xform.createTransformedShape(shape);
		g.fill(xShape);
		g.setColor(Color.BLACK);
		AffineTransform xform2 = AffineTransform.getTranslateInstance(blackOffset, blackOffset);
		Shape xShape2 = xform2.createTransformedShape(shape);
		g.fill(xShape2);
	}

	/**
	 * Returns true if the view is zoomed far enough out that the user cannot interact with 
	 * its internal UI widgets
	 * 
	 * @return true if the vertex is scaled past the interaction threshold
	 */
	protected boolean isScaledPastVertexInteractionThreshold(RenderContext<V, E> rc) {
		double scale = getScale(rc);
		return scale < INTERACTION_ZOOM_THRESHOLD;
	}

	/**
	 * Uses the render context to create a compact shape for the given vertex
	 * 
	 * @param rc the render context
	 * @param layout the layout
	 * @param vertex the vertex
	 * @return the vertex shape
	 * @see VertexShapeProvider#getCompactShape()
	 */
	protected Shape getCompactShape(RenderContext<V, E> rc, Layout<V, E> layout, V vertex) {

		Function<? super V, Shape> vertexShaper = rc.getVertexShapeTransformer();
		Shape shape = null;
		if (vertexShaper instanceof VisualGraphVertexShapeTransformer) {
			@SuppressWarnings("unchecked")
			VisualGraphVertexShapeTransformer<V> vgShaper =
				(VisualGraphVertexShapeTransformer<V>) vertexShaper;

			// use the viewable shape here, as it is visually pleasing
			shape = vgShaper.transformToCompactShape(vertex);
		}
		else {
			shape = vertexShaper.apply(vertex);
		}

		return transformFromLayoutToView(rc, layout, vertex, shape);
	}

	/**
	 * Uses the render context to create a compact shape for the given vertex
	 * 
	 * @param rc the render context
	 * @param layout the layout
	 * @param vertex the vertex
	 * @return the vertex shape
	 * @see VertexShapeProvider#getFullShape()
	 */
	public Shape getFullShape(RenderContext<V, E> rc, Layout<V, E> layout, V vertex) {
		Function<? super V, Shape> vertexShaper = rc.getVertexShapeTransformer();
		Shape shape = null;
		if (vertexShaper instanceof VisualGraphVertexShapeTransformer) {
			@SuppressWarnings("unchecked")
			VisualGraphVertexShapeTransformer<V> vgShaper =
				(VisualGraphVertexShapeTransformer<V>) vertexShaper;

			// use the viewable shape here, as it is visually pleasing
			shape = vgShaper.transformToFullShape(vertex);
		}
		else {
			shape = vertexShaper.apply(vertex);
		}

		return transformFromLayoutToView(rc, layout, vertex, shape);
	}

	/**
	 * Takes the given shape and translates its coordinates to the view space
	 * 
	 * @param rc the render context
	 * @param layout the model space layout
	 * @param vertex the vertex
	 * @param shape the shape to translate
	 * @return the new shape
	 */
	protected Shape transformFromLayoutToView(RenderContext<V, E> rc, Layout<V, E> layout, V vertex,
			Shape shape) {

		Point2D p = layout.apply(vertex);
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		p = multiLayerTransformer.transform(Layer.LAYOUT, p);
		float x = (float) p.getX();
		float y = (float) p.getY();

		// create a transform that translates to the location of
		// the vertex to be rendered
		AffineTransform xform = AffineTransform.getTranslateInstance(x, y);
		return xform.createTransformedShape(shape);
	}

	/**
	 * Adjusts the given value based upon the current scale applied the the view.  The more
	 * scaled out the view, the larger the value returned.   This allows view effects to be
	 * discernable at scale.
	 * 
	 * @param rc the render context
	 * @param value the value to scale
	 * @param ratioToScale the ratio to scale to
	 * @return the scaled value
	 */
	protected double adjustValueForCurrentScale(RenderContext<V, E> rc, double value,
			double ratioToScale) {
		double scale = getScale(rc);
		return value / Math.pow(scale, ratioToScale);
	}

	protected double getScale(RenderContext<V, E> rc) {
		MutableTransformer vt = rc.getMultiLayerTransformer().getTransformer(Layer.VIEW);
		if (vt instanceof MutableTransformerDecorator) {
			vt = ((MutableTransformerDecorator) vt).getDelegate();
		}

		return vt.getScale();
	}
}
