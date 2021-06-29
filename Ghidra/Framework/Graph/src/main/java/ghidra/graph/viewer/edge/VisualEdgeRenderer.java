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

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.geom.Point2D;

import javax.swing.JComponent;

import com.google.common.base.Function;
import com.google.common.base.Predicate;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.graph.util.Context;
import edu.uci.ics.jung.graph.util.Pair;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.renderers.BasicEdgeRenderer;
import edu.uci.ics.jung.visualization.transform.LensTransformer;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import edu.uci.ics.jung.visualization.transform.shape.GraphicsDecorator;
import edu.uci.ics.jung.visualization.util.VertexShapeFactory;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.graph.viewer.vertex.VertexShapeProvider;
import ghidra.graph.viewer.vertex.VisualGraphVertexShapeTransformer;

/**
 * Edge render for the {@link VisualGraph} system
 * 
 * <h2 style="text-align:center">Implementation Notes</h2>
 * 
 * <h3>Jung Vertex/Edge Rendering</h3>
 * <p>Jung creates shapes for vertices (see {@link VertexShapeFactory}) that are centered.  They
 * do this by getting the width/height of the shape and then creating an x/y value that is 
 * half of the width and height, respectively.  This has the effect of the vertex appearing 
 * centered over its connected edge.  We mimic that with our 
 * {@link VisualGraphVertexShapeTransformer} so that our edge rendering code is similar to 
 * Jung's.
 * <p>If we ever decide instead to not center our shapes, then this renderer would have to be
 * updated to itself center the edge shape created herein, like this:
 * <pre>{@literal
 * 		Rectangle b1 = s1.getBounds();
 *		Rectangle b2 = s2.getBounds();
 *
 *		// translate the edge to be centered in the vertex
 *		int w1 = b1.width >> 1;
 *		int h1 = b1.height >> 1;
 *		int w2 = b2.width >> 1;
 *		int h2 = b2.height >> 1;
 *
 *		float tx1 = x1 + w1;
 *		float ty1 = y1 + h1;
 *		float tx2 = x2 + w2;
 *		float ty2 = y2 + h2;
 * 		Shape edgeShape = getEdgeShape(rc, graph, e, tx1, ty1, tx2, ty2, isLoop, xs1);
 * }</pre>
 * <p>Also, there are other spots in the system where we account for this center that would 
 * have to be changed, such as the {@link AbstractVisualGraphLayout}, which needs the centering
 * offsets to handle vertex clipping.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public abstract class VisualEdgeRenderer<V extends VisualVertex, E extends VisualEdge<V>>
		extends BasicEdgeRenderer<V, E> {

	private static final float HOVERED_PATH_STROKE_WIDTH = 8.0f;
	private static final float FOCUSED_PATH_STROKE_WIDTH = 4.0f;
	private static final float SELECTED_STROKE_WIDTH = FOCUSED_PATH_STROKE_WIDTH + 2;
	private static final float EMPHASIZED_STOKE_WIDTH = SELECTED_STROKE_WIDTH + 3.0f;

	private float dashingPatternOffset;

	private Color defaultBaseColor = Color.BLACK;
	private Color defaultHighlightColor = Color.GRAY;

	private VisualEdgeArrowRenderingSupport<V, E> arrowRenderingSupport =
		new VisualEdgeArrowRenderingSupport<>();

	/**
	 * Sets the offset value for painting dashed lines.  This allows clients to animate the 
	 * lines being drawn for edges in the edge direction.
	 * 
	 * @param dashingPatterOffset the offset value
	 */
	// TODO this method is too specific for this interface. It paints a special view when
	//      the edge is part of a given path.  This should probably be part of a subclass
	public void setDashingPatternOffset(float dashingPatterOffset) {
		this.dashingPatternOffset = dashingPatterOffset;
	}

	public void setBaseColor(Color color) {
		this.defaultBaseColor = color;
	}

	public Color getBaseColor(Graph<V, E> g, E e) {
		return defaultBaseColor;
	}

	public void setHighlightColor(Color highlightColor) {
		this.defaultHighlightColor = highlightColor;
	}

	public Color getHighlightColor(Graph<V, E> g, E e) {
		return defaultHighlightColor;
	}

	// template method
	protected boolean isInHoveredVertexPath(E e) {
		return e.isInHoveredVertexPath();
	}

	// template method
	protected boolean isInFocusedVertexPath(E e) {
		return e.isInFocusedVertexPath();
	}

	// template method
	protected boolean isSelected(E e) {
		return e.isSelected();
	}

	// template method
	protected boolean isEmphasiszed(E e) {
		return e.getEmphasis() != 0;
	}

	@Override
	public void drawSimpleEdge(RenderContext<V, E> rc, Layout<V, E> layout, E e) {

		GraphicsDecorator gDecorator = rc.getGraphicsContext();
		Graphics2D graphicsCopy = (Graphics2D) gDecorator.create();
		GraphicsDecorator g = new GraphicsDecorator(graphicsCopy);

		double alpha = e.getAlpha();
		if (alpha < 1D) {
			g.setComposite(
				AlphaComposite.getInstance(AlphaComposite.SrcOver.getRule(), (float) alpha));
		}

		Graph<V, E> graph = layout.getGraph();
		Pair<V> endpoints = graph.getEndpoints(e);
		V v1 = endpoints.getFirst();
		V v2 = endpoints.getSecond();
		float scalex = (float) g.getTransform().getScaleX();
		float scaley = (float) g.getTransform().getScaleY();

		boolean isInHoveredPath = isInHoveredVertexPath(e);
		boolean isInFocusedPath = isInFocusedVertexPath(e);
		boolean isSelected = isSelected(e);
		boolean isEmphasized = isEmphasiszed(e);

		Color highlightColor = getHighlightColor(graph, e);
		Color baseColor = getBaseColor(graph, e);
		Color hoveredColor = highlightColor;
		Color focusedColor = baseColor;
		Color selectedColor = highlightColor.darker(); // note: we can do better for selected color
		Color selectedAccentColor = highlightColor;

		float scale = Math.min(scalex, scaley);

		Point2D p1 = layout.apply(v1);
		Point2D p2 = layout.apply(v2);
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		p1 = multiLayerTransformer.transform(Layer.LAYOUT, p1);
		p2 = multiLayerTransformer.transform(Layer.LAYOUT, p2);
		float x1 = (float) p1.getX();
		float y1 = (float) p1.getY();
		float x2 = (float) p2.getX();
		float y2 = (float) p2.getY();

		boolean isLoop = v1.equals(v2);
		Rectangle deviceRectangle = null;
		JComponent vv = rc.getScreenDevice();
		if (vv != null) {
			Dimension d = vv.getSize();
			deviceRectangle = new Rectangle(0, 0, d.width, d.height);
		}

		Shape vs1 = getCompactShape(rc, layout, v1);
		Shape edgeShape = getEdgeShape(rc, graph, e, x1, y1, x2, y2, isLoop, vs1);

		MutableTransformer vt = multiLayerTransformer.getTransformer(Layer.VIEW);
		if (vt instanceof LensTransformer) {
			vt = ((LensTransformer) vt).getDelegate();
		}

		Context<Graph<V, E>, E> context = Context.<Graph<V, E>, E> getInstance(graph, e);
		boolean edgeHit = vt.transform(edgeShape).intersects(deviceRectangle);
		if (!edgeHit) {
			return;
		}

		Paint oldPaint = g.getPaint();

		// get Paints for filling and drawing
		// (filling is done first so that drawing and label use the same Paint)		
		BasicStroke hoverStroke = getHoveredPathStroke(e, scale);
		BasicStroke focusedStroke = getFocusedPathStroke(e, scale);
		BasicStroke selectedStroke = getSelectedStroke(e, scale);
		BasicStroke selectedAccentStroke = getSelectedAccentStroke(e, scale);
		BasicStroke empahsisStroke = getEmphasisStroke(e, scale);

		//
		// Fill
		// 
		Paint fillPaint = rc.getEdgeFillPaintTransformer().apply(e);
		if (fillPaint != null) {
			// basic shape
			g.setPaint(fillPaint);
			g.fill(edgeShape);

			// Currently, graphs with complicated edge shapes (those with articulations) do not
			// use a fill paint.  If we execute this code with articulated edges, the display 
			// looks unusual.   So, for now, only 'fill' with these effects when the client has
			// explicitly used a fill paint transformer.
			if (isEmphasized) {
				Stroke saveStroke = g.getStroke();
				g.setPaint(fillPaint);
				g.setStroke(empahsisStroke);
				g.fill(edgeShape);
				g.setStroke(saveStroke);
			}

			if (isInHoveredPath) {
				Stroke saveStroke = g.getStroke();
				g.setPaint(hoveredColor);
				g.setStroke(hoverStroke);
				g.fill(edgeShape);
				g.setStroke(saveStroke);
			}

			if (isInFocusedPath) {
				Stroke saveStroke = g.getStroke();
				g.setPaint(focusedColor);
				g.setStroke(focusedStroke);
				g.fill(edgeShape);
				g.setStroke(saveStroke);
			}

			if (isSelected) {
				Stroke saveStroke = g.getStroke();
				g.setPaint(selectedColor);
				g.setStroke(selectedStroke);
				g.fill(edgeShape);
				g.setStroke(saveStroke);
			}
		}

		//
		// Draw
		//
		Paint drawPaint = rc.getEdgeDrawPaintTransformer().apply(e);
		if (drawPaint != null) {
			// basic shape
			g.setPaint(drawPaint);
			g.draw(edgeShape);
		}

		if (isEmphasized) {
			Stroke saveStroke = g.getStroke();
			g.setPaint(drawPaint);
			g.setStroke(empahsisStroke);
			g.draw(edgeShape);
			g.setStroke(saveStroke);
		}

		if (isInHoveredPath) {
			Stroke saveStroke = g.getStroke();
			g.setPaint(hoveredColor);
			g.setStroke(hoverStroke);
			g.draw(edgeShape);
			g.setStroke(saveStroke);
		}

		if (isInFocusedPath) {
			Stroke saveStroke = g.getStroke();
			g.setPaint(focusedColor);
			g.setStroke(focusedStroke);
			g.draw(edgeShape);
			g.setStroke(saveStroke);
		}

		if (isSelected) {
			Stroke saveStroke = g.getStroke();

			g.setPaint(selectedAccentColor);
			g.setStroke(selectedAccentStroke);
			g.draw(edgeShape);

			g.setPaint(selectedColor);
			g.setStroke(selectedStroke);
			g.draw(edgeShape);
			g.setStroke(saveStroke);
		}

		// debug - draw a box around the edge
		//Rectangle shapeBounds = edgeShape.getBounds();
		//g.setPaint(Color.ORANGE);
		//g.draw(shapeBounds);

		// can add this feature as needed to speed up painting 
		//if (scale < .3) {
		//	return;
		//}

		//
		// Arrow Head
		//
		Predicate<Context<Graph<V, E>, E>> predicate = rc.getEdgeArrowPredicate();
		boolean drawArrow = predicate.apply(context);
		if (!drawArrow) {
			g.setPaint(oldPaint);
			return;
		}

		Stroke arrowStroke = rc.getEdgeArrowStrokeTransformer().apply(e);
		Stroke oldArrowStroke = g.getStroke();
		if (arrowStroke != null) {
			g.setStroke(arrowStroke);
		}

		Shape vs2 = getVertexShapeForArrow(rc, layout, v2);	// end vertex

		boolean arrowHit = vt.transform(vs2).intersects(deviceRectangle);
		if (!arrowHit) {
			g.setPaint(oldPaint);
			return;
		}

		AffineTransform at = arrowRenderingSupport.createArrowTransform(rc, edgeShape, vs2);
		if (at == null || at.isIdentity()) {
			g.setPaint(oldPaint);
			g.setStroke(oldArrowStroke);
			return;
		}

		Paint arrowFillPaint = rc.getArrowFillPaintTransformer().apply(e);
		Paint arrowDrawPaint = rc.getArrowDrawPaintTransformer().apply(e);
		Shape arrow = rc.getEdgeArrowTransformer().apply(context);
		arrow = scaleArrowForBetterVisibility(rc, arrow);
		arrow = at.createTransformedShape(arrow);

		// basic shape
		g.setPaint(arrowFillPaint);
		g.fill(arrow);
		g.setPaint(arrowDrawPaint);
		g.draw(arrow);

		if (isEmphasized) {
			Stroke saveStroke = g.getStroke();
			g.setPaint(arrowDrawPaint);
			g.setStroke(empahsisStroke);
			g.fill(arrow);
			g.draw(arrow);
			g.setStroke(saveStroke);
		}

		if (isInHoveredPath) {
			Stroke saveStroke = g.getStroke();
			g.setPaint(hoveredColor);
			g.setStroke(hoverStroke);
			g.fill(arrow);
			g.draw(arrow);
			g.setStroke(saveStroke);
		}

		if (isInFocusedPath) {
			Stroke saveStroke = g.getStroke();
			g.setPaint(focusedColor);
			g.setStroke(focusedStroke);
			g.draw(edgeShape);
			g.setStroke(saveStroke);
		}

		if (isSelected) {
			Stroke saveStroke = g.getStroke();
			g.setPaint(selectedColor);
			g.setStroke(selectedStroke);
			g.fill(arrow);
			g.draw(arrow);
			g.setStroke(saveStroke);
		}

		g.setStroke(oldArrowStroke);
		g.setPaint(oldPaint);
	}

	protected Shape getVertexShapeForArrow(RenderContext<V, E> rc, Layout<V, E> layout, V v) {
		// we use the default shape (the full shape) for arrow detection
		return getFullShape(rc, layout, v);
	}

	/**
	 * Returns the edge shape for the given points
	 * 
	 * @param rc the render context for the graph
	 * @param graph the graph
	 * @param e the edge to shape
	 * @param x1 the start vertex point x; layout space
	 * @param y1 the start vertex point y; layout space
	 * @param x2 the end vertex point x; layout space
	 * @param y2 the end vertex point y; layout space
	 * @param isLoop true if the start == end, which is a self-loop
	 * @param vertexShape the vertex shape (used in the case of a loop to draw a circle from the 
	 *              shape to itself)
	 * @return the edge shape
	 */
	public abstract Shape getEdgeShape(RenderContext<V, E> rc, Graph<V, E> graph, E e, float x1,
			float y1, float x2, float y2, boolean isLoop, Shape vertexShape);

	private BasicStroke getHoveredPathStroke(E e, float scale) {
		float width = HOVERED_PATH_STROKE_WIDTH / (float) Math.pow(scale, .80);
		return new BasicStroke(width, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND, 0f,
			new float[] { width * 1, width * 2 }, width * 3 * dashingPatternOffset);
	}

	private BasicStroke getFocusedPathStroke(E e, float scale) {
		float width = FOCUSED_PATH_STROKE_WIDTH / (float) Math.pow(scale, .80);
		return new BasicStroke(width);
	}

	private BasicStroke getSelectedStroke(E e, float scale) {
		float width = SELECTED_STROKE_WIDTH / (float) Math.pow(scale, .80);
		return new BasicStroke(width);
	}

	private BasicStroke getSelectedAccentStroke(E e, float scale) {
		float width = (SELECTED_STROKE_WIDTH + 2) / (float) Math.pow(scale, .80);
		return new BasicStroke(width);
	}

	private BasicStroke getEmphasisStroke(E e, float scale) {
		double emphasisRatio = e.getEmphasis(); // this value is 0 when no emphasis
		float fullEmphasis = EMPHASIZED_STOKE_WIDTH;
		float emphasis = (float) (fullEmphasis * emphasisRatio);
		float width = emphasis / (float) Math.pow(scale, .80);
		return new BasicStroke(width);
	}

	private Shape scaleArrowForBetterVisibility(RenderContext<V, E> rc, Shape arrow) {
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		MutableTransformer viewTransformer = multiLayerTransformer.getTransformer(Layer.VIEW);

		double scaleX2 = viewTransformer.getScaleX();
		double scaleY2 = viewTransformer.getScaleY();

		// make the arrow bigger so that later when the view scale is applied, the shape does
		// not get as small as fast as the graph
		AffineTransform fine = AffineTransform.getScaleInstance(1 / Math.pow(scaleX2, .68),
			1 / Math.pow(scaleY2, .68));
		return fine.createTransformedShape(arrow);
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

}
