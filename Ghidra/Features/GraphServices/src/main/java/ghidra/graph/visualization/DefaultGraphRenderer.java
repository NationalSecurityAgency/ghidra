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
package ghidra.graph.visualization;

import static org.jungrapht.visualization.renderers.BiModalRenderer.*;

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;

import javax.swing.*;
import javax.swing.border.Border;

import org.jungrapht.visualization.RenderContext;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.decorators.*;
import org.jungrapht.visualization.layout.algorithms.util.InitialDimensionFunction;
import org.jungrapht.visualization.renderers.*;
import org.jungrapht.visualization.renderers.Renderer;
import org.jungrapht.visualization.renderers.Renderer.VertexLabel.Position;
import org.jungrapht.visualization.util.RectangleUtils;

import generic.util.image.ImageUtils;
import ghidra.service.graph.*;

/**
 * Handles the rendering of graphs for the {@link DefaultGraphDisplay}
 */
public class DefaultGraphRenderer implements GraphRenderer {
	private static final double ARROW_WIDTH_TO_LENGTH_RATIO = 1.3;
	private static final int DEFAULT_MARGIN_BORDER_SIZE = 4;
	private static final int DEFAULT_STROKE_THICKNESS = 6;

	// This is an arbitrary scale factor applied after creating a node's icon
	// This somehow causes the low level jungrapht layout to perform better
	// If the icon is not zoomed, the icons are rendered too small and too far apart
	// somehow, by giving it bigger icons, the layouts seem to produce better results
	// When/if this is fixed in the jungrapht library, this can be removed
	private static final int ICON_ZOOM = 2;

	// put a limit on node size. Nodes are sized based on user supplied vertex names, so need to
	// protect them from becoming too large, so just picked some limits.
	private static final int MAX_WIDTH = 500;
	private static final int MAX_HEIGHT = 500;

	private int labelBorderSize = DEFAULT_MARGIN_BORDER_SIZE;
	private int strokeThickness = DEFAULT_STROKE_THICKNESS;
	private JLabel label;

	private GraphDisplayOptions options;
	private final Map<AttributedVertex, Icon> iconCache = new ConcurrentHashMap<>();
	private final Map<RenderingHints.Key, Object> renderingHints = new HashMap<>();
	private Stroke edgeStroke = new BasicStroke(4.0f);

	public DefaultGraphRenderer() {
		this(new DefaultGraphDisplayOptions());
	}

	public DefaultGraphRenderer(GraphDisplayOptions options) {
		this.options = options;
		renderingHints.put(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
		label = new JLabel();
		label.setForeground(Color.black);
		label.setBackground(Color.white);
		label.setOpaque(false);
		Border marginBorder = BorderFactory.createEmptyBorder(labelBorderSize, 2 * labelBorderSize,
			labelBorderSize, 2 * labelBorderSize);
		label.setBorder(marginBorder);
	}

	@Override
	public void setGraphTypeDisplayOptions(GraphDisplayOptions options) {
		this.options = options;
		clearCache();
	}

	@Override
	public GraphDisplayOptions getGraphDisplayOptions() {
		return options;
	}

	@Override
	public void clearCache() {
		iconCache.clear();
	}

	@Override
	public void initializeViewer(VisualizationViewer<AttributedVertex, AttributedEdge> viewer) {

		RenderContext<AttributedVertex, AttributedEdge> renderContext = viewer.getRenderContext();
		Function<Shape, org.jungrapht.visualization.layout.model.Rectangle> toRectangle =
			s -> RectangleUtils.convert(s.getBounds2D());

		if (options.usesIcons()) {
			// set up the shape and color functions
			IconShapeFunction<AttributedVertex> nodeShaper =
				new IconShapeFunction<>(new EllipseShapeFunction<>());

			nodeShaper.setIconFunction(this::getIcon);
			renderContext.setVertexShapeFunction(nodeShaper);
			renderContext.setVertexIconFunction(this::getIcon);
			int arrowLength = options.getArrowLength() * ICON_ZOOM;
			int arrowWidth = (int) (arrowLength * ARROW_WIDTH_TO_LENGTH_RATIO);
			renderContext.setEdgeArrowWidth(arrowWidth);
			renderContext.setEdgeArrowLength(arrowLength);
			renderContext.setVertexLabelFunction(v -> "");
			viewer.setInitialDimensionFunction(
				InitialDimensionFunction.builder(nodeShaper.andThen(toRectangle)).build());
		}
		else {
			int arrowLength = options.getArrowLength();
			int arrowWidth = (int) (arrowLength * ARROW_WIDTH_TO_LENGTH_RATIO);
			renderContext.setEdgeArrowWidth(arrowWidth);
			renderContext.setEdgeArrowLength(arrowLength);
			renderContext.setVertexIconFunction(null);
			renderContext.setVertexShapeFunction(this::getVertexShape);
			viewer.setInitialDimensionFunction(InitialDimensionFunction
					.builder(renderContext.getVertexShapeFunction().andThen(toRectangle))
					.build());
			renderContext.setVertexLabelFunction(Object::toString);
			GraphLabelPosition labelPosition = options.getLabelPosition();
			renderContext.setVertexLabelPosition(getJungraphTPosition(labelPosition));

		}

		// assign the shapes to the modal renderer
		// the modal renderer optimizes rendering for large graphs by removing detail
		ModalRenderer<AttributedVertex, AttributedEdge> modalRenderer = viewer.getRenderer();
		Renderer.Vertex<AttributedVertex, AttributedEdge> lightWeightRenderer =
			modalRenderer.getVertexRenderer(LIGHTWEIGHT);

		// set the lightweight (optimized) renderer to use the vertex shapes instead
		// of using default shapes.
		if (lightWeightRenderer instanceof LightweightVertexRenderer) {
			LightweightVertexRenderer<AttributedVertex, AttributedEdge> lightweightVertexRenderer =
				(LightweightVertexRenderer<AttributedVertex, AttributedEdge>) lightWeightRenderer;

			Function<AttributedVertex, Shape> vertexShapeFunction =
				renderContext.getVertexShapeFunction();
			lightweightVertexRenderer.setVertexShapeFunction(vertexShapeFunction);
		}

		renderContext.setVertexFontFunction(this::getFont);
		renderContext.setVertexLabelRenderer(new JLabelVertexLabelRenderer(Color.black));
		renderContext.setVertexDrawPaintFunction(this::getVertexColor);
		renderContext.setVertexFillPaintFunction(this::getVertexColor);
		renderContext.setVertexStrokeFunction(n -> new BasicStroke(3.0f));

		renderContext.setEdgeStrokeFunction(this::getEdgeStroke);
		renderContext.setEdgeDrawPaintFunction(this::getEdgeColor);
		renderContext.setArrowDrawPaintFunction(this::getEdgeColor);
		renderContext.setArrowFillPaintFunction(this::getEdgeColor);
		renderContext.setEdgeShapeFunction(EdgeShape.line());
	}

	private Shape getVertexShape(AttributedVertex vertex) {
		if (vertex instanceof GroupVertex) {
			return VertexShape.STAR.getShape();
		}
		VertexShape vertexShape = options.getVertexShape(vertex);
		return vertexShape != null ? vertexShape.getShape() : VertexShape.RECTANGLE.getShape();
	}

	private Position getJungraphTPosition(GraphLabelPosition labelPosition) {
		switch (labelPosition) {
			case CENTER:
				return Position.CNTR;
			case EAST:
				return Position.E;
			case NORTH:
				return Position.N;
			case NORTHEAST:
				return Position.NE;
			case NORTHWEST:
				return Position.NW;
			case SOUTH:
				return Position.S;
			case SOUTHEAST:
				return Position.SE;
			case SOUTHWEST:
				return Position.SW;
			case WEST:
				return Position.W;
			default:
				return Position.AUTO;

		}
	}

	private Color getVertexColor(AttributedVertex vertex) {
		return options.getVertexColor(vertex);
	}

	private Color getEdgeColor(AttributedEdge edge) {
		return options.getEdgeColor(edge);
	}

	private Icon getIcon(AttributedVertex vertex) {

		// WARNING: very important to not use map's computeIfAbsent() method
		// because the map is synchronized and the createIcon() method will
		// attempt to acquire the AWT lock. That combination will cause a deadlock
		// if computeIfAbsent() is used and this method is called from non-swing thread.
		Icon icon = iconCache.get(vertex);
		if (icon == null) {
			icon = createIcon(vertex);
			iconCache.put(vertex, icon);
		}
		return icon;
	}

	private Icon createIcon(AttributedVertex vertex) {
		VertexShape vertexShape = options.getVertexShape(vertex);
		Color vertexColor = options.getVertexColor(vertex);
		String labelText = options.getVertexLabel(vertex);
		return createImage(vertexShape, labelText, vertexColor);
	}

	@Override
	public void vertexChanged(AttributedVertex vertex) {
		iconCache.remove(vertex);
	}

	private ImageIcon createImage(VertexShape vertexShape, String vertexName, Color vertexColor) {
		prepareLabel(vertexName, vertexColor);

		Shape unitShape = vertexShape.getShape();
		Rectangle bounds = unitShape.getBounds();

		// this variable attempts to keep the shape's height from being too out of proportion
		// from the width. 
		int maxWidthToHeightRatio = vertexShape.getMaxWidthToHeightRatio();
		double sizeFactor = vertexShape.getShapeToLabelRatio();

		int labelWidth = label.getWidth();
		int labelHeight = label.getHeight();

		// make height somewhat bigger if label width is really long to avoid really long thin
		// nodes
		labelHeight = Math.max(labelHeight, labelWidth / maxWidthToHeightRatio);

		// adjust for shape size factor (some shapes want to be somewhat bigger than the label)
		// for example, triangles need to be much bigger to get the text to fit inside the shape,
		// whereas, rectangles fit naturally.
		int shapeWidth = (int) (labelWidth * sizeFactor);
		int shapeHeight = (int) (labelHeight * sizeFactor);

		// compute the amount to scale the shape to fit around the label
		double scalex = shapeWidth / bounds.getWidth();
		double scaley = shapeHeight / bounds.getHeight();

		Shape scaledShape =
			AffineTransform.getScaleInstance(scalex, scaley).createTransformedShape(unitShape);

		// this determines the vertical positioning of text in the shape
		// a value of 0 will put the text at the top, 1 at the bottom, and .5 in the center
		double labelOffsetRatio = vertexShape.getLabelPosition();
		bounds = scaledShape.getBounds();
		int iconWidth = bounds.width + (2 * strokeThickness);
		int iconHeight = bounds.height + (2 * strokeThickness);

		BufferedImage bufferedImage =
			new BufferedImage(iconWidth, iconHeight, BufferedImage.TYPE_INT_ARGB);

		Graphics2D graphics = bufferedImage.createGraphics();
		graphics.setRenderingHints(renderingHints);
		AffineTransform graphicsTransform = graphics.getTransform();

		// shapes are centered at the origin, so translate the graphics to compensate
		graphics.translate(-bounds.x + strokeThickness, -bounds.y + strokeThickness);
		graphics.setPaint(Color.WHITE);
		graphics.fill(scaledShape);
		graphics.setPaint(vertexColor);
		graphics.setStroke(new BasicStroke(strokeThickness));
		graphics.draw(scaledShape);

		graphics.setTransform(graphicsTransform);

		// center the text horizontally
		// position the text vertically based on the shape.
		int xOffset = (iconWidth - label.getWidth()) / 2;
		int yOffset = (int) ((iconHeight - label.getHeight()) * labelOffsetRatio);

		graphics.translate(xOffset, yOffset);
		graphics.setPaint(Color.black);
		label.paint(graphics);

		graphics.setTransform(graphicsTransform); // restore the original transform
		graphics.dispose();
		Image scaledImage =
			ImageUtils.createScaledImage(bufferedImage, iconWidth * ICON_ZOOM,
				iconHeight * ICON_ZOOM,
				Image.SCALE_FAST);
		ImageIcon imageIcon = new ImageIcon(scaledImage);
		return imageIcon;

	}

	private void prepareLabel(String vertexName, Color vertexColor) {
		// The label is just used as a renderer and never parented, so no need to be 
		// on the swing thread
		Font font = options.getFont();
		label.setFont(font);
		label.setText(vertexName);
		Dimension labelSize = label.getPreferredSize();

		// make sure the the vertexName doesn't make the icon ridiculously big
		int width = Math.min(labelSize.width, MAX_WIDTH);
		int height = Math.min(labelSize.height, MAX_HEIGHT);
		label.setSize(width, height);
	}

	@Override
	public String getFavoredEdgeType() {
		return options.getFavoredEdgeType();
	}

	@Override
	public Integer getEdgePriority(String edgeType) {
		return options.getEdgePriority(edgeType);
	}

	private Stroke getEdgeStroke(AttributedEdge edge) {
		return edgeStroke;
	}

	@Override
	public Color getVertexSelectionColor() {
		return options.getVertexSelectionColor();
	}

	@Override
	public Color getEdgeSelectionColor() {
		return options.getEdgeSelectionColor();
	}

	private Font getFont(AttributedVertex attributedvertex1) {
		return options.getFont();
	}
}
