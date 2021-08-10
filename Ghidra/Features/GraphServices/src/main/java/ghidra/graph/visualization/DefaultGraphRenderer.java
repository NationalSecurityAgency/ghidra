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
	// scale factor so the icons can be rendered smaller so that fonts read better when zoomed out a bit
	private static final int ICON_ZOOM = 5;

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

		int maxWidthToHeightRatio = vertexShape.getMaxWidthToHeightRatio();
		double sizeFactor = vertexShape.getShapeToLabelRatio();

		int labelWidth = label.getWidth();
		int labelHeight = label.getHeight();

		int iconWidth =
			(int) (Math.max(labelWidth, labelHeight * 2.0) * sizeFactor) + strokeThickness;
		int iconHeight =
			(int) (Math.max(label.getHeight(), labelWidth / maxWidthToHeightRatio) * sizeFactor) +
				strokeThickness;

		double scalex = iconWidth / bounds.getWidth();
		double scaley = iconHeight / bounds.getHeight();

		Shape scaledShape =
			AffineTransform.getScaleInstance(scalex, scaley).createTransformedShape(unitShape);

		double labelOffsetRatio = vertexShape.getLabelPosition();

		bounds = scaledShape.getBounds();

		int width = bounds.width + 2 * strokeThickness;
		int height = bounds.height + strokeThickness;
		BufferedImage bufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);

		Graphics2D graphics = bufferedImage.createGraphics();
		graphics.setRenderingHints(renderingHints);
		AffineTransform graphicsTransform = graphics.getTransform();

		graphics.translate(-bounds.x + strokeThickness, -bounds.y + strokeThickness / 2);
		graphics.setPaint(Color.WHITE);
		graphics.fill(scaledShape);
		graphics.setPaint(vertexColor);
		graphics.setStroke(new BasicStroke(strokeThickness));
		graphics.draw(scaledShape);

		graphics.setTransform(graphicsTransform);
		int xOffset = (width - label.getWidth()) / 2;
		int yOffset = (int) ((height - label.getHeight()) * labelOffsetRatio);
		graphics.translate(xOffset, yOffset);
		graphics.setPaint(Color.black);
		label.paint(graphics);

		graphics.setTransform(graphicsTransform); // restore the original transform
		graphics.dispose();
		Image scaledImage =
			ImageUtils.createScaledImage(bufferedImage, width * ICON_ZOOM, height * ICON_ZOOM,
				Image.SCALE_FAST);

		ImageIcon imageIcon = new ImageIcon(scaledImage);
		return imageIcon;

	}

	private void prepareLabel(String vertexName, Color vertexColor) {
		label.setFont(options.getFont());
		label.setText(vertexName);
		Dimension labelSize = label.getPreferredSize();
		label.setSize(labelSize);
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
