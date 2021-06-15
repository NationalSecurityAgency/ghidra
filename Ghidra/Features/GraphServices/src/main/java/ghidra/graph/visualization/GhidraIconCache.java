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

import java.awt.*;
import java.awt.geom.AffineTransform;
import java.awt.image.BufferedImage;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;

import ghidra.service.graph.AttributedVertex;

public class GhidraIconCache {

	private static final int DEFAULT_STROKE_THICKNESS = 12;
	private static final int DEFAULT_FONT_SIZE = 12;
	private static final String DEFAULT_FONT_NAME = "Dialog";
	private static final int DEFAULT_MARGIN_BORDER_SIZE = 8;
	private static final float LABEL_TO_ICON_PROPORTION = 1.1f;
	private final JLabel rendererLabel = new JLabel();
	private final Map<RenderingHints.Key, Object> renderingHints = new HashMap<>();
	private int strokeThickness = DEFAULT_STROKE_THICKNESS;

	private final Map<AttributedVertex, Icon> map = new ConcurrentHashMap<>();

	private final IconShape.Function iconShapeFunction = new IconShape.Function();
	private String preferredVeretxLabelAttribute = null;

	Icon get(AttributedVertex vertex) {

		// WARNING: very important to not use map's computeIfAbsent() method
		// because the map is synchronized and the createIcon() method will
		// attempt to acquire the AWT lock. That combination will cause a deadlock
		// if computeIfAbsent() is used and this method is called from non-swing thread.
		Icon icon = map.get(vertex);
		if (icon == null) {
			icon = createIcon(vertex);
			map.put(vertex, icon);
		}
		return icon;
	}

	GhidraIconCache() {
		renderingHints.put(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
	}

	private Icon createIcon(AttributedVertex vertex) {
		rendererLabel
				.setText(ProgramGraphFunctions.getLabel(vertex, preferredVeretxLabelAttribute));
		rendererLabel.setFont(new Font(DEFAULT_FONT_NAME, Font.BOLD, DEFAULT_FONT_SIZE));
		rendererLabel.setForeground(Color.black);
		rendererLabel.setBackground(Color.white);
		rendererLabel.setOpaque(true);
		Border lineBorder = BorderFactory.createLineBorder((Color) Colors.getColor(vertex), 2);
		Border marginBorder = BorderFactory.createEmptyBorder(DEFAULT_MARGIN_BORDER_SIZE,
			DEFAULT_MARGIN_BORDER_SIZE, DEFAULT_MARGIN_BORDER_SIZE, DEFAULT_MARGIN_BORDER_SIZE);
		rendererLabel.setBorder(new CompoundBorder(lineBorder, marginBorder));

		Dimension labelSize = rendererLabel.getPreferredSize();
		rendererLabel.setSize(labelSize);
		Shape shape = ProgramGraphFunctions.getVertexShape(vertex);

		IconShape.Type shapeType = iconShapeFunction.apply(shape);

		return createImageIcon(vertex, shapeType, rendererLabel, labelSize, shape);
	}

	/**
	 * Based on the shape and characteristics of the vertex label (color, text) create and cache an ImageIcon
	 * that will be used to draw the vertex
	 *
	 * @param vertex the vertex to draw (and the key for the cache)
	 * @param vertexShapeCategory the type of Ghidra vertex shape
	 * @param label the {@link JLabel} used to draw the label. Note that it will parse html for formatting.
	 * @param labelSize the dimensions of the JLabel after it has been parsed
	 * @param vertexShape the primitive {@link Shape} used to represent the vertex
	 */
	private Icon createImageIcon(AttributedVertex vertex, IconShape.Type vertexShapeCategory,
			JLabel label, Dimension labelSize, Shape vertexShape) {
		int offset = 0;
		double scalex;
		double scaley;
		switch (vertexShapeCategory) {
			// triangles have a non-zero +/- yoffset instead of centering the label
			case TRIANGLE:
				// scale the vertex shape
				scalex = labelSize.getWidth() / vertexShape.getBounds().getWidth() *
					LABEL_TO_ICON_PROPORTION;
				scaley = labelSize.getHeight() / vertexShape.getBounds().getHeight() *
					LABEL_TO_ICON_PROPORTION;
				vertexShape = AffineTransform.getScaleInstance(scalex, scaley)
						.createTransformedShape(vertexShape);
				offset = -(int) ((vertexShape.getBounds().getHeight() - labelSize.getHeight()) / 2);
				break;
			case INVERTED_TRIANGLE:
				scalex = labelSize.getWidth() / vertexShape.getBounds().getWidth() *
					LABEL_TO_ICON_PROPORTION;
				scaley = labelSize.getHeight() / vertexShape.getBounds().getHeight() *
					LABEL_TO_ICON_PROPORTION;
				vertexShape = AffineTransform.getScaleInstance(scalex, scaley)
						.createTransformedShape(vertexShape);
				offset = (int) ((vertexShape.getBounds().getHeight() - labelSize.getHeight()) / 2);
				break;

			// rectangles can fit a full-sized label
			case RECTANGLE:
				scalex = labelSize.getWidth() / vertexShape.getBounds().getWidth();
				scaley = labelSize.getHeight() / vertexShape.getBounds().getHeight();
				vertexShape = AffineTransform.getScaleInstance(scalex, scaley)
						.createTransformedShape(vertexShape);
				break;

			// diamonds and ellipses reduce the label size to fit
			case DIAMOND:
			default: // ELLIPSE
				scalex =
					labelSize.getWidth() / vertexShape.getBounds().getWidth() * 1.1;
				scaley = labelSize.getHeight() / vertexShape.getBounds().getHeight() * 1.1;
				vertexShape = AffineTransform.getScaleInstance(scalex, scaley)
						.createTransformedShape(vertexShape);
				break;
		}
		Rectangle vertexBounds = vertexShape.getBounds();

		BufferedImage bufferedImage = new BufferedImage(vertexBounds.width + (2 * strokeThickness),
			vertexBounds.height + (2 * strokeThickness), BufferedImage.TYPE_INT_ARGB);

		Graphics2D graphics = bufferedImage.createGraphics();
		graphics.setRenderingHints(renderingHints);
		AffineTransform graphicsTransform = graphics.getTransform();

		// draw the shape, offset by 1/2 its width and the strokeThickness
		AffineTransform offsetTransform =
			AffineTransform.getTranslateInstance(strokeThickness + vertexBounds.width / 2.0,
				strokeThickness + vertexBounds.height / 2.0);
		offsetTransform.preConcatenate(graphicsTransform);
		graphics.setTransform(offsetTransform);
		graphics.setPaint(Color.white);
		graphics.fill(vertexShape);
		graphics.setPaint(Colors.getColor(vertex));
		graphics.setStroke(new BasicStroke(strokeThickness));
		graphics.draw(vertexShape);

		// draw the JLabel, offset by 1/2 its width and the strokeThickness
		int xoffset = strokeThickness + (vertexBounds.width - labelSize.width) / 2;
		int yoffset = strokeThickness + (vertexBounds.height - labelSize.height) / 2;
		offsetTransform = AffineTransform.getTranslateInstance(xoffset, yoffset + offset);
		offsetTransform.preConcatenate(graphicsTransform);
		graphics.setPaint(Color.black);
		graphics.setTransform(offsetTransform);
		label.paint(graphics);
		// draw the shape again, but lighter (on top of the label)
		offsetTransform =
			AffineTransform.getTranslateInstance(strokeThickness + vertexBounds.width / 2.0,
				strokeThickness + vertexBounds.height / 2.0);
		offsetTransform.preConcatenate(graphicsTransform);
		graphics.setTransform(offsetTransform);
		Paint paint = Colors.getColor(vertex);
		if (paint instanceof Color) {
			Color color = (Color) paint;
			Color transparent = new Color(color.getRed(), color.getGreen(), color.getBlue(), 50);
			graphics.setPaint(transparent);
			graphics.setStroke(new BasicStroke(strokeThickness));
			graphics.draw(vertexShape);
		}

		graphics.setTransform(graphicsTransform); // restore the original transform
		graphics.dispose();
		return new ImageIcon(bufferedImage);
	}

	public void clear() {
		map.clear();
	}

	/**
	 * evict the passed vertex from the cache so that it will be recomputed
	 * with presumably changed values
	 * @param vertex to remove from the cache
	 */
	public void evict(AttributedVertex vertex) {
		map.remove(vertex);
	}

	/**
	 * Sets the vertex label to the value of the passed attribute name
	 * @param attributeName the attribute key for the vertex label value to be displayed
	 */
	public void setPreferredVertexLabelAttribute(String attributeName) {
		this.preferredVeretxLabelAttribute = attributeName;
	}
}
