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
package ghidra.base.graph;

import java.awt.*;
import java.awt.geom.Area;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Ellipse2D.Double;
import java.awt.image.BufferedImage;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;

import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import generic.theme.GColor;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.graph.viewer.vertex.VertexShapeProvider;
import resources.Icons;
import resources.ResourceManager;

public class CircleWithLabelVertexShapeProvider implements VertexShapeProvider {

	//@formatter:off
	public static final Color DEFAULT_VERTEX_SHAPE_COLOR = new GColor("color.bg.graph.vertex.function");
	//@formatter:on

	protected static final Icon EXPAND_ICON =
		ResourceManager.getScaledIcon(Icons.EXPAND_ALL_ICON, 10, 10);
	protected static final Icon COLLAPSE_ICON =
		ResourceManager.getScaledIcon(Icons.COLLAPSE_ALL_ICON, 10, 10);

	// higher numbered layers go on top
	protected static final Integer VERTEX_SHAPE_LAYER = 100;
	protected static final Integer TOGGLE_BUTTON_LAYER = 200;
	protected static final Integer LABEL_LAYER = 300;

	protected static final int GAP = 2;
	protected static final int VERTEX_SHAPE_SIZE = 50;

	// Note: This should be made into an option
	// based upon the default function name, plus some extra
	protected static final int MAX_NAME_LENGTH = 30;

	protected JLayeredPane layeredPane;
	protected JButton toggleInsButton = new EmptyBorderButton(EXPAND_ICON);
	protected JButton toggleOutsButton = new EmptyBorderButton(EXPAND_ICON);
	protected JLabel nameLabel = new GDLabel();
	protected JLabel vertexImageLabel = new GDLabel();

	protected Double vertexShape;
	protected Double compactShape;
	protected Shape fullShape;

	protected boolean incomingExpanded;
	protected boolean outgoingExpanded;

	// set this to true to see borders around the components of this vertex
	protected boolean useDebugBorders = false;

	private String fullLabelText;
	private int circleCenterYOffset;

	public CircleWithLabelVertexShapeProvider(String label) {
		this.fullLabelText = label;
		buildUi();
	}

	public CircleWithLabelVertexShapeProvider(String label,
			VertexExpansionListener expansionListener) {
		this.fullLabelText = label;
		buildUi();
	}

	public int getCircleCenterYOffset() {
		return circleCenterYOffset;
	}

	protected void buildUi() {

		String name = generateLabelText();
		nameLabel.setText(name);
		buildVertexShape();

		// calculate the needed size
		layeredPane = new JLayeredPane();
		Border border = createDebugBorder(new LineBorder(Palette.GOLD, 1));
		layeredPane.setBorder(border);

		updateLayeredPaneSize();

		// layout the components
		addVertexShape();
		addToggleButtons();
		addNameLabel();

		buildFullShape();
	}

	protected String generateLabelText() {
		return fullLabelText;
	}

	private Border createDebugBorder(Border border) {
		if (useDebugBorders) {
			return border;
		}
		return BorderFactory.createEmptyBorder();
	}

	private void buildFullShape() {

		// Note: this method assumes all bounds have been set
		Area parent = new Area();

		Area v = new Area(vertexShape);
		Area name = new Area(nameLabel.getBounds());
		parent.add(v);
		parent.add(name);

		// for now, the buttons only appear on hover, but if we want to avoid clipping when
		// painting, we need to account for them in the shape's overall bounds
		Area in = new Area(toggleInsButton.getBounds());
		Area out = new Area(toggleOutsButton.getBounds());
		parent.add(in);
		parent.add(out);

		fullShape = parent;
	}

	private void updateLayeredPaneSize() {

		//
		// The overall component size is the total width and height of all components, with any
		// spacing between them.
		//

		Dimension shapeSize = vertexImageLabel.getPreferredSize();
		Dimension nameLabelSize = nameLabel.getPreferredSize();
		int height = shapeSize.height + GAP + nameLabelSize.height;

		Dimension insSize = toggleInsButton.getPreferredSize();
		Dimension outsSize = toggleOutsButton.getPreferredSize();
		int buttonWidth = Math.max(insSize.width, outsSize.width);
		int offset = buttonWidth / 3; // overlap the vertex shape

		int width = offset + shapeSize.width;
		width = Math.max(width, nameLabelSize.width);

		layeredPane.setPreferredSize(new Dimension(width, height));
	}

	private void buildVertexShape() {
		int w = VERTEX_SHAPE_SIZE;
		int h = VERTEX_SHAPE_SIZE;
		Double circle = new Ellipse2D.Double(0, 0, w, h);

		BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		Graphics2D g2 = (Graphics2D) image.getGraphics();
		g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

		g2.setPaint(getVertexShapePaint());

		g2.fill(circle);

		g2.dispose();

		vertexShape = circle;
		compactShape = (Double) vertexShape.clone();
		vertexImageLabel.setIcon(new ImageIcon(image));

		Border border = createDebugBorder(new LineBorder(Palette.PINK, 1));
		vertexImageLabel.setBorder(border);
	}

	protected Paint getVertexShapePaint() {
		return getDefaultVertexShapeColor();
	}

	protected Color getDefaultVertexShapeColor() {
		return DEFAULT_VERTEX_SHAPE_COLOR;
	}

	private void addVertexShape() {

		Dimension parentSize = layeredPane.getPreferredSize();
		Dimension size = vertexImageLabel.getPreferredSize();

		// centered
		int x = (parentSize.width / 2) - (size.width / 2);
		int y = 0;

		vertexImageLabel.setBounds(x, y, size.width, size.height);
		Dimension shapeSize = vertexShape.getBounds().getSize();
		circleCenterYOffset = shapeSize.height / 2 - parentSize.height / 2;

		// setFrame() will make sure the shape's x,y values are where they need to be
		// for the later 'full shape' creation
		vertexShape.setFrame(x, y, shapeSize.width, shapeSize.height);
		layeredPane.add(vertexImageLabel, VERTEX_SHAPE_LAYER);
	}

	private void addNameLabel() {

		Border border = createDebugBorder(new LineBorder(Palette.GREEN, 1));
		nameLabel.setBorder(border);

		// assume the vertex label has been bounded
		Rectangle parentBounds = vertexImageLabel.getBounds();
		Dimension size = nameLabel.getPreferredSize();

		// bottom, centered under the shape
		int x = (parentBounds.x + (parentBounds.width / 2)) - (size.width / 2);
		int y = parentBounds.y + parentBounds.height + GAP;
		nameLabel.setBounds(x, y, size.width, size.height);
		layeredPane.add(nameLabel, LABEL_LAYER);
	}

	private void addToggleButtons() {

		// hide the button background
		toggleInsButton.setBackground(Palette.NO_COLOR);
		toggleOutsButton.setBackground(Palette.NO_COLOR);

		// This is needed for Flat Dark theme to work correctly, due to the fact that it wants to
		// paint its parent background when the button is opaque.  The parent background will get
		// painted over any items that lie between the button and the parent.
		toggleInsButton.setOpaque(false);
		toggleOutsButton.setOpaque(false);

		Rectangle parentBounds = vertexImageLabel.getBounds();
		Dimension size = toggleInsButton.getPreferredSize();

		// upper toggle; upper-left
		int x = parentBounds.x - (size.width / 3);
		int y = 0;
		toggleInsButton.setBounds(x, y, size.width, size.height);
		layeredPane.add(toggleInsButton, TOGGLE_BUTTON_LAYER);

		// lower toggle; lower-left, lined-up with the vertex shape
		size = toggleOutsButton.getPreferredSize();
		Dimension vertexSize = parentBounds.getSize();
		y = vertexSize.height - size.height;
		toggleOutsButton.setBounds(x, y, size.width, size.height);
		layeredPane.add(toggleOutsButton, TOGGLE_BUTTON_LAYER);
	}

	public String getName() {
		return fullLabelText;
	}

	public JButton getIncomingToggleButton() {
		return toggleInsButton;
	}

	public JButton getOutgoingToggleButton() {
		return toggleOutsButton;
	}

	/**
	 * Sets to true if this vertex is showing all edges in the incoming direction
	 *
	 * @param setExpanded true if this vertex is showing all edges in the incoming direction
	 */
	public void setIncomingExpanded(boolean setExpanded) {
		this.incomingExpanded = setExpanded;
		toggleInsButton.setIcon(setExpanded ? COLLAPSE_ICON : EXPAND_ICON);
		String hideShow = setExpanded ? "hide" : "show";
		toggleInsButton.setToolTipText("Click to " + hideShow + " incoming edges");
	}

	/**
	 * Returns true if this vertex is showing all edges in the incoming direction
	 *
	 * @return true if this vertex is showing all edges in the incoming direction
	 */
	public boolean isIncomingExpanded() {
		return incomingExpanded;
	}

	/**
	 * Sets to true if this vertex is showing all edges in the outgoing direction
	 *
	 * @param setExpanded true if this vertex is showing all edges in the outgoing direction
	 */
	public void setOutgoingExpanded(boolean setExpanded) {
		this.outgoingExpanded = setExpanded;
		toggleOutsButton.setIcon(setExpanded ? COLLAPSE_ICON : EXPAND_ICON);
		String hideShow = setExpanded ? "hide" : "show";
		toggleInsButton.setToolTipText("Click to " + hideShow + " outgoing edges");
	}

	/**
	 * Returns true if this vertex is showing all edges in the outgoing direction
	 *
	 * @return true if this vertex is showing all edges in the outgoing direction
	 */
	public boolean isOutgoingExpanded() {
		return outgoingExpanded;
	}

	/**
	 * Returns whether this vertex is fully expanded in its current direction
	 *
	 * @return whether this vertex is fully expanded in its current direction
	 */
	public boolean isExpanded() {
		return isIncomingExpanded() && isOutgoingExpanded();
	}

	/**
	 * Returns true if this node can be expanded
	 * @return true if this node can be expanded
	 */
	public boolean canExpand() {
		return false; // subclasses can override
	}

	protected boolean hasIncomingEdges() {
		return false;
	}

	protected boolean hasOutgoingEdges() {
		return false;
	}

	public void setTogglesVisible(boolean visible) {
		toggleInsButton.setVisible(visible);
		toggleOutsButton.setVisible(visible);
	}

	public JComponent getComponent() {
		return layeredPane;
	}

	@Override
	public Shape getCompactShape() {
		return compactShape;
	}

	@Override
	public Shape getFullShape() {
		return fullShape;
	}

	@Override
	public String toString() {
		return getName();// + " @ " + level; // + " (" + System.identityHashCode(this) + ')';
	}

}
