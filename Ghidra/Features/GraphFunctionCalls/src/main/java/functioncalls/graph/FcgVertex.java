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
package functioncalls.graph;

import java.awt.*;
import java.awt.geom.Area;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Ellipse2D.Double;
import java.awt.image.BufferedImage;
import java.util.Objects;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.LineBorder;

import docking.widgets.EmptyBorderButton;
import docking.widgets.label.GDLabel;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import ghidra.graph.viewer.vertex.VertexShapeProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.util.StringUtilities;
import resources.Icons;
import resources.ResourceManager;

/**
 * A {@link FunctionCallGraph} vertex
 */
public class FcgVertex extends AbstractVisualVertex implements VertexShapeProvider {

	// TODO to be made an option in an upcoming ticket
	public static final Color DEFAULT_VERTEX_SHAPE_COLOR = new Color(110, 197, 174);
	private static final Color TOO_BIG_VERTEX_SHAPE_COLOR = Color.LIGHT_GRAY;

	public static final Icon NOT_ALLOWED_ICON = Icons.ERROR_ICON;
	private static final Icon EXPAND_ICON =
		ResourceManager.getScaledIcon(Icons.EXPAND_ALL_ICON, 10, 10);
	private static final Icon COLLAPSE_ICON =
		ResourceManager.getScaledIcon(Icons.COLLAPSE_ALL_ICON, 10, 10);

	// higher numbered layers go on top	
	private static final Integer VERTEX_SHAPE_LAYER = new Integer(100);
	private static final Integer TOGGLE_BUTTON_LAYER = new Integer(200);
	private static final Integer LABEL_LAYER = new Integer(300);

	private static final int GAP = 2;
	private static final int VERTEX_SHAPE_SIZE = 50;

	// TODO to be made an option in an upcoming ticket
	// based upon the default function name, plus some extra 
	private static final int MAX_NAME_LENGTH = 30;

	private Function function;

	private JLayeredPane layeredPane;
	private JButton toggleInsButton = new EmptyBorderButton(EXPAND_ICON);
	private JButton toggleOutsButton = new EmptyBorderButton(EXPAND_ICON);
	private JLabel nameLabel = new GDLabel();
	private JLabel vertexImageLabel = new GDLabel();

	private Double vertexShape;
	private Double compactShape;
	private Shape fullShape;

	// these values are set after construction from external sources
	private boolean hasIncomingReferences;
	private boolean hasOutgoingReferences;
	private boolean tooManyIncomingReferences;
	private boolean tooManyOutgoingReferences;
	private boolean incomingExpanded;
	private boolean outgoingExpanded;

	// set this to true to see borders around the components of this vertex
	private boolean useDebugBorders = false;

	private Paint inPaint;
	private Paint outPaint;

	private FcgLevel level;

	/**
	 * Constructor
	 * 
	 * @param function the function represented by this vertex
	 * @param level the level of this vertex
	 * @param expansionListener the listener for expanding connections to this vertex
	 */
	public FcgVertex(Function function, FcgLevel level,
			FcgVertexExpansionListener expansionListener) {
		this.function = function;
		this.level = level;
		Objects.requireNonNull(expansionListener);

		toggleInsButton.addActionListener(e -> {
			if (tooManyIncomingReferences) {
				return;
			}
			expansionListener.toggleIncomingVertices(FcgVertex.this);
		});

		toggleOutsButton.addActionListener(e -> {
			if (tooManyOutgoingReferences) {
				return;
			}
			expansionListener.toggleOutgoingVertices(FcgVertex.this);
		});

		buildUi();

		setTogglesVisible(false);
	}

	private void createPaints() {

		Color vertexShapeColor = getVertexShapeColor();

		Color lightColor = vertexShapeColor;
		Color darkColor = vertexShapeColor.darker();
		Color darkestColor = darkColor.darker();
		int offset = 5 * level.getDistance();
		int half = VERTEX_SHAPE_SIZE / 2;
		int start = 0;
		int end = half + offset;

		// paint top-down: dark to light for incoming; light to dark for outgoing 
		inPaint = new LinearGradientPaint(new Point(0, start), new Point(0, end),
			new float[] { .0f, .2f, 1f }, new Color[] { darkestColor, darkColor, lightColor });

		start = half - offset; // (offset + 10);
		end = VERTEX_SHAPE_SIZE;
		outPaint = new LinearGradientPaint(new Point(0, start), new Point(0, end),
			new float[] { .0f, .8f, 1f }, new Color[] { lightColor, darkColor, darkestColor });
	}

	private void buildUi() {

		createPaints();

		// init the components
		String truncated = StringUtilities.trimMiddle(getName(), MAX_NAME_LENGTH);
		nameLabel.setText(truncated);
		buildVertexShape();

		// calculate the needed size
		layeredPane = new JLayeredPane();
		Border border = createDebugBorder(new LineBorder(Color.YELLOW.darker(), 1));
		layeredPane.setBorder(border);

		updateLayeredPaneSize();

		// layout the components
		addVertexShape();
		addToggleButtons();
		addNameLabel();

		buildFullShape();
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

		FcgDirection direction = level.getDirection();
		if (direction.isSource()) {
			g2.setColor(getVertexShapeColor());
		}
		else if (direction.isIn()) {
			g2.setPaint(inPaint);
		}
		else {
			g2.setPaint(outPaint);
		}

		g2.fill(circle);

		g2.dispose();

		vertexShape = circle;
		compactShape = (Double) vertexShape.clone();
		vertexImageLabel.setIcon(new ImageIcon(image));

		Border border = createDebugBorder(new LineBorder(Color.PINK, 1));
		vertexImageLabel.setBorder(border);
	}

	private Color getVertexShapeColor() {

		if (isInDirection() && tooManyIncomingReferences) {
			return TOO_BIG_VERTEX_SHAPE_COLOR;
		}

		if (isOutDirection() && tooManyOutgoingReferences) {
			return TOO_BIG_VERTEX_SHAPE_COLOR;
		}

		return DEFAULT_VERTEX_SHAPE_COLOR;
	}

	private boolean isInDirection() {
		FcgDirection direction = level.getDirection();
		boolean isIn = direction.isIn() || direction.isSource();
		return isIn;
	}

	private boolean isOutDirection() {
		FcgDirection direction = level.getDirection();
		boolean isOut = direction.isOut() || direction.isSource();
		return isOut;
	}

	private void addVertexShape() {

		Dimension parentSize = layeredPane.getPreferredSize();
		Dimension size = vertexImageLabel.getPreferredSize();

		// centered
		int x = (parentSize.width / 2) - (size.width / 2);
		int y = 0;

		vertexImageLabel.setBounds(x, y, size.width, size.height);
		Dimension shapeSize = vertexShape.getBounds().getSize();

		// setFrame() will make sure the shape's x,y values are where they need to be 
		// for the later 'full shape' creation		
		vertexShape.setFrame(x, y, shapeSize.width, shapeSize.height);
		layeredPane.add(vertexImageLabel, VERTEX_SHAPE_LAYER);
	}

	private void addNameLabel() {

		Border border = createDebugBorder(new LineBorder(Color.GREEN, 1));
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
		toggleInsButton.setBackground(new Color(255, 255, 255, 0));
		toggleOutsButton.setBackground(new Color(255, 255, 255, 0));

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
		return function.getName();
	}

	public Function getFunction() {
		return function;
	}

	public Address getAddress() {
		return function.getEntryPoint();
	}

	public FcgLevel getLevel() {
		return level;
	}

	public int getDegree() {
		return level.getRow();
	}

	public FcgDirection getDirection() {
		return level.getDirection();
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

		validateIncomingExpandedState(setExpanded);

		this.incomingExpanded = setExpanded;
		toggleInsButton.setIcon(setExpanded ? COLLAPSE_ICON : EXPAND_ICON);
		String hideShow = setExpanded ? "hide" : "show";
		toggleInsButton.setToolTipText("Click to " + hideShow + " incoming edges");
	}

	private void validateOutgoingExpandedState(boolean isExpanding) {
		if (isExpanding) {
			if (!canExpandOutgoingReferences()) {
				throw new IllegalStateException("Vertex cannot be expanded: " + this);
			}
			return;
		}

		// collapsing
		if (!isOutgoingExpanded()) {
			throw new IllegalStateException("Vertex cannot be collapsed: " + this);
		}
	}

	private void validateIncomingExpandedState(boolean expanding) {

		if (expanding) {
			if (!canExpandIncomingReferences()) {
				throw new IllegalStateException("Vertex cannot be expanded: " + this);
			}
			return;
		}

		// collapsing
		if (!isIncomingExpanded()) {
			throw new IllegalStateException("Vertex cannot be collapsed: " + this);
		}
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

		validateOutgoingExpandedState(setExpanded);

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
		FcgDirection direction = level.getDirection();
		if (direction.isSource()) {
			return isIncomingExpanded() && isOutgoingExpanded();
		}
		if (direction.isIn()) {
			return isIncomingExpanded();
		}
		return isOutgoingExpanded();
	}

	/**
	 * Sets whether this vertex has too many incoming references, where too many is subjectively 
	 * defined by this class.  Too many nodes in the display would ruin rendering and general 
	 * usability.
	 * 
	 * @param tooMany if there are too many references
	 */
	public void setTooManyIncomingReferences(boolean tooMany) {
		this.tooManyIncomingReferences = tooMany;
		toggleInsButton.setIcon(NOT_ALLOWED_ICON);
		toggleInsButton.setToolTipText("Too many incoming references to show");
		buildUi();
	}

	/**
	 * Sets whether this vertex has too many outgoing references, where too many is subjectively 
	 * defined by this class.  Too many nodes in the display would ruin rendering and general 
	 * usability.
	 * 
	 * @param tooMany if there are too many references
	 */
	public void setTooManyOutgoingReferences(boolean tooMany) {
		this.tooManyOutgoingReferences = tooMany;
		toggleOutsButton.setIcon(NOT_ALLOWED_ICON);
		toggleOutsButton.setToolTipText("Too many outgoing references to show");
		buildUi();
	}

	/**
	 * Returns whether this vertex has too many incoming references, where too many is subjectively 
	 * defined by this class.  Too many nodes in the display would ruin rendering and general 
	 * usability.
	 * 
	 * @return true if there are too many references
	 */
	public boolean hasTooManyIncomingReferences() {
		return tooManyIncomingReferences;
	}

	/**
	 * Returns whether this vertex has too many outgoing references, where too many is subjectively 
	 * defined by this class.  Too many nodes in the display would ruin rendering and general 
	 * usability.
	 * 
	 * @return true if there are too many references
	 */
	public boolean hasTooManyOutgoingReferences() {
		return tooManyOutgoingReferences;
	}

	/**
	 * Returns true if this vertex can expand itself in its current direction, or in either 
	 * direction if this is a source vertex
	 * 
	 * @return true if this vertex can be expanded
	 */
	public boolean canExpand() {
		FcgDirection direction = level.getDirection();
		if (direction.isSource()) {
			return canExpandIncomingReferences() || canExpandOutgoingReferences();
		}

		if (direction.isIn()) {
			return canExpandIncomingReferences();
		}

		return canExpandOutgoingReferences();
	}

	public boolean canExpandIncomingReferences() {
		return hasIncomingReferences && !tooManyIncomingReferences && !incomingExpanded;
	}

	public boolean canExpandOutgoingReferences() {
		return hasOutgoingReferences && !tooManyOutgoingReferences && !outgoingExpanded;
	}

	/**
	 * Sets whether this vertex has any incoming references
	 * 
	 * @param hasIncoming true if this vertex has any incoming references
	 */
	public void setHasIncomingReferences(boolean hasIncoming) {
		this.hasIncomingReferences = hasIncoming;
	}

	/**
	 * Sets whether this vertex has any outgoing references
	 * 
	 * @param hasIncoming true if this vertex has any incoming references
	 */

	public void setHasOutgoingReferences(boolean hasOutgoing) {
		this.hasOutgoingReferences = hasOutgoing;
	}

	@Override
	public void setHovered(boolean hovered) {
		super.setHovered(hovered);

		setTogglesVisible(hovered);
	}

	private void setTogglesVisible(boolean visible) {

		boolean isIn = isInDirection();
		boolean turnOn = isIn && hasIncomingReferences && visible;
		toggleInsButton.setVisible(turnOn);

		boolean isOut = isOutDirection();
		turnOn = isOut && hasOutgoingReferences && visible;
		toggleOutsButton.setVisible(turnOn);
	}

	@Override
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

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((function == null) ? 0 : function.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		FcgVertex other = (FcgVertex) obj;
		return Objects.equals(function, other.function);
	}

	@Override
	public void dispose() {
		// nothing to do
	}
}
