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
import java.util.Objects;

import javax.swing.Icon;

import functioncalls.plugin.FcgOptions;
import functioncalls.plugin.FunctionCallGraphPlugin;
import generic.theme.GColor;
import generic.theme.Gui;
import ghidra.base.graph.CircleWithLabelVertexShapeProvider;
import ghidra.util.StringUtilities;
import resources.Icons;

/**
 * A vertex shape provider for the {@link FunctionCallGraphPlugin}.
 */
public class FcgVertexShapeProvider extends CircleWithLabelVertexShapeProvider {

	//@formatter:off
	private static final Color TOO_BIG_VERTEX_SHAPE_COLOR = new GColor("color.bg.plugin.fcg.vertex.toobig");
	//@formatter:on

	public static final Icon NOT_ALLOWED_ICON = Icons.ERROR_ICON;

	private FcgVertex vertex;

	private Paint inPaint;
	private Paint outPaint;

	// these values are set after construction from external sources
	private boolean hasIncomingReferences;
	private boolean hasOutgoingReferences;
	private boolean tooManyIncomingReferences;
	private boolean tooManyOutgoingReferences;

	public FcgVertexShapeProvider(FcgVertex vertex,
			FcgVertexExpansionListener expansionListener) {
		super(vertex.getName());
		this.vertex = vertex;

		Objects.requireNonNull(expansionListener);

		toggleInsButton.addActionListener(e -> {
			if (tooManyIncomingReferences) {
				return;
			}
			expansionListener.toggleIncomingVertices(vertex);
		});

		toggleOutsButton.addActionListener(e -> {
			if (tooManyOutgoingReferences) {
				return;
			}
			expansionListener.toggleOutgoingVertices(vertex);
		});

		buildUi();
		setTogglesVisible(false);
	}

	private void createPaints() {

		Color vertexShapeColor = getDefaultVertexShapeColor();

		Color lightColor = vertexShapeColor;
		Color darkColor = Gui.darker(vertexShapeColor);
		Color darkestColor = Gui.darker(darkColor);
		FcgLevel level = vertex.getLevel();
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

	@Override
	protected void buildUi() {
		if (vertex == null) {
			return; // still being constructed
		}
		createPaints();
		super.buildUi();
	}

	@Override
	protected String generateLabelText() {
		FcgOptions options = vertex.getOptions();
		boolean optionsUseTruncatedName = options.useTruncatedFunctionNames();
		String name = getName();
		if (optionsUseTruncatedName) {
			name = StringUtilities.trimMiddle(getName(), MAX_NAME_LENGTH);
		}
		return name;
	}

	@Override
	protected Paint getVertexShapePaint() {
		FcgLevel level = vertex.getLevel();
		FcgDirection direction = level.getDirection();
		if (direction.isSource()) {
			return getDefaultVertexShapeColor();
		}
		else if (direction.isIn()) {
			return inPaint;
		}
		else {
			return outPaint;
		}
	}

	@Override
	protected Color getDefaultVertexShapeColor() {

		if (isInDirection() && tooManyIncomingReferences) {
			return TOO_BIG_VERTEX_SHAPE_COLOR;
		}

		if (isOutDirection() && tooManyOutgoingReferences) {
			return TOO_BIG_VERTEX_SHAPE_COLOR;
		}

		return DEFAULT_VERTEX_SHAPE_COLOR;
	}

	private boolean isInDirection() {
		FcgLevel level = vertex.getLevel();
		FcgDirection direction = level.getDirection();
		boolean isIn = direction.isIn() || direction.isSource();
		return isIn;
	}

	private boolean isOutDirection() {
		FcgLevel level = vertex.getLevel();
		FcgDirection direction = level.getDirection();
		boolean isOut = direction.isOut() || direction.isSource();
		return isOut;
	}

	/**
	 * Sets to true if this vertex is showing all edges in the incoming direction
	 * @param setExpanded true if this vertex is showing all edges in the incoming direction
	 */
	@Override
	public void setIncomingExpanded(boolean setExpanded) {
		validateIncomingExpandedState(setExpanded);
		super.setIncomingExpanded(setExpanded);
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
	 * Sets to true if this vertex is showing all edges in the outgoing direction
	 * @param setExpanded true if this vertex is showing all edges in the outgoing direction
	 */
	@Override
	public void setOutgoingExpanded(boolean setExpanded) {
		validateOutgoingExpandedState(setExpanded);
		super.setOutgoingExpanded(setExpanded);
	}

	/**
	 * Returns whether this vertex is fully expanded in its current direction
	 * @return whether this vertex is fully expanded in its current direction
	 */
	@Override
	public boolean isExpanded() {
		FcgLevel level = vertex.getLevel();
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
	@Override
	public boolean canExpand() {
		FcgLevel level = vertex.getLevel();
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
	 * @param hasOutgoing true if this vertex has any outgoing references
	 */
	public void setHasOutgoingReferences(boolean hasOutgoing) {
		this.hasOutgoingReferences = hasOutgoing;
	}

	@Override
	public void setTogglesVisible(boolean visible) {

		boolean isIn = isInDirection();
		boolean turnOn = isIn && hasIncomingReferences && visible;
		toggleInsButton.setVisible(turnOn);

		boolean isOut = isOutDirection();
		turnOn = isOut && hasOutgoingReferences && visible;
		toggleOutsButton.setVisible(turnOn);
	}

}
