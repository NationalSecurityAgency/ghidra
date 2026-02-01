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

import java.util.Objects;

import javax.swing.JButton;

import functioncalls.plugin.FcgOptions;
import ghidra.base.graph.CircleWithLabelVertex;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

/**
 * A {@link FunctionCallGraph} vertex
 */
public class FcgVertex extends CircleWithLabelVertex {

	private Function function;
	private FcgLevel level;
	private FcgOptions options;

	private FcgVertexShapeProvider fcgShapeProvider;

	/**
	 * Constructor
	 *
	 * @param function the function represented by this vertex
	 * @param level the level of this vertex
	 * @param expansionListener the listener for expanding connections to this vertex
	 * @param options the tool options
	 */
	public FcgVertex(Function function, FcgLevel level,
			FcgVertexExpansionListener expansionListener, FcgOptions options) {
		super(function.getName());
		this.function = function;
		this.level = level;
		this.options = options;

		fcgShapeProvider = new FcgVertexShapeProvider(this, expansionListener);
		shapeProvider = fcgShapeProvider;

	}

	public Function getFunction() {
		return function;
	}

	public Address getAddress() {
		return function.getEntryPoint();
	}

	public FcgOptions getOptions() {
		return options;
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

	@Override
	public void setHovered(boolean hovered) {
		super.setHovered(hovered);
		fcgShapeProvider.setTogglesVisible(hovered);
	}

	public JButton getIncomingToggleButton() {
		return shapeProvider.getIncomingToggleButton();
	}

	public JButton getOutgoingToggleButton() {
		return shapeProvider.getOutgoingToggleButton();
	}

	/**
	 * Sets whether this vertex has any incoming references
	 *
	 * @param hasIncoming true if this vertex has any incoming references
	 */
	public void setHasIncomingReferences(boolean hasIncoming) {
		fcgShapeProvider.setHasIncomingReferences(hasIncoming);
	}

	/**
	 * Sets whether this vertex has any outgoing references
	 * @param hasOutgoing true if this vertex has any outgoing references
	 */
	public void setHasOutgoingReferences(boolean hasOutgoing) {
		fcgShapeProvider.setHasOutgoingReferences(hasOutgoing);
	}

	/**
	 * Sets whether this vertex has too many incoming references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @param tooMany if there are too many references
	 */
	public void setTooManyIncomingReferences(boolean tooMany) {
		fcgShapeProvider.setTooManyIncomingReferences(tooMany);
	}

	/**
	 * Sets whether this vertex has too many outgoing references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @param tooMany if there are too many references
	 */
	public void setTooManyOutgoingReferences(boolean tooMany) {
		fcgShapeProvider.setTooManyOutgoingReferences(tooMany);
	}

	/**
	 * Returns whether this vertex has too many incoming references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @return true if there are too many references
	 */
	public boolean hasTooManyIncomingReferences() {
		return fcgShapeProvider.hasTooManyIncomingReferences();
	}

	/**
	 * Returns whether this vertex has too many outgoing references, where too many is subjectively
	 * defined by this class.  Too many nodes in the display would ruin rendering and general
	 * usability.
	 *
	 * @return true if there are too many references
	 */
	public boolean hasTooManyOutgoingReferences() {
		return fcgShapeProvider.hasTooManyOutgoingReferences();
	}

	/**
	* Returns true if this vertex is showing all edges in the incoming direction
	*
	* @return true if this vertex is showing all edges in the incoming direction
	*/
	public boolean isIncomingExpanded() {
		return fcgShapeProvider.isIncomingExpanded();
	}

	/**
	 * Returns true if this vertex is showing all edges in the outgoing direction
	 *
	 * @return true if this vertex is showing all edges in the outgoing direction
	 */
	public boolean isOutgoingExpanded() {
		return fcgShapeProvider.isOutgoingExpanded();
	}

	/**
	 * Returns whether this vertex is fully expanded in its current direction
	 *
	 * @return whether this vertex is fully expanded in its current direction
	 */
	public boolean isExpanded() {
		return fcgShapeProvider.isExpanded();
	}

	/**
	 * Returns true if this vertex can expand itself in its current direction, or in either
	 * direction if this is a source vertex
	 *
	 * @return true if this vertex can be expanded
	 */
	public boolean canExpand() {
		return fcgShapeProvider.canExpand();
	}

	public boolean canExpandIncomingReferences() {
		return fcgShapeProvider.canExpandIncomingReferences();
	}

	public boolean canExpandOutgoingReferences() {
		return fcgShapeProvider.canExpandOutgoingReferences();
	}

	/**
	 * Sets to true if this vertex is showing all edges in the incoming direction
	 *
	 * @param setExpanded true if this vertex is showing all edges in the incoming direction
	 */
	public void setIncomingExpanded(boolean setExpanded) {
		fcgShapeProvider.setIncomingExpanded(setExpanded);
	}

	/**
	 * Sets to true if this vertex is showing all edges in the outgoing direction
	 *
	 * @param setExpanded true if this vertex is showing all edges in the outgoing direction
	 */
	public void setOutgoingExpanded(boolean setExpanded) {
		fcgShapeProvider.setOutgoingExpanded(setExpanded);
	}

	@Override
	public String toString() {
		return getName();// + " @ " + level; // + " (" + System.identityHashCode(this) + ')';
	}

	@Override
	public int hashCode() {
		return Objects.hash(function);
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
		this.function = null;
		super.dispose();
	}
}
