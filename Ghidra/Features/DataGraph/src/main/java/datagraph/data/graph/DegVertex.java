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
package datagraph.data.graph;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.util.Comparator;

import datagraph.graph.explore.EgVertex;
import docking.GenericHeader;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import ghidra.graph.viewer.vertex.VertexShapeProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;

/**
 * A vertex for the {@DataExorationGraph}
 */
public abstract class DegVertex extends EgVertex implements VertexShapeProvider,
		Comparator<DegVertex> {
	// enum for returning that status of a vertex when refreshing after a program change
	public enum DegVertexStatus {
		VALID,
		MISSING,
		CHANGED
	}

	protected DegController controller;

	/**
	 * Constructor
	 * @param controller the controller for the data exploration graph
	 * @param source the vertex that spawned this vertex. The original source vertex has no 
	 * parent source, but all the others must have a source which can be used to trace back
	 * to the original source vertex.
	 */
	public DegVertex(DegController controller, DegVertex source) {
		super(source);
		this.controller = controller;
	}

	@Override
	public boolean isGrabbable(Component component) {
		Component c = component;
		while (c != null) {
			if (c instanceof GenericHeader) {
				return true;
			}
			c = c.getParent();
		}
		return false;
	}

	/**
	 *{@return the program's address associated with this node.}
	 */
	public abstract Address getAddress();

	/**
	 *{@return the CodeUnit associated with this node.}
	 */
	public abstract CodeUnit getCodeUnit();

	/**
	 * {@return the tooltip for this vertex}
	 * @param e the the mouse even triggering this call
	 */
	public abstract String getTooltip(MouseEvent e);

	/**
	 * Checks if the given vertex is still valid after a program change.
	 * @param checkDataTypes if true, the underlying datatype should also be checked
	 * @return the status of the vertex. The vertex can be valid, changed, or missing.
	 */
	public abstract DegVertexStatus refreshGraph(boolean checkDataTypes);

	/**
	 * {@return the title of this vertex}
	 */
	public abstract String getTitle();

	/**
	 * {@return true if code unit associated with this vertex contains the given address.}
	 * @param address the address to check if it is at or in this vertex
	 */
	protected abstract boolean containsAddress(Address address);

	/**
	 * {@return the docking action with the given name from this vertex.}
	 * @param name the name of the action to retrieve
	 */
	public DockingActionIf getAction(String name) {
		return null;
	}

	/**
	 * Adds the given action to this vertex.
	 * @param action the action to add to this vertex
	 */
	protected abstract void addAction(DockingAction action);

}
