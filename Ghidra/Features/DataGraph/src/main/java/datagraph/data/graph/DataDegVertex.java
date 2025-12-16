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

import static datagraph.data.graph.DegVertex.DegVertexStatus.*;

import java.awt.Dimension;
import java.awt.Shape;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.util.List;
import java.util.Set;

import javax.swing.JComponent;

import datagraph.DataGraphPlugin;
import datagraph.data.graph.panel.DataVertexPanel;
import datagraph.data.graph.panel.model.row.DataRowObject;
import datagraph.graph.explore.EgVertex;
import docking.action.DockingAction;
import docking.action.DockingActionIf;
import docking.action.builder.ActionBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.util.HelpLocation;
import resources.Icons;

/**
 * A vertex in the data exploration graph for displaying the contents of a single data object.
 */
public class DataDegVertex extends DegVertex {

	private Data data;
	private DataVertexPanel dataVertexPanel;
	private DockingAction deleteAction;
	private long dataTypeHash;

	/**
	 * Constructor
	 * @param controller the controller
	 * @param data the Data object to be displayed by this vertex
	 * @param source the source vertex (from what vertex did you explore to get here)
	 * @param compactFormat determines if the row displays are in a compact format or an expanded
	 * format
	 */
	public DataDegVertex(DegController controller, Data data, DegVertex source,
			boolean compactFormat) {
		super(controller, source);
		this.data = data;
		dataVertexPanel = new DataVertexPanel(controller, this, compactFormat);
		createActions();
		dataVertexPanel.updateHeader();
		dataVertexPanel.updateShape();

		if (source == null) {
			dataVertexPanel.setIsRoot(true);
		}
		dataTypeHash = hash(data.getDataType());
	}

	@Override
	public String getTitle() {
		return dataVertexPanel.getTitle();
	}

	@Override
	public DegVertexStatus refreshGraph(boolean checkDataType) {
		Address address = data.getAddress();
		Data newData = data.getProgram().getListing().getDataAt(address);
		if (newData == null) {
			return MISSING;
		}
		if (data != newData) {
			this.data = newData;
			dataVertexPanel.setData(newData);
			return CHANGED;
		}

		if (checkDataType) {
			long newHash = hash(data.getDataType());
			if (newHash != dataTypeHash) {
				dataTypeHash = newHash;
				dataVertexPanel.setData(data);	// force the data model to reset
				return CHANGED;
			}
		}
		return VALID;
	}

	/**
	 * {@return a list of vertex row objects (currently only used for testing).}
	 */
	public List<DataRowObject> getRowObjects() {
		return dataVertexPanel.getRowObjects();
	}

	@Override
	public void clearUserChangedLocation() {
		super.clearUserChangedLocation();
		controller.relayoutGraph();
	}

	@Override
	public int hashCode() {
		return data.hashCode();
	}

	@Override
	public void setSource(EgVertex source) {
		super.setSource(source);
		dataVertexPanel.setIsRoot(source == null);
		deleteAction.setEnabled(source != null);
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
		DataDegVertex other = (DataDegVertex) obj;
		return data.equals(other.data);
	}

	@Override
	public JComponent getComponent() {
		return dataVertexPanel;
	}

	@Override
	public String toString() {
		return "Data @ " + data.getAddress().toString();
	}

	@Override
	public Address getAddress() {
		return data.getAddress();
	}

	@Override
	public CodeUnit getCodeUnit() {
		return data;
	}

	@Override
	protected void addAction(DockingAction action) {
		dataVertexPanel.addAction(action);
	}

	@Override
	public DockingActionIf getAction(String name) {
		return dataVertexPanel.getAction(name);
	}

	@Override
	public int getOutgoingEdgeOffsetFromCenter(EgVertex v) {
		return dataVertexPanel.getOutgoingEdgeOffsetFromCenter(v);
	}

	@Override
	public int getIncomingEdgeOffsetFromCenter(EgVertex vertex) {
		return dataVertexPanel.getIncommingEdgeOffsetFromCenter(vertex);
	}

	@Override
	public void setSelected(boolean selected) {
		super.setSelected(selected);
		dataVertexPanel.setSelected(selected);
	}

	@Override
	public void setFocused(boolean focused) {
		super.setFocused(focused);
		dataVertexPanel.setFocused(focused);
	}

	@Override
	public void dispose() {
		dataVertexPanel.dispose();
		dataVertexPanel = null;
	}

	@Override
	public Shape getCompactShape() {
		Shape shape = dataVertexPanel.getShape();
		return shape;
	}

	public Data getData() {
		return data;
	}

	public Dimension getSize() {
		return dataVertexPanel.getSize();
	}

	/**
	 * Sets the size of this vertex by the user.
	 * @param dimension the new size for this vertex;
	 */
	public void setSizeByUser(Dimension dimension) {
		dataVertexPanel.setSizeByUser(dimension);
	}

	/**
	 * Records the componentPath of the sub-data in this vertex that the edge going to
	 * the end vertex is associated with. Used to compute the y coordinate of the edge so that
	 * aligns with that data as the data is scrolled within the component.
	 * @param end the vertex that our outgoing edge to attached
	 * @param componentPath the component path of the sub data in this vertex associated with
	 * the edge going to the end vertex
	 */
	public void addOutgoingEdgeAnchor(DegVertex end, int[] componentPath) {
		dataVertexPanel.addOutgoingEdge(end, componentPath);
	}

	/**
	 * Records the Address of the sub-data in this vertex that the edge coming in
	 * from the start vertex is associated with. Used to compute the y coordinate of the edge so
	 * that it aligns with the sub-data as the data is scrolled within the component. For incoming
	 * edges, we only record edges that are offset from the data start. If the incoming edge points
	 * to the overall data object, the edge will always be attached to the top of the vertex
	 * regardless of the scroll position.
	 * 
	 * @param start the vertex that associated with an incoming edge
	 * @param address the address of the sub data in this vertex associated with
	 * the edge coming from the start vertex.
	 */
	public void addIncomingEdgeAnchor(DegVertex start, Address address) {
		dataVertexPanel.addIncommingEdge(start, address);
	}

	@Override
	public int compare(DegVertex v1, DegVertex v2) {
		// outgoing child vertices are ordered based on the paths of the data that references
		// them so that they are in the same order they appear in the referring structure datatype.
		return dataVertexPanel.comparePaths(v1, v2);
	}

	private void createActions() {
		String owner = DataGraphPlugin.class.getSimpleName();
		if (dataVertexPanel.isExpandable()) {
			DockingAction openAllAction = new ActionBuilder("Expand All", owner)
					.toolBarIcon(Icons.EXPAND_ALL_ICON)
					.description("Recursively open all data in this vertex.")
					.helpLocation(new HelpLocation("DataGraphPlugin", "Expand_All"))
					.onAction(c -> dataVertexPanel.expandAll())
					.build();
			addAction(openAllAction);
			DockingAction closeAllAction = new ActionBuilder("Collapse All", owner)
					.toolBarIcon(Icons.COLLAPSE_ALL_ICON)
					.description("Close all data in this vertex.")
					.helpLocation(new HelpLocation("DataGraphPlugin", "Collapse_All"))
					.onAction(c -> dataVertexPanel.collapseAll())
					.build();
			addAction(closeAllAction);
		}

		deleteAction = new ActionBuilder("Close Vertex", owner)
				.toolBarIcon(Icons.CLOSE_ICON)
				.description("Removes this vertex and any of its descendents from the graph.")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Delete_Vertex"))
				.enabled(source != null)
				.onAction(c -> controller.deleteVertices(Set.of(DataDegVertex.this)))
				.build();
		addAction(deleteAction);

	}

	@Override
	public String getTooltip(MouseEvent e) {
		return dataVertexPanel.getToolTipText(e);
	}

	@Override
	protected Point2D getStartingEdgePoint(EgVertex end) {
		Point2D startLocation = getLocation();

		// For the edge leaving this vertex going to the given end vertex, we need the 
		// starting point of the edge.
		//
		// We do this by starting with this vertex's location which is at the center point in
		// the vertex. We want the x coordinate to be on the right edge of the vertex, so we add in
		// half the width. We want the y coordinate to be wherever the corresponding data element
		// is being displayed, so we need to know how much above or below the center point
		// to draw the edge point to make it line up in the scrolled display.

		int yOffset = getOutgoingEdgeOffsetFromCenter(end);
		double x = startLocation.getX() + getSize().width / 2;
		double y = startLocation.getY() + yOffset;
		return new Point2D.Double(x, y);
	}

	@Override
	protected Point2D getEndingEdgePoint(EgVertex start) {
		Point2D endLocation = getLocation();

		// For the edge entering this vertex from the given start vertex, we need the 
		// ending point of the edge.
		//
		// We do this by starting with this vertex's location which is at the center point in
		// the vertex. We want the x coordinate to be on the left edge of the vertex, so we subtract
		// half the width. We want the y coordinate to be wherever the corresponding address of 
		// the reference is being displayed, so we need to know how much above or below the center
		// point to draw the edge point to make it line up in the scrolled display.

		int yOffset = getIncomingEdgeOffsetFromCenter(start);

		double x = endLocation.getX() - getSize().width / 2;
		double y = endLocation.getY() + yOffset;
		return new Point2D.Double(x, y);
	}

	/**
	 * Sets whether the column model should be a compact format or an expanded format. The basic
	 * difference is that expanded format includes a datatype for each row and the compact only
	 * shows a datatype if there is no value.
	 * @param b true to show a compact row, false to show more information.
	 */
	public void setCompactFormat(boolean b) {
		dataVertexPanel.setCompactFormat(b);
	}

	/**
	 * Opens the given data row to show its sub-data components.
	 * @param row the row to expand
	 */
	public void expand(int row) {
		dataVertexPanel.expand(row);
	}

	/**
	 * Adds a new vertex following the reference(s) coming out of the data component on the given
	 * row.
	 * @param row the row to open new vertices from
	 */
	public void openPointerReference(int row) {
		dataVertexPanel.openPointerReference(row);
	}

	/**
	 * {@return true if the selected row in the vertex is expandable.}
	 */
	public boolean isOnExpandableRow() {
		return dataVertexPanel.isSelectedRowExpandable();
	}

	/**
	 * Expands the selected row in the vertex recursively.
	 */
	public void expandSelectedRowRecursively() {
		dataVertexPanel.expandSelectedRowRecursively();
	}

	@Override
	protected boolean containsAddress(Address address) {
		return data.contains(address);
	}

	private long hash(DataType dataType) {
		long hash = dataType.getLength() * 31 + dataType.getName().hashCode();
		if (dataType instanceof Composite composite) {
			for (DataTypeComponent dataTypeComponent : composite.getDefinedComponents()) {
				hash = 31 * hash + hash(dataTypeComponent.getDataType());
			}
		}
		return hash;
	}

}
