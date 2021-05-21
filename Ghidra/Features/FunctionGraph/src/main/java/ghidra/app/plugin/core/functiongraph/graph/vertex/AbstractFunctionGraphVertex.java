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
package ghidra.app.plugin.core.functiongraph.graph.vertex;

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import javax.swing.JButton;
import javax.swing.JComponent;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.util.viewer.listingpanel.ListingModel;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

public abstract class AbstractFunctionGraphVertex implements FGVertex {

	private FGController controller;
	private final Program program;
	private final AddressSetView addressSet;

	private Point2D location;
	private double emphasisLevel;
	private double alpha = 1D;

	private FGVertexType vertexType;
	private FlowType flowType;
	private boolean isEntry;

	private boolean doHashCode = true;
	private int hashCode;

	/**
	 * To be restored when the component for this vertex is created.
	 */
	protected Color pendingRestoreColor;

	private GroupHistoryInfo groupInfo;

	AbstractFunctionGraphVertex(FGController controller, Program program, AddressSetView addresses,
			FlowType flowType, boolean isEntry) {

		if (addresses == null || addresses.isEmpty()) {
			throw new IllegalArgumentException("Vertex cannot have null or empty address body");
		}

		this.controller = controller;
		this.program = program;
		this.addressSet = addresses;
		this.flowType = flowType;
		this.isEntry = isEntry;
		this.location = new Point2D.Double();
	}

	/* Copy constructor */
	AbstractFunctionGraphVertex(FGController controller, AbstractFunctionGraphVertex vertex) {
		this.controller = controller;
		this.program = vertex.program;
		this.addressSet = vertex.addressSet;
		this.location = vertex.location;
		this.vertexType = vertex.vertexType;
		this.isEntry = vertex.isEntry;
		this.flowType = vertex.flowType;
		this.groupInfo = vertex.groupInfo;
	}

	abstract boolean hasLoadedComponent();

	abstract AbstractGraphComponentPanel doGetComponent();

	@Override
	public void writeSettings(FunctionGraphVertexAttributes settings) {
		controller.saveVertexColors(this, settings);
	}

	@Override
	public void readSettings(FunctionGraphVertexAttributes settings) {
		controller.restoreVertexColors(this, settings);
	}

	@Override
	public void updateGroupAssociationStatus(GroupHistoryInfo newGroupInfo) {
		this.groupInfo = newGroupInfo;
		doGetComponent().updateGroupAssociationStatus(groupInfo != null);
	}

	@Override
	public GroupHistoryInfo getGroupInfo() {
		return groupInfo;
	}

	@Override
	public boolean isUncollapsedGroupMember() {
		if (groupInfo == null) {
			return false;
		}

		// we are an uncollapsed group member if we have a group info and we *are* in the graph
		// (not being in the graph means that we are inside of a group)
		return isInGraph();
	}

	private boolean isInGraph() {
		FGData graphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		return graph.containsVertex(this);
	}

	@Override
	public JComponent getComponent() {
		return doGetComponent();
	}

	public FGController getController() {
		return controller;
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public Address getVertexAddress() {
		return addressSet.getMinAddress();
	}

	@Override
	public AddressSetView getAddresses() {
		return addressSet;
	}

	@Override
	public boolean containsProgramLocation(ProgramLocation pl) {
		return addressSet.contains(pl.getAddress());
	}

	@Override
	public boolean containsAddress(Address address) {
		return addressSet.contains(address);
	}

	@Override
	public void setEmphasis(double emphasisLevel) {
		this.emphasisLevel = emphasisLevel;
	}

	@Override
	public double getEmphasis() {
		return emphasisLevel;
	}

	@Override
	public void setAlpha(double alpha) {
		this.alpha = alpha;
	}

	@Override
	public double getAlpha() {
		return alpha;
	}

	@Override
	public void setLocation(Point2D location) {
		this.location = location;
	}

	@Override
	public Point2D getLocation() {
		return location;
	}

	@Override
	public FGVertexType getVertexType() {
		return vertexType;
	}

	@Override
	public void setVertexType(FGVertexType vertexType) {
		if (this.vertexType != null) {
			throw new AssertException("Cannot set the vertex type more than once.  " +
				"Previous type was " + vertexType + " on vertex " + this);
		}

		this.vertexType = vertexType;
	}

	@Override
	public boolean isEntry() {
		// note: not sure if we need the second check; this check will catch any case where
		//       the vertex was manually marked as an entry
		return isEntry || (vertexType != null && vertexType.isEntry());
	}

	@Override
	public FlowType getFlowType() {
		return flowType;
	}

	@Override
	public int hashCode() {
		// code blocks don't overlap, so min address is sufficient for a good hash value
		if (doHashCode) {
			hashCode = addressSet.getMinAddress().hashCode();
			doHashCode = false;
		}

		return hashCode;
	}

	@Override
	public boolean equals(Object obj) {
		if (obj == null) {
			return false;
		}

		if (obj == this) {
			return true;
		}

		if (getClass() != obj.getClass()) {
			return false;
		}

		AbstractFunctionGraphVertex other = (AbstractFunctionGraphVertex) obj;
		Address minAddress = addressSet.getMinAddress();
		Address otherMinAddress = other.addressSet.getMinAddress();
		if (!SystemUtilities.isEqual(minAddress, otherMinAddress)) {
			return false;
		}

		Address maxAddress = addressSet.getMaxAddress();
		Address otherMaxAddress = other.addressSet.getMaxAddress();
		return SystemUtilities.isEqual(maxAddress, otherMaxAddress);
	}

	@Override
	public void dispose() {
		controller = null;
	}

//==================================================================================================
// GraphComponentPanel Delegate Methods
//==================================================================================================

	@Override
	public void restoreColor(Color color) {
		if (hasLoadedComponent()) {
			doGetComponent().restoreColor(color);
			return;
		}

		pendingRestoreColor = color;
	}

	@Override
	public Color getUserDefinedColor() {
		return doGetComponent().getUserDefinedColor();
	}

	@Override
	public Color getDefaultBackgroundColor() {
		return doGetComponent().getDefaultBackgroundColor();
	}

	@Override
	public Color getBackgroundColor() {
		return doGetComponent().getBackgroundColor();
	}

	@Override
	public Color getSelectionColor() {
		return doGetComponent().getSelectionColor();
	}

	@Override
	public void clearColor() {
		doGetComponent().clearColor();
	}

	@Override
	public String getTitle() {
		return doGetComponent().getTitle();
	}

	@Override
	public String getToolTipText(MouseEvent event) {
		return doGetComponent().getToolTipText(event);
	}

	@Override
	public JComponent getToolTipComponentForEdge(FGEdge edge) {
		return doGetComponent().getToolTipComponentForEdge(edge);
	}

	@Override
	public JComponent getToolTipComponentForVertex() {
		return doGetComponent().getToolTipComponentForVertex();
	}

	@Override
	public boolean isDefaultBackgroundColor() {
		return doGetComponent().isDefaultBackgroundColor();
	}

	@Override
	public Rectangle getBounds() {
		return doGetComponent().getBounds();
	}

	@Override
	public boolean isFullScreenMode() {
		return doGetComponent().isFullScreenMode();
	}

	@Override
	public void setFullScreenMode(boolean fullScreen) {
		doGetComponent().setFullScreenMode(fullScreen);
	}

	@Override
	public boolean isSelected() {
		return doGetComponent().isSelected();
	}

	@Override
	public void setSelected(boolean selected) {
		doGetComponent().setSelected(selected);
	}

	@Override
	public void setHovered(boolean hovered) {
		// we don't support this for now
	}

	@Override
	public boolean isHovered() {
		// we don't support this for now
		return false;
	}

	@Override
	public void editLabel(JComponent parentComponent) {
		doGetComponent().editLabel(parentComponent);
	}

	@Override
	public void setFocused(boolean focused) {
		AbstractGraphComponentPanel component = doGetComponent();
		component.setSelected(focused);
		component.setFocused(focused);
	}

	@Override
	public boolean isFocused() {
		AbstractGraphComponentPanel component = doGetComponent();
		return component.isFocused();
	}

	@Override
	public void setProgramSelection(ProgramSelection selection) {
		doGetComponent().setProgramSelection(selection);
	}

	@Override
	public ProgramSelection getProgramSelection() {
		return doGetComponent().getProgramSelection();
	}

	@Override
	public String getTextSelection() {
		return doGetComponent().getTextSelection();
	}

	@Override
	public void setProgramHighlight(ProgramSelection highlight) {
		doGetComponent().setProgramHighlight(highlight);
	}

	@Override
	public void setProgramLocation(ProgramLocation location) {
		doGetComponent().setProgramLocation(location);
	}

	@Override
	public ProgramLocation getProgramLocation() {
		return doGetComponent().getProgramLocation();
	}

	@Override
	public ListingModel getListingModel(Address address) {
		return doGetComponent().getListingModel(address);
	}

	@Override
	public Rectangle getCursorBounds() {
		return doGetComponent().getCursorBounds();
	}

	@Override
	public void setBackgroundColor(Color color) {
		doGetComponent().setBackgroundColor(color);
	}

	@Override
	public boolean isHeaderClick(Component clickedComponent) {
		return doGetComponent().isHeaderClick(clickedComponent);
	}

	@Override
	public boolean isGrabbable(Component c) {
		if (!doGetComponent().isHeaderClick(c)) {
			return false; // only the header is grabbable
		}

		// the user cannot grab buttons, as they can press them
		return !(c instanceof JButton);
	}

	@Override
	public String toString() {
		if (getController() == null || !hasLoadedComponent()) {
			// disposed!
			return getClass().getSimpleName() + "@" + getVertexAddress().toString();
		}

		return doGetComponent().getTitle();
	}

	@Override
	public void refreshModel() {
		doGetComponent().refreshModel();
	}

	@Override
	public void refreshDisplay() {
		doGetComponent().refreshDisplay();
	}

	@Override
	public void refreshDisplayForAddress(Address address) {
		doGetComponent().refreshDisplayForAddress(address);
	}

	@Override
	public void setShowing(boolean isShowing) {
		doGetComponent().setShowing(isShowing);
	}

	@Override
	public Component getMaximizedViewComponent() {
		return doGetComponent().getMaximizedViewComponent();
	}
}
