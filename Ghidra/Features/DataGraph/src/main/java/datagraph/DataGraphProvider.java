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
package datagraph;

import java.awt.BorderLayout;
import java.awt.event.MouseEvent;
import java.util.Set;

import javax.swing.JComponent;
import javax.swing.JPanel;

import datagraph.data.graph.*;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.ToggleDockingAction;
import docking.action.builder.ActionBuilder;
import docking.action.builder.ToggleActionBuilder;
import generic.theme.GIcon;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.GraphComponent.SatellitePosition;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.HelpLocation;
import ghidra.util.exception.AssertException;
import resources.Icons;

/**
 * A {@link ComponentProvider} that is the UI component of the {@link DataGraphPlugin}.  This
 * shows a graph of a Data object in memory and its referenced objects.
 */
public class DataGraphProvider
		extends VisualGraphComponentProvider<DegVertex, DegEdge, DataExplorationGraph> {

	private static final GIcon DETAILS_ICON =
		new GIcon("icon.plugin.datagraph.action.viewer.vertex.format");
	private static final GIcon RESET_ICON = new GIcon("icon.plugin.datagraph.action.viewer.reset");
	private static final String NAME = "Data Graph";

	private AbstractDataGraphPlugin plugin;
	private JPanel mainPanel;

	private DegController controller;
	private ToggleDockingAction navagateInAction;
	private ToggleDockingAction navagateOutAction;
	private ToggleDockingAction expandedFormatAction;

	/**
	 * Constructor
	 * @param plugin the DataGraphPlugin
	 * @param data the initial data object to display in the graph.
	 */
	public DataGraphProvider(AbstractDataGraphPlugin plugin, Data data) {
		super(plugin.getTool(), NAME, plugin.getName());
		this.plugin = plugin;
		controller = new DegController(this, data);
		createActions();
		setTransient();

		buildComponent();
		addToTool();
		addSatelliteFeature(false, SatellitePosition.LOWER_LEFT);

		setHelpLocation(new HelpLocation("DataGraphPlugin", "DataGraphPlugin"));
	}

	private void buildComponent() {
		mainPanel = new JPanel(new BorderLayout());
		mainPanel.add(controller.getComponent());
	}

	@Override
	public VisualGraphView<DegVertex, DegEdge, DataExplorationGraph> getView() {
		return controller.getView();
	}

	@Override
	public ActionContext getActionContext(MouseEvent event) {
		Set<DegVertex> selectedVertices = getSelectedVertices();
		if (event == null) {
			return new DegContext(this, controller.getFocusedVertex(),
				selectedVertices);
		}
		Object source = event.getSource();
		if (source instanceof SatelliteGraphViewer) {
			return new DegSatelliteContext(this);
		}

		if (source instanceof GraphViewer) {
			@SuppressWarnings("unchecked")
			GraphViewer<DegVertex, DegEdge> viewer = (GraphViewer<DegVertex, DegEdge>) source;

			VertexMouseInfo<DegVertex, DegEdge> vertexMouseInfo =
				GraphViewerUtils.convertMouseEventToVertexMouseEvent(viewer, event);
			DegVertex target = vertexMouseInfo != null ? vertexMouseInfo.getVertex() : null;
			return new DegContext(this, target, selectedVertices, vertexMouseInfo);
		}
		throw new AssertException(
			"Received mouse event from unexpected source in getActionContext(): " + source);
	}

	@Override
	public void dispose() {
		plugin.removeProvider(this);
		controller.dispose();
		super.dispose();
		removeFromTool();
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}

	@Override
	public void closeComponent() {
		super.closeComponent();
		dispose();
	}

	public Program getProgram() {
		return controller.getProgram();
	}

	public DegController getController() {
		return controller;
	}

	private void createActions() {
		new ActionBuilder("Select Home Vertex", plugin.getName())
				.toolBarIcon(Icons.HOME_ICON)
				.toolBarGroup("A")
				.description("Selects and Centers Original Source Vertx")
				.onAction(c -> controller.selectAndCenterHomeVertex())
				.buildAndInstallLocal(this);

		new ActionBuilder("Relayout Graph", plugin.getName())
				.toolBarIcon(RESET_ICON)
				.toolBarGroup("A")
				.description("Erases all manual vertex positioning information")
				.onAction(c -> controller.resetAndRelayoutGraph())
				.buildAndInstallLocal(this);
		expandedFormatAction = new ToggleActionBuilder("Show Expanded Format", plugin.getName())
				.toolBarIcon(DETAILS_ICON)
				.toolBarGroup("A")
				.description("Show Expanded information in data vertices.")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Expanded_Format"))
				.onAction(c -> controller.setCompactFormat(!expandedFormatAction.isSelected()))
				.buildAndInstallLocal(this);

		navagateInAction =
			new ToggleActionBuilder("Navigate on Incoming Location Changes", plugin.getName())
					.sharedKeyBinding()
					.toolBarIcon(Icons.NAVIGATE_ON_INCOMING_EVENT_ICON)
					.toolBarGroup("B")
					.description("Attemps to select vertex corresponding to tool location changes.")
					.helpLocation(new HelpLocation("DataGraphPlugin", "Navigate_In"))
					.onAction(c -> controller.setNavigateIn(navagateInAction.isSelected()))
					.buildAndInstallLocal(this);

		// this name is same as SelectionNavigationAction which allows sharing of keybinding
		navagateOutAction = new ToggleActionBuilder("Selection Navigation Action", plugin.getName())
				.toolBarIcon(Icons.NAVIGATE_ON_OUTGOING_EVENT_ICON)
				.toolBarGroup("B")
				.sharedKeyBinding()
				.description(
					"Selecting vetices or locations inside a vertex sends navigates the tool.")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Navigate_Out"))
				.onAction(c -> controller.setNavigateOut(navagateOutAction.isSelected()))
				.selected(true)
				.buildAndInstallLocal(this);

		new ActionBuilder("Incoming References", plugin.getName())
				.popupMenuPath("Add All Incoming References")
				.popupMenuGroup("A", "2")
				.description("Show Vertices for known references to this vertex.")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Add Incoming"))
				.withContext(DegContext.class)
				.enabledWhen(c -> canShowReferences(c.getVertex()))
				.onAction(c -> controller.showAllIncommingReferences((DataDegVertex) c.getVertex()))
				.buildAndInstallLocal(this);

		new ActionBuilder("Outgoing References", plugin.getName())
				.popupMenuPath("Add All Outgoing References")
				.popupMenuGroup("A", "1")
				.description("Show Vertices for known references to this vertex.")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Add Outgoing"))
				.withContext(DegContext.class)
				.enabledWhen(c -> canShowReferences(c.getVertex()))
				.onAction(c -> controller.showAllOutgoingReferences((DataDegVertex) c.getVertex()))
				.buildAndInstallLocal(this);

		new ActionBuilder("Delete Vertices", plugin.getName())
				.popupMenuPath("Delete Selected Vertices")
				.popupMenuGroup("B", "1")
				.description("Removes the selected vertices and their descendents from the graph")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Delete_Selected"))
				.withContext(DegContext.class)
				.enabledWhen(c -> canClose(c.getSelectedVertices()))
				.onAction(c -> controller.deleteVertices(c.getSelectedVertices()))
				.buildAndInstallLocal(this);

		new ActionBuilder("Set Original Vertex", plugin.getName())
				.popupMenuPath("Set Vertex as Original Source")
				.popupMenuGroup("B", "2")
				.description("Reorient graph as though this was the first vertex shown")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Original_Source"))
				.withContext(DegContext.class)
				.enabledWhen(c -> canOrientGraphAround(c.getVertex()))
				.onAction(c -> controller.orientAround(c.getVertex()))
				.buildAndInstallLocal(this);

		new ActionBuilder("Reset Vertex Location", plugin.getName())
				.popupMenuPath("Restore Location")
				.popupMenuGroup("B", "3")
				.popupMenuIcon(Icons.REFRESH_ICON)
				.description("Resets the vertex to the automated layout location.")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Reset_Location"))
				.withContext(DegContext.class)
				.enabledWhen(c -> c.getVertex() != null && c.getVertex().hasUserChangedLocation())
				.onAction(c -> c.getVertex().clearUserChangedLocation())
				.buildAndInstallLocal(this);

		new ActionBuilder("Expand Fully", plugin.getName())
				.popupMenuPath("Expand Fully")
				.popupMenuGroup("C", "1")
				.description("Expand all levels under selected row")
				.helpLocation(new HelpLocation("DataGraphPlugin", "Expand_Fully"))
				.withContext(DegContext.class)
				.enabledWhen(this::canExpandRecursively)
				.onAction(this::expandRecursively)
				.buildAndInstallLocal(this);
	}

	private boolean canOrientGraphAround(DegVertex vertex) {
		if (vertex instanceof DataDegVertex) {
			return !vertex.isRoot();
		}
		return false;
	}

	private boolean canShowReferences(DegVertex vertex) {
		return vertex instanceof DataDegVertex;
	}

	private boolean canClose(Set<DegVertex> selectedVertices) {
		if (selectedVertices.isEmpty()) {
			return false;
		}
		if (selectedVertices.size() > 1) {
			return true;
		}

		// Special case for just one vertex selected. Can't delete the root vertex.
		DegVertex v = selectedVertices.iterator().next();
		return !v.isRoot();
	}

	void goTo(ProgramLocation location) {
		controller.locationChanged(location);
	}

	private boolean canExpandRecursively(DegContext context) {
		DegVertex vertex = context.getVertex();
		if (vertex instanceof DataDegVertex dataVertex) {
			return dataVertex.isOnExpandableRow();
		}
		return false;
	}

	private void expandRecursively(DegContext context) {
		DataDegVertex vertex = (DataDegVertex) context.getVertex();
		vertex.expandSelectedRowRecursively();
	}

	public void navigateOut(ProgramLocation location) {
		plugin.fireLocationEvent(location);

	}

}
