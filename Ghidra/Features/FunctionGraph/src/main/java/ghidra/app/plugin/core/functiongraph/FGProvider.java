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
package ghidra.app.plugin.core.functiongraph;

import java.awt.event.MouseEvent;
import java.util.*;
import java.util.function.Supplier;

import javax.swing.*;

import docking.*;
import docking.widgets.fieldpanel.FieldPanel;
import edu.uci.ics.jung.graph.Graph;
import generic.stl.Pair;
import ghidra.app.context.ListingActionContext;
import ghidra.app.nav.*;
import ghidra.app.plugin.core.functiongraph.action.*;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.services.*;
import ghidra.app.util.HighlightProvider;
import ghidra.framework.model.*;
import ghidra.framework.options.SaveState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.graph.VisualGraphComponentProvider;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.actions.VisualGraphContextMarker;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.options.RelayoutOption;
import ghidra.graph.viewer.options.ViewRestoreOption;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;
import ghidra.util.task.SwingUpdateManager;

public class FGProvider extends VisualGraphComponentProvider<FGVertex, FGEdge, FunctionGraph>
		implements Navigatable, DomainObjectListener {

	private static final String DISPLAY_POPUPS = "DISPLAY_POPUPS";

	private final PluginTool tool;
	private final FunctionGraphPlugin plugin;
	private FGController controller;

	private Program currentProgram;
	private ProgramLocation currentLocation;
	/** A location that will be set by an update manager */
	private ProgramLocation pendingLocation;
	private ProgramSelection currentProgramSelection;
	private ProgramSelection currentProgramHighlight;

	/**
	 * A construct that allows tests to control the notion of whether this provider has focus
	 */
	private Supplier<Boolean> focusStatusDelegate = () -> super.isFocusedProvider();

	private DecoratorPanel decorationPanel;
	private String disconnectedName;

	private SwingUpdateManager rebuildGraphUpdateManager;
	private SwingUpdateManager updateLocationUpdateManager;

	private ClipboardService clipboardService;
	private FGClipboardProvider clipboardProvider;
	private FGActionManager actionManager;

	// Navigatable Fields
	private WeakSet<NavigatableRemovalListener> navigationListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();
	private boolean isConnected;
	private ImageIcon navigatableIcon;
	// End Navigatable Fields

	private boolean disposed = false;

	public FGProvider(FunctionGraphPlugin plugin, boolean isConnected) {
		super(plugin.getTool(), FunctionGraphPlugin.FUNCTION_GRAPH_NAME, plugin.getName(),
			ListingActionContext.class);

		this.tool = plugin.getTool();
		this.plugin = plugin;
		controller = new FGController(this, plugin);

		setConnected(isConnected);
		setIcon(FunctionGraphPlugin.ICON);
		if (!isConnected) {
			setTransient();
		}
		else {
			addToToolbar();
		}

		decorationPanel = new DecoratorPanel(controller.getViewComponent(), isConnected);
		setWindowMenuGroup(FunctionGraphPlugin.FUNCTION_GRAPH_NAME);
		setWindowGroup(FunctionGraphPlugin.FUNCTION_GRAPH_NAME);
		setDefaultWindowPosition(WindowPosition.WINDOW);

		setHelpLocation(new HelpLocation("FunctionGraphPlugin", "FunctionGraphPlugin"));

		addToTool();
		addSatelliteFeature(); // must be after addToTool();

		actionManager = new FGActionManager(plugin, controller, this);

		rebuildGraphUpdateManager =
			new SwingUpdateManager(1000, 10000, () -> refreshAndKeepPerspective());

		updateLocationUpdateManager =
			new SwingUpdateManager(250, 750, () -> setPendingLocationFromUpdateManager());

		clipboardProvider = new FGClipboardProvider(tool, controller);
		ClipboardService service = tool.getService(ClipboardService.class);
		setClipboardService(service);
	}

	@Override
	public boolean isSnapshot() {
		// we are a snapshot when we are 'disconnected' 
		return !isConnected();
	}

	public void setClipboardService(ClipboardService service) {
		clipboardService = service;
		if (clipboardService != null) {
			clipboardService.registerClipboardContentProvider(clipboardProvider);
		}
	}

	FGController getController() {
		return controller;
	}

	Program getCurrentProgram() {
		return currentProgram;
	}

	ProgramLocation getCurrentLocation() {
		return currentLocation;
	}

	ProgramSelection getCurrentProgramSelection() {
		return currentProgramSelection;
	}

	ProgramSelection getCurrentProgramHighlight() {
		return currentProgramHighlight;
	}

	FGActionManager getActionManager() {
		return actionManager;
	}

	AddressSet getAddressesFromHoveredVertices() {
		AddressSet addresses = new AddressSet();
		FGData functionGraphData = controller.getFunctionGraphData();
		if (!functionGraphData.hasResults()) {
			return addresses;
		}

		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> hoveredVertices = GraphViewerUtils.getVerticesOfHoveredEdges(graph);
		for (FGVertex vertex : hoveredVertices) {
			addresses.add(vertex.getAddresses());
		}
		return addresses;
	}

	private AddressSet getAddressesForSelectedVertices() {
		if (currentProgram == null) {
			return new AddressSet();
		}

		AddressSet addresses = new AddressSet();
		FGData functionGraphData = controller.getFunctionGraphData();
		if (!functionGraphData.hasResults()) {
			return addresses;
		}

		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> selectedVertices = GraphViewerUtils.getVerticesOfSelectedEdges(graph);
		for (FGVertex vertex : selectedVertices) {
			addresses.add(vertex.getAddresses());
		}
		return addresses;
	}

	void cloneWindow() {
		FGProvider newProvider = plugin.createNewDisconnectedProvider();
		Swing.runLater(() -> {
			newProvider.doSetProgram(currentProgram);

			FGData currentData = controller.getFunctionGraphData();

			SaveState state = new SaveState();
			writeConfigState(state);

			newProvider.readConfigState(state);

			FGController newController = newProvider.controller;
			FGData newData = FunctionGraphFactory.createClonedGraph(currentData, newController);
			newController.setFunctionGraphData(newData);
			newProvider.setLocationNow(currentLocation);
			newProvider.setGraphPerspective(controller.getGraphPerspective(currentLocation));
		});
	}

	private void setGraphPerspective(GraphPerspectiveInfo<FGVertex, FGEdge> info) {
		controller.setGraphPerspective(info);
	}

	private boolean arePopupsVisible() {
		return controller.arePopupsEnabled();
	}

	public void setPopupsVisible(boolean visible) {
		actionManager.popupVisibilityChanged(visible);
	}

	/**
	 * Gives to the clipboard of this provider the given string.  This will prime the clipboard
	 * such that a copy action will copy the given string.
	 * 
	 * @param string the string to set
	 */
	public void setClipboardStringContent(String string) {
		clipboardProvider.setStringContent(string);
	}

	public void saveLocationToHistory() {
		NavigationHistoryService historyService = tool.getService(NavigationHistoryService.class);
		historyService.addNewLocation(this);
	}

	@Override
	public VisualGraphView<FGVertex, FGEdge, FunctionGraph> getView() {
		return controller.getView();
	}

	@Override
	public PluginTool getTool() {
		return plugin.getTool();
	}

	@SuppressWarnings("unchecked")
	@Override
	public ActionContext getActionContext(MouseEvent event) {
		if (currentProgram == null) {
			return null;
		}

		if (controller.getGraphedFunction() == null) {
			return new FunctionGraphEmptyGraphActionContext(this);
		}

		if (event == null) { // keybinding/menu/toolbar (no popup)
			return createKeybindingContext();
		}

		Object source = event.getSource();
		if (source instanceof SatelliteGraphViewer) {
			// we may want to change the actions over the satellite in the future
			return new FunctionGraphSatelliteViewerActionContext(this);
		}
		else if (source instanceof VisualGraphContextMarker) {
			return new FunctionGraphValidGraphActionContext(this, new HashSet<FGVertex>());
		}

		// handle the 'full vertex zoom' case, where only one vertex is in the view (not graph mode)
		if (source instanceof FieldPanel) {
			FGVertex vertex = controller.getFocusedVertex();
			return new FunctionGraphVertexLocationInFullViewModeActionContext(this, vertex);
		}

		if (source instanceof GraphViewer) {
			GraphViewer<FGVertex, FGEdge> viewer = (GraphViewer<FGVertex, FGEdge>) source;

			Set<FGVertex> selectedVertices = getSelectedVertices();
			VertexMouseInfo<FGVertex, FGEdge> vertexMouseInfo =
				GraphViewerUtils.convertMouseEventToVertexMouseEvent(viewer, event);
			if (vertexMouseInfo == null) {
				return new FunctionGraphValidGraphActionContext(this, selectedVertices);
			}

			FGVertex vertexAtPoint = vertexMouseInfo.getVertex();
			VertexActionContextInfo vertexInfo = createContexInfo(vertexAtPoint);
			if (controller.isScaledPastInteractionThreshold() || vertexMouseInfo.isGrabArea()) {
				return new FunctionGraphUneditableVertexLocationActionContext(this, vertexInfo);
			}

			FGVertex vertex = vertexInfo.getActiveVertex();
			if (vertex instanceof GroupedFunctionGraphVertex) {
				return new FunctionGraphUneditableVertexLocationActionContext(this, vertexInfo);
			}

			if (selectedVertices.size() > 1) {
				return new FunctionGraphUneditableVertexLocationActionContext(this, vertexInfo);
			}

			return new FunctionGraphEditableVertexLocationActionContext(this, vertexInfo);
		}

		throw new AssertException(
			"Received mouse event from unexpected source in getActionContext(): " + source);
	}

	private ActionContext createKeybindingContext() {
		boolean isPastInteractionThreshold = controller.isScaledPastInteractionThreshold();
		FGVertex vertex = controller.getFocusedVertex();
		if (vertex == null || isPastInteractionThreshold) {
			return new FunctionGraphValidGraphActionContext(this, getSelectedVertices());
		}

		VertexActionContextInfo vertexInfo = createContexInfo(vertex);
		return new FunctionGraphEditableVertexLocationActionContext(this, vertexInfo);
	}

	private VertexActionContextInfo createContexInfo(FGVertex vertex) {
		AddressSet hoveredVerticesAddresses = getAddressesFromHoveredVertices();
		AddressSet selectedVerticesAddresses = getAddressesForSelectedVertices();
		Set<FGVertex> selectedVertices = getSelectedVertices();
		return new VertexActionContextInfo(vertex, selectedVertices, hoveredVerticesAddresses,
			selectedVerticesAddresses);
	}

	@Override
	public JComponent getComponent() {
		return decorationPanel;
	}

	/**
	 * Called to signal to this provider that it should update its state due to a new function
	 * being graphed.  The UI is updated by the controller without this provider's knowledge. 
	 * This call here is to signal that the provider needs to update its metadata.
	 */
	public void functionGraphDataChanged() {
		updateTitle();
		notifyContextChanged();
		setStatusInfo(""); // this seems odd here--why clear the status?
	}

	private void updateTitle() {
		Pair<String, String> result = getTitleFromGraphData("Function Graph");
		String title = result.first;
		String subTitle = result.second;

		if (!isConnected()) {
			title = "[" + title + "]";
		}

		setTitle(title);
		setSubTitle(subTitle);
	}

	private Pair<String, String> getTitleFromGraphData(String title) {

		FGData graphData = controller.getFunctionGraphData();
		Pair<String, String> result = new Pair<>(title, "");
		if (graphData == null) {
			return result;
		}

		Function function = graphData.getFunction();
		if (function == null) {
			return result;
		}

		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		String first = "Function Graph";

		String programName =
			(currentProgram != null) ? currentProgram.getDomainFile().getName() : "";
		String second = function.getName() + " - " + graph.getVertexCount() + " vertices  (" +
			programName + ")";

		return new Pair<>(first, second);
	}

	void doSetProgram(Program newProgram) {
		controller.clear();
		clipboardProvider.setProgram(newProgram);
		if (currentProgram != null) {
			currentProgram.removeListener(this);
		}
		currentProgram = newProgram;
		if (currentProgram != null) {
			currentProgram.addListener(this);
		}
	}

	/**
	 * Called from within the FunctionGraph when locations are changed (e.g., if a user clicks
	 * inside of a vertex)
	 * 
	 * @param newLocation the new location 
	 */
	public void graphLocationChanged(ProgramLocation newLocation) {
		storeLocation(newLocation);

		if (isFocusedProvider()) {

			// Note: this is the easy way to avoid odd event bouncing--only send events out if 
			//       we are focused, as this implies the user is driving the events.  A better
			//       metaphor for handling external and internal program locations is needed to
			//       simplify the logic of when to broadcast location changes.
			notifyLocationChanged(newLocation);
		}

		notifyContextChanged();
	}

	/**
	 * Called from within the FunctionGraph when selections are changed (e.g., if a user clicks
	 * inside of a vertex)
	 * 
	 * @param selection the new selection 
	 */
	public void graphSelectionChanged(ProgramSelection selection) {
		storeSelection(selection);
		notifySelectionChanged(selection);
	}

	private void storeSelection(ProgramSelection selection) {
		currentProgramSelection = selection;
		clipboardProvider.setSelection(selection);
		notifyContextChanged();
	}

	private void storeLocation(ProgramLocation location) {
		currentLocation = location;
		clipboardProvider.setLocation(location);
	}

	private void notifyLocationChanged(ProgramLocation location) {
		plugin.handleProviderLocationChanged(this, location);
	}

	private void notifySelectionChanged(ProgramSelection selection) {
		plugin.handleProviderSelectionChanged(this, selection);
	}

	private void notifyHighlightChanged(ProgramSelection selection) {
		plugin.handleProviderHighlightChanged(this, selection);
	}

	private void notifyContextChanged() {
		tool.contextChanged(this);
	}

	void programClosed(Program program) {
		storeLocation(null);
		controller.clear();
		controller.programClosed(program);
	}

	/**
	 * Called when for location changes that are <b>external</b> to the function graph (e.g., 
	 * when the user clicks in Ghidra's Listing window)
	 * 
	 * @param newLocation the new location 
	 */
	void setLocation(ProgramLocation newLocation) {
		pendingLocation = newLocation;
		updateLocationUpdateManager.update();
	}

	private void setPendingLocationFromUpdateManager() {
		if (pendingLocation == null) {
			return;
		}

		ProgramLocation newLocation = pendingLocation;
		pendingLocation = null;
		if (SystemUtilities.isEqual(currentLocation, newLocation)) {
			return;
		}

		setLocationNow(newLocation);
	}

	private void setLocationNow(ProgramLocation newLocation) {
		if (newLocation == null) {
			return;
		}

		if (SystemUtilities.isEqual(currentLocation, newLocation)) {
			return;
		}

		storeLocation(newLocation);
		displayLocation(newLocation);
		notifyContextChanged();
	}

	void displayLocation(ProgramLocation newLocation) {
		Address newAddress = newLocation != null ? newLocation.getAddress() : null;
		if (isVisible() && newAddress != null) {
			controller.display(currentProgram, newLocation);
		}
	}

	/**
	 * Tells this provider to refresh, which means to rebuild the graph and relayout the 
	 * vertices.
	 */
	private void refresh(boolean keepPerspective) {
		FGData functionGraphData = controller.getFunctionGraphData();
		if (functionGraphData.hasResults()) {
			//
			// We use the graph's data over the 'currentXXX' data, as there is a chance that the
			// latter values have been set to new values, while the graph has differing data.  In
			// that case we have made the decision to prefer the graph's data.
			//
			Function function = functionGraphData.getFunction();
			Address address = function.getEntryPoint();
			Address currentAddress = currentLocation.getAddress();
			if (function.getBody().contains(currentAddress)) {
				// prefer the current address if it is within the current function (i.e., the 
				// location hasn't changed out from under the graph due to threading issues)
				address = currentAddress;
			}

			Program program = function.getProgram();
			ProgramLocation programLocation = new ProgramLocation(program, address);
			controller.rebuildDisplay(program, programLocation, keepPerspective);
			return;
		}

		controller.rebuildDisplay(currentProgram, currentLocation, keepPerspective);
	}

	/**
	 * Rebuilds the graph and restores the zoom and location of the graph to the values prior
	 * to rebuilding.
	 */
	public void refreshAndKeepPerspective() {
		refresh(true);
	}

	/**
	 * Rebuilds the graph <b>and</b> will zoom the graph such that it fits on the screen and
	 * is centered.
	 */
	public void refreshAndResetPerspective() {
		refresh(false);
	}

	/**
	 * Tells the graph that some display data may have changed, but the changes are not worth 
	 * performing a full rebuild
	 */
	public void refreshDisplayWithoutRebuilding() {
		FGData functionGraphData = controller.getFunctionGraphData();
		if (functionGraphData.hasResults()) {
			controller.refreshDisplayWithoutRebuilding();
		}
	}

	public void optionsChanged() {
		controller.optionsChanged();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (!isVisible()) {
			return;
		}

		if (controller.getGraphedFunction() == null) {
			return;
		}

		boolean graphChangedButNotRebuilt = false;
		boolean rebuildGraphOnChanges = isPerformingGraphRebuildOnDataChanges();

		//
		// Note: since we are not looping and we are using 'else if's, order is important!
		// 

		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED) ||
			ev.containsEvent(ChangeManager.DOCR_FUNCTION_BODY_CHANGED)) {
			if (graphDataMissing()) {
				controller.clear();
				return; // something really destructive has happened--give up!
			}

			graphChangedButNotRebuilt = !handleObjectRestored(ev, rebuildGraphOnChanges);
		}
		else if (ev.containsEvent(ChangeManager.DOCR_SYMBOL_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_SYMBOL_REMOVED)) {

			if (currentGraphContainsEventAddress(ev)) {
				graphChangedButNotRebuilt = !handleSymbolAddedRemoved(ev, rebuildGraphOnChanges);
			}
		}
		else if (ev.containsEvent(ChangeManager.DOCR_MEM_REFERENCE_ADDED) ||
			ev.containsEvent(ChangeManager.DOCR_MEM_REFERENCE_REMOVED)) {

			if (currentGraphContainsReferenceChangedEvent(ev)) {
				graphChangedButNotRebuilt = !handleReferenceAddedRemoved(ev, rebuildGraphOnChanges);
			}
		}
		else if (ev.containsEvent(ChangeManager.DOCR_SYMBOL_RENAMED)) {
			handleSymbolRenamed(ev);
		}

		if (graphChangedButNotRebuilt) {
			updateGraphForAffectedAddresses(ev);
		}

		// force a repaint for any type of event to make sure we are up-to-date, even for events
		// we are not directly interested in.
		controller.repaint();
	}

	/**
	 * Returns true when something destructive has happened to the data upon which the graph
	 * has created, like a memory block move.
	 */
	private boolean graphDataMissing() {
		FGData data = controller.getFunctionGraphData();
		if (!data.hasResults()) {
			return true;
		}

		FunctionGraph functionGraph = data.getFunctionGraph();
		FGVertex rootVertex = functionGraph.getRootVertex();
		if (rootVertex == null) {
			return true; // this can happen in bad state with undo/redo...not sure how
		}

		AddressSetView addresses = rootVertex.getAddresses();
		FunctionManager functionManager = currentProgram.getFunctionManager();
		Function currentFunctionInMemory = functionManager.getFunctionAt(addresses.getMinAddress());
		return currentFunctionInMemory == null;
	}

	private void updateGraphForAffectedAddresses(DomainObjectChangedEvent ev) {
		if (ev.containsEvent(DomainObject.DO_OBJECT_RESTORED)) {
			controller.invalidateAllCacheForProgram(currentProgram);
			return;
		}

		AddressSet addresses = new AddressSet();

		Iterator<DomainObjectChangeRecord> iterator = ev.iterator();
		while (iterator.hasNext()) {
			DomainObjectChangeRecord record = iterator.next();
			if (record instanceof ProgramChangeRecord) {
				ProgramChangeRecord programRecord = (ProgramChangeRecord) record;
				Address start = programRecord.getStart();
				Address end = programRecord.getEnd();

				if (start != null && end != null) {
					addresses.addRange(start, end);
				}
			}
		}

		controller.invalidateCacheForAddresses(addresses);
	}

	private boolean handleObjectRestored(DomainObjectChangedEvent ev, boolean isRebuildingGraph) {
		if (isRebuildingGraph) {
			rebuildGraphUpdateManager.updateLater();
			return true;
		}

		controller.refreshDisplayWithoutRebuilding();
		return false;
	}

	private boolean handleReferenceAddedRemoved(DomainObjectChangedEvent ev,
			boolean isRebuildingGraph) {
		if (isRebuildingGraph) {
			rebuildGraphUpdateManager.updateLater();
			return true;
		}

		//
		// Do we need to modify the affected vertex?
		//
		for (DomainObjectChangeRecord record : ev) {
			int eventType = record.getEventType();
			if (eventType == ChangeManager.DOCR_MEM_REFERENCE_ADDED) {
				handleReferenceAdded(record);
			}
			else if (eventType == ChangeManager.DOCR_MEM_REFERENCE_REMOVED) {
				handleReferenceRemoved(record);
			}
		}

		return false;
	}

	private void handleReferenceRemoved(DomainObjectChangeRecord record) {
		// 
		// Get the affected vertex (if any).  Determine if we have to combine the vertex with
		// the vertex below it (adding a reference creates a new basic block, which creates a new
		// vertex--we may need to reverse that process)
		//
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Reference reference = (Reference) record.getOldValue();
		Address toAddress = reference.getToAddress();
		FGVertex destinationVertex = functionGraph.getVertexForAddress(toAddress);
		if (destinationVertex == null) {
			return; // this particular removal doesn't affect our graph
		}

		// 
		// How do we know if we can combine this vertex with its parent?  Well, we have some
		// tests that must hold true:
		// -There must be only a fallthrough edge to the affected vertex
		// -The parent vertex must have only one flow--FallThrough
		// -There must not be any other references to the entry of the vertex
		// -There must not be any non-dynamic labels on the vertex
		//
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGEdge> inEdgesForDestination = graph.getInEdges(destinationVertex);
		if (inEdgesForDestination.size() == 0) {
			// must be in a dirty state with vertices and edges that don't match reality
			return;
		}

		if (inEdgesForDestination.size() > 1) {
			return;
		}

		FGEdge incomingEdge = inEdgesForDestination.iterator().next();
		FGVertex parentVertex = incomingEdge.getStart();
		Collection<FGEdge> outEdges = graph.getOutEdges(parentVertex);
		if (outEdges.size() > 1) {
			return;
		}

		FlowType flowType = incomingEdge.getFlowType();
		if (!flowType.isFallthrough()) {
			return;
		}

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		AddressSetView vertexAddresses = destinationVertex.getAddresses();
		Address minAddress = vertexAddresses.getMinAddress();

		Symbol primary = symbolTable.getPrimarySymbol(minAddress);
		// if there is a symbol, then the block should not be merged
		if (primary == null) {
			controller.mergeVertexWithParent(destinationVertex);
		}
	}

	private void handleReferenceAdded(DomainObjectChangeRecord record) {

		// 
		// Get the affected vertex (if any).  Determine if we have to split the vertex.
		//
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Reference reference = (Reference) record.getNewValue();
		Address toAddress = reference.getToAddress();
		FGVertex destinationVertex = functionGraph.getVertexForAddress(toAddress);
		if (destinationVertex == null) {
			return; // this particular removal doesn't affect our graph
		}

		// 
		// How do we know if we need to split this vertex?  Well, we have some
		// tests that must hold true:
		// -The 'to' address for the reference must not be to the minimum address for that vertex		
		//
		AddressSetView addresses = destinationVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();
		if (toAddress.equals(minAddress)) {
			return; // the 'to' is not in the middle of the code block--no need to split
		}

		controller.splitVertex(destinationVertex, toAddress);
	}

	private boolean handleSymbolAddedRemoved(DomainObjectChangedEvent ev,
			boolean isRebuildingGraph) {
		if (isRebuildingGraph) {
			rebuildGraphUpdateManager.updateLater();
			return true;
		}

		//
		// Do we need to modify the affected vertex?
		//
		for (DomainObjectChangeRecord record : ev) {
			int eventType = record.getEventType();
			if (eventType == ChangeManager.DOCR_SYMBOL_ADDED) {
				handleSymbolAdded(record);
			}
			else if (eventType == ChangeManager.DOCR_SYMBOL_REMOVED) {
				handleSymbolRemoved(record);
			}
		}

		return false;
	}

	private void handleSymbolRemoved(DomainObjectChangeRecord record) {
		// 
		// Get the affected vertex (if any).  Determine if we have to combine the vertex with
		// the vertex below it (adding a symbol creates a new basic block, which creates a new
		// vertex--we may need to reverse that process)
		//
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Address address = ((ProgramChangeRecord) record).getStart();
		FGVertex destinationVertex = functionGraph.getVertexForAddress(address);
		if (destinationVertex == null) {
			return; // this particular removal doesn't affect our graph
		}

		// 
		// How do we know if we can combine this vertex with its parent?  Well, we have some
		// tests that must hold true:
		// -There must be only a fallthrough edge to the affected vertex
		// -The parent vertex must have only one flow--FallThrough
		// -There must not be any other references to the entry of the vertex
		// -There must not be any non-dynamic labels on the vertex		
		//
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGEdge> inEdgesForDestination = graph.getInEdges(destinationVertex);
		if (inEdgesForDestination.size() == 0) {
			// must be in a dirty state with vertices and edges that don't match reality
			return;
		}

		if (inEdgesForDestination.size() > 1) {
			controller.refreshDisplayWithoutRebuilding();
			return;
		}

		FGEdge incomingEdge = inEdgesForDestination.iterator().next();
		FGVertex parentVertex = incomingEdge.getStart();
		Collection<FGEdge> outEdges = graph.getOutEdges(parentVertex);
		if (outEdges.size() > 1) {
			return;
		}

		FlowType flowType = incomingEdge.getFlowType();
		if (!flowType.isFallthrough()) {
			controller.refreshDisplayWithoutRebuilding();
			return;
		}

		SymbolTable symbolTable = currentProgram.getSymbolTable();
		AddressSetView vertexAddresses = destinationVertex.getAddresses();
		Address minAddress = vertexAddresses.getMinAddress();
		Symbol[] symbols = symbolTable.getSymbols(minAddress);
		if (symbols.length > 1) {
			controller.refreshDisplayWithoutRebuilding();
			return; // real user symbols
		}
		else if (symbols.length == 1) {
			if (!symbols[0].isDynamic()) {
				controller.refreshDisplayWithoutRebuilding();
				return; // real user symbol
			}
		}

		ReferenceManager referenceManager = currentProgram.getReferenceManager();
		ReferenceIterator references = referenceManager.getReferencesTo(minAddress);
		if (references.hasNext()) {
			return; // other references to this vertex entry point
		}

		controller.mergeVertexWithParent(destinationVertex);
	}

	private void handleSymbolAdded(DomainObjectChangeRecord record) {
		// 
		// Get the affected vertex (if any).  Determine if we have to split the vertex.
		//
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Address address = ((ProgramChangeRecord) record).getStart();
		FGVertex destinationVertex = functionGraph.getVertexForAddress(address);
		if (destinationVertex == null) {
			return; // this particular removal doesn't affect our graph
		}

		// 
		// How do we know if we need to split this vertex?  Well, we have some
		// tests that must hold true:
		// -The address for the symbol must not be to the minimum address for that vertex		
		//
		AddressSetView addresses = destinationVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();
		if (address.equals(minAddress)) {
			controller.refreshDisplayWithoutRebuilding();
			return; // the 'to' is not in the middle of the code block--no need to split
		}

		controller.splitVertex(destinationVertex, address);
	}

	private void handleSymbolRenamed(DomainObjectChangedEvent ev) {
		for (int i = 0; i < ev.numRecords(); i++) {
			DomainObjectChangeRecord record = ev.getChangeRecord(i);
			int eventType = record.getEventType();
			if (eventType == ChangeManager.DOCR_SYMBOL_RENAMED) {
				Address address = getChangedAddress(record);
				if (address != null) {
					controller.refreshDisplayForAddress(address);
				}
			}
		}
	}

	private boolean isPerformingGraphRebuildOnDataChanges() {
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		RelayoutOption relayoutOption = options.getRelayoutOption();

		switch (relayoutOption) {
			case ALWAYS:
			case BLOCK_MODEL_CHANGES:
				return true;
			case NEVER:
			case VERTEX_GROUPING_CHANGES:
				return false;
			default:
				throw new AssertException(
					"Unhandled case statement for Function Graph RelayoutOption");
		}
	}

	private boolean currentGraphContainsEventAddress(DomainObjectChangedEvent ev) {
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph graph = functionGraphData.getFunctionGraph();
		for (int i = 0; i < ev.numRecords(); i++) {
			Address address = getChangedAddress(ev.getChangeRecord(i));
			if (address != null && graph.getVertexForAddress(address) != null) {
				return true;
			}
		}
		return false;
	}

	private Address getChangedAddress(DomainObjectChangeRecord changeRecord) {
		if (changeRecord instanceof ProgramChangeRecord) {
			return ((ProgramChangeRecord) changeRecord).getStart();
		}

		return null;
	}

	private boolean currentGraphContainsReferenceChangedEvent(DomainObjectChangedEvent ev) {
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph graph = functionGraphData.getFunctionGraph();

		for (DomainObjectChangeRecord record : ev) {
			int eventType = record.getEventType();
			if (eventType == ChangeManager.DOCR_MEM_REFERENCE_ADDED) {
				Reference reference = (Reference) record.getNewValue();
				Address toAddress = reference.getToAddress();
				if (graph.getVertexForAddress(toAddress) != null) {
					return true;
				}
			}
			else if (eventType == ChangeManager.DOCR_MEM_REFERENCE_REMOVED) {
				Reference reference = (Reference) record.getOldValue();
				Address toAddress = reference.getToAddress();
				if (graph.getVertexForAddress(toAddress) != null) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public void dispose() {

		unregisterNavigatable();
		disposed = true;
		for (NavigatableRemovalListener listener : navigationListeners) {
			listener.navigatableRemoved(this);
		}

		super.dispose();

		controller.cleanup();
		if (currentProgram != null) {
			currentProgram.removeListener(this);
			currentProgram = null;
		}
	}

	@Override
	public void componentHidden() {
		storeLocation(null);
		controller.primaryProviderHidden();
		super.componentHidden();
	}

	@Override
	public void componentShown() {
		super.componentShown();

		if (currentLocation == null) {
			return;
		}
		refreshAndResetPerspective();
	}

	@Override
	public void closeComponent() {
		controller.cleanup();
		plugin.closeProvider(this);
	}

	@Override
	public String getWindowGroup() {
		if (isConnected()) {
			return FunctionGraphPlugin.FUNCTION_GRAPH_NAME;
		}
		return "disconnected";
	}

	public void formatChanged() {
		controller.formatChanged();
	}

	@Override
	public void writeConfigState(SaveState saveState) {
		super.writeConfigState(saveState);

		saveState.putBoolean(DISPLAY_POPUPS, arePopupsVisible());
		actionManager.writeConfigState(saveState);
	}

	@Override
	public void readConfigState(SaveState saveState) {

		super.readConfigState(saveState);

		actionManager.readConfigState(saveState);

		boolean showPopups = saveState.getBoolean(DISPLAY_POPUPS, true);
		setPopupsVisible(showPopups);
	}

	public void writeDataState(SaveState saveState) {

		// navigatable stuff
		saveState.putLong("NAV_ID", getInstanceID());

		if (!controller.hasResults()) {
			return;
		}

		if (currentLocation != null) {
			currentLocation.saveState(saveState);
		}

		GraphPerspectiveInfo<FGVertex, FGEdge> info =
			controller.getGraphPerspective(currentLocation);
		info.saveState(saveState);
	}

	public void readDataState(SaveState saveState) {

		// navigatable stuff
		unregisterNavigatable();
		initializeInstanceID(saveState.getLong("NAV_ID", getInstanceID()));
		registerNavigatable();

		if (currentProgram == null) {
			return;
		}

		ProgramLocation newLocation = ProgramLocation.getLocation(currentProgram, saveState);
		storeLocation(newLocation);
		if (newLocation != null) {
			controller.display(currentProgram, newLocation);
		}

		controller.setGraphPerspective(new GraphPerspectiveInfo<>(saveState));
	}

	@Override
	protected ComponentProvider getSatelliteProvider() {
		return super.getSatelliteProvider();
	}

	String getDisconnectedName() {
		return disconnectedName;
	}

	void setDisconnectedName(String name) {
		disconnectedName = name;
	}

	public void configChanged() {
		tool.setConfigChanged(true);
	}

	public void clearViewSettings() {
		GraphPerspectiveInfo<FGVertex, FGEdge> info =
			GraphPerspectiveInfo.createInvalidGraphPerspectiveInfo();
		controller.setGraphPerspective(info);
	}

//==================================================================================================
// Navigatable interface methods
//==================================================================================================

	@Override
	public Program getProgram() {
		return currentProgram;
	}

	@Override
	public void setSelection(ProgramSelection selection) {
		storeSelection(selection);
		controller.setSelection(selection);
		notifySelectionChanged(selection);
	}

	@Override
	public ProgramSelection getSelection() {
		if (currentProgramSelection == null || currentProgramSelection.isEmpty()) {
			return null;
		}

		FGData currentData = controller.getFunctionGraphData();
		if (!currentData.hasResults()) {
			return null;
		}

		// we want to limit the selections we return here to that which is inside of our 
		// graph (the current selection of this provider is that for the entire program)
		Function function = currentData.getFunction();
		AddressSetView functionBody = function.getBody();
		AddressSet intersection = currentProgramSelection.intersect(functionBody);
		return new ProgramSelection(intersection);
	}

	@Override
	public ProgramSelection getHighlight() {
		if (currentProgramHighlight == null || currentProgramHighlight.isEmpty()) {
			return null;
		}

		FGData currentData = controller.getFunctionGraphData();
		if (!currentData.hasResults()) {
			return null;
		}

		// we want to limit the selections we return here to that which is inside of our 
		// graph (the current selection of this provider is that for the entire program)
		Function function = currentData.getFunction();
		AddressSetView functionBody = function.getBody();
		AddressSet intersection = currentProgramHighlight.intersect(functionBody);
		return new ProgramSelection(intersection);
	}

	@Override
	public String getTextSelection() {

		FGData currentData = controller.getFunctionGraphData();
		if (!currentData.hasResults()) {
			return null;
		}

		FGVertex focusedVertex = controller.getFocusedVertex();
		if (focusedVertex == null) {
			return null;
		}

		return focusedVertex.getTextSelection();
	}

	@Override
	public boolean supportsHighlight() {
		return true;
	}

	@Override
	public void setHighlight(ProgramSelection highlight) {
		storeHighlight(highlight);
		controller.setHighlight(highlight);
		notifyHighlightChanged(highlight);
	}

	private void storeHighlight(ProgramSelection highlight) {
		currentProgramHighlight = highlight;
		notifyContextChanged();
	}

	@Override
	public ProgramLocation getLocation() {
		return currentLocation;
	}

	@Override
	public LocationMemento getMemento() {
		FGLocationMemento memento = new FGLocationMemento(currentProgram, currentLocation,
			controller.getGraphPerspective(currentLocation));
		return memento;
	}

	@Override
	public void setMemento(LocationMemento memento) {

		/*
			This code may have issues (see SCR 9208).  For now we've made it an option so that
			users have to enable and disable it at will.
		*/

		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		ViewRestoreOption viewOption = options.getViewRestoreOption();
		if (viewOption == ViewRestoreOption.REMEMBER_SETTINGS) {
			FGLocationMemento fgMemento = (FGLocationMemento) memento;
			controller.setGraphPerspective(fgMemento.getGraphPerspectiveInfo());
		}
	}

	private void setStatusInfo(String message) {
		tool.setStatusInfo(message);
	}

	public void internalGoTo(ProgramLocation location, Program program) {
		GoToService goToService = tool.getService(GoToService.class);
		goToService.goTo(this, location, program);
	}

	@Override
	public boolean goTo(Program gotoProgram, ProgramLocation location) {
		if (gotoProgram != currentProgram) {
			if (!isConnected()) {
				tool.setStatusInfo("Program location not applicable for this provider!");
				return false;
			}
			ProgramManager programManagerService = tool.getService(ProgramManager.class);
			if (programManagerService != null) {
				programManagerService.setCurrentProgram(gotoProgram);
			}
		}
		setLocation(location);
		notifyLocationChanged(location);
		tool.showComponentProvider(this, true);
		return true;
	}

	@Override
	public void requestFocus() {
		if (!isVisible()) {
			return; // we will popup incorrectly without this check
		}

		controller.requestFocus();
		tool.toFront(this);
	}

	@Override
	public boolean isFocusedProvider() {
		return focusStatusDelegate.get();
	}

	void setFocusStatusDelegate(Supplier<Boolean> focusStatusDelegate) {
		this.focusStatusDelegate = focusStatusDelegate;
	}

	@Override
	public void removeHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// currently unsupported
	}

	@Override
	public void setHighlightProvider(HighlightProvider highlightProvider, Program program) {
		// currently unsupported
	}

	@Override
	public Icon getIcon() {
		if (isConnected()) {
			return super.getIcon();
		}

		if (navigatableIcon == null) {
			Icon primaryIcon = super.getIcon();
			navigatableIcon = NavigatableIconFactory.createSnapshotOverlayIcon(primaryIcon);
		}
		return navigatableIcon;
	}

	@Override
	public Icon getNavigatableIcon() {
		return getIcon();
	}

	@Override
	public boolean isConnected() {
		return isConnected;
	}

	@Override
	public boolean supportsMarkers() {
		return isConnected;
	}

	protected void setConnected(boolean newValue) {
		isConnected = newValue;
	}

	@Override
	public boolean isDisposed() {
		return disposed;
	}

	private void registerNavigatable() {
		NavigatableRegistry.registerNavigatable(tool, this);
	}

	private void unregisterNavigatable() {
		NavigatableRegistry.unregisterNavigatable(tool, this);
	}

	@Override
	public void addNavigatableListener(NavigatableRemovalListener listener) {
		navigationListeners.add(listener);
	}

	@Override
	public void removeNavigatableListener(NavigatableRemovalListener listener) {
		navigationListeners.remove(listener);
	}
}
