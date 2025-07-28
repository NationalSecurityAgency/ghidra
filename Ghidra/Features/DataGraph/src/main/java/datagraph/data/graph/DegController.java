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

import static ghidra.framework.model.DomainObjectEvent.*;
import static ghidra.program.util.ProgramEvent.*;

import java.awt.*;
import java.awt.event.*;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import javax.swing.JComponent;

import datagraph.DataGraphProvider;
import datagraph.data.graph.DegVertex.DegVertexStatus;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import ghidra.app.util.XReferenceUtils;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.graph.job.RelayoutAndCenterVertexGraphJob;
import ghidra.graph.job.RelayoutAndEnsureVisible;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.event.mouse.VisualGraphPluggableGraphMouse;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * The controller for managing and controlling a DataExplorationGraph
 */
public class DegController implements DomainObjectListener {
	// max number of references to add automatically.  50 is just a guess as to what is reasonable
	private static final int MAX_REFS = 50;
	private DegGraphView view;
	private DataExplorationGraph graph;
	private DegLayoutProvider layoutProvider = new DegLayoutProvider();
	private Program program;
	private boolean navigateOut = true;
	private boolean navigateIn = false;
	private boolean compactFormat = true;
	private DataGraphProvider provider;

	/**
	 * Constructs a new data exploration graph controller.
	 * @param provider The data graph provider that created this controller
	 * @param data the initial data to display in the graph
	 */
	public DegController(DataGraphProvider provider, Data data) {
		this.provider = provider;
		this.program = data.getProgram();
		view = new DegGraphView();
		DegVertex root = new DataDegVertex(this, data, null, true);
		graph = new DataExplorationGraph(root);
		graph.setLayout(getLayout());
		view.setGraph(graph);
		installMouseListeners();
		program.addListener(this);
		setFocusedVertex(root);
	}

	/**
	 * If outgoing navigation is on, navigate the tool to the selected graph location.
	 * @param address the address associated with the current graph location
	 * @param componentPath the component path associated with the current graph location
	 */
	public void navigateOut(Address address, int[] componentPath) {
		if (navigateOut) {
			ProgramLocation location =
				new ProgramLocation(program, address, address, componentPath, null, 0, 0, 0);
			provider.navigateOut(location);
		}
	}

	public void dispose() {
		program.removeListener(this);
	}

	public void repaint() {
		view.repaint();
	}

	public DegLayoutProvider getLayoutProvider() {
		return (DegLayoutProvider) view.getLayoutProvider();
	}

	public Component getComponent() {
		return view.getViewComponent();
	}

	public void relayoutGraph() {
		VisualGraphViewUpdater<DegVertex, DegEdge> viewUpdater = view.getViewUpdater();
		viewUpdater.relayoutGraph();
	}

	/**
	 * Center the graph on the given vertex.
	 * @param vertex the vertex to center the graph on
	 */
	public void centerVertex(DegVertex vertex) {
		VisualGraphViewUpdater<DegVertex, DegEdge> viewUpdater = view.getViewUpdater();
		viewUpdater.moveVertexToCenterWithAnimation(vertex);
	}

	public void centerPoint(Point point) {
		VisualGraphViewUpdater<DegVertex, DegEdge> viewUpdater = view.getViewUpdater();
		viewUpdater.moveViewerLocationWithoutAnimation(point);
	}

	/**
	 * Removes the given vertices from the graph.
	 * @param selectedVertices the set of vertices to remove
	 */
	public void deleteVertices(Set<DegVertex> selectedVertices) {
		Set<DegVertex> toRemove = new HashSet<>();

		for (DegVertex dgVertex : selectedVertices) {
			if (dgVertex.isRoot()) {
				continue;	// can't delete root vertex
			}
			if (!toRemove.contains(dgVertex)) {
				toRemove.addAll(graph.getDescendants(dgVertex));
			}
			toRemove.add(dgVertex);
		}

		graph.removeVertices(toRemove);
		repaint();
	}

	/**
	 * Add new vertices and edges to all references from the given sub data.
	 * @param source the vertex that is being explored out of
	 * @param subData the data within the source vertex that has outgoing references that we
	 * are adding to the graph
	 */
	public void addOutGoingReferences(DataDegVertex source, Data subData) {
		List<DegVertex> addedVertices = new ArrayList<>();
		doAddOutGoingReferences(source, subData, addedVertices);
		if (!addedVertices.isEmpty()) {
			relayoutGraphAndEnsureVisible(source, addedVertices.getLast());
		}
	}

	/**
	 * Add new vertices for all incoming references to the given vertex's data (including offcut)
	 * @param sourceVertex the vertex for which to add new incoming reference vertices
	 */
	public void showAllIncommingReferences(DataDegVertex sourceVertex) {
		CodeUnit target = sourceVertex.getCodeUnit();
		Listing listing = program.getListing();
		List<Reference> refs = XReferenceUtils.getXReferences(target, MAX_REFS + 1);
		if (refs.size() < MAX_REFS) {
			int offcutMax = MAX_REFS + 1 - refs.size();
			List<Reference> offcuts = XReferenceUtils.getOffcutXReferences(target, offcutMax);
			refs.addAll(offcuts);
		}
		if (refs.size() > MAX_REFS) {
			Msg.showWarn(this, null, "Too Many References",
				"Only showing the first " + MAX_REFS + " number of references");
			refs = refs.subList(0, MAX_REFS);
		}
		if (refs.isEmpty()) {
			Msg.showInfo(this, null, "No References Found",
				"There were no references or offcut references found to this data.");
			return;
		}

		doAddIncomingReferences(sourceVertex, listing, refs);

	}

	/**
	 * Add new vertices for all outgoing references from the given vertex's data (including 
	 * sub-data)
	 * @param sourceVertex the vertex for which to add new outgoing reference vertices
	 */
	public void showAllOutgoingReferences(DataDegVertex sourceVertex) {
		Data data = sourceVertex.getData();
		int edgeCount = graph.getEdgeCount();
		List<DegVertex> addedVertices = new ArrayList<>();
		if (!showAllOutgoingReferencesRecursively(sourceVertex, data, addedVertices)) {
			Msg.showWarn(this, null, "Too Many References",
				"Only added the first " + MAX_REFS + " references");
		}

		if (!addedVertices.isEmpty()) {
			relayoutGraphAndEnsureVisible(sourceVertex, addedVertices.getLast());
		}
		else if (graph.getEdgeCount() != edgeCount) {
			relayoutGraph();
		}
		else {
			Msg.showInfo(data, null, "No New Outgoing References Found",
				"There were no additional references found to this data.");
		}
	}

	/**
	 * Sets the graph's root (home) vertex. This will completely rearrange the graph as though
	 * the given vertex was the original vertex that all the other vertexes were explored from.
	 * @param newRoot the new root source vertex (original explore vertex)
	 */
	public void orientAround(DegVertex newRoot) {
		graph.setRoot(newRoot);
		relayoutGraphAndCenter(newRoot);
	}

	public VisualGraphView<DegVertex, DegEdge, DataExplorationGraph> getView() {
		return view;
	}

	public DegVertex getFocusedVertex() {
		return view.getFocusedVertex();
	}

	public Program getProgram() {
		return program;
	}

	/**
	 * Turns on or off outgoing program location navigation
	 * @param b if true, clicking in the graph will cause the tools location to change. If false
	 * clicking the graph will not affect the rest of the tool.
	 */
	public void setNavigateOut(boolean b) {
		navigateOut = b;
	}

	/**
	 * Turns on if this graph should track tool location events. 
	 * @param b if true, the graph will try and select the vertex associated with the current tool's
	 * location. If false, the graph will be unaffected by tool program location changes.
	 */
	public void setNavigateIn(boolean b) {
		navigateIn = b;
	}

	/**
	 * Sets if the tool should display data in a compact format or a more detailed format.
	 * @param b true for compact, false for detailed
	 */
	public void setCompactFormat(boolean b) {
		compactFormat = b;
		graph.getVertices().forEach(v -> {
			if (v instanceof DataDegVertex dataVertex) {
				dataVertex.setCompactFormat(b);
			}
		});
		relayoutGraph();
	}

	public boolean isCompactFormat() {
		return compactFormat;
	}

	/**
	 * Clears any user set location and positions all the vertices to the standard computed layout.
	 */
	public void resetAndRelayoutGraph() {
		graph.getVertices().forEach(v -> v.clearUserChangedLocation());
		relayoutGraph();
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		if (ev.contains(RESTORED)) {
			refreshGraph(true);
			return;
		}
		boolean dataTypesChanged = ev.contains(DATA_TYPE_CHANGED, DATA_TYPE_REMOVED);
		boolean refreshNeeded = ev.contains(CODE_REMOVED) | dataTypesChanged;
		if (refreshNeeded) {
			refreshGraph(dataTypesChanged);
		}
		repaint();
	}

	/**
	 * {@return a collection of vertices that can be reached by following outgoing edges.}
	 * @param vertex the vertex to get outgoing vertices for
	 */
	public Set<DegVertex> getOutgoingVertices(DataDegVertex vertex) {
		Collection<DegEdge> outEdges = graph.getOutEdges(vertex);
		return outEdges.stream().map(e -> e.getEnd()).collect(Collectors.toSet());
	}

	/**
	 * {@return a collection of vertices that can be reached by following incoming edges.}
	 * @param vertex the vertex to get incoming vertices for
	 */
	public Set<DegVertex> getIncomingVertices(DataDegVertex vertex) {
		Collection<DegEdge> inEdges = graph.getOutEdges(vertex);
		return inEdges.stream().map(e -> e.getStart()).collect(Collectors.toSet());
	}

	public DataExplorationGraph getGraph() {
		return graph;
	}

	public GraphViewer<DegVertex, DegEdge> getPrimaryViewer() {
		return view.getPrimaryGraphViewer();
	}

	/**
	 * Informs the controller that the tool's location changed. If navigation in is turned on,
	 * this will attempt to find the vertex matching the given location. If a match is found, the
	 * graph will select that vertex.
	 * @param location the new location for the tool
	 */
	public void locationChanged(ProgramLocation location) {
		if (!navigateIn) {
			return;
		}
		if (program != location.getProgram()) {
			return;
		}
		Address address = location.getAddress();
		Collection<DegVertex> vertices = graph.getVertices();
		for (DegVertex dgVertex : vertices) {
			if (dgVertex.containsAddress(address)) {
				navigateTo(dgVertex);
				break;
			}
		}

	}

	private void doAddIncomingReferences(DataDegVertex sourceVertex, Listing listing,
			List<Reference> xReferences) {
		boolean vertexOrEdgeAdded = false;
		for (Reference reference : xReferences) {
			vertexOrEdgeAdded |= doAddIncomingVertices(sourceVertex, listing, reference);

		}
		if (!vertexOrEdgeAdded) {
			Msg.showInfo(this, null, "No New References Found",
				"There were no additional references or offcut references found to this data.");
		}
	}

	private boolean doAddIncomingVertices(DataDegVertex sourceVertex, Listing listing,
			Reference reference) {
		Address toAddress = reference.getToAddress();
		Address fromAddress = reference.getFromAddress();
		CodeUnit cu = listing.getCodeUnitContaining(fromAddress);
		DegVertex v = createVertex(cu, sourceVertex);

		// if vertex is new, add it and the edge
		if (!graph.containsVertex(v)) {
			graph.getLayout().setLocation(v, sourceVertex.getLocation());
			graph.addVertex(v);
			DegEdge newEdge = new DegEdge(v, sourceVertex);
			addIncomingEdge(fromAddress, toAddress, cu, newEdge);
			return true;
		}

		// see if we need to just add an edge
		v = resolve(v);
		DegEdge newEdge = new DegEdge(v, sourceVertex);
		if (!graph.containsEdge(newEdge)) {
			addIncomingEdge(fromAddress, toAddress, cu, newEdge);
			return true;
		}
		return false;
	}

	private void addIncomingEdge(Address fromAddress, Address toAddress,
			CodeUnit cu, DegEdge newEdge) {
		graph.addEdge(newEdge);
		DegVertex newVertex = newEdge.getStart();
		DataDegVertex sourceVertex = (DataDegVertex) newEdge.getEnd();
		if (newVertex instanceof DataDegVertex dv) {
			dv.addOutgoingEdgeAnchor(sourceVertex, findComponentPath((Data) cu, fromAddress));
		}
		sourceVertex.addIncomingEdgeAnchor(newVertex, toAddress);
		relayoutGraphAndEnsureVisible(sourceVertex, newVertex);
	}

	private DegVertex addDestinationVertex(DataDegVertex sourceVertex, Address a,
			Data sourceData) {

		CodeUnit cu = program.getListing().getCodeUnitContaining(a);
		if (cu == null) {
			return null;
		}

		DegVertex v = createVertex(cu, sourceVertex);
		if (!graph.containsVertex(v)) {
			graph.getLayout().setLocation(v, sourceVertex.getLocation());
			graph.addVertex(v);
			graph.addEdge(new DegEdge(sourceVertex, v));
			sourceVertex.addOutgoingEdgeAnchor(v, sourceData.getComponentPath());
			if (v instanceof DataDegVertex dataVertex) {
				dataVertex.addIncomingEdgeAnchor(sourceVertex, a);
			}
			return v;	// this is the only case where we actually added a new vertex
		}

		// we already had the vertex in the graph, but we may need to add an edge
		if (!graph.containsEdge(new DegEdge(sourceVertex, v))) {
			v = resolve(v);
			graph.addEdge(new DegEdge(sourceVertex, v));
			sourceVertex.addOutgoingEdgeAnchor(v, sourceData.getComponentPath());
			if (v instanceof DataDegVertex dataVertex) {
				dataVertex.addIncomingEdgeAnchor(sourceVertex, a);
			}
		}
		else {
			// if  a vertex has multiple references to the same location, this will move the
			// outgoing edge offset to this component (taking from any other outgoing component
			// to the same location).
			sourceVertex.addOutgoingEdgeAnchor(v, sourceData.getComponentPath());
		}
		return null;	// the vertex already exited in the graph
	}

	private Set<Address> getOutgoingReferenceAddresses(Data data) {
		Set<Address> destinations = new HashSet<>();
		ReferenceManager referenceManager = program.getReferenceManager();
		Address fromAddress = data.getAddress();
		Reference[] referencesFrom = referenceManager.getReferencesFrom(fromAddress);
		for (Reference reference : referencesFrom) {
			destinations.add(reference.getToAddress());
		}
		Object value = data.getValue();
		if (value instanceof Address address) {
			destinations.add(address);
		}
		return destinations;
	}

	private DegVertex createVertex(CodeUnit cu, DegVertex source) {
		if (cu instanceof Data data) {
			return new DataDegVertex(this, data, source, compactFormat);
		}
		return new CodeDegVertex(this, (Instruction) cu, source);
	}

	void relayoutGraphAndEnsureVisible(DegVertex primary, DegVertex secondary) {
		if (primary == null || secondary == null) {
			relayoutGraph();
			return;
		}
		VisualGraphViewUpdater<DegVertex, DegEdge> viewUpdater = view.getViewUpdater();
		GraphViewer<DegVertex, DegEdge> viewer = view.getPrimaryGraphViewer();
		RelayoutAndEnsureVisible<DegVertex, DegEdge> job =
			new RelayoutAndEnsureVisible<>(viewer, primary, secondary,
				viewUpdater.isAnimationEnabled());

		viewUpdater.scheduleViewChangeJob(job);
	}

	void relayoutGraphAndCenter(DegVertex vertex) {

		VisualGraphViewUpdater<DegVertex, DegEdge> viewUpdater = view.getViewUpdater();
		GraphViewer<DegVertex, DegEdge> viewer = view.getPrimaryGraphViewer();
		RelayoutAndCenterVertexGraphJob<DegVertex, DegEdge> job =
			new RelayoutAndCenterVertexGraphJob<>(viewer, vertex, viewUpdater.isAnimationEnabled());

		viewUpdater.scheduleViewChangeJob(job);
	}

	private DegVertex resolve(DegVertex searchVertex) {
		for (DegVertex v : graph.getVertices()) {
			if (v.equals(searchVertex)) {
				return v;
			}
		}
		return null;
	}

	private boolean showAllOutgoingReferencesRecursively(DataDegVertex sourceVertex, Data data,
			List<DegVertex> added) {
		if (data.getNumComponents() == 0) {
			doAddOutGoingReferences(sourceVertex, data, added);
		}

		for (int i = 0; i < data.getNumComponents(); i++) {
			if (added.size() >= MAX_REFS) {
				return false;
			}
			Data subData = data.getComponent(i);
			if (!showAllOutgoingReferencesRecursively(sourceVertex, subData, added)) {
				return false;
			}
		}
		return true;
	}

	private void doAddOutGoingReferences(DataDegVertex source, Data data, List<DegVertex> added) {
		Set<Address> addresses = getOutgoingReferenceAddresses(data);

		for (Address address : addresses) {
			DegVertex newVertex = addDestinationVertex(source, address, data);
			if (newVertex != null) {
				added.add(newVertex);
			}
		}
	}

	private int[] findComponentPath(Data data, Address fromAddress) {
		if (data == null) {
			return new int[0];
		}
		int offset = (int) fromAddress.subtract(data.getAddress());
		if (offset == 0) {
			return data.getComponentPath();
		}
		Data componentContaining = data.getComponentContaining(offset);
		return findComponentPath(componentContaining, fromAddress);

	}

	private void refreshGraph(boolean checkDataTypes) {

		Set<DegVertex> toDelete = new HashSet<>();
		for (DegVertex dgVertex : graph.getVertices()) {
			DegVertexStatus status = dgVertex.refreshGraph(checkDataTypes);

			if (status == DegVertexStatus.MISSING) {
				toDelete.add(dgVertex);
				toDelete.addAll(graph.getDescendants(dgVertex));
			}
			else if (status == DegVertexStatus.CHANGED) {
				// Since the datatype for this vertex changed, we must eliminate all outgoing edges
				// since they may be invalid now. To remove an edge we need to either remove the
				// changed node or the node it points to.
				removeOutgoingEdges(toDelete, dgVertex);
			}
		}
		graph.removeVertices(toDelete);
	}

	private void removeOutgoingEdges(Set<DegVertex> toDelete, DegVertex dgVertex) {
		Collection<DegEdge> outEdges = graph.getOutEdges(dgVertex);
		for (DegEdge edge : outEdges) {
			DegVertex other = edge.getEnd();

			// If the other vertex is a descendent of this vertex, it and all its
			// descendants should be removed. Otherwise, this vertex is a descendent of the
			// other vertex and therefore it should be removed. This is
			// because when pruning nodes, you must always prune descendant sub trees.

			if (other.getSourceVertex() == dgVertex) {
				toDelete.add(other);
				toDelete.addAll(graph.getDescendants(other));
			}
			else {
				// else dgVertex is the descendent of the other vertex, so dgVertex and its
				// descendants should be removed
				toDelete.add(dgVertex);
				toDelete.addAll(graph.getDescendants(dgVertex));
			}
		}
	}

	/**
	 * Selects and centers the original source vertex
	 */
	public void selectAndCenterHomeVertex() {
		navigateTo(graph.getRoot());
	}

	private void navigateTo(DegVertex dgVertex) {
		setFocusedVertex(dgVertex);
		centerVertex(dgVertex);
	}

	private void installMouseListeners() {
		VisualGraphPluggableGraphMouse<DegVertex, DegEdge> graphMouse =
			view.getPrimaryGraphViewer().getGraphMouse();

		graphMouse.prepend(new DataMousePlugin());
	}

	private VisualGraphLayout<DegVertex, DegEdge> getLayout() {
		try {
			return layoutProvider.getLayout(graph, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			return null;
		}
	}

	private void setFocusedVertex(DegVertex v) {
		view.getGraphComponent().setVertexFocused(v);
	}

	private boolean isOnResizeCorner(VertexMouseInfo<DegVertex, DegEdge> vertexMouseInfo) {
		DegVertex vertex = vertexMouseInfo.getVertex();
		Point2D p = vertexMouseInfo.getVertexRelativeClickPoint();
		Dimension vertexSize = vertex.getComponent().getSize();
		return p.getX() > vertexSize.width - 10 && p.getY() > vertexSize.height - 10;
	}

	/**
	 * Mouse plugin for the data explore graph. Mainly used to forward mouse wheel events so thet
	 * the scrollable vertex components can be scrolled via the mouse wheel. Also, is used used
	 * to manually resize a node.
	 */
	private class DataMousePlugin extends AbstractGraphMousePlugin
			implements MouseWheelListener, MouseMotionListener, MouseListener {

		private VertexMouseInfo<DegVertex, DegEdge> dragStart;
		private Dimension startSize;
		private boolean isFiringWheelEvent;

		public DataMousePlugin() {
			super(0);
		}

		@Override
		public void mouseWheelMoved(MouseWheelEvent e) {
			if (isFiringWheelEvent) {
				return;
			}
			VertexMouseInfo<DegVertex, DegEdge> vertexMouseInfo = getTranslatedMouseInfo(e);
			if (vertexMouseInfo == null) {
				return;
			}

			if (vertexMouseInfo.isScaledPastInteractionThreshold()) {
				return;
			}
			if (e.getModifiersEx() != 0) {
				// let graph handle modified mouse wheel events
				return;
			}

			try {
				isFiringWheelEvent = true;
				vertexMouseInfo.forwardEvent();
			}
			finally {
				isFiringWheelEvent = false;
			}
			repaint();
		}

		private VertexMouseInfo<DegVertex, DegEdge> getTranslatedMouseInfo(MouseEvent e) {
			GraphViewer<DegVertex, DegEdge> viewer = view.getPrimaryGraphViewer();
			return GraphViewerUtils.convertMouseEventToVertexMouseEvent(viewer, e);
		}

		@Override
		public void mouseDragged(MouseEvent e) {
			if (dragStart == null) {
				return;
			}
			MouseEvent startEv = dragStart.getOriginalMouseEvent();
			int x = e.getX() - startEv.getX();
			int y = e.getY() - startEv.getY();

			DataDegVertex vertex = (DataDegVertex) dragStart.getVertex();
			int newWidth = Math.max(startSize.width + x, 50);
			int newHeight = Math.max(startSize.height + y, 50);
			vertex.setSizeByUser(new Dimension(newWidth, newHeight));
		}

		@Override
		public void mouseMoved(MouseEvent e) {
			VertexMouseInfo<DegVertex, DegEdge> vertexMouseInfo = getTranslatedMouseInfo(e);
			if (vertexMouseInfo == null) {
				return;
			}

			if (vertexMouseInfo.isScaledPastInteractionThreshold()) {
				return;
			}
			JComponent c = (JComponent) vertexMouseInfo.getEventSource();
			if (isOnResizeCorner(vertexMouseInfo)) {
				c.setCursor(Cursor.getPredefinedCursor(Cursor.SE_RESIZE_CURSOR));
				// we need to consume the event or else a follow-on mouse
				// process may change the cursor
				e.consume();
			}
			else {
				// here we don't want to consume the event because we WANT follow on mouse
				// processing to possibly change the cursor
				c.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
			}
		}

		@Override
		public void mouseClicked(MouseEvent e) {
			// not currently used
		}

		@Override
		public void mousePressed(MouseEvent e) {
			VertexMouseInfo<DegVertex, DegEdge> vertexMouseInfo = getTranslatedMouseInfo(e);
			if (vertexMouseInfo == null) {
				return;
			}

			if (vertexMouseInfo.isScaledPastInteractionThreshold()) {
				return;
			}
			DegVertex vertex = vertexMouseInfo.getVertex();
			if (vertex instanceof DataDegVertex dataVertex && isOnResizeCorner(vertexMouseInfo)) {
				dragStart = vertexMouseInfo;
				startSize = dataVertex.getSize();
			}

		}

		@Override
		public void mouseReleased(MouseEvent e) {
			if (dragStart != null) {
				relayoutGraph();
				dragStart = null;
			}
		}

		@Override
		public void mouseEntered(MouseEvent e) {
			// not currently used
		}

		@Override
		public void mouseExited(MouseEvent e) {
			// not currently used
		}
	}

}
