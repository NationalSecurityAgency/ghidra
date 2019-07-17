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
package ghidra.graph.viewer;

import java.awt.Rectangle;
import java.awt.geom.Point2D;
import java.util.*;

import javax.swing.JComponent;

import docking.widgets.OptionDialog;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.VisualizationServer;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout;
import ghidra.app.plugin.core.functiongraph.graph.vertex.*;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.plugin.core.functiongraph.util.job.*;
import ghidra.graph.VisualGraph;
import ghidra.graph.job.RelayoutFunctionGraphJob;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;

/**
 * Houses view update methods specific to the {@link FunctionGraph} API.
 */
public class FGViewUpdater extends VisualGraphViewUpdater<FGVertex, FGEdge> {

	// TODO
	// TODO Most, if not all, of these method can be pulled-up when grouping is moved up.  Some
	//      of the code references Software Modeling classes.  That code really belongs in 
	//      the group vertex itself and not in this utility class.
	// TODO
	// TODO

	public FGViewUpdater(GraphViewer<FGVertex, FGEdge> viewer,
			VisualGraph<FGVertex, FGEdge> graph) {
		super(viewer, graph);
	}

	/**
	 * Performs a relayout of the graph currently used by the given controller.
	 * @param controller The controller whose graph should have relayout called
	 */
	public void relayoutGraph(FGController controller) {
		FGView view = controller.getView();
		GraphViewer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
		VisualGraphViewUpdater<FGVertex, FGEdge> updater = viewer.getViewUpdater();
		updater.scheduleViewChangeJob(new RelayoutFunctionGraphJob<>(viewer, isAnimationEnabled()));
	}

//==================================================================================================
// Grouping Methods
//==================================================================================================	

	public void ungroupVertex(FGController controller, GroupedFunctionGraphVertex groupedVertex) {
		ungroupVertex(controller, groupedVertex, false);
	}

	public void ungroupVertex(FGController controller, GroupedFunctionGraphVertex groupedVertex,
			boolean isUngroupAll) {

		stopAllNonMutativeAnimation();

		//
		// Get the original vertices and add them back to the graph.
		//
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		if (!graph.containsVertex(groupedVertex)) {
			throw new IllegalArgumentException(
				"Cannot ungroup a vertex that is not in the graph!: " +
					groupedVertex.getUserText());
		}

		Set<FGVertex> vertices = groupedVertex.getVertices();
		for (FGVertex newVertex : vertices) {
			graph.addVertex(newVertex);
		}

		//
		// Add the edges back to the graph
		//
		Set<FGEdge> ungroupedIncomingEdges = groupedVertex.getUngroupedEdges();
		for (FGEdge edge : ungroupedIncomingEdges) {
			validateAndAddEdge(controller, functionGraph, groupedVertex, edge);
		}

		//
		// Create the animator to smooth the process.  The animator will not
		// animate if animation is disabled.
		//
		UngroupVertexFunctionGraphJob job = new UngroupVertexFunctionGraphJob(controller,
			groupedVertex, isAnimationEnabled(), isUngroupAll);
		scheduleViewChangeJob(job);
	}

	private void validateAndAddEdge(FGController controller, FunctionGraph functionGraph,
			GroupedFunctionGraphVertex groupedVertex, FGEdge edge) {

		Graph<FGVertex, FGEdge> graph = functionGraph;
		FGVertex startVertex =
			updateEdgeVertexForUngrouping(functionGraph, groupedVertex, edge.getStart());
		FGVertex destinationVertex =
			updateEdgeVertexForUngrouping(functionGraph, groupedVertex, edge.getEnd());
		if (edge.getStart() != startVertex || edge.getEnd() != destinationVertex) {

			// one or both of the original endpoints must have been grouped
			edge = edge.cloneEdge(startVertex, destinationVertex);
		}

		graph.addEdge(edge, startVertex, destinationVertex);
	}

	public FGVertex updateEdgeVertexForUngrouping(FunctionGraph functionGraph,
			GroupedFunctionGraphVertex groupedVertex, FGVertex originalVertex) {

		Graph<FGVertex, FGEdge> graph = functionGraph;
		if (graph.containsVertex(originalVertex)) {
			return originalVertex;
		}

		//
		// Look through the vertices to find the vertex that contains the given address.  We may
		// have multiple vertices that contain the address, as is the case when we are
		// transitioning from a group vertex that contains a group vertex that contains the
		// given address.
		//
		Address address = originalVertex.getVertexAddress();
		Collection<FGVertex> vertices = graph.getVertices();
		for (FGVertex vertex : vertices) {
			if (vertex.containsAddress(address) && !vertex.equals(groupedVertex)) {
				return vertex;
			}
		}

		// should never happen
		throw new AssertException("Cannot find any vertex for address: " + address);
	}

	/**
	 * Ungroups all {@link GroupedFunctionGraphVertex group vertices} found in the graph.  This
	 * method is recursive in that it will keep running until no group vertices remain.
	 *
	 * @param controller The controller in use with the current function graph
	 */
	public void ungroupAllVertices(final FGController controller) {

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Collection<FGVertex> vertices = graph.getVertices();

		Set<GroupedFunctionGraphVertex> groupVertices = new HashSet<>();
		for (FGVertex vertex : vertices) {
			if (vertex instanceof GroupedFunctionGraphVertex) {
				groupVertices.add((GroupedFunctionGraphVertex) vertex);
			}
		}

		if (groupVertices.size() == 0) {
			return; // nothing left to ungroup
		}

		ungroupVertex(controller, groupVertices.iterator().next(), true);

		// this follow-up job will call this method again until all groups are gone
		scheduleViewChangeJob(new UngroupAllVertexFunctionGraphJob(controller));
	}

	public void addToGroup(FGController controller, GroupedFunctionGraphVertex groupVertex,
			Set<FGVertex> groupedVertices) {

		stopAllNonMutativeAnimation();

		// don't include the group to which we are adding in the set to be added
		groupedVertices.remove(groupVertex);

		String currentText = groupVertex.getUserText();
		String defaultText =
			GroupedFunctionGraphVertex.generateGroupVertexDescription(groupVertex.getVertices());
		if (currentText.equals(defaultText)) {
			// the user has not changed the text--generate a new default from all vertices
			// that will be in the group
			HashSet<FGVertex> allGroupedVertices = new HashSet<>(groupedVertices);
			allGroupedVertices.addAll(groupVertex.getVertices());
			currentText =
				GroupedFunctionGraphVertex.generateGroupVertexDescription(allGroupedVertices);
		}

		JComponent viewComponent = controller.getViewComponent();
		String text = promptUserForGroupVertexText(viewComponent, currentText, groupedVertices);
		if (text == null) {
			return; // cancelled
		}

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Set<FGEdge> ungroupedEdges = new HashSet<>();
		accumulateUngroupedIncidentEdges(graph, groupedVertices, ungroupedEdges);

		createNewGroupedEdges(controller, groupVertex, ungroupedEdges);

		//
		// Update the existing group with the new vertex/edge data
		//
		GroupedFunctionGraphVertex newGroupVertex =
			groupVertex.derriveGroupVertex(groupedVertices, text, ungroupedEdges);
		swapVertices(controller, groupVertex, newGroupVertex);

		//
		// Create the animator to smooth the process.  The animator will not
		// animate if animation is disabled.
		//
		GroupVertexFunctionGraphJob job = GroupVertexFunctionGraphJob.createUpdateGroupJob(
			controller, newGroupVertex, groupedVertices, isAnimationEnabled());
		scheduleViewChangeJob(job);
	}

	private void swapVertices(FGController controller, GroupedFunctionGraphVertex oldGroupVertex,
			GroupedFunctionGraphVertex newGroupVertex) {

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Collection<FGEdge> inEdges = graph.getInEdges(oldGroupVertex);
		Collection<FGEdge> outEdges = graph.getOutEdges(oldGroupVertex);

		graph.addVertex(newGroupVertex);

		FGView view = controller.getView();
		VisualizationServer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
		Layout<FGVertex, FGEdge> graphLayout = viewer.getGraphLayout();
		Point2D location = graphLayout.apply(oldGroupVertex);
		graphLayout.setLocation(newGroupVertex, (Point2D) location.clone());

		for (FGEdge edge : inEdges) {
			FGVertex startVertex = edge.getStart();
			FGEdge clonedEdge = edge.cloneEdge(startVertex, newGroupVertex);
			graph.addEdge(clonedEdge, startVertex, newGroupVertex);
		}

		for (FGEdge edge : outEdges) {
			FGVertex destinationVertex = edge.getEnd();
			graph.addEdge(edge.cloneEdge(newGroupVertex, destinationVertex), newGroupVertex,
				destinationVertex);
		}

		graph.removeVertex(oldGroupVertex);
	}

	public void regroupVertices(FGController controller, FGVertex vertex) {

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		GroupHistoryInfo groupHistory = functionGraph.getGroupHistory(vertex);
		if (groupHistory == null) {
			throw new AssertException("Cannot find group history for regroup operation!");
		}

		Set<FGVertex> vertices = new HashSet<>(groupHistory.getVertices());
		Point2D location = groupHistory.getGroupLocation();
		if (location == null) {
			FGView view = controller.getView();
			VisualizationServer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
			Rectangle containingBounds =
				GraphViewerUtils.getBoundsForVerticesInLayoutSpace(viewer, vertices);
			location =
				new Point2D.Double(containingBounds.getCenterX(), containingBounds.getCenterY());
		}

		fixupVerticesForUncollapsedGroupMembers(functionGraph, vertices);

		String text = groupHistory.getGroupDescription();
		groupVertices(controller, text, vertices, location, true);
	}

	/**
	 * Checks each vertex in the given set to see if it is a group vertex.  If so, this method
	 * will check to see if the group is still in the graph.  If not, assume that it has been
	 * uncollapsed and find it's children (recursively) and add them to the set to be regrouped,
	 * replacing that original group.
	 *
	 * @param graph the graph containing all vertices
	 * @param fixupVertices the vertices to examine
	 */
	private void fixupVerticesForUncollapsedGroupMembers(Graph<FGVertex, FGEdge> graph,
			Set<FGVertex> fixupVertices) {

		Set<FGVertex> updatedChildren = new HashSet<>();

		Iterator<FGVertex> iterator = fixupVertices.iterator();
		while (iterator.hasNext()) {
			FGVertex vertex = iterator.next();
			if (graph.containsVertex(vertex)) {
				continue; // still there, nothing to do
			}

			if (!(vertex instanceof GroupedFunctionGraphVertex)) {
				continue;
			}

			GroupedFunctionGraphVertex groupedVertex = (GroupedFunctionGraphVertex) vertex;
			Set<FGVertex> dependentVertices = new HashSet<>(groupedVertex.getVertices());
			fixupVerticesForUncollapsedGroupMembers(graph, dependentVertices);
			iterator.remove();
			updatedChildren.addAll(dependentVertices);
		}

		fixupVertices.addAll(updatedChildren);
	}

	public void groupSelectedVertices(FGController controller) {
		groupSelectedVertices(controller, null);
	}

	public void groupSelectedVertices(FGController controller, Point2D location) {
		Set<FGVertex> selectedVertices = controller.getSelectedVertices();
		int vertexCount = selectedVertices.size();
		if (vertexCount == 1) {
			FGVertex vertex = selectedVertices.iterator().next();
			if (vertex instanceof GroupedFunctionGraphVertex) {
				FGView view = controller.getView();
				Msg.showInfo(FGViewUpdater.class, view.getPrimaryGraphViewer(),
					"Cannot Group a Single Group Vertex",
					"You cannot create a group vertex from a single group vertex");
				return;
			}
		}

		JComponent viewComponent = controller.getViewComponent();
		String text = promptUserForGroupVertexText(viewComponent, null, selectedVertices);
		if (text == null) {
			return; // cancelled
		}

		if (location == null) {
			FGView view = controller.getView();
			VisualizationServer<FGVertex, FGEdge> viewer = view.getPrimaryGraphViewer();
			Rectangle containingBounds =
				GraphViewerUtils.getBoundsForVerticesInLayoutSpace(viewer, selectedVertices);
			location =
				new Point2D.Double(containingBounds.getCenterX(), containingBounds.getCenterY());
		}

		groupVertices(controller, text, selectedVertices, location);
	}

	public String promptUserForGroupVertexText(JComponent centerOverComponent, String currentText,
			Set<FGVertex> selectedVertices) {
		String text = currentText == null
				? GroupedFunctionGraphVertex.generateGroupVertexDescription(selectedVertices)
				: currentText;

		// TODO: List<String> groupDescriptionHistory;
		//
//			 ...have the plugin pull the history to save
//			 ...have the plugin set the history on startup

		return OptionDialog.showInputMultilineDialog(centerOverComponent, "Enter Group Vertex Text",
			"Text", text);
	}

	public void groupVertices(FGController controller, String groupVertexText,
			Set<FGVertex> groupedVertices, Point2D groupVertexLocation) {

		groupVertices(controller, groupVertexText, groupedVertices, groupVertexLocation, false);
	}

	private void groupVertices(FGController controller, String groupVertexText,
			Set<FGVertex> groupedVertices, Point2D groupVertexLocation, boolean isRegroup) {

		int vertexCount = groupedVertices.size();
		if (vertexCount == 0) {
			return;
		}

		if (vertexCount == 1) {
			FGVertex vertex = groupedVertices.iterator().next();
			if (vertex instanceof GroupedFunctionGraphVertex) {
				Msg.showInfo(FGViewUpdater.class, null, "Cannot Group a Single Group Vertex",
					"You cannot create a group vertex from a single group vertex");
				return;
			}
		}

		//
		// Keep track of edges that will be incoming to the new grouped vertex.
		//
		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Set<FGEdge> ungroupedEdges = new HashSet<>();
		accumulateUngroupedIncidentEdges(graph, groupedVertices, ungroupedEdges);

		GroupedFunctionGraphVertex groupVertex = new GroupedFunctionGraphVertex(controller,
			groupVertexText, groupedVertices, ungroupedEdges);

		boolean relayoutOverride = false; // user operation--don't force relayout
		installGroupVertex(controller, groupVertex, groupVertexLocation, relayoutOverride,
			isAnimationEnabled(), isRegroup);
	}

	/**
	 * Install the given grouped vertex into the graph, optionally animating the process.
	 *
	 * @param controller the controller of the graph to be ungrouped
	 * @param groupVertex The group vertex to be ungrouped
	 * @param groupVertexLocation The default groupVertex location (only used if not
	 * 							  performing a relayout).
	 * @param relayoutOverride true signals to always relayout the graph after grouping; false
	 *                         indicates to use the tool's options to decide
	 * @param animate whether to animate
	 * @return true if the given group was added to the graph
	 */
	public boolean installGroupVertex(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Point2D groupVertexLocation) {

		return installGroupVertex(controller, groupVertex, groupVertexLocation, false, false,
			false);
	}

	private boolean installGroupVertex(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Point2D groupVertexLocation,
			boolean relayoutOverride, boolean animate, boolean isRegroup) {

		boolean doAnimate = animate & isAnimationEnabled(); // never animate when the user has disabled it
		if (groupVertex.getVertices().size() == 0) {
			return false;
		}

		stopAllNonMutativeAnimation();

		//
		// Note: we must set the location here, as the graph may paint before the job below
		//       has a chance to run.  If we don't have a location set, things explode.
		// Also: we don't want this 'transient' location to be saved as a user location in our
		//       database of user settings.  So, disable that feature before setting the value.
		//
		FGData data = controller.getFunctionGraphData();
		FunctionGraph graph = data.getFunctionGraph();
		FGLayout fgLayout = graph.getLayout();
		fgLayout.setLocation(groupVertex, groupVertexLocation, ChangeType.TRANSIENT);

		//
		// Put the new group vertex into the graph
		//
		graph.addVertex(groupVertex);

		Set<FGEdge> ungroupedEdges = groupVertex.getUngroupedEdges();
		createNewGroupedEdges(controller, groupVertex, ungroupedEdges);

		//
		// Create the animator to smooth the process.  The animator will not
		// animate if animation is disabled.
		//
		GroupVertexFunctionGraphJob job;
		if (isRegroup) {
			job = GroupVertexFunctionGraphJob.createRegroupJob(controller, groupVertex,
				groupVertexLocation, relayoutOverride, doAnimate);
		}
		else {
			job = GroupVertexFunctionGraphJob.createNewGroupJob(controller, groupVertex,
				groupVertexLocation, relayoutOverride, doAnimate);
		}
		scheduleViewChangeJob(job);
		return true;
	}

	private void accumulateUngroupedIncidentEdges(Graph<FGVertex, FGEdge> graph,
			Set<FGVertex> ungroupedVertices, Set<FGEdge> ungroupedEdges) {

		for (FGVertex vertex : ungroupedVertices) {
			Collection<FGEdge> inEdges = graph.getInEdges(vertex);
			if (inEdges == null) {
				throw new AssertException(
					"cannot group vertex--it is not in the graph: " + vertex.getTitle());
			}

			for (FGEdge edge : inEdges) {
				ungroupedEdges.add(edge);
			}

			Collection<FGEdge> outEdges = graph.getOutEdges(vertex);
			for (FGEdge edge : outEdges) {
				ungroupedEdges.add(edge);
			}
		}
	}

	private void createNewGroupedEdges(FGController controller,
			GroupedFunctionGraphVertex groupVertex, Set<FGEdge> ungroupedEdges) {

		FGData functionGraphData = controller.getFunctionGraphData();
		FunctionGraph graph = functionGraphData.getFunctionGraph();

		Set<FGVertex> vertices = groupVertex.getVertices();

		for (FGEdge edge : ungroupedEdges) {
			FGVertex startVertex = edge.getStart();
			if (vertices.contains(startVertex)) {
				continue; // start vertex is in the group--can't be an incoming edge
			}

			if (!graph.containsVertex(startVertex)) {
				// must have been grouped--go find the containing group
				startVertex = graph.findMatchingVertex(startVertex);
				if (vertices.contains(startVertex)) {
					continue; // the *group* has been grouped!--can't be an incoming edge
				}
			}

			if (startVertex == groupVertex) {
				continue; // the start vertex now lives inside of the current group vertex--ignore
			}

			FGEdge clonedEdge = edge.cloneEdge(startVertex, groupVertex);
			graph.addEdge(clonedEdge, startVertex, groupVertex);
		}

		for (FGEdge edge : ungroupedEdges) {
			FGVertex destinationVertex = edge.getEnd();
			if (vertices.contains(destinationVertex)) {
				continue; // destination vertex is in the group--can't be an outgoing edge
			}

			if (!graph.containsVertex(destinationVertex)) {
				// must have been grouped
				destinationVertex = graph.findMatchingVertex(destinationVertex);
				if (vertices.contains(destinationVertex)) {
					continue; // the *group* has been grouped!--can't be an incoming edge
				}
			}

			if (destinationVertex == groupVertex) {
				continue; // the destination vertex now lives inside of the current group vertex--ignore
			}

			FGEdge clonedEdge = edge.cloneEdge(groupVertex, destinationVertex);
			graph.addEdge(clonedEdge, groupVertex, destinationVertex);
		}

	}

	public void splitVertex(FGController controller, FGVertex vertexToSplit,
			Address newVertexMinAddress) {

		// For now we do not handle splitting when the vertex to split is a group vertex, which
		// means that the real vertex is inside of the grouped vertex.  The work to update
		// everything does not seem worth the result at this time (the result being an updated
		// group vertex display and proper ungrouping).  For now, the user will just have to
		// hit refresh to see the new vertices, but, they will no longer be grouped.
		if (vertexToSplit instanceof GroupedFunctionGraphVertex) {
			return;
		}

		stopAllAnimation();

		FGView view = controller.getView();
		VisualizationServer<FGVertex, FGEdge> primaryViewer = view.getPrimaryGraphViewer();

		//
		// First: create the new parent and child vertices from the given vertex
		//
		Layout<FGVertex, FGEdge> graphLayout = primaryViewer.getGraphLayout();
		Graph<FGVertex, FGEdge> graph = graphLayout.getGraph();

		boolean isOldVertexAnEntry = vertexToSplit.isEntry();
		FlowType oldFlowType = vertexToSplit.getFlowType();
		FGVertexType oldVertexType = vertexToSplit.getVertexType();
		AddressSetView oldAddresses = vertexToSplit.getAddresses();

		AddressSet newParentAddresses = new AddressSet();
		AddressSet newChildAddresses = new AddressSet();

		// grab the addresses for the new child node first, then we can subtract those for the
		// parent set
		AddressIterator iterator = oldAddresses.getAddresses(newVertexMinAddress, true);
		while (iterator.hasNext()) {
			Address address = iterator.next();
			newChildAddresses.addRange(address, address);
		}

		newParentAddresses = oldAddresses.subtract(newChildAddresses);

		FGVertex parentVertex = new ListingFunctionGraphVertex(controller, newParentAddresses,
			oldFlowType, isOldVertexAnEntry);
		FGVertex childVertex = new ListingFunctionGraphVertex(controller, newChildAddresses,
			RefType.FALL_THROUGH, false);

		if (oldVertexType == FGVertexType.SINGLETON) {
			parentVertex.setVertexType(FGVertexType.ENTRY);
			childVertex.setVertexType(FGVertexType.EXIT);
		}
		else if (oldVertexType.isEntry()) {
			parentVertex.setVertexType(oldVertexType);
			childVertex.setVertexType(FGVertexType.BODY);
		}
		else if (oldVertexType.isExit()) {
			parentVertex.setVertexType(FGVertexType.BODY);
			childVertex.setVertexType(oldVertexType);
		}
		else {
			parentVertex.setVertexType(oldVertexType);
			childVertex.setVertexType(oldVertexType);
		}

		graph.addVertex(parentVertex);
		graph.addVertex(childVertex);

		//
		// Second: add the edges from the original vertices to the new vertices
		//
		// To do this, we have to:
		// -move the edge(s) coming into the old vertex to the new parent vertex
		// -move the edge(s) coming out of the old vertex to the new child vertex
		// -add a fallthrough edge between the two new vertices
		//
		Collection<FGEdge> oldInEdges = graph.getInEdges(vertexToSplit);
		Collection<FGEdge> oldOutEdges = graph.getOutEdges(vertexToSplit);

		// copy to keep a reference, as given collection is backed by the graph's state
		oldInEdges = new ArrayList<>(oldInEdges);
		oldOutEdges = new ArrayList<>(oldOutEdges);

		// ...now move the edges to the new parent vertex
		for (FGEdge edge : oldInEdges) {
			FGVertex oldStartVertex = edge.getStart();
			FGEdge newEdge = edge.cloneEdge(oldStartVertex, parentVertex);
			graph.addEdge(newEdge, oldStartVertex, parentVertex);
		}

		// ...now move the edges to the new child vertex
		for (FGEdge edge : oldOutEdges) {
			FGVertex oldDestinationVertex = edge.getEnd();
			graph.addEdge(edge.cloneEdge(childVertex, oldDestinationVertex), childVertex,
				oldDestinationVertex);
		}

		// ...now connect the two new vertices
		FGEdge edge = new FGEdgeImpl(parentVertex, childVertex, RefType.FALL_THROUGH,
			controller.getFunctionGraphOptions());
		graph.addEdge(edge, parentVertex, childVertex);

		//
		// Third: Create the animator to smooth the process.  The animator will not
		//        animate if animation is disabled.
		//
		SplitVertexFunctionGraphJob job = new SplitVertexFunctionGraphJob(controller, primaryViewer,
			vertexToSplit, parentVertex, childVertex, isAnimationEnabled());
		scheduleViewChangeJob(job);
	}

	public void mergeVertexWithParent(FGController controller, FGVertex childVertex) {

		// For now we do not handle merging when the vertex to merge is a group vertex, which
		// means that the real vertex is inside of the grouped vertex.  The work to update
		// everything does not seem worth the result at this time (the result being an updated
		// group vertex display and proper ungrouping).  For now, the user will just have to
		// hit refresh to see the new vertices, but, they will no longer be grouped.
		if (childVertex instanceof GroupedFunctionGraphVertex) {
			return;
		}

		stopAllAnimation();

		FGView view = controller.getView();
		VisualizationServer<FGVertex, FGEdge> primaryViewer = view.getPrimaryGraphViewer();

		//
		// First: create the new vertex from the given vertex and its parent
		//
		Layout<FGVertex, FGEdge> graphLayout = primaryViewer.getGraphLayout();
		Graph<FGVertex, FGEdge> graph = graphLayout.getGraph();

		// we assume that the client has verified that there is only one fallthrough edge to
		// this vertex
		Collection<FGEdge> parentChildEdges = graph.getInEdges(childVertex);
		FGEdge parentChildEdge = parentChildEdges.iterator().next();
		FGVertex parentVertex = parentChildEdge.getStart();
		if (parentVertex instanceof GroupedFunctionGraphVertex) {
			// see above
			return;
		}

		AddressSet newAddresses = new AddressSet();
		newAddresses.add(parentVertex.getAddresses());
		newAddresses.add(childVertex.getAddresses());

		FlowType flowType = parentVertex.getFlowType();
		boolean isEntry = parentVertex.isEntry();
		FGVertex newVertex =
			new ListingFunctionGraphVertex(controller, newAddresses, flowType, isEntry);

		FGVertexType parentVertexType = parentVertex.getVertexType();
		FGVertexType childVertexType = childVertex.getVertexType();
		if (parentVertexType.isEntry() && childVertexType.isExit()) {
			newVertex.setVertexType(FGVertexType.SINGLETON);
		}
		else if (parentVertexType.isEntry()) {
			newVertex.setVertexType(FGVertexType.ENTRY);
		}
		else if (childVertexType.isExit()) {
			newVertex.setVertexType(FGVertexType.EXIT);
		}
		else {
			newVertex.setVertexType(parentVertexType);
		}

		graph.addVertex(newVertex);

		//
		// Second: add the edges from the two vertices to the new vertex
		//
		// To do this, we have to:
		// -move the edge(s) coming into the parent to the new vertex
		// -move the edge(s) coming out of the child vertex to the new vertex
		//

		// for the parent - first remove...
		Collection<FGEdge> parentInEdges = graph.getInEdges(parentVertex);
		// copy to keep a reference, as given collection is backed by the graph's state
		parentInEdges = new ArrayList<>(parentInEdges);

		// ...now move
		for (FGEdge edge : parentInEdges) {
			FGVertex oldStartVertex = edge.getStart();
			graph.addEdge(edge.cloneEdge(oldStartVertex, newVertex), oldStartVertex, newVertex);
		}

		// for the previous child - first remove...
		Collection<FGEdge> childOutEdges = graph.getOutEdges(childVertex);
		// copy to keep a reference, as given collection is backed by the graph's state
		childOutEdges = new ArrayList<>(childOutEdges);

		// ...now move
		for (FGEdge edge : childOutEdges) {
			FGVertex oldDestinationVertex = edge.getEnd();
			graph.addEdge(edge.cloneEdge(newVertex, oldDestinationVertex), newVertex,
				oldDestinationVertex);
		}

		//
		// Third: Create the animator to smooth the process.  The animator will not
		//        animate if animation is disabled.
		//
		MergeVertexFunctionGraphJob job = new MergeVertexFunctionGraphJob(controller, primaryViewer,
			newVertex, parentVertex, childVertex, isAnimationEnabled());
		scheduleViewChangeJob(job);
	}

//==================================================================================================
// End Grouping Methods
//==================================================================================================	

}
