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
package ghidra.app.plugin.core.functiongraph.graph;

import java.awt.Point;
import java.util.*;

import org.jdom.Element;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.layout.FGLayout;
import ghidra.app.plugin.core.functiongraph.graph.vertex.*;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.graphs.GroupingVisualGraph;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.util.ProgramSelection;

/**
 * The Function Graph is a composite object that contains a Graph (for holding vertices and
 * edges), a layout (for arranging the vertices and edges visually), settings (for things like
 * coloring and grouping of nodes), and edge information (for things like finding paths between
 * nodes).
 */
public class FunctionGraph extends GroupingVisualGraph<FGVertex, FGEdge> {

	/** Keep a copy around for later retrieval */
	private Set<FGEdge> ungroupedEdges = new HashSet<>();
	private Set<GroupHistoryInfo> groupHistorySet = new HashSet<>();

	private Function function;

	private FGVertex rootVertex;
	private FunctionGraphVertexAttributes settings; // refers to vertex location info
	private FunctionGraphOptions options;   // refers to layout options and such
	private FGLayout graphLayout;// set after construction

	private GroupListener groupListener = new GroupListener() {
		@Override
		public void groupDescriptionChanged(String oldText, String newText) {
			updateGroupHistory(oldText, newText);
		}

		private void updateGroupHistory(String oldText, String newText) {
			for (GroupHistoryInfo info : groupHistorySet) {
				String currentDescription = info.getGroupDescription();
				if (currentDescription.equals(oldText)) {
					info.setGroupDescription(newText);
				}
			}
		}
	};

	/**
	 * Construct a function graph with the given (optional) vertices and edges
	 * 
	 * @param function the function upon which this graph is based
	 * @param settings the settings that will be used for vertices added in the future
	 * @param vertices the vertices
	 * @param edges the edges
	 */
	FunctionGraph(Function function, FunctionGraphVertexAttributes settings,
			Collection<FGVertex> vertices, Collection<FGEdge> edges) {

		this(function, settings);

		vertices.forEach(v -> addVertex(v));
		edges.forEach(e -> addEdge(e));

		restoreSettings();
	}

	/**
	 * Construct an empty graph with data from this graph
	 * 
	 * @param function the function upon which this graph is based
	 * @param settings the settings that will be used for vertices added in the future
	 */
	private FunctionGraph(Function function, FunctionGraphVertexAttributes settings) {
		this.function = function;
		this.settings = settings;
	}

	@Override
	public FGVertex findMatchingVertex(FGVertex v) {
		FGVertex matching = getVertexForAddress(v.getVertexAddress());
		return matching;
	}

	@Override
	public FGVertex findMatchingVertex(FGVertex v, Collection<FGVertex> ignore) {
		FGVertex matching = getVertexForAddress(v.getVertexAddress(), ignore);
		return matching;
	}

	public Function getFunction() {
		return function;
	}

	public void restoreSettings() {
		for (FGVertex vertex : getVertices()) {
			vertex.readSettings(settings);
		}
	}

	public void saveSettings() {
		saveVertexSettings();
		settings.save();
	}

	private void saveVertexSettings() {
		for (FGVertex vertex : getVertices()) {
			vertex.writeSettings(settings);
		}
	}

	public void clearVertexColor(FGVertex vertex) {
		settings.clearVertexColor(vertex.getVertexAddress());
	}

	public FunctionGraphVertexAttributes getSettings() {
		return settings;
	}

	public Element getSavedGroupedVertexSettings() {
		return settings.getGroupedVertexSettings(this);
	}

	public Element getSavedGroupHistory() {
		return settings.getRegroupVertexSettings(this);
	}

	/**
	 * Returns any saved location information for the vertices of this graph.  Location information
	 * is saved when users manually move vertices in the graph.
	 *
	 * @return any saved location information for the vertices of this graph.
	 */
	public Map<FGVertex, Point> getSavedVertexLocations() {
		return settings.getVertexLocations(this);
	}

	private void clearSavedVertexLocation(FGVertex vertex) {
		settings.clearVertexLocation(vertex);
	}

	// TODO make private?
	public void clearSavedVertexLocations() {
		settings.clearVertexLocations(this);
	}

	// TODO make private?
	public void clearAllUserLayoutSettings() {
		clearSavedVertexLocations();
		settings.clearGroupSettings(this);
		settings.clearRegroupSettings(this);
	}

	@Override
	public void vertexLocationChanged(FGVertex v, Point point, ChangeType changeType) {
		if (changeType == ChangeType.USER) {
			settings.putVertexLocation(v, point);
		}
	}

	public FunctionGraphOptions getOptions() {
		return options;
	}

	public void setOptions(FunctionGraphOptions options) {
		this.options = options;
	}

	public void setGraphLayout(FGLayout layout) {
		this.graphLayout = layout;
	}

	@Override
	public FGLayout getLayout() {
		return graphLayout;
	}

	public FGVertex getVertexForAddress(Address address) {
		return getVertexForAddress(address, Collections.emptySet());
	}

	public FGVertex getVertexForAddress(Address address, Collection<FGVertex> ignore) {

		for (FGVertex v : getVertices()) {
			if (v.containsAddress(address) && !ignore.contains(v)) {
				return v;
			}
		}

		return null;
	}

	public void setProgramSelection(ProgramSelection selection) {
		for (FGVertex vertex : getVertices()) {
			vertex.setProgramSelection(selection);
		}
	}

	public void setProgramHighlight(ProgramSelection highlight) {
		for (FGVertex vertex : getVertices()) {
			vertex.setProgramHighlight(highlight);
		}
	}

	/**
	 * This method returns all vertices known by this class.  This differs from the vertices
	 * returned from {@link Graph} in that those may be a smaller subset of the collection returned
	 * here.  Due to graph manipulation after creation time (e.g., vertex grouping), the
	 * vertices known by the {@link Graph} may not include all vertices created at the same time
	 * as the graph and any others created by graph mutating operations <b>that are not the
	 * result of a grouping operation</b>.
	 *
	 * @return all vertices known by this class, visible or not.
	 */
	public Set<FGVertex> getUngroupedVertices() {
		return generateUngroupedVertices();
	}

	private Set<FGVertex> generateUngroupedVertices() {
		Set<FGVertex> ungrouped = new HashSet<>();
		for (FGVertex v : getVertices()) {
			accumulateUngroupedVertices(v, ungrouped);
		}
		return ungrouped;
	}

	private void accumulateUngroupedVertices(FGVertex v, Set<FGVertex> ungrouped) {
		if (!(v instanceof GroupedFunctionGraphVertex)) {
			ungrouped.add(v);
			return;
		}

		GroupedFunctionGraphVertex gv = (GroupedFunctionGraphVertex) v;
		Set<FGVertex> grouped = gv.getVertices();
		for (FGVertex child : grouped) {
			accumulateUngroupedVertices(child, ungrouped);
		}
	}

	/**
	 * This method returns all edges known by this class.  This differs from the edges 
	 * returned from {@link Graph} in that those may be a smaller subset of the collection returned
	 * here.  Due to graph manipulation after creation time (e.g., vertex grouping), the 
	 * edges known by the {@link Graph} may not include all edges created at the same time
	 * as the graph and any others created by graph mutating operations <b>that are not the 
	 * result of a grouping operation</b>.
	 * 
	 * @return all edges known by this class, visible or not.
	 */
	public Set<FGEdge> getUngroupedEdges() {
		return generateUngroupedEdges();
	}

	private Set<FGEdge> generateUngroupedEdges() {
		Set<FGEdge> ungrouped = new HashSet<>();
		for (FGVertex v : getVertices()) {
			accumulateUngroupedEdges(v, ungrouped);
		}
		ungrouped.addAll(getCurrentUngroupedEdges());
		return ungrouped;
	}

	private Collection<FGEdge> getCurrentUngroupedEdges() {

		Collection<FGEdge> result = new HashSet<>(getEdges());
		result.removeIf(e -> e.getStart() instanceof GroupedFunctionGraphVertex ||
			e.getEnd() instanceof GroupedFunctionGraphVertex);

		return result;
	}

	private void accumulateUngroupedEdges(FGVertex v, Set<FGEdge> ungrouped) {
		if (!(v instanceof GroupedFunctionGraphVertex)) {
			return;
		}

		GroupedFunctionGraphVertex gv = (GroupedFunctionGraphVertex) v;
		Set<FGEdge> gvEdges = gv.getUngroupedEdges();
		ungrouped.addAll(gvEdges);

		Set<FGVertex> grouped = gv.getVertices();
		for (FGVertex child : grouped) {
			accumulateUngroupedEdges(child, ungrouped);
		}
	}

	/**
	 * Returns history objects that represent previously grouped vertices and their description.
	 *
	 * @param vertex the vertex for which to check group belonging
	 * @return history objects that represent previously grouped vertices and their description.
	 */
	public GroupHistoryInfo getGroupHistory(FGVertex vertex) {
		return vertex.getGroupInfo();
	}

	public Collection<GroupHistoryInfo> getGroupHistory() {
		return Collections.unmodifiableSet(groupHistorySet);
	}

	public void setGroupHistory(Collection<GroupHistoryInfo> history) {
		this.groupHistorySet = new HashSet<>(history);
		for (GroupHistoryInfo info : history) {
			Set<FGVertex> infoVertices = info.getVertices();
			notifyVerticesOfGroupAssociation(infoVertices, info);
		}
	}

	public void removeFromGroupHistory(FGVertex vertex) {
		removeFromAllHistory(vertex);
	}

	/**
	 * A signal that the given group has been 'regrouped'.
	 *
	 * @param group the restored group
	 */
	public void groupRestored(GroupedFunctionGraphVertex group) {
		group.addGroupListener(groupListener);
	}

	/**
	 * A signal to this graph that a group has been created and added to the graph.
	 * @param group the ungrouped group
	 */
	public void groupAdded(GroupedFunctionGraphVertex group) {
		group.addGroupListener(groupListener);
		removeAssociatedGroups(group.getVertices());
	}

	/**
	 * A signal to this graph that a group has been ungrouped.
	 * @param group the ungrouped group
	 */
	public void groupRemoved(GroupedFunctionGraphVertex group) {
		group.removeGroupListener(groupListener);

		Set<FGVertex> groupVertices = group.getVertices();
		if (hasExistingGroupInfo(groupVertices)) {
			return;
		}

		GroupHistoryInfo info = new GroupHistoryInfo(this, group);
		notifyVerticesOfGroupAssociation(groupVertices, info);
		groupHistorySet.add(info);
	}

	private boolean hasExistingGroupInfo(Set<FGVertex> groupVertices) {
		Iterator<FGVertex> iterator = groupVertices.iterator();
		if (!iterator.hasNext()) {
			return false;// this should never happen
		}

		return iterator.next().getGroupInfo() != null;
	}

	/**
	 * Any time a vertex is grouped we want to make sure that any previous group affiliations
	 * are removed.
	 *
	 * @param groupVertices the new grouping of vertices
	 */
	private void removeAssociatedGroups(Collection<FGVertex> groupVertices) {
		for (FGVertex vertex : groupVertices) {
			Iterator<GroupHistoryInfo> iterator = groupHistorySet.iterator();
			for (; iterator.hasNext();) {
				GroupHistoryInfo info = iterator.next();
				if (!info.contains(vertex)) {
					continue;
				}

				//
				// NOTE: this code is setup such that for any given GroupHistoryInfo, if any of
				//       its internal vertices are *moved to a new group*, then the entire history
				//       is removed.  We could do something different, like simply remove the
				// 	     vertex from the history entry.  For now, the current code seems simpler
				//       in that once you alter an 'uncollapsed' group entry, the whole thing
				//       goes away.
				//
				// SUBNOTE: if a vertex is manually removed from an 'uncollapsed' group, then the
				//          history is NOT removed.
				//

				notifyVerticesOfGroupAssociation(info.getVertices(), null);
				iterator.remove();
			}
		}
	}

	private void removeFromAllHistory(FGVertex vertex) {
		boolean didRemove = false;
		Iterator<GroupHistoryInfo> iterator = groupHistorySet.iterator();
		for (; iterator.hasNext();) {
			GroupHistoryInfo info = iterator.next();
			if (!info.contains(vertex)) {
				continue;
			}

			info.removeVertex(vertex);
			didRemove = true;

			// we want to update the vertices associated with the info, which lets them update
			// their display with any new info
			notifyVerticesOfGroupAssociation(info.getVertices(), info);
		}

		if (didRemove) {
			notifyVerticesOfGroupAssociation(Arrays.asList(vertex), null);
		}
	}

	private void notifyVerticesOfGroupAssociation(Collection<FGVertex> groupVertices,
			GroupHistoryInfo groupInfo) {
		for (FGVertex vertex : groupVertices) {
			vertex.updateGroupAssociationStatus(groupInfo);
		}
	}

	public FGVertex getRootVertex() {
		return rootVertex;
	}

	public void setRootVertex(FGVertex rootVertex) {
		if (this.rootVertex != null) {
			throw new IllegalStateException("Cannot set the root vertex more than once!");
		}

		this.rootVertex = rootVertex;

		//
		// Unusual Code Alert!: we are putting into the settings an object that will pull the
		//                      group state of this graph at the time of saving.  This allows
		//                      other clients to clear the settings object, which will also
		//                      clear this lazy loading object, thus preventing saving.  This
		//                      differs a bit from the normal settings mechanism, which is based
		//                      upon either 1) updating the settings object as the data changes, or
		//                      2) pulling the data to save on command.
		//
		settings.putGroupedVertexSettings(this, new LazyGraphGroupSaveableXML(this));
		settings.putRegroupSettings(this, new LazyGraphRegroupSaveableXML(this));
	}

	public ProgramSelection getProgramSelectionForAllVertices() {
		AddressSet addresses = new AddressSet();
		for (FGVertex vertex : getVertices()) {
			ProgramSelection programSelection = vertex.getProgramSelection();
			if (programSelection == null) {
				continue;
			}
			addresses.add(programSelection);
		}

		return new ProgramSelection(addresses);
	}

	public Set<FGVertex> getEntryPoints() {
		HashSet<FGVertex> result = new LinkedHashSet<>();
		for (FGVertex vertex : getVertices()) {
			FGVertexType vertexType = vertex.getVertexType();
			if (vertex.isEntry()) {
				result.add(vertex);
			}
			else if (vertexType == FGVertexType.GROUP) {
				if (groupContainsEntry((GroupedFunctionGraphVertex) vertex)) {
					result.add(vertex);
				}
			}
		}
		return result;
	}

	private boolean groupContainsEntry(GroupedFunctionGraphVertex vertex) {
		Set<FGVertex> groupVertices = vertex.getVertices();
		for (FGVertex groupedVertex : groupVertices) {
			FGVertexType vertexType = groupedVertex.getVertexType();
			if (vertex.isEntry()) {
				return true;
			}
			else if (vertexType == FGVertexType.GROUP) {
				return groupContainsEntry((GroupedFunctionGraphVertex) groupedVertex);
			}
		}
		return false;
	}

	private boolean groupContainsExit(GroupedFunctionGraphVertex vertex) {
		Set<FGVertex> groupVertices = vertex.getVertices();
		for (FGVertex groupedVertex : groupVertices) {
			FGVertexType vertexType = groupedVertex.getVertexType();
			if (vertexType.isExit()) {
				return true;
			}
			else if (vertexType == FGVertexType.GROUP) {
				return groupContainsExit((GroupedFunctionGraphVertex) groupedVertex);
			}
		}
		return false;
	}

	public Set<FGVertex> getExitPoints() {
		HashSet<FGVertex> result = new LinkedHashSet<>();
		for (FGVertex vertex : getVertices()) {
			if (vertex.getVertexType().isExit()) {
				result.add(vertex);
			}
			else if (vertex.getVertexType() == FGVertexType.GROUP) {
				if (groupContainsExit((GroupedFunctionGraphVertex) vertex)) {
					result.add(vertex);
				}
			}
		}
		return result;
	}

	@Override
	public void dispose() {

		//
		// Let's go a bit overboard and help the garbage collector cleanup by nulling out
		// references and removing the data from Jung's graph
		//
		for (FGVertex vertex : getVertices()) {
			vertex.dispose();
		}

		vertices.clear();
		edges.clear();

		ungroupedEdges.clear();
		groupHistorySet.clear();
		ungroupedEdges = null;
		groupHistorySet = null;
		focusedVertex = null;
		rootVertex = null;
		settings = null;

		graphLayout.dispose();

		graphLayout = null;

		super.dispose();
	}

	@Override
	protected void verticesRemoved(Collection<FGVertex> removed) {

		removed.forEach(v -> {
			clearSavedVertexLocation(v);
		});

		super.fireVerticesRemoved(removed);
	}

	/**
	 * Creates a copy of the given graph <b>while using the exact vertex and edge instances
	 * used in the original graph</b>.
	 *
	 * @return the newly created graph
	 */
	@Override
	public FunctionGraph copy() {

		Collection<FGVertex> v = getVertices();
		Collection<FGEdge> e = getEdges();
		FunctionGraph newGraph = new FunctionGraph(getFunction(), getSettings(), v, e);
		newGraph.setOptions(getOptions());
		return newGraph;
	}

	/**
	 * A method to create dummy edges (with dummy vertices).  This is used to add entry and 
	 * exit vertices as needed when a user grouping operation has consumed the entries or exits.
	 * The returned edge will connect the current vertex containing the entry to a new dummy 
	 * vertex that is a source for the graph.   Calling this method does not mutate this graph.
	 * 
	 * @return the edge
	 */
	public Set<FGEdge> createDummySources() {

		Set<FGEdge> dummyEdges = new HashSet<>();
		Set<FGVertex> entries = getEntryPoints();
		for (FGVertex entry : entries) {
			AbstractFunctionGraphVertex abstractVertex = (AbstractFunctionGraphVertex) entry;
			FGController controller = abstractVertex.getController();
			ListingFunctionGraphVertex newEntry = new DummyListingFGVertex(controller,
				abstractVertex.getAddresses(), RefType.UNCONDITIONAL_JUMP, true);
			newEntry.setVertexType(FGVertexType.ENTRY);
			FGVertex groupVertex = getVertexForAddress(entry.getVertexAddress());
			FGEdgeImpl edge =
				new FGEdgeImpl(newEntry, groupVertex, RefType.UNCONDITIONAL_JUMP, options);
			dummyEdges.add(edge);
		}

		return dummyEdges;
	}

	/**
	 * A method to create dummy edges (with dummy vertices).  This is used to add entry and 
	 * exit vertices as needed when a user grouping operation has consumed the entries or exits.
	 * The returned edge will connect the current vertex containing the exit to a new dummy 
	 * vertex that is a sink for the graph.   Calling this method does not mutate this graph.
	 * 
	 * @return the edge
	 */
	public Set<FGEdge> createDummySinks() {

		Set<FGEdge> dummyEdges = new HashSet<>();
		Set<FGVertex> exits = getExitPoints();
		for (FGVertex exit : exits) {
			AbstractFunctionGraphVertex abstractVertex = (AbstractFunctionGraphVertex) exit;
			FGController controller = abstractVertex.getController();
			ListingFunctionGraphVertex newExit = new ListingFunctionGraphVertex(controller,
				abstractVertex.getAddresses(), RefType.UNCONDITIONAL_JUMP, true);
			newExit.setVertexType(FGVertexType.EXIT);
			FGVertex groupVertex = getVertexForAddress(exit.getVertexAddress());
			FGEdgeImpl edge =
				new FGEdgeImpl(groupVertex, newExit, RefType.UNCONDITIONAL_JUMP, options);
			dummyEdges.add(edge);
		}

		return dummyEdges;
	}

//==================================================================================================
// Overridden Methods
//==================================================================================================

	@Override
	public GDirectedGraph<FGVertex, FGEdge> emptyCopy() {
		return new FunctionGraph(function, settings);
	}

}
