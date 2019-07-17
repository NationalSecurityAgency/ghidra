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
package ghidra.graph.graphs;

import static util.CollectionUtils.asList;

import java.util.*;

import com.google.common.base.Predicate;
import com.google.common.collect.Iterators;

import edu.uci.ics.jung.graph.util.EdgeType;
import edu.uci.ics.jung.graph.util.Pair;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import util.CollectionUtils;
import utility.function.Callback;

/**
 * A graph implementation that allows clients to mark vertices and edges as filtered.  When
 * filtered, a vertex is removed from this graph, but kept around for later unfiltering. Things
 * of note:
 * <UL>
 * 		<LI>As vertices are filtered, so to will be their edges
 * 		</LI>
 * 		<LI>If additions are made to the graph while it is filtered, the new additions will
 *          not be added to the current graph, but will be kept in the background for later 
 *          restoring
 * 		</LI>
 *  		<LI>
 * 		</LI>
 * </UL>
 *
 * <P>Implementation Note: this class engages in some odd behavior when removals and additions
 * are need to this graph.  A distinction is made between events that are generated from 
 * external clients and those that happen due to filtering and restoring.  This distinction
 * allows this class to know when to update this graph, based upon whether or not data has
 * been filtered.   Implementation of this is achieved by using a flag.  Currently, this flag
 * is thread-safe.  If this graph is to be multi-threaded (such as if changes are to be 
 * made by multiple threads, then this update flag will have to be revisited to ensure thread
 * visibility. 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public abstract class FilteringVisualGraph<V extends VisualVertex, E extends VisualEdge<V>>
		extends DefaultVisualGraph<V, E> {

	/**
	 * A graph that always holds the unfiltered, complete graph data.  We use this to restore
	 * filtered items.
	 */
	private UnfilteredGraph completeGraph = new UnfilteredGraph();

	// a flag to track the stack of updates so we know when to ignore events
	private int internalCallCount;

	public void filterVertices(Collection<V> toFilter) {

		for (V v : toFilter) {
			removeVertexFromView(v);
		}
	}

	public void filterEdges(Collection<E> toFilter) {
		for (E e : toFilter) {
			removeEdgeFromView(e);
		}
	}

	/**
	 * Restores the given filtered vertices into the graph.  This will only happen if both
	 * endpoints are in the graph.
	 * 
	 * @param toUnfilter the edges to restore
	 */
	public void unfilterVertices(Collection<V> toUnfilter) {
		maybeRestoreVertices(toUnfilter);
		maybeRestoreRelatedEdges(toUnfilter);
	}

	/**
	 * Restores the given filtered edges into the graph.  This will only happen if both
	 * endpoints are in the graph.
	 * 
	 * @param toUnfilter the edges to restore
	 */
	public void unfilterEdges(Collection<E> toUnfilter) {
		maybeRestoreEdges(toUnfilter);
	}

	public Iterator<V> getAllVertices() {
		return completeGraph.getVertices().iterator();
	}

	public Iterator<E> getAllEdges() {
		return completeGraph.getEdges().iterator();
	}

	public Iterator<V> getFilteredVertices() {

		// a vertex is 'filtered' if it is in the complete graph, but not in the current graph
		Predicate<? super V> isFiltered = v -> {
			return !containsVertex(v) && completeGraph.containsVertex(v);
		};
		return Iterators.filter(getAllVertices(), isFiltered);
	}

	public Iterator<E> getFilteredEdges() {

		// an edge is 'filtered' if it is in the complete graph, but not in the current graph
		Predicate<? super E> isFiltered = e -> {
			return !containsEdge(e) && completeGraph.containsEdge(e);
		};
		return Iterators.filter(getAllEdges(), isFiltered);
	}

	public Iterator<V> getUnfilteredVertices() {
		// a vertex is 'unfiltered' if it is in the current graph
		return getVertices().iterator();
	}

	public Iterator<E> getUnfilteredEdges() {
		// an edge is 'unfiltered' if it is in the current graph
		return getEdges().iterator();
	}

	public boolean isFiltered() {
		if (completeGraph.getVertexCount() != getVertexCount()) {
			return true;
		}

		return completeGraph.getEdgeCount() != getEdgeCount();
	}

	public void clearFilter() {
		vertices.clear();
		edges.clear();

		restoreAllVertices();
		restoreAllEdges();
	}

	/**
	 * Returns all vertices that are reachable by the given vertices.
	 * 
	 * <P>This method is needed if you wish to find relationships that have been filtered 
	 * out.
	 * 
	 * @param sourceVertices the vertices for which to find the other reachable vertices
	 * @return the reachable vertices
	 */
	public Set<V> getAllReachableVertices(Set<V> sourceVertices) {
		Set<E> relatedEdges = new HashSet<>();
		for (V v : sourceVertices) {
			relatedEdges.addAll(GraphAlgorithms.getEdgesFrom(completeGraph, asList(v), true));
			relatedEdges.addAll(GraphAlgorithms.getEdgesFrom(completeGraph, asList(v), false));
		}

		return GraphAlgorithms.toVertices(relatedEdges);
	}

	/**
	 * Returns all edges connected to the given vertices.
	 * 
	 * <P>This method is needed if you wish to find relationships that have been filtered 
	 * out.
	 * 
	 * @param sourceVertices the vertices for which to get the edges
	 * @return the reachable edges
	 */
	public Set<E> getAllEdges(Set<V> sourceVertices) {

		Set<E> connectedEdges = new HashSet<>();
		for (V vertex : sourceVertices) {
			connectedEdges.addAll(CollectionUtils.nonNull(completeGraph.getIncidentEdges(vertex)));
		}
		return connectedEdges;
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void restoreAllVertices() {
		Collection<V> allVertices = completeGraph.getVertices();
		performInternalUpdate(() -> {
			allVertices.forEach(v -> addVertex(v));
		});
	}

	private void restoreAllEdges() {
		Collection<E> allEdges = completeGraph.getEdges();
		performInternalUpdate(() -> {
			allEdges.forEach(e -> addEdge(e));
		});
	}

	private void maybeRestoreVertices(Collection<V> toRestore) {
		for (V v : toRestore) {
			if (!completeGraph.containsVertex(v)) {
				// don't restore vertices that were never added through the normal interface
				continue;
			}

			performInternalUpdate(() -> super.addVertex(v));
		}
	}

	private void maybeRestoreEdges(Collection<E> toUnfilter) {
		for (E e : toUnfilter) {

			if (!completeGraph.containsEdge(e)) {
				// don't restore edges that were never added through the normal interface
				continue;
			}

			V start = e.getStart();
			V end = e.getEnd();

			// only add the edge if both vertices are in the graph
			if (containsVertex(start) && containsVertex(end)) {
				performInternalUpdate(() -> super.addEdge(e));
			}
		}
	}

	private void maybeRestoreRelatedEdges(Collection<V> toUnfilter) {

		for (V v : toUnfilter) {

			Collection<E> vertexEdges = completeGraph.getIncidentEdges(v);
			if (vertexEdges == null) {
				continue;
			}

			for (E e : vertexEdges) {
				V start = e.getStart();
				V end = e.getEnd();

				// only add the edge if both vertices are in the graph
				if (containsVertex(start) && containsVertex(end)) {
					performInternalUpdate(() -> super.addEdge(e));
				}
			}
		}
	}

	/**
	 * This method is to be called internally to remove a vertex from this graph, but not the
	 * underlying 'complete graph'.
	 * 
	 * @param v the vertex
	 */
	private void removeVertexFromView(V v) {
		performInternalUpdate(() -> super.removeVertex(v));
	}

	/**
	 * This method is to be called internally to remove an edge from this graph, but not the
	 * underlying 'complete graph'.
	 * 
	 * @param e the edge
	 */
	private void removeEdgeFromView(E e) {
		performInternalUpdate(() -> super.removeEdge(e));
	}

	private void performInternalUpdate(Callback c) {
		internalCallCount++;
		try {
			c.call();
		}
		finally {
			internalCallCount--;
		}
	}

	/**
	 * Performs a remove only if this graph is not in the process of an internal update
	 * @param c the callback to perform the remove
	 */
	private void maybePerformRemove(Callback c) {
		if (isInternalUpdate()) {
			// 
			// Ignore internal updates.   
			// We have to know when a remover operation should update us vs our 'complete graph'. 
			// When the client calls our public API, we wish to update our 'complete graph', when
			// we trigger a filter operation to remove content from us, we do NOT want to 
			// update the 'complete graph', as it stores those removed items for later 
			// retrieval.
			//
			return;
		}

		c.call();
	}

	private boolean isInternalUpdate() {
		return internalCallCount > 0;
	}

	private void maybePerformAdd(Callback c) {
		if (isInternalUpdate()) {

			// This is the opposite of removes--we always wish to add vertices when we are in
			// the processes of restoring filtered vertices
			c.call();
			return;
		}

		// an outside API addition--only add to us if we are not filtered
		if (isFiltered()) {
			return;
		}

		// O.K., we are going to perform the add--now we have to mark the update as internal
		// so all subsequent additions work (e.g., when adding a new edge, the vertices also
		// get added)
		performInternalUpdate(c);
	}

//==================================================================================================
// Overridden Methods
//==================================================================================================	

	@Override
	public boolean removeVertex(V v) {
		boolean removed = super.removeVertex(v);
		maybePerformRemove(() -> completeGraph.removeVertex(v));
		return removed;
	}

	@Override
	public void removeVertices(Iterable<V> verticesToRemove) {
		List<E> edgesToRemove = new LinkedList<>();
		List<V> removed = new LinkedList<>();
		for (V v : verticesToRemove) {

			if (super.containsVertex(v)) {
				edgesToRemove.addAll(getIncidentEdges(v));
				removed.add(v);
				super.removeVertex(v);
			}
		}

		maybePerformRemove(() -> {
			completeGraph.removeVertices(verticesToRemove);
			completeGraph.removeEdges(edgesToRemove);
		});

		verticesRemoved(removed);
	}

	@Override
	public boolean removeEdge(E e) {
		boolean removed = super.removeEdge(e);

		List<E> asList = Arrays.asList(e);
		if (removed) {
			fireEdgesRemoved(asList);
		}

		maybePerformRemove(() -> completeGraph.removeEdge(e));

		return removed;
	}

	@Override
	public void removeEdges(Iterable<E> toRemove) {
		toRemove.forEach(e -> super.removeEdge(e));

		super.removeEdges(toRemove);

		maybePerformRemove(() -> {
			completeGraph.removeEdges(toRemove);
		});

		fireEdgesRemoved(toRemove);
	}

	@Override
	public boolean addVertex(V v) {
		maybePerformAdd(() -> super.addVertex(v));
		return completeGraph.addVertex(v);
	}

	@Override
	public void addEdge(E e) {
		maybePerformAdd(() -> super.addEdge(e));
		completeGraph.addEdge(e);
	}

	@Override
	public boolean addEdge(E e, Pair<? extends V> endpoints, EdgeType type) {
		maybePerformAdd(() -> super.addEdge(e, endpoints, type));
		return completeGraph.addEdge(e, endpoints, type);
	}

	@Override
	public boolean addEdge(E e, Collection<? extends V> edgeVertices) {
		maybePerformAdd(() -> super.addEdge(e, edgeVertices));
		return completeGraph.addEdge(e, edgeVertices);
	}

	@Override
	public boolean addEdge(E e, Collection<? extends V> edgeVertices, EdgeType type) {
		maybePerformAdd(() -> super.addEdge(e, edgeVertices, type));
		return completeGraph.addEdge(e, edgeVertices, type);
	}

	@Override
	public boolean addEdge(E e, V v1, V v2) {
		maybePerformAdd(() -> super.addEdge(e, v1, v2));
		return completeGraph.addEdge(e, v1, v2);
	}

	@Override
	public boolean addEdge(E e, V v1, V v2, EdgeType edgeType) {
		maybePerformAdd(() -> super.addEdge(e, v1, v2, edgeType));
		return completeGraph.addEdge(e, v1, v2, edgeType);
	}

	@Override
	public boolean addEdge(E e, Pair<? extends V> endpoints) {
		maybePerformAdd(() -> super.addEdge(e, endpoints));
		return completeGraph.addEdge(e, endpoints);
	}

	@Override
	public void dispose() {
		completeGraph.dispose();
		vertices.clear();
		edges.clear();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	private class UnfilteredGraph extends DefaultVisualGraph<V, E> {

		@Override
		public VisualGraphLayout<V, E> getLayout() {
			// stub
			return null;
		}

		@Override
		public DefaultVisualGraph<V, E> copy() {
			// stub
			return null;
		}

		@Override
		public void dispose() {
			vertices.clear();
			edges.clear();
		}
	}
}
