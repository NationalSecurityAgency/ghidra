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

import static util.CollectionUtils.nonNull;

import java.awt.Point;
import java.awt.geom.Point2D;
import java.util.*;

import org.apache.commons.collections4.IterableUtils;

import com.google.common.collect.Iterables;

import edu.uci.ics.jung.graph.util.EdgeType;
import edu.uci.ics.jung.graph.util.Pair;
import ghidra.graph.VisualGraph;
import ghidra.graph.event.VisualGraphChangeListener;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * A default {@link VisualGraph} that implements basic setup for things like event processing.
 * 
 * <P>Notes:
 * <UL>
 * 	<LI><U>Selected Vertices and the Focused Vertex</U> - 
 * 		there can be multiple selected vertices, but only a single focused vertex.  
 *      <B>{@link #getSelectedVertices()} will return both 
 *      the selected vertices or	the focused vertex if there are no vertices selected.</B>
 *  </LI>
 *  <LI>Clicking a single vertex will focus it.  Control-clicking multiple vertices will
 *  		cause them all to be selected, with no focused vertex.
 * 	</LI>
 *  <LI><U>Rendering Edges</U> - edges are rendered with or without articulations if 
 *         they have them.  This is built-in to the default graphing edge renderer.  
 *         Some layouts require custom edge rendering and will provide their own 
 *         renderer as needed.
 *  </LI>
 * </UL>
 *
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public abstract class DefaultVisualGraph<V extends VisualVertex, 
										 E extends VisualEdge<V>>
		extends JungDirectedVisualGraph<V, E> {
//@formatter:on

	protected V focusedVertex;

	private Set<V> selectedVertices = Collections.emptySet();

	private WeakSet<VisualGraphChangeListener<V, E>> changeListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	@Override
	public abstract DefaultVisualGraph<V, E> copy();

	@Override
	public void setSelectedVertices(Set<V> selectedVertices) {
		clearFocusedVertex();
		setVerticesSelected(this.selectedVertices, false);

		this.selectedVertices = selectedVertices;
		setVerticesSelected(selectedVertices, true);
	}

	private void setVerticesSelected(Set<V> vertices, boolean selected) {
		for (V vertex : vertices) {
			vertex.setSelected(selected);
		}
	}

	@Override
	public void setVertexFocused(V vertex, boolean focused) {
		clearSelectedVertices();

		vertex.setFocused(focused);

		if (focused) {
			vertex.setSelected(focused);
			focusedVertex = vertex;
		}
	}

	@Override
	public V getFocusedVertex() {
		return focusedVertex;
	}

	private void clearFocusedVertex() {
		if (focusedVertex == null) {
			return;
		}

		focusedVertex.setFocused(false);
		focusedVertex.setSelected(false);
		focusedVertex = null;// can only have one 'focused' vertex at a time
	}

	@Override
	public void clearSelectedVertices() {
		clearFocusedVertex();
		setVerticesSelected(selectedVertices, false);
		selectedVertices.clear();
	}

	@Override
	public Set<V> getSelectedVertices() {
		//
		// Implementation note: the 'focusedVertex' is considered selected.  A selected vertex
		//                      will be considered focused when it is the only selected vertex.
		//

		// quick check for no selected vertices
		boolean hasGroupSelection = selectedVertices.size() > 0;
		if (!hasGroupSelection && focusedVertex == null) {
			return Collections.emptySet();
		}

		// there is some vertex selected...
		if (hasGroupSelection) {
			return new HashSet<>(selectedVertices);
		}

		// no group selection, there must be a focused vertex
		Set<V> set = new HashSet<>();
		set.add(focusedVertex);
		return set;
	}

	@Override
	public void vertexLocationChanged(V v, Point point, ChangeType type) {
		// stub
	}

	public void dispose() {

		selectedVertices.clear();
		selectedVertices = Collections.emptySet();

		changeListeners.clear();
		changeListeners = null;
	}

	/*
	 * We need to set the initial location for each vertex so that the various UI graph 
	 * algorithms can work correctly.
	 */
	protected void initializeLocation(V v) {
		VisualGraphLayout<V, E> layout = getLayout();
		if (layout == null) {
			// we cannot initialize our locations without a layout; this should be set after
			// the graph and layout have both been created
			return;
		}

		Point2D location = layout.apply(v);
		v.setLocation(location);
	}

	/**
	 * A convenience method to combine retrieval of in and out edges for the given vertex
	 * 
	 * @param v the vertex
	 * @return the edges
	 */
	public Iterable<E> getAllEdges(V v) {

		Collection<E> in = getInEdges(v);
		Collection<E> out = getOutEdges(v);
		Iterable<E> concatenated = Iterables.concat(in, out);
		return concatenated;
	}

	/**
	 * Returns all edges shared between the two given vertices
	 * 
	 * @param start the start vertex
	 * @param end the end vertex
	 * @return the edges
	 */
	public Iterable<E> getEdges(V start, V end) {

		Collection<E> outs = nonNull(getOutEdges(start));
		Collection<E> ins = nonNull(getInEdges(end));
		Set<E> unique = new HashSet<>();
		unique.addAll(outs);
		unique.addAll(ins);

		Iterable<E> filtered = IterableUtils.filteredIterable(unique, e -> {
			return e.getStart().equals(start) && e.getEnd().equals(end);
		});
		return filtered;
	}

//==================================================================================================
// Overridden Methods / Listener Methods
//==================================================================================================

	@Override
	public boolean addVertex(V v) {

		boolean added = super.addVertex(v);
		if (added) {
			initializeLocation(v);
			verticesAdded(Arrays.asList(v));
		}

		return added;
	}

	@Override
	public boolean addEdge(E edge, Pair<? extends V> endpoints, EdgeType edgeType) {
		boolean added = super.addEdge(edge, endpoints, edgeType);
		if (added) {
			fireEdgesAdded(Arrays.asList(edge));
		}
		return added;
	}

	@Override
	public boolean removeVertex(V v) {
		boolean removed = super.removeVertex(v);
		if (removed) {
			verticesRemoved(Arrays.asList(v));
		}
		return removed;
	}

	@Override
	public void removeVertices(Iterable<V> toRemove) {
		List<V> removed = new ArrayList<>();
		for (V v : toRemove) {
			if (super.removeVertex(v)) {
				removed.add(v);
			}
		}

		verticesRemoved(removed);
	}

	@Override
	public boolean removeEdge(E edge) {
		boolean removed = super.removeEdge(edge);
		if (removed) {
			fireEdgesRemoved(Arrays.asList(edge));
		}
		return removed;
	}

	/**
	 * Called after one or more vertices have been added.  The callback will happen after
	 * all additions have taken place.  This is an extension point for subclasses.
	 * 
	 * @param added the added vertices
	 */
	protected void verticesAdded(Collection<V> added) {
		fireVerticesAdded(added);
	}

	/**
	 * Called after one or more vertices have been removed.  The callback will happen after
	 * all removals have taken place.  This is an extension point for subclasses.
	 * 
	 * @param removed the removed vertices
	 */
	protected void verticesRemoved(Collection<V> removed) {
		fireVerticesRemoved(removed);
	}

	protected void fireVerticesRemoved(Collection<V> removed) {
		if (removed.isEmpty()) {
			return;
		}
		changeListeners.forEach(l -> l.verticesRemoved(removed));
	}

	protected void fireVerticesAdded(Collection<V> added) {
		if (added.isEmpty()) {
			return;
		}
		changeListeners.forEach(l -> l.verticesAdded(added));
	}

	protected void fireEdgesRemoved(Iterable<E> removed) {
		if (IterableUtils.isEmpty(removed)) {
			return;
		}
		changeListeners.forEach(l -> l.edgesRemoved(removed));
	}

	protected void fireEdgesAdded(Iterable<E> added) {
		if (IterableUtils.isEmpty(added)) {
			return;
		}
		changeListeners.forEach(l -> l.edgesAdded(added));
	}

	@Override
	public void addGraphChangeListener(VisualGraphChangeListener<V, E> l) {
		changeListeners.add(l);
	}

	@Override
	public void removeGraphChangeListener(VisualGraphChangeListener<V, E> l) {
		changeListeners.remove(l);
	}
}
