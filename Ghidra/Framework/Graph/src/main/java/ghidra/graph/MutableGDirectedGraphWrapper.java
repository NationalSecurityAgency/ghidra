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
package ghidra.graph;

import java.util.*;
import java.util.function.BiFunction;
import java.util.function.Function;

import ghidra.graph.jung.JungDirectedGraph;
import util.CollectionUtils;

/**
 * A class that can wrap a {@link GDirectedGraph} and allows for vertex and edge additions 
 * without changing the underlying graph.
 *
 * <P><B>Warning: </B>As mentioned above, this graph is meant for additive operations.  In its
 * current form, removal operations will not work.  To facilitate removals, this class will 
 * have to be updated to track removed vertices and edges, using them to correctly report
 * the state of the graph for methods like {@link #containsVertex(Object)} and 
 *  {@link #containsEdge(GEdge)}.
 *
 * <P>Implementation Note: there is some 'magic' in this class to add 'dummy' vertices to the
 * graph.  To facilitate this, the mutated graph in this class does not have the <code>V</code>
 * type, but rather is typed on Object.   This means that this class can only be used 
 * generically, with templated types (like by algorithms and such).  Any usage of this class
 * that expects concrete implementations to be returned can trigger ClassCastExceptions.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class MutableGDirectedGraphWrapper<V, E extends GEdge<V>> implements GDirectedGraph<V, E> {

	private GDirectedGraph<V, E> delegate;

	private GDirectedGraph<Object, DefaultGEdge<Object>> mutatedGraph;

	public MutableGDirectedGraphWrapper(GDirectedGraph<V, E> delegate) {
		this.delegate = delegate;
		this.mutatedGraph = new JungDirectedGraph<>();
	}

	public V addDummyVertex(String name) {

		@SuppressWarnings("unchecked")
		V v = (V) new DummyVertex(name);
		mutatedGraph.addVertex(v);
		return v;
	}

	public boolean isDummy(V v) {
		return v instanceof DummyVertex;
	}

	public boolean isDummy(E e) {
		return e instanceof DummyEdge;
	}

	@SuppressWarnings("unchecked")
	public E addDummyEdge(V start, V end) {
		DummyEdge e = new DummyEdge(start, end);
		mutatedGraph.addEdge(e);
		return (E) e;
	}

	@Override
	public boolean addVertex(V v) {
		return mutatedGraph.addVertex(v);
	}

	@Override
	public boolean removeVertex(V v) {
		if (delegate.containsVertex(v)) {
			// not sure if this is the right behavior
			throw new UnsupportedOperationException();
		}
		return mutatedGraph.removeVertex(v);
	}

	@Override
	public void removeVertices(Iterable<V> vertices) {
		vertices.forEach(v -> removeVertex(v));
	}

	@Override
	public void removeEdges(Iterable<E> edges) {
		edges.forEach(e -> removeEdge(e));
	}

	@SuppressWarnings("unchecked")
	@Override
	public void addEdge(E e) {
		if (e instanceof DefaultGEdge) {
			mutatedGraph.addEdge((DefaultGEdge<Object>) e);
			return;
		}

		V start = e.getStart();
		V end = e.getEnd();
		addDummyEdge(start, end);
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean removeEdge(E e) {
		if (delegate.containsEdge(e)) {
			// not sure if this is the right behavior
			throw new UnsupportedOperationException();
		}
		return mutatedGraph.removeEdge((DefaultGEdge<Object>) e);
	}

	@Override
	public Collection<V> getVertices() {
		Set<V> set = callOnBothGraphs(GDirectedGraph::getVertices);
		return set;
	}

	@Override
	public Collection<E> getEdges() {
		Set<E> set = callOnBothGraphs(GDirectedGraph::getEdges);
		return set;
	}

	@Override
	public boolean containsVertex(V v) {
		return delegate.containsVertex(v) || mutatedGraph.containsVertex(v);
	}

	@SuppressWarnings("unchecked")
	@Override
	public boolean containsEdge(E e) {
		return delegate.containsEdge(e) || mutatedGraph.containsEdge((DefaultGEdge<Object>) e);
	}

	@Override
	public boolean containsEdge(V from, V to) {
		return delegate.containsEdge(from, to) || mutatedGraph.containsEdge(from, to);
	}

	@Override
	public E findEdge(V start, V end) {
		@SuppressWarnings("unchecked")
		E e = (E) mutatedGraph.findEdge(start, end);
		if (e != null) {
			return e;
		}
		return delegate.findEdge(start, end);
	}

	@Override
	public boolean isEmpty() {
		return getVertexCount() == 0;
	}

	@Override
	public int getVertexCount() {
		return delegate.getVertexCount() + mutatedGraph.getVertexCount();
	}

	@Override
	public int getEdgeCount() {
		return delegate.getEdgeCount() + mutatedGraph.getEdgeCount();
	}

	@Override
	public Collection<E> getInEdges(V v) {
		Set<E> set = callOnBothGraphs(GDirectedGraph::getInEdges, v);
		return set;
	}

	@Override
	public Collection<E> getOutEdges(V v) {
		Set<E> set = callOnBothGraphs(GDirectedGraph::getOutEdges, v);
		return set;
	}

	@Override
	public Collection<V> getPredecessors(V v) {
		Set<V> set = callOnBothGraphs(GDirectedGraph::getPredecessors, v);
		return set;
	}

	@Override
	public Collection<V> getSuccessors(V v) {
		Set<V> set = callOnBothGraphs(GDirectedGraph::getSuccessors, v);
		return set;
	}

	@Override
	public GDirectedGraph<V, E> copy() {
		MutableGDirectedGraphWrapper<V, E> copy =
			new MutableGDirectedGraphWrapper<>(delegate.copy());

		for (Object v : mutatedGraph.getVertices()) {
			copy.mutatedGraph.addVertex(v);
		}

		for (DefaultGEdge<Object> e : mutatedGraph.getEdges()) {
			copy.mutatedGraph.addEdge(e);
		}

		return copy;
	}

	@Override
	public GDirectedGraph<V, E> emptyCopy() {
		return delegate.emptyCopy();
	}

	@SuppressWarnings("unchecked")
	private <R> Set<R> callOnBothGraphs(Function<GDirectedGraph<V, E>, Collection<R>> f) {
		Set<R> set = new HashSet<>();
		set.addAll(CollectionUtils.nonNull(f.apply((GDirectedGraph<V, E>) mutatedGraph)));
		set.addAll(CollectionUtils.nonNull(f.apply(delegate)));
		return set;
	}

	@SuppressWarnings("unchecked")
	private <R> Set<R> callOnBothGraphs(BiFunction<GDirectedGraph<V, E>, V, Collection<R>> f, V v) {
		Set<R> set = new HashSet<>();
		set.addAll(CollectionUtils.nonNull(f.apply((GDirectedGraph<V, E>) mutatedGraph, v)));
		set.addAll(CollectionUtils.nonNull(f.apply(delegate, v)));
		return set;
	}

	private static class DummyVertex {

		private String name;

		public DummyVertex(String name) {
			this.name = name;
		}

		@Override
		public String toString() {
			return "Dummy " + name;
		}
	}

	public static class DummyEdge extends DefaultGEdge<Object> {
		public DummyEdge(Object start, Object end) {
			super(start, end);
		}
	}

}
