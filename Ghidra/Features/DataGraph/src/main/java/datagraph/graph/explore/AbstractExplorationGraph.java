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
package datagraph.graph.explore;

import java.util.*;

import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.layout.VisualGraphLayout;

/**
 * Base graph for exploration graphs. An exploration graph is a graph that typically starts with
 * just one vertex, but then is interactively expanded with additional vertices by exploring
 * incoming and outgoing links.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public abstract class AbstractExplorationGraph<V extends EgVertex, E extends EgEdge<V>>
		extends DefaultVisualGraph<V, E> {

	private V root;
	private EgGraphLayout<V, E> layout;

	/**
	 * Constructor
	 * @param root the initial vertex in the graph. All nodes in the graph must be connected directly
	 * or indirectly to this vertex.
	 */
	public AbstractExplorationGraph(V root) {
		this.root = root;
		addVertex(root);
	}

	/**
	 * {@return the original source vertex for this graph.}
	 */
	public V getRoot() {
		return root;
	}

	public void setLayout(EgGraphLayout<V, E> layout) {
		this.layout = layout;
	}

	@Override
	public VisualGraphLayout<V, E> getLayout() {
		return layout;
	}

	/**
	 * {@return a set of all vertices that can trace a source path back to the given vertex. In
	 * other words either getSource() or getSource().getSource(), and so on, on the given vertex.}
	 * @param source the vertex to see if a vertex is a descendant from.
	 */
	public Set<V> getDescendants(V source) {
		Set<V> descendents = new HashSet<>();
		getDescendants(source, descendents);
		return descendents;
	}

	/**
	 * Sets the root of this graph to the new root.
	 * @param newRoot the new source root for the graph
	 */
	public void setRoot(V newRoot) {

		// First clear out the source from each vertex to so they can be reassigned as we
		// explore from the new root. We will use a null source to indicate the vertex hasn't been
		// processed.
		getVertices().forEach(v -> v.setSource(null));

		// temporarily set the root source to mark it as processed
		newRoot.setSource(newRoot);

		// create a queue of vertices to process and prime with the new root
		Queue<V> vertexQueue = new LinkedList<>();
		vertexQueue.add(newRoot);

		// follow edges assigning new source vertices 
		assignSource(vertexQueue);

		// set the root source to null to indicate it is the root source vertex.
		newRoot.setSource(null);

		this.root = newRoot;
	}

	private void getDescendants(V source, Set<V> descendents) {
		for (E e : getOutEdges(source)) {
			V end = e.getEnd();
			if (source.equals(end.source)) {
				descendents.add(end);
				getDescendants(end, descendents);
			}
		}
		for (E e : getInEdges(source)) {
			V start = e.getStart();
			if (source.equals(start.source)) {
				descendents.add(start);
				getDescendants(start, descendents);
			}
		}
	}

	private void assignSource(Queue<V> vertexQueue) {
		while (!vertexQueue.isEmpty()) {
			V remove = vertexQueue.remove();
			processEdges(remove, vertexQueue);
		}
	}

	private void processEdges(V v, Queue<V> vertexQueue) {
		Collection<E> outEdges = getOutEdges(v);
		for (EgEdge<V> edge : outEdges) {
			V next = edge.getEnd();
			if (next.getSourceVertex() == null) {
				next.setSource(v);
				vertexQueue.add(next);
			}
		}
		Collection<E> inEdges = getInEdges(v);
		for (E e : inEdges) {
			V previous = e.getStart();
			if (previous.getSourceVertex() == null) {
				previous.setSource(v);
				vertexQueue.add(previous);
			}
		}
	}
}
