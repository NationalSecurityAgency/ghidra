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
package ghidra.graph.jung;

import edu.uci.ics.jung.graph.DirectedSparseGraph;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;

public class JungDirectedGraph<V, E extends GEdge<V>> extends DirectedSparseGraph<V, E>
		implements GDirectedGraph<V, E> {

	@Override
	public void addEdge(E e) {
		super.addEdge(e, e.getStart(), e.getEnd());
	}

	@Override
	public void removeVertices(Iterable<V> toRemove) {
		toRemove.forEach(v -> super.removeVertex(v));
	}

	@Override
	public void removeEdges(Iterable<E> toRemove) {
		toRemove.forEach(e -> super.removeEdge(e));
	}

	@Override
	public boolean containsEdge(V from, V to) {
		return findEdge(from, to) != null;
	}

	@Override
	public GDirectedGraph<V, E> emptyCopy() {
		JungDirectedGraph<V, E> newGraph = new JungDirectedGraph<>();
		return newGraph;
	}

	@Override
	public GDirectedGraph<V, E> copy() {
		JungDirectedGraph<V, E> newGraph = new JungDirectedGraph<>();

		for (V v : vertices.keySet()) {
			newGraph.addVertex(v);
		}

		for (E e : edges.keySet()) {
			newGraph.addEdge(e);
		}

		return newGraph;
	}

	@Override
	public boolean isEmpty() {
		return getVertexCount() == 0;
	}
}
