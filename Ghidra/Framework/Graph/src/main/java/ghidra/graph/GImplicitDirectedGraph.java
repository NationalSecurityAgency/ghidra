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

/**
 * A directed graph that need not be constructed explicitly
 * 
 * <P>Instead, the graph is constructed (and usually cached) as it is explored. For instance, if
 * a path searching algorithm is being applied, incident edges and neighboring nodes need not
 * be computed if they're never visited. This allows conceptually large (even infinite) graphs to
 * be represented. A graph algorithm can be applied so long as it supports this interface, and
 * does not attempt to exhaust an infinite graph.
 * 
 * @param <V> the type of vertices
 * @param <E> the type of edges
 */
public interface GImplicitDirectedGraph<V, E extends GEdge<V>> {
	/**
	 * Compute the incident edges that end at the given vertex
	 * 
	 * (Optional operation)
	 * 
	 * NOTE: This method ought to return cached results if available
	 * NOTE: As part of computing in-edges, this method will also provide predecessors
	 * 
	 * @param v the destination vertex
	 * @return the in-edges to the given vertex
	 */
	public Collection<E> getInEdges(V v);

	/**
	 * Compute the incident edges that start at the given vertex
	 * 
	 * NOTE: This method ought to return cached results if available
	 * NOTE: As part of computing out-edges, this method will also provide successors
	 * 
	 * @param v the source vertex
	 * @return the out-edges from the given vertex
	 */
	public Collection<E> getOutEdges(V v);

	/**
	 * Compute a vertex's predecessors
	 * 
	 * The default implementation computes this from the in-edges
	 * 
	 * NOTE: If a non-default implementation is provided, it ought to return cached results if
	 * available
	 * 
	 * @param v the destination vertex
	 * @return the predecessors
	 */
	public default Collection<V> getPredecessors(V v) {
		Set<V> result = new LinkedHashSet<>();
		for (E edge : getInEdges(v)) {
			result.add(edge.getStart());
		}
		return result;
	}

	/**
	 * Compute a vertex's successors
	 * 
	 * The default implementation compute this from the out-edges
	 * 
	 * NOTE: If a non-default implementation is provided, it ought to return cached results if
	 * available
	 * 
	 * @param v the source vertex
	 * @return the successors
	 */
	public default Collection<V> getSuccessors(V v) {
		Set<V> result = new LinkedHashSet<>();
		for (E edge : getOutEdges(v)) {
			result.add(edge.getEnd());
		}
		return result;
	}

	/**
	 * Copy some portion of the implicit graph to an explicit graph
	 * 
	 * Usually, this returns the cached (explored) portion of the graph
	 * @return a "copy" of this implicit graph
	 */
	public GDirectedGraph<V, E> copy();
}
