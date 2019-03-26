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

import java.util.Collection;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A visual graph with methods needed to facilitate grouping of vertices.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public abstract class GroupingVisualGraph<V extends VisualVertex, E extends VisualEdge<V>>
		extends DefaultVisualGraph<V, E> {

	/**
	 * Finds a vertex that matches the given vertex.  
	 * 
	 * <P>Grouping can trigger vertex adds and removals.  This method is a way for subclasses
	 * to search for a vertex that matches the given vertex, but may or may not be the same 
	 * instance.
	 * 
	 * @param v the vertex
	 * @return the matching vertex or null
	 */
	public abstract V findMatchingVertex(V v);

	/**
	 * The same as {@link #findMatchingVertex(VisualVertex)}, except that you can provide a
	 * collection of vertices to be ignored.
	 * 
	 * <P>This is useful during graph transformations when duplicate vertices may be in the 
	 * graph at the same time.
	 * 
	 * @param v the vertex
	 * @param ignore vertices to ignore when searching
	 * @return the matching vertex or null
	 */
	public abstract V findMatchingVertex(V v, Collection<V> ignore);
}
