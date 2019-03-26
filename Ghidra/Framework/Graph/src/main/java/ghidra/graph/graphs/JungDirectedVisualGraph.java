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

import ghidra.graph.VisualGraph;
import ghidra.graph.jung.JungDirectedGraph;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;

/**
 * A class to combine the {@link JungDirectedGraph} and the {@link VisualGraph} 
 * interfaces
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public abstract class JungDirectedVisualGraph <V extends VisualVertex, 
                                               E extends VisualEdge<V>>
	extends JungDirectedGraph<V, E> implements VisualGraph<V, E> {
//@formatter:on

	@Override
	// overridden to redefine the return type
	public abstract JungDirectedVisualGraph<V, E> copy();
}
