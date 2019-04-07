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
package ghidra.graph.viewer.vertex;

import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.graph.viewer.event.mouse.VertexMouseInfo;
import ghidra.graph.viewer.event.mouse.VisualGraphMousePlugin;

/**
 * A listener that allows clients to be notified of vertex clicks.  Normal 
 * mouse processing is handled by the {@link VisualGraphMousePlugin} class.  This is a
 * convenience method so that clients do not have to deal with the mouse plugin.
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 * @see VertexFocusListener
 */
public interface VertexClickListener<V extends VisualVertex, E extends VisualEdge<V>> {

	/**
	 * Called when a vertex is double-clicked
	 * @param v the clicked vertex
	 * @param mouseInfo the info object that contains mouse information for the graph and 
	 *        the low-level vertex's clicked component
	 * @return true if this call wants to stop all further mouse event processing
	 */
	public boolean vertexDoubleClicked(V v, VertexMouseInfo<V, E> mouseInfo);
}
