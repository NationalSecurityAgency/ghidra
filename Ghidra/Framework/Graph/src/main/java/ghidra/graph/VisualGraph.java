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

import java.awt.Point;
import java.util.Set;

import ghidra.graph.event.VisualGraphChangeListener;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.event.picking.GPickedState;
import ghidra.graph.viewer.layout.LayoutListener.ChangeType;
import ghidra.graph.viewer.layout.VisualGraphLayout;

/**
 * The primary interface for graphs that are to be rendered.  This class defines methods 
 * commonly used in the GUI while extending the primary non-visual graph interface.
 * 
 * <P>The Visual Graph API will typically provide services for taking a Visual Graph and 
 * creating a UI that handles basic user interaction elements (similar to how complex Java
 * widgets handle user interaction for the developer).  The Visual Graph is the model of the
 * UI components.  A typical Visual Graph UI will render developer-defined components, 
 * handling mouse event translations for the developer. 
 *  
 * <P>Some features found in Visual Graphs:
 * <UL>
 * 	<LI>Mouse event translation - the JComponent being rendered in the graph will be handed 
 *      mouse events that are relative to its coordinate space, not that of the graph.
 * 	</LI>
 *  <LI>Hover and Selection - vertex hover and selection events are handled by the API
 *  </LI>
 *  <LI>Zooming - zoom level and related events (when zoomed too far, mouse events are 
 *      not passed-through to the component) and handled by the API
 *  </LI>
 * </UL>
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public interface VisualGraph<V extends VisualVertex, E extends VisualEdge<V>>
		extends GDirectedGraph<V, E> {

	/**
	 * A callback notifying this graph that the given vertex's location has changed
	 * 
	 * @param v the vertex
	 * @param point the new location
	 * @param changeType the type of change
	 */
	public void vertexLocationChanged(V v, Point point, ChangeType changeType);

	/**
	 * Returns the focused vertex; null if no vertex has focus.  Focus is equivalent to 
	 * being selected, but further distinguishes the vertex as being the only selected 
	 * vertex.  This is useful for key event processing.
	 * 
	 * @return the focused vertex
	 */
	public V getFocusedVertex();

	/**
	 * Sets the given vertex to be focused or not
	 * 
	 * <P>Note: this method is called by other APIs to ensure that the graph's notion of the 
	 * focused vertex matches what is happening externally (e.g., from the user clicking the
	 * screen).  If you wish to programmatically focus a vertex, then you should not be calling
	 * this API directly, but you should instead be using the {@link GPickedState} or one
	 * of the APIs that uses that, such as the {@link GraphComponent}.
	 * 
	 * @param v the focused vertex
	 * @param b true for focused; false for not focused
	 */
	public void setVertexFocused(V v, boolean b);

	/**
	 * Clears any selected vertices as well as the focused vertex
	 */
	public void clearSelectedVertices();

	/**
	 * Selects the given vertices
	 * 
	 * <P>Note: this method is called by other APIs to ensure that the graph's notion of the 
	 * focused vertex matches what is happening externally (e.g., from the user clicking the
	 * screen).  If you wish to programmatically select a vertex, then you should not be calling
	 * this API directly, but you should instead be using the {@link GPickedState} or one
	 * of the APIs that uses that, such as the {@link GraphComponent}.
	 * 
	 * @param vertices the vertices
	 */
	public void setSelectedVertices(Set<V> vertices);

	/**
	 * Returns the selected vertices.
	 * 
	 * @return the selected vertices
	 */
	public Set<V> getSelectedVertices();

	/**
	 * Adds the given listener to this graph
	 * 
	 * @param l the listener
	 */
	public void addGraphChangeListener(VisualGraphChangeListener<V, E> l);

	/**
	 * Removes the given listener from this graph
	 * 
	 * @param l the listener
	 */
	public void removeGraphChangeListener(VisualGraphChangeListener<V, E> l);

	/**
	 * Returns the layout that has been applied to the graph.  The graph does not need its 
	 * layout to function, but rather it is convenient for the visual graph system to be able
	 * to get the layout from the graph, rather than passing the layout everywhere it is 
	 * needed.
	 * 
	 * @return the layout applied to the graph
	 */
	public VisualGraphLayout<V, E> getLayout();

	@Override
	// overridden to redefine the return type
	public VisualGraph<V, E> copy();
}
