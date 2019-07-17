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
package ghidra.graph.viewer.event.mouse;

import java.awt.event.MouseEvent;

import javax.swing.JComponent;

/**
 * Creates tooltips for a given vertex.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public interface VertexTooltipProvider<V, E> {

	/**
	 * Returns a tooltip component for the given vertex
	 * 
	 * <p>This is used when the vertex is scaled too far for the user to see individual 
	 * vertex subcomponents.
	 * 
	 * @param v the vertex
	 * @return a tooltip component
	 */
	public JComponent getTooltip(V v);

	/**
	 * Returns a tooltip component for the given vertex and edge.  This is used to create
	 * an edge tooltip, allowing for vertex data to appear in the tip.
	 * 
	 * @param v the vertex
	 * @param e the edge for 
	 * @return a tooltip component
	 */
	public JComponent getTooltip(V v, E e);

	/**
	 * Returns a tooltip string for the given vertex and mouse event
	 * 
	 * @param v the vertex
	 * @param e the mouse event 
	 * @return the tooltip text
	 */
	public String getTooltipText(V v, MouseEvent e);
}
