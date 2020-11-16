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
package ghidra.graph.viewer.popup;

import java.awt.Window;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;

/**
 * An interface that provides graph and component information to the {@link PopupRegulator} 
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public interface PopupSource<V, E> {

	/**
	 * Returns the tool tip info object for the given mouse event.  Implementations will use the
	 * event to determine whether a popup should be created for a vertex, edge, the graph or 
	 * not at all.
	 * 
	 * @param event the event
	 * @return the info; null for no popup
	 */
	public ToolTipInfo<?> getToolTipInfo(MouseEvent event);

	/**
	 * Returns a vertex for the given event
	 * @param event the event
	 * @return the vertex or null
	 */
	public V getVertex(MouseEvent event);

	/**
	 * Returns an edge for the given event
	 * @param event the event
	 * @return the edge or null
	 */
	public E getEdge(MouseEvent event);

	/**
	 * Adds the given mouse motion listener to the graph component.  This allows the popup 
	 * regulator to decided when to show and hide popups.
	 * 
	 * @param l the listener
	 */
	public void addMouseMotionListener(MouseMotionListener l);

	/**
	 * Signals that the graph needs to repaint
	 */
	public void repaint();

	/**
	 * Returns a suitable window parent for the popup window
	 * @return the window parent
	 */
	public Window getPopupParent();
}
