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
package ghidra.graph.visualization.mouse;

import java.awt.Cursor;
import java.awt.event.*;

import org.jungrapht.visualization.SatelliteVisualizationViewer;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.control.AbstractGraphMousePlugin;
import org.jungrapht.visualization.selection.MutableSelectedState;

/**
 * Graph mouse plugin base class.
 * 
 * Usage Notes:
 * <ul>
 * 		<li>We clear state on mouseReleased() and mouseExited(), since we will get 
 * 			at least one of those calls</li>
 * </ul>
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public abstract class AbstractJgtGraphMousePlugin<V, E>
		extends AbstractGraphMousePlugin
		implements MouseListener, MouseMotionListener { 
//@formatter:on

	protected boolean isHandlingMouseEvents;

	protected V selectedVertex;
	protected E selectedEdge;

	public VisualizationViewer<V, E> getViewer(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getGraphViewer(e);
		return viewer;
	}

	/**
	 * Returns the <b>primary/master</b> graph viewer.
	 * 
	 * @param e the mouse event from which to get the viewer
	 * @return the viewer
	 */
	@SuppressWarnings("unchecked")
	public VisualizationViewer<V, E> getGraphViewer(MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();

		// is this the satellite viewer? 
		if (viewer instanceof SatelliteVisualizationViewer) {
			return ((SatelliteVisualizationViewer<V, E>) viewer).getMaster();
		}

		return viewer;
	}

	/**
	 * Returns the satellite graph viewer.  This assumes that the mouse event originated from 
	 * the satellite viewer.
	 * 
	 * @param e the mouse event from which to get the viewer
	 * @return the viewer
	 */
	@SuppressWarnings("unchecked")
	public SatelliteVisualizationViewer<V, E> getSatelliteGraphViewer(MouseEvent e) {

		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();

		// is this the satellite viewer? 
		if (viewer instanceof SatelliteVisualizationViewer) {
			return (SatelliteVisualizationViewer<V, E>) viewer;
		}

		throw new IllegalStateException("Do not have a satellite GraphViewer");
	}

	/**
	 * Signals to perform any cleanup when this plugin is going away
	 */
	public void dispose() {
		// stub
	}

	/**
	 * Checks the given mouse event to see if it is a valid event for selecting a vertex at the
	 * mouse location.  If so, then the vertex is selected in this mouse handler and the event
	 * is consumed.
	 * @param e the event
	 * @return true if a vertex was selected
	 */
	protected boolean checkForVertex(MouseEvent e) {
		if (!checkModifiers(e)) {
			selectedVertex = null;
			return false;
		}

		VisualizationViewer<V, E> vv = getViewer(e);
		selectedVertex = JgtUtils.getVertex(e, vv);
		if (selectedVertex == null) {
			return false;
		}

		e.consume();
		return true;
	}

	/**
	 * Checks the given mouse event to see if it is a valid event for selecting an edge at the
	 * mouse location.  If so, then the edge is selected in this mouse handler and the event
	 * is consumed.
	 * @param e the event
	 * @return true if an edge was selected
	 */
	protected boolean checkForEdge(MouseEvent e) {
		if (!checkModifiers(e) || isOverVertex(e)) {
			selectedEdge = null;
			return false;
		}

		VisualizationViewer<V, E> vv = getViewer(e);
		selectedEdge = JgtUtils.getEdge(e, vv);
		if (selectedEdge == null) {
			return false;
		}

		e.consume();
		isHandlingMouseEvents = true;
		return true;
	}

	/**
	 * Selects the given vertex
	 * @param vertex the vertex
	 * @param viewer the graph viewer
	 * @return true if the vertex is selected
	 */
	protected boolean selectVertex(V vertex, VisualizationViewer<V, E> viewer) {
		MutableSelectedState<V> selectedVertexState = viewer.getSelectedVertexState();
		if (selectedVertexState == null) {
			return false;
		}

		selectedVertexState.isSelected(vertex);

		if (selectedVertexState.isSelected(vertex) == false) {
			selectedVertexState.clear();
			selectedVertexState.select(vertex, true);
		}

		return true;
	}

	/**
	 * Selects the given edge
	 * @param edge the edge
	 * @param viewer the graph viewer
	 * @return true if the edge is selected
	 */
	protected boolean selectEdge(E edge, VisualizationViewer<V, E> viewer) {

		MutableSelectedState<E> selectedVertexState = viewer.getSelectedEdgeState();
		if (selectedVertexState == null) {
			return false;
		}

		selectedVertexState.isSelected(edge);

		if (selectedVertexState.isSelected(edge) == false) {
			selectedVertexState.clear();
			selectedVertexState.select(edge, true);
		}
		return true;
	}

	/**
	 * Returns true if the location of the mouse event is over a vertex
	 * @param e the event
	 * @return true if the location of the mouse event is over a vertex
	 */
	protected boolean isOverVertex(MouseEvent e) {
		return getVertex(e) != null;
	}

	/**
	 * Returns the vertex if the mouse event is over a vertex
	 * @param e the event
	 * @return a vertex or null
	 */
	protected V getVertex(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		return JgtUtils.getVertex(e, viewer);
	}

	/**
	 * Returns true if the location of the mouse event is over a edge
	 * @param e the event
	 * @return true if the location of the mouse event is over a edge
	 */
	protected boolean isOverEdge(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		E edge = JgtUtils.getEdge(e, viewer);
		if (edge == null) {
			return false;
		}

		return !isOverVertex(e);
	}

	protected void installCursor(Cursor newCursor, MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		viewer.setCursor(newCursor);
	}

	protected boolean shouldShowCursor(MouseEvent e) {
		return isOverVertex(e); // to showing cursor over vertices
	}

	@Override
	public void mousePressed(MouseEvent e) {
		if (!checkModifiers(e)) {
			return;
		}

		// override this method to do stuff
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		if (!isHandlingMouseEvents) {
			return;
		}

		e.consume();
		resetState();
	}

	protected void resetState() {
		isHandlingMouseEvents = false;
		selectedVertex = null;
		selectedEdge = null;
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		if (!isHandlingMouseEvents) {
			return;
		}

		e.consume();
		resetState();
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		if (isHandlingMouseEvents) {
			e.consume();
		}

		// only "turn on" the cursor; resetting is handled elsewhere (in the mouse driver)
		if (shouldShowCursor(e)) {
			installCursor(cursor, e);
			e.consume();
		}
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		if (isHandlingMouseEvents) {
			e.consume();
		}

		if (shouldShowCursor(e)) {
			installCursor(cursor, e);
		}
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		if (shouldShowCursor(e)) {
			installCursor(cursor, e);
			e.consume();
		}
	}

	@Override
	public void mouseExited(MouseEvent e) {
		installCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR), e);
	}
}
