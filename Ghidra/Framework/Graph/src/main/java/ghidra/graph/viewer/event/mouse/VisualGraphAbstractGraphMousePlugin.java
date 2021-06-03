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

import java.awt.Cursor;
import java.awt.event.*;
import java.awt.geom.Point2D;

import edu.uci.ics.jung.algorithms.layout.GraphElementAccessor;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import edu.uci.ics.jung.visualization.picking.PickedState;
import ghidra.graph.viewer.*;

/**
 * Usage Notes:
 * <ul>
 * 		<li>We clear state on mouseReleased() and mouseExited(), since we will get 
 * 			at least one of those calls</li>
 * </ul>
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public abstract class VisualGraphAbstractGraphMousePlugin<V extends VisualVertex, 
														  E extends VisualEdge<V>>
		extends AbstractGraphMousePlugin
		implements MouseListener, MouseMotionListener, VisualGraphMousePlugin<V, E> { 
//@formatter:on

	protected boolean isHandlingMouseEvents;

	protected V selectedVertex;
	protected E selectedEdge;

	public VisualGraphAbstractGraphMousePlugin() {
		this(InputEvent.BUTTON1_DOWN_MASK);
	}

	public VisualGraphAbstractGraphMousePlugin(int selectionModifiers) {
		super(selectionModifiers);
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == modifiers;
	}

	protected boolean checkForVertex(MouseEvent e) {
		if (!checkModifiers(e)) {
			selectedVertex = null;
			return false;
		}

		VisualizationViewer<V, E> vv = getViewer(e);
		GraphElementAccessor<V, E> pickSupport = vv.getPickSupport();
		Layout<V, E> layout = vv.getGraphLayout();
		if (pickSupport == null) {
			return false;
		}

		// p is the screen point for the mouse event
		Point2D p = e.getPoint();
		selectedVertex = pickSupport.getVertex(layout, p.getX(), p.getY());
		if (selectedVertex == null) {
			return false;
		}

		e.consume();
		return true;
	}

	protected boolean checkForEdge(MouseEvent e) {
		if (!checkModifiers(e) || isOverVertex(e)) {
			selectedEdge = null;
			return false;
		}

		VisualizationViewer<V, E> vv = getViewer(e);
		GraphElementAccessor<V, E> pickSupport = vv.getPickSupport();
		Layout<V, E> layout = vv.getGraphLayout();
		if (pickSupport == null) {
			return false;
		}

		// p is the screen point for the mouse event
		Point2D p = e.getPoint();
		selectedEdge = pickSupport.getEdge(layout, p.getX(), p.getY());
		if (selectedEdge == null) {
			return false;
		}

		e.consume();
		isHandlingMouseEvents = true;
		return true;
	}

	protected boolean pickVertex(V vertex, VisualizationViewer<V, E> viewer) {
		PickedState<V> pickedVertexState = viewer.getPickedVertexState();
		if (pickedVertexState == null) {
			return false;
		}

		if (pickedVertexState.isPicked(vertex) == false) {
			pickedVertexState.clear();
			pickedVertexState.pick(vertex, true);
		}

		return true;
	}

	protected boolean pickEdge(E edge, VisualizationViewer<V, E> viewer) {
		PickedState<E> pickedVertexState = viewer.getPickedEdgeState();
		if (pickedVertexState == null) {
			return false;
		}

		if (pickedVertexState.isPicked(edge) == false) {
			pickedVertexState.clear();
			pickedVertexState.pick(edge, true);
		}

		return true;
	}

	protected boolean isOverVertex(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		return (GraphViewerUtils.getVertexFromPointInViewSpace(viewer, e.getPoint()) != null);
	}

	protected boolean isOverEdge(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		E edge = GraphViewerUtils.getEdgeFromPointInViewSpace(viewer, e.getPoint());
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
		return isOverVertex(e); // default to showing cursor over vertices
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
