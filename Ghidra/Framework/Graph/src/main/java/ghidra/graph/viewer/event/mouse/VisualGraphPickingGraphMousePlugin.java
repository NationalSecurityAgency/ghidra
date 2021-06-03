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
import java.awt.Point;
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.awt.geom.Rectangle2D;
import java.util.Collection;

import docking.DockingUtils;
import edu.uci.ics.jung.algorithms.layout.GraphElementAccessor;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.picking.PickedState;
import ghidra.graph.viewer.*;

public class VisualGraphPickingGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends JungPickingGraphMousePlugin<V, E> implements VisualGraphMousePlugin<V, E> {

// ALERT: -this class was created because mouseDragged() has a bug that generates a NPE
//        -also, mousePressed() has a bug in that it does not check the modifiers when the method is entered

	public VisualGraphPickingGraphMousePlugin() {
		super(InputEvent.BUTTON1_DOWN_MASK,
			InputEvent.BUTTON1_DOWN_MASK | DockingUtils.CONTROL_KEY_MODIFIER_MASK);
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		if (e.getModifiersEx() == addToSelectionModifiers) {
			return true;
		}
		return e.getModifiersEx() == modifiers;
	}

	@Override
	public void mousePressed(MouseEvent e) {
		if (!checkModifiers(e)) {
			return;
		}
		super.mousePressed(e);
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		if (locked) {
			return;
		}

		GraphViewer<V, E> viewer = getGraphViewer(e);
		if (vertex != null) {
			dragVertices(e, viewer);
		}
		else {
			increaseDragRectangle(e);
		}

		viewer.repaint();
	}

	private void increaseDragRectangle(MouseEvent e) {
		Point2D out = e.getPoint();
		int theModifiers = e.getModifiersEx();
		if (theModifiers == addToSelectionModifiers || theModifiers == modifiers) {
			if (down != null) {
				rect.setFrameFromDiagonal(down, out);
			}
		}
	}

	private void dragVertices(MouseEvent e, GraphViewer<V, E> viewer) {

		Point p = e.getPoint();
		RenderContext<V, E> context = viewer.getRenderContext();
		MultiLayerTransformer xformer = context.getMultiLayerTransformer();
		Point2D layoutPoint = xformer.inverseTransform(p);
		Point2D layoutDown = xformer.inverseTransform(down);
		Layout<V, E> layout = viewer.getGraphLayout();
		double dx = layoutPoint.getX() - layoutDown.getX();
		double dy = layoutPoint.getY() - layoutDown.getY();
		PickedState<V> ps = viewer.getPickedVertexState();

		for (V v : ps.getPicked()) {
			Point2D vertexPoint = layout.apply(v);
			vertexPoint.setLocation(vertexPoint.getX() + dx, vertexPoint.getY() + dy);
			layout.setLocation(v, vertexPoint);
			updatedArticulatedEdges(viewer, v);
		}

		down = p;
		e.consume();
	}

	private void updatedArticulatedEdges(GraphViewer<V, E> viewer, V v) {

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();

		Collection<E> edges = graph.getIncidentEdges(v);
		VisualGraphViewUpdater<V, E> updater = getViewUpdater(viewer);
		updater.updateEdgeShapes(edges);
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		if (isOverVertex(e)) {
			installCursor(cursor, e);
			e.consume();
		}
	}

	private boolean isOverVertex(MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		return (GraphViewerUtils.getVertexFromPointInViewSpace(viewer, e.getPoint()) != null);
	}

	@SuppressWarnings("unchecked")
	private void installCursor(Cursor newCursor, MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();
		viewer.setCursor(newCursor);
	}

	/* Pretty sure we don't need this now that we update the vertex locations directly.  This 
	   was old code that pre-existed the preferred method for updating vertex locations.   Once
	   all tests are passing, and selecting edges of previously dragged vertices still works, 
	   the delete this code.
	   
	private void updateVertexLocationToCompensateForDraggingWorkaround(double dx, double dy, V v) {
		Point2D original = v.getLocation();
		original.setLocation(original.getX() + dx, original.getY() + dy);
		v.setLocation(original);
	}
	*/

	@Override
	public void mouseReleased(MouseEvent e) {

		// We overrode this method here to clear the picked state of edges and vertices if we 
		// ever get a released event when the user is clicking somewhere that is not an edge or
		// vertex
		if (!isDragging() && vertex == null && edge == null) {
			maybeClearPickedState(e);
		}
		super.mouseReleased(e);
	}

	private boolean isDragging() {
		Rectangle2D frame = rect.getFrame();
		return frame.getHeight() > 0;
	}

	@SuppressWarnings("unchecked")
	private void maybeClearPickedState(MouseEvent event) {
		VisualizationViewer<V, E> vv = (VisualizationViewer<V, E>) event.getSource();
		PickedState<V> pickedVertexState = vv.getPickedVertexState();
		PickedState<E> pickedEdgeState = vv.getPickedEdgeState();
		if (pickedEdgeState == null || pickedVertexState == null) {
			return;
		}

		GraphElementAccessor<V, E> pickSupport = vv.getPickSupport();
		Layout<V, E> layout = vv.getGraphLayout();

		Point2D mousePoint = event.getPoint();
		V v = pickSupport.getVertex(layout, mousePoint.getX(), mousePoint.getY());
		if (v != null) {
			return;
		}

		E e = pickSupport.getEdge(layout, mousePoint.getX(), mousePoint.getY());
		if (e != null) {
			return;
		}

		pickedEdgeState.clear();
		pickedVertexState.clear();
	}
}
