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
import java.awt.event.*;
import java.awt.geom.Point2D;

import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import edu.uci.ics.jung.visualization.control.TranslatingGraphMousePlugin;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import ghidra.graph.viewer.*;

/**
 * Note: this class is based on {@link TranslatingGraphMousePlugin}.
 * <p>
 * TranslatingGraphMousePlugin uses a MouseButtonOne press and drag gesture to translate 
 * the graph display in the x and y direction. The default MouseButtonOne modifier can be overridden
 * to cause a different mouse gesture to translate the display.
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphTranslatingGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractGraphMousePlugin
		implements MouseListener, MouseMotionListener, VisualGraphMousePlugin<V, E> {

	private boolean panning;
	private boolean isHandlingEvent;

	public VisualGraphTranslatingGraphMousePlugin() {
		this(InputEvent.BUTTON1_DOWN_MASK);
	}

	public VisualGraphTranslatingGraphMousePlugin(int modifiers) {
		super(modifiers);
		this.cursor = Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR);
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == modifiers;
	}

	@Override
	public void mousePressed(MouseEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);
		boolean accepted = checkModifiers(e) && isInDraggingArea(e);
		if (!accepted) {
			return;
		}

		down = e.getPoint();
		viewer.setCursor(cursor);
		isHandlingEvent = true;
		e.consume();
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		boolean wasHandlingEvent = isHandlingEvent;
		isHandlingEvent = false;
		down = null;
		installCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR), e);

		// NOTE: we are only consuming the event here if we actually did pan...this allows follow-on
		// mouse handlers to process the mouseReleased() event.  This is a bit odd and not the 
		// normal event processing (which is to consume all related events).
		if (wasHandlingEvent && panning) {
			e.consume();
		}

		panning = false;
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);
		boolean accepted = checkModifiers(e);
		if (!accepted) {
			return;
		}

		if (!isHandlingEvent) {
			return;
		}

		panning = true;

		RenderContext<V, E> context = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = context.getMultiLayerTransformer();
		MutableTransformer layoutTransformer = multiLayerTransformer.getTransformer(Layer.LAYOUT);
		viewer.setCursor(cursor);
		Point2D downPoint = multiLayerTransformer.inverseTransform(down);
		Point2D p = multiLayerTransformer.inverseTransform(e.getPoint());
		float dx = (float) (p.getX() - downPoint.getX());
		float dy = (float) (p.getY() - downPoint.getY());

		layoutTransformer.translate(dx, dy);
		down.x = e.getX();
		down.y = e.getY();
		e.consume();
		viewer.repaint();
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		// don't care
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		if (isHandlingEvent) {
			return;
		}

		if (!isInDraggingArea(e)) {
			return;
		}

		if (!checkModifiersForCursor(e)) {
			return;
		}

		installCursor(cursor, e);
	}

	@Override
	public void mouseExited(MouseEvent e) {
		installCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR), e);
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		if (!checkModifiersForCursor(e)) {
			return;
		}

		if (isHandlingEvent) {
			e.consume();
		}

		if (isInDraggingArea(e)) {
			installCursor(cursor, e);
			e.consume();
		}
	}

	private boolean checkModifiersForCursor(MouseEvent e) {
		if (e.getModifiersEx() == 0) {
			return true;
		}
		return false;
	}

//==================================================================================================
// Private methods
//==================================================================================================    

	private boolean isInDraggingArea(MouseEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);

		// make sure we are not over a graph or edge
		Point p = e.getPoint();
		if (GraphViewerUtils.getVertexFromPointInViewSpace(viewer, p) != null) {
			return false;
		}

		if (GraphViewerUtils.getEdgeFromPointInViewSpace(viewer, p) != null) {
			return false;
		}

		return true;
	}

	private void installCursor(Cursor newCursor, MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		viewer.setCursor(newCursor);
	}
}
