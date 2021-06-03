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
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import org.jungrapht.visualization.*;
import org.jungrapht.visualization.MultiLayerTransformer.Layer;
import org.jungrapht.visualization.control.TranslatingGraphMousePlugin;
import org.jungrapht.visualization.transform.MutableTransformer;

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
public class JgtTranslatingPlugin<V, E>
		extends AbstractJgtGraphMousePlugin<V, E> {

	private boolean panning;
	private boolean isHandlingEvent;
	private int translatingMask;

	public JgtTranslatingPlugin() {
		this(InputEvent.BUTTON1_DOWN_MASK);
	}

	public JgtTranslatingPlugin(int modifiers) {
		this.translatingMask = modifiers;
		this.cursor = Cursor.getPredefinedCursor(Cursor.MOVE_CURSOR);
	}

	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == translatingMask;
	}

	@Override
	public void mousePressed(MouseEvent e) {
		boolean accepted = checkModifiers(e) && isInDraggingArea(e);
		if (!accepted) {
			return;
		}

		down = e.getPoint();
		VisualizationViewer<V, E> viewer = getGraphViewer(e);
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
		boolean accepted = checkModifiers(e);
		if (!accepted) {
			return;
		}

		if (!isHandlingEvent) {
			return;
		}

		panning = true;

		VisualizationViewer<V, E> viewer = getGraphViewer(e);
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
		return !(isOverVertex(e) || isOverEdge(e));
	}

	@Override
	public void installCursor(Cursor newCursor, MouseEvent e) {
		VisualizationViewer<V, E> viewer = getViewer(e);
		viewer.setCursor(newCursor);
	}
}
