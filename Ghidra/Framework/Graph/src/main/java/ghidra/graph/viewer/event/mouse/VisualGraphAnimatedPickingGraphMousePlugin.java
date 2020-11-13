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
import java.awt.event.InputEvent;
import java.awt.event.MouseEvent;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.AnimatedPickingGraphMousePlugin;
import ghidra.graph.viewer.*;

/**
 * A mouse handler to center a vertex when the header is double-clicked
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphAnimatedPickingGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends AnimatedPickingGraphMousePlugin<V, E> implements VisualGraphMousePlugin<V, E> {

	private boolean isHandlingMouseEvents;

	public VisualGraphAnimatedPickingGraphMousePlugin() {
		super(InputEvent.BUTTON1_DOWN_MASK);
		this.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		if (e.getClickCount() != 2) {
			return;
		}

		super.mousePressed(e);

		if (vertex == null) {
			return; // no vertex clicked, nothing to do
		}

		isHandlingMouseEvents = true;
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		if (!checkModifiers(e) || !isHandlingMouseEvents) {
			return;
		}

		isHandlingMouseEvents = false;

		GraphViewer<V, E> viewer = getGraphViewer(e);
		VisualGraphViewUpdater<V, E> updater = viewer.getViewUpdater();
		updater.moveVertexToCenterWithAnimation(vertex);
		e.consume();
		vertex = null;
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		if (isHandlingMouseEvents) {
			e.consume();
		}
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		if (isHandlingMouseEvents) {
			e.consume();
		}

		if (isOverVertex(e)) {
			installCursor(cursor, e);
			e.consume();
		}
	}

	@SuppressWarnings("unchecked")
	private boolean isOverVertex(MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();
		return (GraphViewerUtils.getVertexFromPointInViewSpace(viewer, e.getPoint()) != null);
	}

	@SuppressWarnings("unchecked")
	private void installCursor(Cursor newCursor, MouseEvent e) {
		VisualizationViewer<V, E> viewer = (VisualizationViewer<V, E>) e.getSource();
		viewer.setCursor(newCursor);
	}

	/*
	 * Override subclass method to translate the master view instead of this satellite view 
	 */
	@Override
	public void mouseReleased(MouseEvent e) {
		if (isHandlingMouseEvents) {
			e.consume();
		}
	}
}
