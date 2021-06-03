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

import ghidra.graph.viewer.*;

/**
 * A handler to zoom nodes when double-clicked.  If the vertex is zoomed out, then we will zoom
 * in and center.  If the vertex is zoomed to full size, then we will zoom out and center.
 * 
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphZoomingPickingGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualGraphAbstractGraphMousePlugin<V, E> {

	public VisualGraphZoomingPickingGraphMousePlugin() {
		super(InputEvent.BUTTON1_DOWN_MASK);
		this.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);
	}

	@Override
	public void mousePressed(MouseEvent e) {
		if (!checkModifiers(e)) {
			return;
		}

		if (e.getClickCount() != 2) {
			return;
		}

		if (!checkForVertex(e)) {
			return; // no vertex clicked, nothing to do
		}

		isHandlingMouseEvents = true;
		e.consume();
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		if (!isHandlingMouseEvents) {
			return;
		}

		GraphViewer<V, E> viewer = getGraphViewer(e);
		VisualGraphViewUpdater<V, E> updater = viewer.getViewUpdater();

		Double currentScale = GraphViewerUtils.getGraphScale(viewer);
		if (currentScale.intValue() == 1) {
			updater.fitGraphToViewerNow(viewer);
		}
		else {
			updater.setGraphScale(1.0);
		}
		updater.moveVertexToCenterWithoutAnimation(selectedVertex);

		e.consume();
		resetState();
	}
}
