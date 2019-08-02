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
import java.awt.event.MouseEvent;

import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.graph.Graph;
import edu.uci.ics.jung.visualization.picking.PickedState;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.event.picking.GPickedState;

public class VisualGraphEdgeSelectionGraphMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends VisualGraphAbstractGraphMousePlugin<V, E> {

	public VisualGraphEdgeSelectionGraphMousePlugin() {
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

		checkForEdge(e); // this will select an edge if we can and store off the edge
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		if (!isHandlingMouseEvents) {
			return;
		}

		E edgeReference = selectedEdge; // grab a copy before we reset our state

		e.consume();
		resetState();

		// on double-clicks we go to the vertex in the current edge direction unless that vertex
		// is already selected, then we go to the other vertex
		GraphViewer<V, E> viewer = getGraphViewer(e);
		PickedState<V> pickedVertexState = viewer.getPickedVertexState();

		Layout<V, E> layout = viewer.getGraphLayout();
		Graph<V, E> graph = layout.getGraph();
		V destination = graph.getDest(edgeReference);
		if (!pickedVertexState.isPicked(destination)) {
			pickAndShowVertex(destination, pickedVertexState, viewer);
			return;
		}

		// the destination was picked, go the other direction
		V source = graph.getSource(edgeReference);
		pickAndShowVertex(source, pickedVertexState, viewer);
	}

	private void pickAndShowVertex(V vertex, PickedState<V> pickedVertexState,
			GraphViewer<V, E> viewer) {

		VisualGraphViewUpdater<V, E> updater = viewer.getViewUpdater();
		updater.moveVertexToCenterWithAnimation(vertex, isBusy -> {

			// pick the vertex after the animation has run
			if (!isBusy) {
				GPickedState<V> pickedStateWrapper = (GPickedState<V>) pickedVertexState;
				pickedStateWrapper.pickToActivate(vertex);
			}
		});
	}

	@Override
	protected boolean shouldShowCursor(MouseEvent e) {
		return isOverEdge(e);
	}
}
