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
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;

import org.jgrapht.Graph;
import org.jungrapht.visualization.VisualizationViewer;
import org.jungrapht.visualization.layout.model.Point;
import org.jungrapht.visualization.selection.MutableSelectedState;

import ghidra.graph.visualization.CenterAnimationJob;

/**
 * Mouse plugin to allow for edge navigation
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class JgtEdgeNavigationPlugin<V, E> extends AbstractJgtGraphMousePlugin<V, E> {

	protected int getSingleSelectionMask;

	public JgtEdgeNavigationPlugin(int singleSelectionMask) {
		this.singleSelectionMask = singleSelectionMask;
		this.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);
	}

	protected int singleSelectionMask;

	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == singleSelectionMask;
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

		E edge = selectedEdge; // save off before we reset
		e.consume();
		resetState();

		// on double-clicks we go to the vertex in the current edge direction unless that vertex
		// is already selected, then we go to the other vertex
		VisualizationViewer<V, E> viewer = getViewer(e);
		MutableSelectedState<V> selectedState = viewer.getSelectedVertexState();

		Graph<V, E> graph = viewer.getVisualizationModel().getGraph();
		V end = graph.getEdgeTarget(edge);
		if (!selectedState.isSelected(end)) {
			pickAndShowVertex(end, selectedState, viewer);
			return;
		}

		// the destination was picked, go the other direction
		V source = graph.getEdgeSource(edge);
		pickAndShowVertex(source, selectedState, viewer);
	}

	private void pickAndShowVertex(V vertex, MutableSelectedState<V> selectedVertexState,
			VisualizationViewer<V, E> viewer) {

		// TODO animate; this requires a single view updater
		Point2D existingCenter = viewer.getRenderContext()
				.getMultiLayerTransformer()
				.inverseTransform(viewer.getCenter());
		Point vp = viewer.getVisualizationModel().getLayoutModel().get(vertex);
		Point2D newCenter = new Point2D.Double(vp.x, vp.y);
		CenterAnimationJob job = new CenterAnimationJob(viewer, existingCenter, newCenter);
		job.finished();

		selectedVertexState.clear();
		selectedVertexState.select(vertex);

		/*
		VisualGraphViewUpdater<V, E> updater = viewer.getViewUpdater();
		updater.moveVertexToCenterWithAnimation(vertex, isBusy -> {
		
			// pick the vertex after the animation has run
			if (!isBusy) {
				GPickedState<V> pickedStateWrapper = (GPickedState<V>) selectedVertexState;
				pickedStateWrapper.pickToActivate(vertex);
			}
		});
		*/
	}

	@Override
	protected boolean shouldShowCursor(MouseEvent e) {
		return isOverEdge(e);
	}
}
