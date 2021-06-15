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

import java.awt.event.*;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import ghidra.graph.VisualGraph;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.edge.VisualGraphPathHighlighter;
import ghidra.util.task.SwingUpdateManager;

/**
 * A mouse plugin to handle vertex hovers, to include animating paths in the graph, based 
 * upon the current {@link PathHighlightMode}.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphHoverMousePlugin<V extends VisualVertex, E extends VisualEdge<V>>
		extends AbstractGraphMousePlugin
		implements MouseMotionListener, MouseListener, VisualGraphMousePlugin<V, E> {

	private final GraphComponent<V, E, ?> graphComponent;
	private final VisualGraphPathHighlighter<V, E> pathHighlighter;
	private final VisualGraph<V, E> graph;

	// Note: we used to have code that would differentiate between the hovered and 'other' 
	//       viewer, which would be the primary viewer and the satellite viewer, depending
	//       upon how this class was created.   We currently don't need to know the difference,
	//       but it may be needed in the future.
	private final VisualizationViewer<V, E> sourceViewer;
	private final VisualizationViewer<V, E> otherViewer;

	private SwingUpdateManager mouseHoverUpdater = new SwingUpdateManager(this::updateMouseHovers);
	private MouseEvent lastMouseEvent;
	private V hoveredVertex;

	public VisualGraphHoverMousePlugin(GraphComponent<V, E, ?> graphComponent,
			VisualizationViewer<V, E> viewer, VisualizationViewer<V, E> otherViewer) {

		super(0);
		this.graphComponent = graphComponent;
		this.pathHighlighter = graphComponent.getPathHighlighter();
		this.graph = graphComponent.getGraph();
		this.sourceViewer = viewer;
		this.otherViewer = otherViewer;
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		return e.getModifiersEx() == modifiers;
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		lastMouseEvent = e;
		mouseHoverUpdater.update();
	}

	private void updateMouseHovers() {
		if (graphComponent.isUninitialized()) {
			return;
		}

		GraphViewer<V, E> viewer = getGraphViewer(lastMouseEvent);
		V newHoveredVertex =
			GraphViewerUtils.getVertexFromPointInViewSpace(viewer, lastMouseEvent.getPoint());
		if (newHoveredVertex == hoveredVertex) {
			return;
		}

		updateMouseHoversForVertex(viewer, newHoveredVertex);
	}

	private void updateMouseHoversForVertex(GraphViewer<V, E> viewer, V newHoveredVertex) {
		VisualGraphViewUpdater<V, E> updater = getViewUpdater(viewer);
		updater.stopEdgeHoverAnimation();
		setHovered(hoveredVertex, false);
		hoveredVertex = newHoveredVertex;
		setHovered(hoveredVertex, true);

		setupHoverEdgesForVertex(newHoveredVertex);
	}

	private void setHovered(V v, boolean hovered) {
		if (v != null) {
			v.setHovered(hovered);
		}
	}

	private void setupHoverEdgesForVertex(V newHoveredVertex) {
		if (graph.getEdgeCount() == 0) {
			return;	// no edges to animate
		}

		pathHighlighter.setHoveredVertex(newHoveredVertex);
		repaint();
	}

	private void repaint() {
		sourceViewer.repaint();
		otherViewer.repaint();
	}

	@Override
	public void mouseExited(MouseEvent e) {
		// don't care
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		VisualGraphViewUpdater<V, E> updater = getViewUpdater(e);
		updater.stopEdgeHoverAnimation();
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		if (e.isPopupTrigger()) {
			return;
		}

		lastMouseEvent = e;
		updateMouseHovers();
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		// don't care
	}

	@Override
	public void mousePressed(MouseEvent e) {
		// don't care
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		// handled by dragged and released
	}

	@Override
	public void dispose() {
		mouseHoverUpdater.dispose();
	}
}
