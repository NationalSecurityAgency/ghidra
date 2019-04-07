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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.util.Objects;

import javax.swing.*;

import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.picking.PickedState;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.event.picking.GPickedState;

/**
 * A class that knows how and where a given vertex was clicked.  Further, this class knows how 
 * to get clicked components within a given vertex.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VertexMouseInfo<V extends VisualVertex, E extends VisualEdge<V>> {

	private static final Cursor DEFAULT_CURSOR = Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR);
	private static final Cursor HAND_CURSOR = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR);

	private final MouseEvent originalMouseEvent;
	private final GraphViewer<V, E> viewer;

	// TODO make these private if the subclass goes away
	protected final V vertex;
	private MouseEvent translatedMouseEvent;
	protected Component mousedDestinationComponent;

	public VertexMouseInfo(MouseEvent originalMouseEvent, V vertex, Point2D vertexBasedClickPoint,
			GraphViewer<V, E> viewer) {
		this.originalMouseEvent = Objects.requireNonNull(originalMouseEvent);
		this.vertex = Objects.requireNonNull(vertex);
		this.viewer = Objects.requireNonNull(viewer);

		JComponent component = vertex.getComponent();
		Component deepestComponent = SwingUtilities.getDeepestComponentAt(component,
			(int) vertexBasedClickPoint.getX(), (int) vertexBasedClickPoint.getY());
		setClickedComponent(deepestComponent, vertexBasedClickPoint);
	}

	public boolean isScaledPastInteractionThreshold() {
		RenderContext<V, E> renderContext = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = renderContext.getMultiLayerTransformer();
		MutableTransformer viewTransformer = multiLayerTransformer.getTransformer(Layer.VIEW);
		double scale = viewTransformer.getScale();
		return scale < GraphViewerUtils.INTERACTION_ZOOM_THRESHOLD;
	}

	public Cursor getCursorForClickedComponent() {
		if (isGrabArea()) {
			return HAND_CURSOR;
		}

		if (!isVertexSelected()) {
			return HAND_CURSOR;
		}
		return DEFAULT_CURSOR;
	}

	public boolean isGrabArea() {
		// subclasses can override to specify areas of the vertex that they can click in order
		// to edit and perform keyboard operations
		if (isButtonClick()) {
			return false;
		}

		return vertex.isGrabbable(getClickedComponent());
	}

	public boolean isButtonClick() {
		Component clickedComponent = getClickedComponent();
		if (clickedComponent instanceof JButton) {
			return true;
		}
		return false;
	}

	public boolean isVertexSelected() {
		PickedState<V> pickedVertexState = viewer.getPickedVertexState();
		return pickedVertexState.isPicked(vertex);
	}

	/**
	 * Selects, or 'pick's the given vertex.  
	 * 
	 * @param addToSelection true signals to add the given vertex to the set of selected vertices;
	 *                       false signals to clear the existing selected vertices before selecting
	 *                       the given vertex
	 */
	public void selectVertex(boolean addToSelection) {
		// when the user manually clicks a vertex, we no longer want an edge selected
		PickedState<E> pickedEdgeState = viewer.getPickedEdgeState();
		pickedEdgeState.clear();
		if (isVertexSelected()) {
			return;
		}

		GPickedState<V> pickedState = viewer.getGPickedVertexState();
		pickedState.pickToSync(vertex, addToSelection);
	}

	Component getVertexComponent() {
		return vertex.getComponent();
	}

	public Component getClickedComponent() {
		return mousedDestinationComponent;
	}

	public GraphViewer<V, E> getViewer() {
		return viewer;
	}

	public V getVertex() {
		return vertex;
	}

	public Point getDeepestComponentBasedClickPoint() {
		return translatedMouseEvent.getPoint();
	}

	/**
	 * You can use this method to override which Java component will get the forwarded event.  By
	 * default, the mouse info will forward the event to the component that is under the point in
	 * the event.
	 * @param clickedComponent the component that was clicked
	 * @param vertexBasedPoint the point, relative to the vertex's coordinates
	 */
	public void setClickedComponent(Component clickedComponent, Point2D vertexBasedPoint) {
		this.mousedDestinationComponent = clickedComponent;

		Point componentPoint =
			new Point((int) vertexBasedPoint.getX(), (int) vertexBasedPoint.getY());

		// default values...
		Component newEventSource = vertex.getComponent();
		Point pointInClickedComponentCoordinates = componentPoint;
		if (clickedComponent != null) {
			// the component can be null when it hasn't been shown yet, like in fast rendering
			newEventSource = clickedComponent;
			pointInClickedComponentCoordinates =
				SwingUtilities.convertPoint(getVertexComponent(), componentPoint, clickedComponent);
		}

		translatedMouseEvent = createMouseEventFromSource(newEventSource, originalMouseEvent,
			pointInClickedComponentCoordinates);
	}

	public Object getEventSource() {
		return originalMouseEvent.getSource();
	}

	public MouseEvent getOriginalMouseEvent() {
		return originalMouseEvent;
	}

	public MouseEvent getTranslatedMouseEvent() {
		return translatedMouseEvent;
	}

	public void forwardEvent() {
		if (mousedDestinationComponent == null) {
			return;
		}

		mousedDestinationComponent.dispatchEvent(translatedMouseEvent);
		if (!isPopupClick()) {
			// don't consume popup because we want DockableComponent to get the event also to popup
			originalMouseEvent.consume();
		}
	}

	public void simulateMouseEnteredEvent() {
		if (mousedDestinationComponent == null) {
			return;
		}

		MouseEvent mouseEnteredEvent = createMouseEnteredEvent();
		mousedDestinationComponent.dispatchEvent(mouseEnteredEvent);
		viewer.repaint();
	}

	public void simulateMouseExitedEvent() {
		if (mousedDestinationComponent == null) {
			return;
		}

		MouseEvent mouseExitedEvent = createMouseExitedEvent();
		mousedDestinationComponent.dispatchEvent(mouseExitedEvent);
		viewer.repaint();
	}

	private MouseEvent createMouseEnteredEvent() {
		return new MouseEvent(mousedDestinationComponent, MouseEvent.MOUSE_ENTERED,
			System.currentTimeMillis(), 0, 0, 0, 0, false);
	}

	private MouseEvent createMouseExitedEvent() {
		return new MouseEvent(mousedDestinationComponent, MouseEvent.MOUSE_EXITED,
			System.currentTimeMillis(), 0, 0, 0, 0, false);
	}

	private MouseEvent createMouseEventFromSource(Component source, MouseEvent progenitor,
			Point2D clickPoint) {
		return new MouseEvent(source, progenitor.getID(), progenitor.getWhen(),
			progenitor.getModifiers() | progenitor.getModifiersEx(), (int) clickPoint.getX(),
			(int) clickPoint.getY(), progenitor.getClickCount(), progenitor.isPopupTrigger(),
			progenitor.getButton());
	}

	public boolean isPopupClick() {
		return getOriginalMouseEvent().getButton() == MouseEvent.BUTTON3;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tvertex: " + vertex + ",\n"+
			"\tclickedComponent: " + mousedDestinationComponent+ ",\n"+
			"\tevent: " + originalMouseEvent + ",\n"+
			"\ttranslatedEvent: " + translatedMouseEvent + "\n"+
		"}";
		//@formatter:on
	}
}
