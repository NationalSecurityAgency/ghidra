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
import java.awt.event.*;

import javax.swing.JComponent;

import docking.DockingUtils;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import ghidra.graph.viewer.*;

//@formatter:off
public class VisualGraphEventForwardingGraphMousePlugin<V extends VisualVertex, 
														E extends VisualEdge<V>>
		extends AbstractGraphMousePlugin 
		implements MouseListener, MouseMotionListener, VisualGraphMousePlugin<V, E> {
//@formatter:on

	private static final Cursor DEFAULT_CURSOR = Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR);

	private VertexMouseInfo<V, E> mousePressedInfo;
	private VertexMouseInfo<V, E> currentMouseEnteredInfo;

	private boolean isHandlingEvent = false;

	public VisualGraphEventForwardingGraphMousePlugin() {
		this(InputEvent.BUTTON1_DOWN_MASK | InputEvent.BUTTON2_DOWN_MASK |
			InputEvent.BUTTON3_DOWN_MASK);
	}

	public VisualGraphEventForwardingGraphMousePlugin(int modifiers) {
		super(modifiers);
		this.cursor = DEFAULT_CURSOR;
	}

	@Override
	public boolean checkModifiers(MouseEvent e) {
		int eventModifiers = e.getModifiersEx();
		eventModifiers = turnOffControlKey(eventModifiers);
		return ((eventModifiers & getModifiers()) == eventModifiers);
	}

	private int turnOffControlKey(int eventModifiers) {
		return eventModifiers & (~DockingUtils.CONTROL_KEY_MODIFIER_MASK);
	}

	private boolean isControlClick(MouseEvent e) {
		int allModifiers = e.getModifiersEx();
		int osSpecificMask = DockingUtils.CONTROL_KEY_MODIFIER_MASK;
		return (allModifiers & osSpecificMask) == osSpecificMask;

		// can't use this until we fix the old modifiers usage
		// boolean controlDown = DockingUtils.isControlModifier(e);
		// return controlDown;
	}

	@Override
	public void mousePressed(MouseEvent e) {
		mousePressedInfo = null;
		isHandlingEvent = false;

		if (!checkModifiers(e)) {
			return;
		}

		VertexMouseInfo<V, E> vertexMouseInfo = getTranslatedMouseInfo(e);
		if (vertexMouseInfo == null) {
			return;
		}

		if (vertexMouseInfo.isScaledPastInteractionThreshold()) {
			return;
		}

		updateCursor(vertexMouseInfo);
		if (allowHeaderClickThroughToLowerLevelMouseHandlers(vertexMouseInfo)) {
			// let the follow-on mouse processors, well, process (this allows dragging to happen)
			return;
		}

		isHandlingEvent = true;
		mousePressedInfo = vertexMouseInfo;

		// When clicking a button on the header, we do not want to clear the other selected
		// vertices, as some of the buttons (like grouping) work on multiple selected vertices.
		// Further, if a user wants to click a button to work on the selection, then we don't
		// want to clear that selection as they click the button.
//		boolean addToSelection = isHeaderButtonClick(vertexMouseInfo) || isControlClick(e);
		boolean addToSelection = isControlClick(e);
		vertexMouseInfo.selectVertex(addToSelection); // make sure the pick state is in synch
		vertexMouseInfo.forwardEvent();
	}

	private VertexMouseInfo<V, E> getTranslatedMouseInfo(MouseEvent e) {
		GraphViewer<V, E> viewer = getGraphViewer(e);
		return GraphViewerUtils.convertMouseEventToVertexMouseEvent(viewer, e);
	}

	private boolean allowHeaderClickThroughToLowerLevelMouseHandlers(VertexMouseInfo<V, E> info) {
		if (info.isPopupClick()) {
			return false;
		}
		return info.isGrabArea();
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		isHandlingEvent = false;
		if (mousePressedInfo != null) {
			VertexMouseInfo<V, E> mouseReleasedMouseInfo = getTranslatedMouseInfo(e);
			if (mouseReleasedMouseInfo == null) {
				// NOTE: getting here implies we had a mousePressed() inside of a vertex, but the
				// mouseReleased() is outside of that vertex (like during a drag operation).  In
				// that case, we want to consume the event, so that other mouse listeners (like
				// the vertex picking listener) do not do unexpected things (like deselecting a
				// vertex after a drag operation).
				handleMouseEventAfterLeavingVertex(e, mousePressedInfo);
				return;
			}

			// Compare the mouse pressed Java component with the mouse released Java 
			// component.  If they are different, then forward the released event to the
			// original, mouse pressed component.  This helps fix issues where dragging started
			// in the contents of a vertex, but ended on the header.
			Component pressedComponent = mousePressedInfo.getClickedComponent();
			Component releasedComponent = mouseReleasedMouseInfo.getClickedComponent();
			if (pressedComponent != releasedComponent) {
				handleMouseEventAfterLeavingVertex(e, mousePressedInfo);
				return;
			}

			if (mouseReleasedMouseInfo.isScaledPastInteractionThreshold()) {
				return;
			}

			mouseReleasedMouseInfo.forwardEvent();
			isHandlingEvent = true;
		}
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		isHandlingEvent = false;
		if (mousePressedInfo != null) {
			isHandlingEvent = true;
			VertexMouseInfo<V, E> mouseDraggedMouseInfo = getTranslatedMouseInfo(e);
			if (mouseDraggedMouseInfo == null) {
				handleMouseEventAfterLeavingVertex(e, mousePressedInfo);
				return;
			}
			else if (mousePressedInfo != mouseDraggedMouseInfo) {
				// don't allow dragging from one vertex into another
				handleMouseEventAfterLeavingVertex(e, mousePressedInfo);
				return;
			}

			if (mouseDraggedMouseInfo.isScaledPastInteractionThreshold()) {
				return;
			}

			mouseDraggedMouseInfo.forwardEvent();
			mouseDraggedMouseInfo.getViewer().repaint();
			return;
		}

		DockingUtils.hideTipWindow();
	}

	/*
	 * The user has initiated a mouse operation, going from inside a vertex to outside the vertex, 
	 * and we want to make sure that event are still given to the original vertex (this allows 
	 * operations like dragging inside of vertices to work as expected)
	 */
	private void handleMouseEventAfterLeavingVertex(MouseEvent e,
			VertexMouseInfo<V, E> startMouseInfo) {
		if (startMouseInfo.isScaledPastInteractionThreshold()) {
			return;
		}

		// create a mouse info for the current event
		GraphViewer<V, E> viewer = startMouseInfo.getViewer();
		V vertex = startMouseInfo.getVertex();
		Point vertexRelativePoint =
			GraphViewerUtils.translatePointFromViewSpaceToVertexRelativeSpace(viewer, e.getPoint(),
				vertex);

		VertexMouseInfo<V, E> currentDraggedInfo =
			viewer.createVertexMouseInfo(e, vertex, vertexRelativePoint);
		currentDraggedInfo.setClickedComponent(startMouseInfo.getClickedComponent(),
			vertexRelativePoint);
		currentDraggedInfo.forwardEvent();
		viewer.repaint();
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		isHandlingEvent = false;
		if (mousePressedInfo != null) {
			isHandlingEvent = true;
			repaintVertex(e, mousePressedInfo);
			VertexMouseInfo<V, E> mouseClickedMouseInfo = getTranslatedMouseInfo(e);
			if (mouseClickedMouseInfo == null) {
				return;
			}

			if (mouseClickedMouseInfo.isScaledPastInteractionThreshold()) {
				return;
			}

			mouseClickedMouseInfo.forwardEvent();
		}

		mousePressedInfo = null;
	}

	private void repaintVertex(MouseEvent e, VertexMouseInfo<V, E> mouseInfo) {
		GraphViewer<V, E> viewer = getGraphViewer(e);
		viewer.repaint();
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		setDefaultCursor(e);
	}

	@Override
	public void mouseExited(MouseEvent e) {
		setDefaultCursor(e);
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		isHandlingEvent = false;
		VertexMouseInfo<V, E> mouseMovedMouseInfo = getTranslatedMouseInfo(e);
		if (mouseMovedMouseInfo == null) {
			triggerMouseExited(currentMouseEnteredInfo, mouseMovedMouseInfo);
			setDefaultCursor(e);
			currentMouseEnteredInfo = null;
			return;
		}

		if (mouseMovedMouseInfo.isScaledPastInteractionThreshold()) {
			return;
		}

		isHandlingEvent = true;
		triggerMouseExited(currentMouseEnteredInfo, mouseMovedMouseInfo);
		triggerMouseEntered(currentMouseEnteredInfo, mouseMovedMouseInfo);

		currentMouseEnteredInfo = mouseMovedMouseInfo;

		mouseMovedMouseInfo.forwardEvent();
	}

	private void triggerMouseExited(VertexMouseInfo<V, E> currentInfo,
			VertexMouseInfo<V, E> newInfo) {
		if (currentInfo == null) {
			return;
		}

		if (newInfo == null) {
			currentInfo.simulateMouseExitedEvent(); // different infos, send the event
		}
		else if (newInfo.getClickedComponent() != currentInfo.getClickedComponent()) {
			currentInfo.simulateMouseExitedEvent(); // different infos, send the event
		}
	}

	private void triggerMouseEntered(VertexMouseInfo<V, E> currentInfo,
			VertexMouseInfo<V, E> newInfo) {
		if (currentInfo == null ||
			(newInfo.getClickedComponent() != currentInfo.getClickedComponent())) {
			newInfo.simulateMouseEnteredEvent();
		}

		updateCursor(newInfo);
	}

	private void updateCursor(VertexMouseInfo<V, E> info) {
		if (!isHandlingEvent) {
			return;
		}
		JComponent c = (JComponent) info.getEventSource();
		c.setCursor(info.getCursorForClickedComponent());
	}

	private void setDefaultCursor(MouseEvent e) {
		if (!isHandlingEvent) {
			return;
		}
		JComponent c = (JComponent) e.getSource();
		c.setCursor(Cursor.getPredefinedCursor(Cursor.DEFAULT_CURSOR));
	}
}
