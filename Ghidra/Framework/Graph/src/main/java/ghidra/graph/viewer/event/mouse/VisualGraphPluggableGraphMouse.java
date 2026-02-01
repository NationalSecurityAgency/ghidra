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

import java.awt.Component;
import java.awt.event.*;
import java.util.concurrent.CopyOnWriteArrayList;

import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.control.GraphMousePlugin;
import ghidra.graph.viewer.VisualEdge;
import ghidra.graph.viewer.VisualVertex;
import ghidra.util.Msg;

/**
 * This is the class that controls which mouse plugins get installed into the graph.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
public class VisualGraphPluggableGraphMouse<V extends VisualVertex, E extends VisualEdge<V>>
		implements VisualizationViewer.GraphMouse {

	protected CopyOnWriteArrayList<GraphMousePlugin> mousePlugins = new CopyOnWriteArrayList<>();

	public VisualGraphPluggableGraphMouse() {
		addPlugins();
	}

	protected void addPlugins() {

		//
		// Note: the order of these additions matters, as an event will flow to each plugin until
		//       it is handled.
		//

		// passes events to the Ghidra components
		add(new VisualGraphEventForwardingGraphMousePlugin<V, E>());

		// edge and vertex picking
		add(new VisualGraphEdgeSelectionGraphMousePlugin<V, E>());
//        add( new VisualGraphAnimatedPickingGraphMousePlugin<V, E>() );
		add(new VisualGraphZoomingPickingGraphMousePlugin<V, E>());

		// zooming and alternate mouse wheel operation--panning
		add(new VisualGraphScalingGraphMousePlugin<V, E>());
		add(new VisualGraphScrollWheelPanningPlugin<V, E>());

		// the grab/pan feature
		add(new VisualGraphTranslatingGraphMousePlugin<V, E>());

		// ...more picking (dragging an area and single node picking)
		add(new VisualGraphPickingGraphMousePlugin<V, E>());

		// cursor cleanup
		add(new VisualGraphCursorRestoringGraphMousePlugin<V, E>());
	}

	/** 
	 * Places the given plugin at the front of the list
	 * 
	 * @param p the mouse plugin to prepend
	 */
	public void prepend(GraphMousePlugin p) {

		if (mousePlugins.contains(p)) {
			mousePlugins.remove(p);
		}

		mousePlugins.add(0, p);
	}

	public void add(GraphMousePlugin p) {
		if (mousePlugins.contains(p)) {
			mousePlugins.remove(p);
		}

		mousePlugins.add(p);
	}

	public void remove(GraphMousePlugin p) {
		mousePlugins.remove(p);
	}

	public void dispose() {
		for (GraphMousePlugin mp : mousePlugins) {
			if (mp instanceof VisualGraphMousePlugin) {
				((VisualGraphMousePlugin<?, ?>) mp).dispose();
			}
		}
		mousePlugins.clear();
	}

	private void trace(String s) {
		Msg.trace(this, s);
	}

	private void trace(String s, MouseEvent e) {
		Msg.trace(this, "click count = " + e.getClickCount() + " - " + s);
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		MouseEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}
			trace("mouseClicked() on " + p, copy);
			((MouseListener) p).mouseClicked(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mousePressed(MouseEvent e) {
		MouseEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mousePressed() on " + p, copy);
			((MouseListener) p).mousePressed(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		MouseEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mouseReleased() on " + p, copy);
			((MouseListener) p).mouseReleased(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		MouseEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mouseEntered() on " + p, copy);
			((MouseListener) p).mouseEntered(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseExited(MouseEvent e) {
		MouseEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mouseExited() on " + p, copy);
			((MouseListener) p).mouseExited(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		MouseEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseMotionListener)) {
				continue;
			}

			trace("mouseDragged() on " + p, copy);
			((MouseMotionListener) p).mouseDragged(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		MouseEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseMotionListener)) {
				continue;
			}

			trace("mouseMoved() on " + p, copy);
			((MouseMotionListener) p).mouseMoved(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseWheelMoved(MouseWheelEvent e) {
		MouseWheelEvent copy = copy(e);
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseWheelListener)) {
				continue;
			}

			trace("mouseWheelMoved() on " + p, copy);
			((MouseWheelListener) p).mouseWheelMoved(copy);
			if (copy.isConsumed()) {
				e.consume();
				trace("\tconsumed");
				return;
			}
		}
	}

	/**
	 * Copies the given mouse event. We do this so that we allow our mouse plugins to process 
	 * mouse events. This was done specifically allow us to update state when user right-clicks.
	 * Ghidra has code that will consume mouse clicks before we get the event.
	 * <P>
	 * This pluggable graph mouse sub-system will stop processing when one of the plugins consumes
	 * the mouse event. We have to create a copy to avoid an already consumed incoming event from
	 * short-circuiting our event processing.
	 * @param e
	 * @return a copy if the original incoming event with the consumed flag cleared.
	 */
	private MouseEvent copy(MouseEvent e) {
		Component source = e.getComponent();
		int id = e.getID();
		int button = e.getButton();
		long when = e.getWhen();
		int modifiers = e.getModifiersEx();
		int x = e.getX();
		int y = e.getY();
		int clickCount = e.getClickCount();
		boolean popupTrigger = e.isPopupTrigger();
		return new MouseEvent(source, id, when, modifiers, x, y, clickCount, popupTrigger, button);
	}

	private MouseWheelEvent copy(MouseWheelEvent e) {
		Component source = e.getComponent();
		int id = e.getID();
		long when = e.getWhen();
		int modifiers = e.getModifiersEx();
		int x = e.getX();
		int y = e.getY();
		int clickCount = e.getClickCount();
		boolean popupTrigger = e.isPopupTrigger();
		int scrollType = e.getScrollType();
		int scrollAmount = e.getScrollAmount();
		int wheelRotation = e.getWheelRotation();
		return new MouseWheelEvent(source, id, when, modifiers, x, y, clickCount, popupTrigger,
			scrollType, scrollAmount, wheelRotation);
	}
}
