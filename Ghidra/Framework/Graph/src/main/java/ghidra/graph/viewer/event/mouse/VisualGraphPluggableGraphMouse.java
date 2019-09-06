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
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mouseClicked() on " + p, e);
			((MouseListener) p).mouseClicked(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mousePressed(MouseEvent e) {
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mousePressed() on " + p, e);
			((MouseListener) p).mousePressed(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mouseReleased() on " + p, e);
			((MouseListener) p).mouseReleased(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mouseEntered() on " + p, e);
			((MouseListener) p).mouseEntered(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseExited(MouseEvent e) {
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseListener)) {
				continue;
			}

			trace("mouseExited() on " + p, e);
			((MouseListener) p).mouseExited(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseDragged(MouseEvent e) {
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseMotionListener)) {
				continue;
			}

			trace("mouseDragged() on " + p, e);
			((MouseMotionListener) p).mouseDragged(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseMoved(MouseEvent e) {
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseMotionListener)) {
				continue;
			}

			trace("mouseMoved() on " + p, e);
			((MouseMotionListener) p).mouseMoved(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}

	@Override
	public void mouseWheelMoved(MouseWheelEvent e) {
		for (GraphMousePlugin p : mousePlugins) {
			if (!(p instanceof MouseWheelListener)) {
				continue;
			}

			trace("mouseWheelMoved() on " + p, e);
			((MouseWheelListener) p).mouseWheelMoved(e);
			if (e.isConsumed()) {
				trace("\tconsumed");
				return;
			}
		}
	}
}
