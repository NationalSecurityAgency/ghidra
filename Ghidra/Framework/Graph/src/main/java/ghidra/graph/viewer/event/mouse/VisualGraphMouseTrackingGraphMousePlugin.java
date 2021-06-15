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

import java.awt.Color;
import java.awt.Point;
import java.awt.event.*;
import java.awt.geom.AffineTransform;
import java.util.Objects;

import docking.DockingUtils;
import edu.uci.ics.jung.visualization.*;
import edu.uci.ics.jung.visualization.control.AbstractGraphMousePlugin;
import edu.uci.ics.jung.visualization.transform.MutableTransformer;
import ghidra.graph.viewer.*;
import ghidra.graph.viewer.renderer.*;

/**
 * A simple plugin that allows clients to be notified of mouse events before any of the other
 * mouse plugins.
 *
 * @param <V> the vertex type
 * @param <E> the edge type
 */
//@formatter:off
public class VisualGraphMouseTrackingGraphMousePlugin<V extends VisualVertex, 
                                                      E extends VisualEdge<V>> 
	extends AbstractGraphMousePlugin
	implements MouseListener, MouseMotionListener, VisualGraphMousePlugin<V, E> {
//@formatter:on

	private MouseDebugPaintable paintable = new MouseDebugPaintable();
	private GraphViewer<V, E> viewer;

	private Point dragEnd;
	private MouseDraggedPaintableShape dragShape;
	private MouseDraggedLinePaintableShape dragLineShape;
	private int mouseMovedCount;

	public VisualGraphMouseTrackingGraphMousePlugin(GraphViewer<V, E> viewer) {
		super(InputEvent.BUTTON1_DOWN_MASK | InputEvent.BUTTON2_DOWN_MASK |
			InputEvent.BUTTON3_DOWN_MASK);
		this.viewer = Objects.requireNonNull(viewer);
		viewer.addPostRenderPaintable(paintable);
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

	@Override
	public void mouseDragged(MouseEvent e) {

		RenderContext<?, ?> rc = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		MutableTransformer layoutXformer = multiLayerTransformer.getTransformer(Layer.LAYOUT);
		AffineTransform layoutXform = layoutXformer.getTransform();
		double tx = layoutXform.getTranslateX();
		double ty = layoutXform.getTranslateY();

		Point p = e.getPoint();
		Point gp = GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(p, viewer);
		dragEnd = gp;

		Point gDown = GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(down, viewer);
		if (dragShape == null) {
			dragShape = new MouseDraggedPaintableShape(gDown, gp, tx, ty);
			paintable.addShape(dragShape, viewer);
		}
		else {
			dragShape.setPoints(gDown, dragEnd);
		}

		int offset = 20;
		Point downOver = new Point(down.x + offset, down.y + offset);
		Point pOver = new Point(p.x + offset, p.y + offset);
		Point gpOver = GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(pOver, viewer);
		if (dragLineShape == null) {

			Point gDownOver =
				GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(downOver, viewer);
			dragLineShape = new MouseDraggedLinePaintableShape(gDownOver, gpOver, tx, ty);
			paintable.addShape(dragLineShape, viewer);
		}
		else {
			dragLineShape.addPoint(gpOver);
		}

		viewer.repaint();

	}

	@Override
	public void mouseMoved(MouseEvent e) {

		// we get a lot of these events, so don't record them all
		if (++mouseMovedCount % 5 == 0) {
			addPointMousePaintable(e, new Color(0, 255, 0, 127)); // greenish	
		}
	}

	@Override
	public void mouseClicked(MouseEvent e) {

		int button = e.getButton();
		if (button == MouseEvent.BUTTON2) {
			paintable.clear();
			return;
		}

		addPointMousePaintable(e, Color.ORANGE);
	}

	private void addPointMousePaintable(MouseEvent e, Color color) {
		Point p = e.getPoint();
		Point gp = GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(p, viewer);

		RenderContext<?, ?> rc = viewer.getRenderContext();
		MultiLayerTransformer multiLayerTransformer = rc.getMultiLayerTransformer();
		MutableTransformer layoutXformer = multiLayerTransformer.getTransformer(Layer.LAYOUT);
		AffineTransform layoutXform = layoutXformer.getTransform();
		double tx = layoutXform.getTranslateX();
		double ty = layoutXform.getTranslateY();

		MouseClickedPaintableShape ps = new MouseClickedPaintableShape(gp, tx, ty, color);
		paintable.addShape(ps, viewer);
		viewer.repaint();
	}

	@Override
	public void mousePressed(MouseEvent e) {
		Point p = e.getPoint();
		down = p;
	}

	@Override
	public void mouseReleased(MouseEvent e) {

		down = null;
		dragEnd = null;
		if (dragShape != null) {
			dragShape.shapeFinished();
			dragShape = null;
		}

		if (dragLineShape != null) {
			dragLineShape.shapeFinished();
			dragLineShape = null;
		}

		viewer.repaint();
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		// stub
	}

	@Override
	public void mouseExited(MouseEvent e) {
		// stub
	}
}
