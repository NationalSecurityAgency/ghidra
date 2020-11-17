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
package ghidra.graph.viewer;

import static org.junit.Assert.*;

import java.awt.Point;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.awt.geom.Point2D;
import java.util.Collection;
import java.util.HashSet;
import java.util.function.Supplier;

import javax.swing.JFrame;

import org.junit.After;
import org.junit.Before;

import docking.test.AbstractDockingTest;
import edu.uci.ics.jung.algorithms.layout.Layout;
import generic.test.AbstractGenericTest;
import ghidra.graph.graphs.AbstractTestVertex;
import ghidra.graph.graphs.TestEdge;
import ghidra.graph.support.*;
import ghidra.graph.viewer.event.mouse.VisualGraphMouseTrackingGraphMousePlugin;
import ghidra.graph.viewer.event.mouse.VisualGraphPluggableGraphMouse;
import ghidra.graph.viewer.event.picking.GPickedState;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import util.CollectionUtils;

/**
 * Creates a basic test environment that uses a JFrame to house a {@link GraphComponent}, which
 * itself has a primary and satellite viewer, all initialized with a graph of your setup, 
 * with reasonable default settings.
 */
public abstract class AbstractVisualGraphTest extends AbstractDockingTest {

	protected JFrame frame;
	protected TestVisualGraph graph;
	protected GraphComponent<AbstractTestVertex, TestEdge, TestVisualGraph> graphComponent;

	@Before
	public void setUp() throws Exception {

		buildAndLayoutGraph();

		initialize();

		frame = new JFrame("Graph Viewer Test");
		swing(() -> {
			frame.setSize(400, 400);
			frame.getContentPane().add(graphComponent.getComponent());
			frame.setVisible(true);
			frame.validate();
		});
	}

	protected void buildAndLayoutGraph() throws CancelledException {
		// the test machine has odd Swing exceptions when we construct UIs off the Swing thread
		graph = runSwing(() -> buildGraph());

		TestLayoutProvider layoutProvider = createLayoutProvider();
		graph.setLayout(layoutProvider.getLayout(graph, TaskMonitor.DUMMY));
		graphComponent = runSwing(() -> createGraphComponent(layoutProvider));
	}

	protected TestLayoutProvider createLayoutProvider() {
		return new TestLayoutProvider();
	}

	protected GraphComponent<AbstractTestVertex, TestEdge, TestVisualGraph> createGraphComponent(
			TestLayoutProvider layoutProvider) {
		return new GraphComponent<>(graph);
	}

	protected void initialize() {
		// for subclasses to perform post-setup work
	}

	protected abstract TestVisualGraph buildGraph();

	@After
	public void tearDown() {
		swing(() -> {
			frame.setVisible(false);
			graphComponent.dispose();
		});
	}

	protected AbstractTestVertex getVertex(String name) {
		Collection<AbstractTestVertex> vertices = graph.getVertices();
		for (AbstractTestVertex v : vertices) {
			if (v.getName().equals(name)) {
				return v;
			}
		}
		return null;
	}

	protected AbstractTestVertex getAnyVertex() {
		return CollectionUtils.any(graph.getVertices());
	}

	protected TestEdge getEdge(AbstractTestVertex v1, AbstractTestVertex v2) {
		TestEdge e = graph.findEdge(v1, v2);
		return e;
	}

	protected void swing(Runnable r) {
		AbstractGenericTest.runSwing(r);
	}

	protected <T> T swing(Supplier<T> s) {
		return AbstractGenericTest.runSwing(s);
	}

	protected void waitForAnimation() {

		//
		// Note: we need to stop edge hover animations, as they can go on for a long time.  If
		//       any test needs them, then we can add a different wait method.
		//

		waitForSwing();
		VisualGraphViewUpdater<AbstractTestVertex, TestEdge> updater =
			graphComponent.getViewUpdater();
		swing(() -> updater.stopEdgeHoverAnimation());

		// animation sometimes takes too long on the test machine, so we may try more than once
		int tryCount = 0;
		while (tryCount++ < 5 && updater.isBusy()) {
			waitForConditionWithoutFailing(() -> !updater.isBusy());
		}

		assertFalse("Timed-out waiting for animation", updater.isBusy());
		waitForSwing();
	}

	protected void assertPointsAreAboutEqual(String message, Point2D primaryPoint,
			Point2D clonePoint) {
		double x1 = primaryPoint.getX();
		double x2 = clonePoint.getX();

		// 'fudge' is the amount by which we may be off when comparing point values (I think
		// we run into rounding errors when converting doubles to integers as we are processing
		// mouse events)
		double fudge = 5; // this can be bigger if needed
		assertEquals(message + ": x value for points is not the same", x1, x2, fudge);

		double y1 = primaryPoint.getY();
		double y2 = clonePoint.getY();
		assertEquals(message + ": y value for points is not the same", y1, y2, fudge);
	}

	protected void setZoom(double newZoom) {

		VisualGraphViewUpdater<AbstractTestVertex, TestEdge> updater =
			graphComponent.getViewUpdater();
		swing(() -> updater.setGraphScale(newZoom));
		waitForAnimation();
		waitForCondition(() -> Double.compare(newZoom, getZoom()) == 0);
	}

	protected double getZoom() {
		return runSwing(() -> GraphViewerUtils.getGraphScale(graphComponent.getPrimaryViewer()));
	}

	protected void moveVertex(AbstractTestVertex v, int xOffset, int yOffset) {

		waitForAnimation();

		Point2D viewPoint = new Point2D.Double(xOffset, yOffset);
		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		Point layoutPoint =
			GraphViewerUtils.translatePointFromViewSpaceToLayoutSpace(viewPoint, viewer);

		swing(() -> {
			TestGraphLayout layout = graph.getLayout();
			Point2D p = layout.apply(v);
			layout.setLocation(v,
				new Point2D.Double(p.getX() + layoutPoint.getX(), p.getY() + layoutPoint.getY()));
		});
		waitForAnimation();
	}

	protected Point getViewLocation(AbstractTestVertex v) {

		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		Point vertexUpperLeftCornerInViewSpace =
			swing(() -> GraphViewerUtils.getVertexUpperLeftCornerInViewSpace(viewer, v));

		return vertexUpperLeftCornerInViewSpace;
	}

	/**
	 * Makes the given vertex visible by, as needed, moving it away (out from under) other 
	 * vertices and moving the viewers visible area so that it is on screen.
	 * 
	 * @param v the vertex
	 */
	protected void ensureVertexVisible(AbstractTestVertex v) {
		isolateVertex(v);

		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		swing(() -> viewer.getViewUpdater().ensureVertexVisible(v, null));
		waitForAnimation();
	}

	/**
	 * Moves the given vertex as necessary so that it is not touching any other vertex
	 * 
	 * @param v the vertex
	 */
	protected void isolateVertex(AbstractTestVertex v) {
		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		Layout<AbstractTestVertex, TestEdge> layout = viewer.getGraphLayout();
		Rectangle vBounds = GraphViewerUtils.getVertexBoundsInLayoutSpace(viewer, v);

		boolean hit = false;
		Collection<AbstractTestVertex> others = new HashSet<>(graph.getVertices());
		others.remove(v);
		for (AbstractTestVertex other : others) {
			Rectangle otherBounds = GraphViewerUtils.getVertexBoundsInLayoutSpace(viewer, other);
			if (vBounds.intersects(otherBounds)) {
				hit = true;
				Point p = vBounds.getLocation();
				int w = (int) vBounds.getWidth();
				int h = (int) vBounds.getHeight();
				Point newPoint = new Point(p.x + w, p.y + h);
				swing(() -> layout.setLocation(v, newPoint));
				viewer.repaint();
				sleep(50); // let us see the effect
				waitForSwing();
			}
		}

		if (hit) {
			// keep moving until we are clear of other vertices
			isolateVertex(v);
		}
	}

	protected void clickViewer(int x, int y) {
		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		AbstractGenericTest.clickMouse(viewer, MouseEvent.BUTTON1, x, y, 1, 0);
		waitForSwing();
	}

	protected void clickVertex(AbstractTestVertex v, int xOffset, int yOffset) throws Exception {
		clickVertex(v, xOffset, yOffset, 1);
	}

	protected void clickVertex(AbstractTestVertex v, int xOffset, int yOffset, int clickCount) {

		AbstractTestVertex preClickFocused = swing(() -> graph.getFocusedVertex());

		Msg.debug(this, "clicking vertex: " + v);

		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		Point p = getViewLocation(v);
		int x = p.x + xOffset;
		int y = p.y + yOffset;
		AbstractGenericTest.clickMouse(viewer, MouseEvent.BUTTON1, x, y, clickCount, 0);
		waitForSwing();

		AbstractTestVertex focused = swing(() -> graph.getFocusedVertex());

		Msg.debug(this, "pre-click focused: " + preClickFocused);
		Msg.debug(this, "post-click focused: " + focused);
		Msg.debug(this, "expected focused: " + v);
		Msg.debug(this, "actual focused: " + focused);

		if (!v.equals(focused)) {

			assertEquals("Clicking the vertex did not select it", v, focused);
		}
	}

	protected void dragMouse(AbstractTestVertex v, int yOffset, int distance) throws Exception {

		Point startViewPoint = getViewLocation(v);

		int inABit = 10; // be sure we are inside the vertex
		int x1 = startViewPoint.x + inABit;
		int y1 = startViewPoint.y + yOffset;

		int x2 = x1 + distance;
		int y2 = y1 + distance;

		drag(x1, y1, x2, y2);
	}

	protected void moveMouse(AbstractTestVertex v) {
		//
		// Use the center of the vertex, which is easier than adding an arbitrary offset to 
		// the mouse points when dealing with scaling
		//

		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();

		Point2D p = swing(() -> GraphViewerUtils.getVertexCenterPointInViewSpace(viewer, v));

		int x = (int) p.getX();
		int y = (int) p.getY();
		AbstractGenericTest.moveMouse(viewer, x, y);
	}

	protected void drag(int x1, int y1, int x2, int y2) {
		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		AbstractGenericTest.dragMouse(viewer, MouseEvent.BUTTON1, x1, y1, x2, y2, 0);
		waitForAnimation();
	}

	protected void scaleGraphPastInteractionThreshold() {
		VisualGraphViewUpdater<AbstractTestVertex, TestEdge> updater =
			graphComponent.getViewUpdater();

		double scale = GraphViewerUtils.INTERACTION_ZOOM_THRESHOLD - .01;
		swing(() -> updater.setGraphScale(scale));
	}

	protected void installMouseDebugger() {

		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		VisualGraphPluggableGraphMouse<AbstractTestVertex, TestEdge> graphMouse =
			viewer.getGraphMouse();

		VisualGraphMouseTrackingGraphMousePlugin<AbstractTestVertex, TestEdge> plugin =
			new VisualGraphMouseTrackingGraphMousePlugin<>(viewer);

		// put in first so it will get all events (listeners later in the list will not get 
		// consumed events)
		graphMouse.prepend(plugin);
	}

	/**
	 * Focuses the given vertex, which means to trigger it to be picked/selected in the UI, 
	 * causing it to be the focused vertex of the graph.
	 * 
	 * @param v the vertex
	 */
	protected void focusVertex(AbstractTestVertex v) {
		GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		GPickedState<AbstractTestVertex> ps = viewer.getGPickedVertexState();
		swing(() -> {
			ps.clear();
			ps.pick(v, true);
		});
		AbstractTestVertex focused = swing(() -> graph.getFocusedVertex());
		assertEquals(v, focused);
	}

	protected void hoverVertex(AbstractTestVertex v) {
		ensureVertexVisible(v);
		moveMouse(v);

		waitForSwing();
		if (!v.isHovered()) {
			fail("Attempted to hover vertex, but it was not set to hovered: " + v);
		}
	}

	protected boolean isSatelliteVisible() {
		return swing(() -> graphComponent.isSatelliteShowing());
	}

	protected boolean isSatelliteUndocked() {
		return swing(() -> graphComponent.isSatelliteUnDocked());
	}

	protected void hideSatellite() {
		swing(() -> graphComponent.setSatelliteVisible(false));
		waitForSwing();
	}
}
