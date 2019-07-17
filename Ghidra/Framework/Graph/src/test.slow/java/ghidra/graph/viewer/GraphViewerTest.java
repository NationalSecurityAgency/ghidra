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

import java.awt.*;
import java.awt.event.MouseEvent;
import java.awt.event.MouseMotionListener;
import java.awt.geom.*;
import java.util.Collection;
import java.util.List;

import org.junit.Test;

import edu.uci.ics.jung.algorithms.layout.KKLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import generic.test.AbstractGTest;
import ghidra.graph.graphs.*;
import ghidra.graph.support.*;
import ghidra.graph.support.TestVertexTooltipProvider.SpyTooltip;

public class GraphViewerTest extends AbstractVisualGraphTest {

	private GraphViewer<AbstractTestVertex, TestEdge> viewer;
	private TestVertexTooltipProvider tooltipSpy;

	@Override
	protected TestVisualGraph buildGraph() {
		TestVisualGraph g = new TestVisualGraph();

		AbstractTestVertex v1 = new LabelTestVertex("1");
		AbstractTestVertex v2 = new LabelTestVertex("2");
		TestEdge e1 = new TestEdge(v1, v2);

		g.addVertex(v1);
		g.addVertex(v2);
		g.addEdge(e1);

		return g;
	}

	@Override
	protected TestLayoutProvider createLayoutProvider() {
		return new TestLayoutProvider() {
			@Override
			protected Layout<AbstractTestVertex, TestEdge> createJungLayout(TestVisualGraph g) {
				return new KKLayout<>(g);
			}
		};
	}

	@Override
	protected void initialize() {
		viewer = graphComponent.getPrimaryViewer();
		viewer.setPopupDelay(100); // shorter value to make test faster
		tooltipSpy = new TestVertexTooltipProvider();
		viewer.setVertexTooltipProvider(tooltipSpy);
	}

	@Test
	public void testShowPopupForVertex() {

		AbstractTestVertex v = getVertex("1");

		assertPopupsShown(v, 0);
		hoverVertex(v);
		assertPopupsShown(v, 1);
	}

	@Test
	public void testDraggingHidesPopup() throws Exception {
		AbstractTestVertex v = getVertex("1");
		hoverVertex(v);
		assertPopupShowing(true);

		AbstractTestVertex v2 = getVertex("2");

		dragVertex(v2);
		assertPopupShowing(false);
	}

	@Test
	public void testShowingPopupEmphasizesPopeeWhenScaled() {

		scaleGraphPastInteractionThreshold();

		AbstractTestVertex v = getVertex("1");
		hoverVertex(v);
		assertPopupsShown(v, 1);
		assertTrue(v.hasBeenEmphasised());
	}

	@Test
	public void testShowPopupForEdge() {

		//
		// The edge tooltip is created from its incident vertices
		//

		installMouseDebugger();

		AbstractTestVertex v1 = getVertex("1");
		AbstractTestVertex v2 = getVertex("2");
		TestEdge e = getEdge(v1, v2);

		assertPopupsShown(v1, 0);
		assertPopupsShown(v2, 0);
		hoverEdge(e);
		assertPopupsShown(v1, 1);
		assertPopupsShown(v2, 1);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	@Override
	protected void hoverVertex(AbstractTestVertex v) {

		tooltipSpy.clearTooltipTriggered();

		super.hoverVertex(v);

		AbstractGTest.waitForCondition(() -> tooltipSpy.isTooltipTriggered(),
			"Timed-out waiting for tooltip to appear");
		waitForSwing();
	}

	private void hoverEdge(TestEdge edge) {

		// if the vertex is visible, then at least part of the edge will be
		ensureVertexVisible(edge.getStart());

		Point2D graphSpaceEdgePoint = findHoverPointInGraphSpace(edge);
		Point viewPoint =
			GraphViewerUtils.translatePointFromGraphSpaceToViewSpace(graphSpaceEdgePoint, viewer);

		int mods = 0;
		MouseEvent e = new MouseEvent(viewer, MouseEvent.MOUSE_MOVED, System.currentTimeMillis(),
			mods, viewPoint.x, viewPoint.y, 0, false);

		MouseMotionListener[] listeners = viewer.getMouseMotionListeners();
		swing(() -> {
			for (MouseMotionListener listener : listeners) {
				listener.mouseMoved(e);
			}
		});

		tooltipSpy.clearTooltipTriggered();
		AbstractGTest.waitForCondition(() -> tooltipSpy.isTooltipTriggered(),
			"Timed-out waiting for tooltip to appear");
		waitForSwing();
	}

	/**
	 * Finds a point which intersects the given edge and does not intersect any vertex.
	 * 
	 * @param e the edge
	 * @return the point
	 */
	private Point2D findHoverPointInGraphSpace(TestEdge e) {

		//
		// Get the edge shape.  Then, walk from start to end, incrementally, looking for a 
		// point that hovers the edge.
		//
		Shape edgeShape = GraphViewerUtils.getEdgeShapeInGraphSpace(viewer, e);

		float[] coords = new float[6];
		GeneralPath path = new GeneralPath(edgeShape);
		PathIterator iterator = path.getPathIterator(null);

		iterator.currentSegment(coords);
		float startX = coords[0];
		float startY = coords[1];

		iterator.next();
		iterator.currentSegment(coords);
		float endX = coords[0];
		float endY = coords[1];

		Point2D sp = new Point2D.Float(startX, startY);

		Point vsp = GraphViewerUtils.translatePointFromGraphSpaceToViewSpace(sp, viewer);
		clickViewer(vsp.x, vsp.y);

		Point2D ep = new Point2D.Float(endX, endY);

		Point vep = GraphViewerUtils.translatePointFromGraphSpaceToViewSpace(ep, viewer);
		clickViewer(vep.x, vep.y);

		float offset = .1f;
		for (int i = 1; i < 10; i++) {

			// move towards the endpoint until we are not occluded by the vertex
			float dx = endX - startX;
			float dy = endY - startY;
			float testX = startX + (dx * (offset * i));
			float testY = startY + (dy * (offset * i));

			Point2D testPoint = new Point2D.Float(testX, testY);

			Point viewPoint =
				GraphViewerUtils.translatePointFromGraphSpaceToViewSpace(testPoint, viewer);
			clickViewer(viewPoint.x, viewPoint.y);

			// give the area some size to make the intersection a bit easier
			int size = 2;
			Rectangle2D pickArea = new Rectangle2D.Double(testPoint.getX() - size / 2,
				testPoint.getY() - size / 2, size, size);

			if (edgeShape.intersects(pickArea)) {
				if (!intersectsAnyVertex(pickArea)) {
					// found a point that hits the edge and not the vertex
					return testPoint;
				}
			}
		}

		fail("Unable to find a point on the edge to hover");
		return null; // unreachable
	}

	private boolean intersectsAnyVertex(Rectangle2D graphSpaceArea) {
		Collection<AbstractTestVertex> vertices = graph.getVertices();
		for (AbstractTestVertex v : vertices) {
			Rectangle bounds = GraphViewerUtils.getVertexBoundsInGraphSpace(viewer, v);
			if (bounds.intersects(graphSpaceArea)) {
				return true;
			}
		}
		return false;
	}

	private void dragVertex(AbstractTestVertex v) throws Exception {
		dragMouse(v, 5, 20);
	}

	private void assertPopupShowing(boolean showing) {
		boolean isShowing = swing(() -> viewer.isPopupShowing());
		assertEquals(showing, isShowing);
	}

	private void assertPopupsShown(AbstractTestVertex v, int n) {
		List<SpyTooltip> tooltips = swing(() -> tooltipSpy.getShownTooltips(v));
		assertEquals(n, tooltips.size());
	}

	/*
	
	setVertexTooltipProvider(VertexTooltipProvider<V, E>)
	useMouseRelativeZoom()
	setPopupsVisible(boolean)
	getToolTipText(MouseEvent)
	createVertexMouseInfo(MouseEvent, V, Point2D)
	 
	 */
}
