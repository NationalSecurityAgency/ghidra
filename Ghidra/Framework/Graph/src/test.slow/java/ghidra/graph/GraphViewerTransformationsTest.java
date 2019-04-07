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
package ghidra.graph;

import java.awt.Dimension;
import java.awt.Point;
import java.awt.geom.Point2D;

import javax.swing.JFrame;

import org.junit.*;

import edu.uci.ics.jung.algorithms.layout.DAGLayout;
import edu.uci.ics.jung.algorithms.layout.Layout;
import generic.test.AbstractGenericTest;
import ghidra.graph.graphs.*;
import ghidra.graph.support.*;
import ghidra.graph.viewer.GraphViewerUtils;

public class GraphViewerTransformationsTest {

	private TestGraphViewer viewer;
	private JFrame frame;
	private TestVisualGraph graph;

	@Before
	public void setUp() throws Exception {

		graph = buildGraph();
		Layout<AbstractTestVertex, TestEdge> jungLayout = new DAGLayout<>(graph);
		TestGraphLayout testLayout = new TestGraphLayout(jungLayout);
		viewer = new TestGraphViewer(testLayout, new Dimension(400, 400));

		frame = new JFrame("Graph Viewer Test");
		frame.setSize(400, 400);
		frame.getContentPane().add(viewer);
		frame.setVisible(true);
	}

	@After
	public void tearDown() {
		swing(() -> {
			frame.setVisible(false);
			graph.dispose();
			viewer.dispose();
		});
	}

	protected void swing(Runnable r) {
		AbstractGenericTest.runSwing(r);
	}

	private TestVisualGraph buildGraph() {

		TestVisualGraph g = new TestVisualGraph();

		AbstractTestVertex v1 = new LabelTestVertex("1");
		AbstractTestVertex v2 = new LabelTestVertex("2");
		TestEdge e1 = new TestEdge(v1, v2);

		g.addVertex(v1);
		g.addVertex(v2);
		g.addEdge(e1);

		return g;
	}

	@Test
	public void testViewToLayoutSpacePoint() {
		// full zoom
		setZoom(1d);

		Point2D viewSpacePoint = new Point2D.Double(100D, 100D);
		Point layoutSpacePoint =
			GraphViewerUtils.translatePointFromViewSpaceToLayoutSpace(viewSpacePoint, viewer);

		Point newViewSpacePoint =
			GraphViewerUtils.translatePointFromLayoutSpaceToViewSpace(layoutSpacePoint, viewer);
		assertPointEquals(viewSpacePoint, newViewSpacePoint);

		// zoomed out
		setZoom(.5d);

		layoutSpacePoint =
			GraphViewerUtils.translatePointFromViewSpaceToLayoutSpace(viewSpacePoint, viewer);

		newViewSpacePoint =
			GraphViewerUtils.translatePointFromLayoutSpaceToViewSpace(layoutSpacePoint, viewer);
		assertPointEquals(viewSpacePoint, newViewSpacePoint);
	}

	@Test
	public void testViewToGraphSpacePoint() {
		// full zoom
		setZoom(1d);

		Point2D viewSpacePoint = new Point2D.Double(100D, 100D);
		Point layoutSpacePoint =
			GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(viewSpacePoint, viewer);

		Point newViewSpacePoint =
			GraphViewerUtils.translatePointFromGraphSpaceToViewSpace(layoutSpacePoint, viewer);
		assertPointEquals(viewSpacePoint, newViewSpacePoint);

		// zoomed out
		setZoom(.5d);

		layoutSpacePoint =
			GraphViewerUtils.translatePointFromViewSpaceToGraphSpace(viewSpacePoint, viewer);

		newViewSpacePoint =
			GraphViewerUtils.translatePointFromGraphSpaceToViewSpace(layoutSpacePoint, viewer);
		assertPointEquals(viewSpacePoint, newViewSpacePoint);
	}

	@Test
	public void testLayoutToGraphSpacePoint() {
		// full zoom
		setZoom(1d);

		Point2D layoutSpacePoint = new Point2D.Double(100D, 100D);
		Point graphSpacePoint =
			GraphViewerUtils.translatePointFromLayoutSpaceToGraphSpace(layoutSpacePoint, viewer);

		Point newLayoutSpacePoint =
			GraphViewerUtils.translatePointFromGraphSpaceToLayoutSpace(graphSpacePoint, viewer);
		assertPointEquals(layoutSpacePoint, newLayoutSpacePoint);

		// zoomed out
		setZoom(.5d);

		graphSpacePoint =
			GraphViewerUtils.translatePointFromLayoutSpaceToGraphSpace(layoutSpacePoint, viewer);

		newLayoutSpacePoint =
			GraphViewerUtils.translatePointFromGraphSpaceToLayoutSpace(graphSpacePoint, viewer);
		assertPointEquals(layoutSpacePoint, newLayoutSpacePoint);
	}

	@Test
	public void testGraphToLayoutSpacePoint() {
		// full zoom
		setZoom(1d);

		Point2D graphSpacePoint = new Point2D.Double(100D, 100D);
		Point layoutSpacePoint =
			GraphViewerUtils.translatePointFromGraphSpaceToLayoutSpace(graphSpacePoint, viewer);

		Point newLayoutSpacePoint =
			GraphViewerUtils.translatePointFromLayoutSpaceToGraphSpace(layoutSpacePoint, viewer);
		assertPointEquals(graphSpacePoint, newLayoutSpacePoint);

		// zoomed out
		setZoom(.5d);

		layoutSpacePoint =
			GraphViewerUtils.translatePointFromGraphSpaceToLayoutSpace(graphSpacePoint, viewer);

		newLayoutSpacePoint =
			GraphViewerUtils.translatePointFromLayoutSpaceToGraphSpace(layoutSpacePoint, viewer);
		assertPointEquals(graphSpacePoint, newLayoutSpacePoint);
	}

	private void assertPointEquals(Point2D expected, Point2D actual) {
		double x = expected.getX();
		double x2 = actual.getX();

		if (Math.abs(x - x2) > 1) {
			Assert.fail("X values of points are not the same - expected: " + expected +
				"; actual: " + actual);
		}

		double y = expected.getY();
		double y2 = actual.getY();
		if (Math.abs(y - y2) > 1) {
			Assert.fail("Y values of points are not the same - expected: " + expected +
				"; actual: " + actual);
		}
	}

	private void setZoom(double d) {
		// waitForBusyGraph();

		// TODO move up the Swing methods? ...to reduce dependencies on slow startup stuff?

		AbstractGenericTest.runSwing(() -> GraphViewerUtils.setGraphScale(viewer, d));
		AbstractGenericTest.waitForSwing();
	}
}
