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
package datagraph.graph;

import static org.junit.Assert.*;

import java.awt.Dimension;
import java.awt.Point;
import java.awt.geom.Point2D;
import java.util.Collection;
import java.util.Comparator;

import javax.swing.*;

import org.junit.Before;
import org.junit.Test;

import datagraph.graph.explore.*;
import docking.test.AbstractDockingTest;
import docking.widgets.label.GDLabel;
import generic.theme.GThemeDefaults.Colors.Palette;
import ghidra.graph.VisualGraph;
import ghidra.graph.graphs.DefaultVisualGraph;
import ghidra.graph.viewer.GraphComponent;
import ghidra.graph.viewer.layout.AbstractVisualGraphLayout;
import ghidra.util.Swing;

public class EgGraphLayoutTest extends AbstractDockingTest {
	private static int VERTEX_SIZE = 50;
	private static int VERTEX_GAP = 100;
	private TestExplorationGraph g;

	private TestVertex root = new TestVertex(null, "R", VERTEX_SIZE, VERTEX_SIZE);
	private GraphComponent<TestVertex, TestEdge, TestExplorationGraph> graphComponent;

	@Before
	public void setUp() {
		g = new TestExplorationGraph(root);
	}

	@Test
	public void testGraphOneOutgoingChild() {
		TestVertex A = v(root, "A");
		edge(root, A);

		showGraph();

		assertEquals(p(0, 0), root.getLocation());
		int expectedX = VERTEX_GAP + root.width / 2 + A.width / 2;
		assertEquals(p(expectedX, 0), A.getLocation());
	}

	@Test
	public void testGraphTwoOutgoingChildren() {
		TestVertex A = v(root, "A");
		TestVertex B = v(root, "B");
		edge(root, A);
		edge(root, B);

		showGraph();

		assertEquals(p(0, 0), root.getLocation());
		int expectedX = VERTEX_GAP + root.width / 2 + A.width / 2;
		int totalHeight = VERTEX_GAP + A.height + B.height;
		int expectedYa = -totalHeight / 2 + A.height / 2;
		int expectedYb = totalHeight / 2 - B.height / 2;
		assertEquals(p(expectedX, expectedYa), A.getLocation());
		assertEquals(p(expectedX, expectedYb), B.getLocation());
	}

	@Test
	public void testGraphOneIncomingChild() {
		TestVertex A = v(root, "A", VERTEX_SIZE, VERTEX_SIZE);
		edge(A, root);

		showGraph();

		assertEquals(p(0, 0), root.getLocation());
		int expectedX = -VERTEX_GAP - root.width / 2 - A.width / 2;
		assertEquals(p(expectedX, 0), A.getLocation());
	}

	@Test
	public void testGraphTwoIncomingChildren() {
		TestVertex A = v(root, "A");
		TestVertex B = v(root, "B");
		edge(A, root);
		edge(B, root);

		showGraph();

		assertEquals(p(0, 0), root.getLocation());
		int expectedX = -VERTEX_GAP - root.width / 2 - A.width / 2;
		int expectedYa = -VERTEX_GAP / 2 - A.height / 2;
		int expectedYb = VERTEX_GAP / 2 + B.height / 2;
		assertEquals(p(expectedX, expectedYa), A.getLocation());
		assertEquals(p(expectedX, expectedYb), B.getLocation());
	}

	@Test
	public void testGraphTwoOutgoingChildrenDifferentSize() {
		TestVertex A = v(root, "A");
		TestVertex B = bigV(root, "B");
		edge(root, A);
		edge(root, B);

		showGraph();

		assertEquals(p(0, 0), root.getLocation());
		int expectedXa = VERTEX_GAP + root.width / 2 + A.width / 2;
		int expectedXb = VERTEX_GAP + root.width / 2 + B.width / 2;
		int totalHeight = VERTEX_GAP + A.height + B.height;
		int expectedYa = -totalHeight / 2 + A.height / 2;
		int expectedYb = totalHeight / 2 - B.height / 2;
		assertEquals(p(expectedXa, expectedYa), A.getLocation());
		assertEquals(p(expectedXb, expectedYb), B.getLocation());
	}

	@Test
	public void testGraphTwoIncomingChildrenDifferentSize() {
		TestVertex A = v(root, "A");
		TestVertex B = bigV(root, "B");
		edge(A, root);
		edge(B, root);

		showGraph();

		assertEquals(p(0, 0), root.getLocation());
		int expectedXa = -VERTEX_GAP - root.width / 2 - A.width / 2;
		int expectedXb = -VERTEX_GAP - root.width / 2 - B.width / 2;
		int totalHeight = VERTEX_GAP + A.height + B.height;
		int expectedYa = -totalHeight / 2 + A.height / 2;
		int expectedYb = totalHeight / 2 - B.height / 2;
		assertEquals(p(expectedXa, expectedYa), A.getLocation());
		assertEquals(p(expectedXb, expectedYb), B.getLocation());
	}

	private Point p(int x, int y) {
		return new Point(x, y);
	}

	protected void showGraph() {

		Swing.runNow(() -> {
			JFrame frame = new JFrame("Graph Viewer Test");

			TestEgGraphLayout layout = new TestEgGraphLayout(g, root);
			g.setLayout(layout);
			graphComponent = new GraphComponent<>(g);
			graphComponent.setSatelliteVisible(false);

			frame.setSize(new Dimension(800, 800));
			frame.setLocation(2400, 100);
			frame.getContentPane().add(graphComponent.getComponent());
			frame.setVisible(true);
			frame.validate();
		});
	}

	protected TestVertex bigV(TestVertex source, String name) {
		TestVertex v = new TestVertex(source, name, VERTEX_SIZE * 2, VERTEX_SIZE * 2);
		g.addVertex(v);
		return v;
	}

	protected TestVertex v(TestVertex source, String name) {
		TestVertex v = new TestVertex(source, name, VERTEX_SIZE, VERTEX_SIZE);
		g.addVertex(v);
		return v;
	}

	private TestVertex v(TestVertex source, String name, int width, int height) {
		TestVertex v = new TestVertex(source, name, width, height);
		g.addVertex(v);
		return v;
	}

	protected TestEdge edge(TestVertex v1, TestVertex v2) {
		TestEdge testEdge = new TestEdge(v1, v2);
		g.addEdge(testEdge);
		return testEdge;
	}

	private class TestVertex extends EgVertex {

		private JLabel label;
		private String name;
		private int width;
		private int height;

		TestVertex(TestVertex source, String name, int width, int height) {
			super(source);
			this.name = name;
			this.width = width;
			this.height = height;
		}

		@Override
		public String toString() {
			return name;
		}

		@Override
		public JComponent getComponent() {
			if (label == null) {
				label = new GDLabel();
				label.setText(name);
				label.setPreferredSize(new Dimension(width, height));
				label.setBackground(Palette.GOLD);
				label.setOpaque(true);
				label.setBorder(BorderFactory.createRaisedBevelBorder());
				label.setHorizontalAlignment(SwingConstants.CENTER);
			}
			return label;
		}

		@Override
		protected Point2D getStartingEdgePoint(EgVertex end) {
			return new Point(0, 0);
		}

		@Override
		protected Point2D getEndingEdgePoint(EgVertex start) {
			return new Point(0, 0);
		}

	}

	private class TestEdge extends EgEdge<TestVertex> {

		public TestEdge(TestVertex start, TestVertex end) {
			super(start, end);
		}

		@SuppressWarnings("unchecked")
		// Suppressing warning on the return type; we know our class is the right type
		@Override
		public TestEdge cloneEdge(TestVertex start, TestVertex end) {
			return new TestEdge(start, end);
		}

	}

	private class TestExplorationGraph extends AbstractExplorationGraph<TestVertex, TestEdge> {

		TestExplorationGraph(TestVertex root) {
			super(root);
		}

		@Override
		public DefaultVisualGraph<TestVertex, TestEdge> copy() {
			Collection<TestVertex> v = getVertices();
			Collection<TestEdge> e = getEdges();
			TestExplorationGraph newGraph = new TestExplorationGraph(getRoot());
			v.forEach(newGraph::addVertex);
			e.forEach(newGraph::addEdge);
			return newGraph;
		}

	}

	private static class TestEgGraphLayout
			extends EgGraphLayout<TestVertex, TestEdge> {

		protected TestEgGraphLayout(TestExplorationGraph graph, TestVertex root) {
			super(graph, "Test", VERTEX_GAP, VERTEX_GAP);
		}

		@Override
		public AbstractVisualGraphLayout<TestVertex, TestEdge> createClonedLayout(
				VisualGraph<TestVertex, TestEdge> newGraph) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected EgEdgeTransformer<TestVertex, TestEdge> createEdgeTransformer() {
			return new EgEdgeTransformer<EgGraphLayoutTest.TestVertex, EgGraphLayoutTest.TestEdge>();
		}

		@Override
		protected Comparator<TestVertex> getIncommingVertexComparator() {
			return (v1, v2) -> v1.name.compareTo(v2.name);
		}

		@Override
		protected Comparator<TestVertex> getOutgoingVertexComparator() {
			return (v1, v2) -> v1.name.compareTo(v2.name);
		}

	}
}
