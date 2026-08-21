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
package ghidra.app.plugin.core.functiongraph.graph.layout.flowchart;

import static org.junit.Assert.*;

import java.awt.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map.Entry;
import java.util.function.Function;

import javax.swing.JFrame;

import org.junit.Before;

import docking.test.AbstractDockingTest;
import ghidra.graph.VisualGraph;
import ghidra.graph.graphs.*;
import ghidra.graph.support.TestVisualGraph;
import ghidra.graph.viewer.GraphComponent;
import ghidra.graph.viewer.layout.*;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;

abstract public class AbstractFlowChartLayoutTest extends AbstractDockingTest {
	protected TestVisualGraph g;
	protected GridLocationMap<AbstractTestVertex, TestEdge> grid;
	protected OrthogonalGridToLayoutMapper<AbstractTestVertex, TestEdge> layoutMap;
	private boolean alignLeft;

	protected LabelTestVertex A = v('A');
	protected LabelTestVertex B = v('B');
	protected LabelTestVertex C = v('C');
	protected LabelTestVertex D = v('D');
	protected LabelTestVertex E = v('E');
	protected LabelTestVertex F = v('F');
	protected LabelTestVertex G = v('G');
	protected LabelTestVertex H = v('H');
	protected LabelTestVertex I = v('I');
	protected LabelTestVertex J = v('J');
	protected LabelTestVertex K = v('K');

	protected AbstractFlowChartLayoutTest(boolean alignLeft) {
		this.alignLeft = alignLeft;
	}

	@Before
	public void setUp() {
		g = new TestVisualGraph();
	}

	protected void showGraph() {

		Swing.runNow(() -> {
			JFrame frame = new JFrame("Graph Viewer Test");

			TestFlowChartLayout layout = new TestFlowChartLayout(g, A, alignLeft);
			g.setLayout(layout);
			GraphComponent<AbstractTestVertex, TestEdge, TestVisualGraph> graphComponent =
				new GraphComponent<>(g);
			graphComponent.setSatelliteVisible(false);

			frame.setSize(new Dimension(800, 800));
			frame.setLocation(2400, 100);
			frame.getContentPane().add(graphComponent.getComponent());
			frame.setVisible(true);
			frame.validate();
		});
	}

	protected void assertEdge(EdgeVerifier edgeVerifier) {
		edgeVerifier.checkEdge();
	}

	protected void assertVertices(String expected) {
		String actual = generateCompactGridVertexString();
		if (!expected.equals(actual)) {
			reportGridError(expected, actual);
		}
	}

	private void reportGridError(String expectedString, String actualString) {
		String[] actual = StringUtilities.toLines(actualString, false);
		String[] expected = StringUtilities.toLines(expectedString, false);
		assertEquals("Number of rows don't match! ", expected.length, actual.length);
		checkCols(expected);
		assertEquals("Number of columns don't match! ", expected[0].length(), actual[0].length());

		if (!expectedString.equals(actualString)) {
			printGridsToConsole(actual, expected);
			int firstRowDiff = findFirstRowDiff(actual, expected);
			int firstColDiff = findFirstColDiff(actual[firstRowDiff], expected[firstRowDiff]);
			fail("Graphs don't match! First diff is at row " + firstRowDiff + ", col " +
				firstColDiff + ". See console for details.");
		}

	}

	private int findFirstColDiff(String string1, String string2) {
		for (int i = 0; i < string1.length(); i++) {
			if (string1.charAt(i) != string2.charAt(i)) {
				return i;
			}
		}
		return -1;
	}

	private int findFirstRowDiff(String[] actual, String[] expected) {
		for (int i = 0; i < actual.length; i++) {
			if (!actual[i].equals(expected[i])) {
				return i;
			}
		}
		return -1;
	}

	private void printGridsToConsole(String[] actual, String[] expected) {
		StringWriter writer = new StringWriter();
		PrintWriter out = new PrintWriter(writer);
		out.println("Graphs don't match!\n");
		String expectedLabel = "Expected: ";
		String actualLabel = "  Actual: ";
		String diffLabel = "   Diffs: ";
		String[] diffs = computeDiffs(actual, expected);
		for (int row = 0; row < expected.length; row++) {
			out.print(expectedLabel);
			out.print(expected[row]);
			out.print(actualLabel);
			out.print(actual[row]);
			out.print(diffLabel);
			out.println(diffs[row]);
			expectedLabel = "          ";
			actualLabel = expectedLabel;
			diffLabel = expectedLabel;
		}
		Msg.error(this, writer.toString());
	}

	private String[] computeDiffs(String[] actual, String[] expected) {
		String[] diffs = new String[actual.length];
		for (int i = 0; i < diffs.length; i++) {
			diffs[i] = computeDiffString(actual[i], expected[i]);
		}
		return diffs;
	}

	private String computeDiffString(String string1, String string2) {
		StringBuilder buf = new StringBuilder();
		for (int i = 0; i < string1.length(); i++) {
			char c = string1.charAt(i) == string2.charAt(i) ? '.' : 'x';
			buf.append(c);
		}
		return buf.toString();
	}

	private void checkCols(String[] expected) {
		int len = expected[0].length();
		for (String line : expected) {
			if (line.length() != len) {
				fail("Invalid graph grid specified in test. Lines vary in length!");
			}
		}
	}

	private String generateCompactGridEdgeString(TestEdge e, List<GridPoint> points) {
		char[][] gridChars = createEmptyGridChars();
		fillGridCharColumn(gridChars, points.get(0), points.get(1));

		for (int i = 1; i < points.size() - 2; i++) {
			fillGridCharRow(gridChars, points.get(i), points.get(i + 1));
			fillGridCharColumn(gridChars, points.get(i + 1), points.get(i + 2));
		}

		AbstractTestVertex start = e.getStart();
		AbstractTestVertex end = e.getEnd();
		GridPoint startPoint = grid.gridPoint(start);
		GridPoint endPoint = grid.gridPoint(end);
		gridChars[startPoint.row][startPoint.col] = start.toString().charAt(0);
		gridChars[endPoint.row][endPoint.col] = end.toString().charAt(0);

		return toString(gridChars);
	}

	private void fillGridCharRow(char[][] gridChars, GridPoint p1, GridPoint p2) {
		int row = p1.row;
		int startCol = Math.min(p1.col, p2.col);
		int endCol = Math.max(p1.col, p2.col);
		for (int col = startCol; col <= endCol; col++) {
			gridChars[row][col] = '*';
		}
	}

	private void fillGridCharColumn(char[][] gridChars, GridPoint p1, GridPoint p2) {
		int col = p1.col;
		int startRow = Math.min(p1.row, p2.row);
		int endRow = Math.max(p1.row, p2.row);
		for (int row = startRow; row <= endRow; row++) {
			gridChars[row][col] = '*';
		}
	}

	private String generateCompactGridVertexString() {
		char[][] gridChars = createEmptyGridChars();

		for (Entry<AbstractTestVertex, GridPoint> entry : grid.getVertexPoints().entrySet()) {
			char id = entry.getKey().toString().charAt(0);
			GridPoint point = entry.getValue();
			gridChars[point.row][point.col] = id;
		}

		return toString(gridChars);
	}

	private String toString(char[][] gridChars) {
		StringBuilder buf = new StringBuilder();
		for (int row = 0; row < grid.height(); row++) {
			for (int col = 0; col < grid.width(); col++) {
				buf.append(gridChars[row][col]);
			}
			buf.append("\n");
		}
		return buf.toString();
	}

	private char[][] createEmptyGridChars() {
		int rows = grid.height();
		int cols = grid.width();
		char[][] gridChars = new char[rows][cols];
		for (int row = 0; row < rows; row++) {
			for (int col = 0; col < cols; col++) {
				gridChars[row][col] = '.';
			}
		}
		return gridChars;
	}

	protected EdgeVerifier e(LabelTestVertex start, LabelTestVertex end) {
		return new EdgeVerifier(start, end);
	}

	protected class EdgeVerifier {

		private TestEdge edge;
		private List<GridPoint> expectedPoints = new ArrayList<>();
		private List<Integer> expectedOffsets = new ArrayList<>();

		public EdgeVerifier(LabelTestVertex start, LabelTestVertex end) {
			this.edge = new TestEdge(start, end);
			expectedPoints.add(grid.gridPoint(start));
		}

		public EdgeVerifier colSegment(int rows, int offset) {
			GridPoint lastPoint = expectedPoints.get(expectedPoints.size() - 1);
			GridPoint p = new GridPoint(lastPoint.row + rows, lastPoint.col);
			if (!grid.containsPoint(p)) {
				fail("Bad column specification. Row movement of " + rows + " exceeds grid size!");
			}
			expectedPoints.add(p);
			expectedOffsets.add(offset);
			return this;
		}

		public EdgeVerifier rowSegment(int cols, int offset) {
			GridPoint lastPoint = expectedPoints.get(expectedPoints.size() - 1);
			GridPoint p = new GridPoint(lastPoint.row, lastPoint.col + cols);
			if (!grid.containsPoint(p)) {
				fail("Bad row specification. Column movement of " + cols + " exceeds grid size!");
			}
			expectedPoints.add(p);
			expectedOffsets.add(offset);
			return this;
		}

		public void checkEdge() {
			List<GridPoint> actual = grid.getArticulations(edge);
			if (expectedPoints.size() < 2) {
				fail("Specified Edge for edge " + edge + " is missing segment specifications!");
			}

			if (actual.isEmpty()) {
				fail("Expected edge articulations for " + edge + "not found!");
			}

			if (!actual.equals(expectedPoints)) {

				printEdgeDiffs(actual);
				fail("Articulations for edge " + edge + " don't match! See console for details");
			}

			List<Integer> actualOffsets = layoutMap.getEdgeOffsets(edge);
			for (int i = 0; i < expectedOffsets.size(); i++) {
				GridPoint p1 = expectedPoints.get(i);
				GridPoint p2 = expectedPoints.get(i + 1);
				assertEquals(
					"Edge Offsets differ for edge " + edge + " at segment " + i +
						", from " + p1 + " to " + p2 + "! ",
					expectedOffsets.get(i), actualOffsets.get(i));
			}
		}

		private void printEdgeDiffs(List<GridPoint> actualPoints) {
			StringWriter writer = new StringWriter();
			PrintWriter out = new PrintWriter(writer);
			String expectedString = generateCompactGridEdgeString(edge, expectedPoints);
			String actualString = generateCompactGridEdgeString(edge, actualPoints);
			String[] expected = StringUtilities.toLines(expectedString, false);
			String[] actual = StringUtilities.toLines(actualString, false);

			out.println("Edge articulations don't match for " + edge.toString() + "!\n");
			String expectedLabel = "Expected: ";
			String actualLabel = "  Actual: ";
			for (int row = 0; row < expected.length; row++) {
				out.print(expectedLabel);
				out.print(expected[row]);
				out.print(actualLabel);
				out.println(actual[row]);
				expectedLabel = "          ";
				actualLabel = expectedLabel;

			}
			Msg.error(this, writer.toString());
		}
	}

	protected int offset(int i) {
		return i;
	}

	protected int down(int i) {
		return i;
	}

	protected int up(int i) {
		return -i;
	}

	protected int left(int i) {
		return -i;
	}

	protected int right(int i) {
		return i;
	}

	protected void applyLayout() throws CancelledException {
		TestFlowChartLayout layout = new TestFlowChartLayout(g, A, alignLeft);
		grid = layout.performInitialGridLayout(g);
		Function<AbstractTestVertex, Shape> transformer = v -> new Rectangle(0, 0, 50, 50);
		layoutMap =
			new OrthogonalGridToLayoutMapper<AbstractTestVertex, TestEdge>(grid, transformer, true);
	}

	// a shortcut for edge(v(startId), v(endId)), for readability
	protected TestEdge edge(LabelTestVertex v1, LabelTestVertex v2) {
		TestEdge testEdge = new TestEdge(v1, v2);
		g.addEdge(testEdge);
		return testEdge;
	}

	protected LabelTestVertex v(char id) {
		return new LabelTestVertex("" + id);
	}

	private static class TestFlowChartLayout
			extends AbstractFlowChartLayout<AbstractTestVertex, TestEdge> {

		private AbstractTestVertex root;

		protected TestFlowChartLayout(DefaultVisualGraph<AbstractTestVertex, TestEdge> graph,
				AbstractTestVertex root, boolean leftAlign) {
			super(graph, new TestEdgeComparator(), leftAlign);
			this.root = root;
		}

		@Override
		public AbstractVisualGraphLayout<AbstractTestVertex, TestEdge> createClonedLayout(
				VisualGraph<AbstractTestVertex, TestEdge> newGraph) {
			throw new UnsupportedOperationException();
		}

		@Override
		protected AbstractTestVertex getRoot(VisualGraph<AbstractTestVertex, TestEdge> g) {
			return root;
		}

		@Override
		protected GridLocationMap<AbstractTestVertex, TestEdge> performInitialGridLayout(
				VisualGraph<AbstractTestVertex, TestEdge> g) throws CancelledException {

			return super.performInitialGridLayout(g);
		}

	}

	private static class TestEdgeComparator implements Comparator<TestEdge> {

		@Override
		public int compare(TestEdge e1, TestEdge e2) {
			return e1.toString().compareTo(e2.toString());
		}
	}

}
