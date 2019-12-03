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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.geom.Point2D;
import java.util.Collection;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;

import javax.swing.JDialog;
import javax.swing.JTextArea;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import edu.uci.ics.jung.visualization.RenderContext;
import generic.test.AbstractGenericTest;
import generic.test.TestUtils;
import generic.util.WindowUtilities;
import ghidra.graph.graphs.*;
import ghidra.graph.support.*;
import ghidra.util.Msg;
import util.CollectionUtils;

public class GraphComponentTest extends AbstractVisualGraphTest {

	private static final String SATELLITE_VIEWER_TITLE = "Satellite Viewer";
	private TextAreaTestVertex textAreaVertex;

	// callback for when the satellite is docked/undocked
	protected AtomicBoolean satelliteDockedSpy = new AtomicBoolean();
	protected AtomicBoolean satelliteVisibleSpy = new AtomicBoolean();

	private JDialog satelliteDialog;

	@Override
	protected TestVisualGraph buildGraph() {

		TestVisualGraph g = new TestVisualGraph();

		AbstractTestVertex v1 = new LabelTestVertex("1");
		AbstractTestVertex v2 = new LabelTestVertex("2");
		AbstractTestVertex v3 = new LabelTestVertex("3");
		textAreaVertex = new TextAreaTestVertex("Text Area vertex...");
		TestEdge e1 = new TestEdge(v1, v2);
		TestEdge e2 = new TestEdge(v2, v3);
		TestEdge e3 = new TestEdge(v1, textAreaVertex);

		g.addVertex(v1);
		g.addVertex(v2);
		g.addVertex(v3);
		g.addVertex(textAreaVertex);
		g.addEdge(e1);
		g.addEdge(e2);
		g.addEdge(e3);

		return g;
	}

	@Override
	protected GraphComponent<AbstractTestVertex, TestEdge, TestVisualGraph> createGraphComponent(
			TestLayoutProvider layoutProvider) {

		//
		// We have to show our own dialog, as the base GraphComponent does not manage its own.
		//
		GraphComponent<AbstractTestVertex, TestEdge, TestVisualGraph> component =
			new GraphComponent<>(graph);

		GraphSatelliteListener l = (docked, visible) -> {

			satelliteDockedSpy.set(docked);
			satelliteVisibleSpy.set(visible);

			if (visible && !docked) {
				showUndockedSatelliteViewer();
			}
		};
		component.setSatelliteLisetener(l);
		return component;
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		// Since we are sending and testing events, zoom in, so that we don't move past the
		// interaction threshold, which would prevent us from header and body clicking.  Plus,
		// if we are zoomed out, then we have to deal with translating the mouse event offsets
		// we fire to account for the zoom level.
		waitForAnimation(); // painting may change the zoom--wait for it to settle down
		setZoom(1);
	}

	protected void showUndockedSatelliteViewer() {

		if (satelliteDialog != null && satelliteDialog.isShowing()) {
			return; // already showing
		}

		Window window = WindowUtilities.windowForComponent(graphComponent.getComponent());
		JDialog dialog = new JDialog(window);
		dialog.getContentPane().add(graphComponent.getSatelliteContentComponent());
		dialog.pack();
		dialog.setTitle("Satellite Viewer");
		dialog.setVisible(true);
		satelliteDialog = dialog;
	}

	@Override
	protected void initialize() {
		installMouseDebugger();
	}

	@Test
	public void testSetDockedSatelliteVisible() throws Exception {

		swing(() -> {
			graphComponent.setSatelliteDocked(true);
			graphComponent.setSatelliteVisible(true);
		});
		assertNoUndockedProvider();
		assertDockedSatelliteVisible();

		swing(() -> graphComponent.setSatelliteVisible(false));
		assertSatelliteHidden();

		swing(() -> graphComponent.setSatelliteVisible(true));
		assertDockedSatelliteVisible();
	}

	@Test
	public void testShowDockedSatelliteViewer() throws Exception {

		hideSatellite();
		assertSatelliteHidden();

		swing(() -> {
			graphComponent.setSatelliteDocked(true);
			graphComponent.setSatelliteVisible(true);
		});
		assertDockedSatelliteVisible();
	}

	@Test
	public void testShowUndockedSatelliteViewer() throws Exception {

		assertNoUndockedProvider();
		assertDockedSatelliteVisible();

		swing(() -> graphComponent.setSatelliteDocked(false));
		assertUndockedSatelliteVisible();
	}

	@Test
	public void testSetGraphViewStale() throws Exception {

		swing(() -> graphComponent.setGraphViewStale(true));
		assertGraphStaleViewVisible();

		swing(() -> graphComponent.setGraphViewStale(false));
		assertGraphStaleViewHidden();
	}

	@Test
	public void testSetStatusMessage() throws Exception {

		assertStatusMessage(null);
		String message = "Hello Graph!";
		swing(() -> graphComponent.setStatusMessage(message));
		assertStatusMessage(message);
	}

	@Test
	public void testTwinkleVertex() throws Exception {

		Collection<AbstractTestVertex> vertices = graph.getVertices();
		AbstractTestVertex v = CollectionUtils.any(vertices);

		twinkle(v);

		// TODO debug
		if (v.hasBeenEmphasised()) {

			// below, once we are zoomed-out, then the emphasis should happen
			Msg.debug(this, "No vertice should have been emphasized, since we are zoomed in " +
				" - twinkled vertex: " + v + "; all vertex states: ");
			vertices.forEach(vertex -> {
				Msg.debug(this, vertex + " - " + vertex.hasBeenEmphasised());
			});

			// maybe the graph was scaled??
			Msg.debug(this, "graph scale (should be 1.0): " +
				GraphViewerUtils.getGraphScale(graphComponent.getPrimaryViewer()));
		}

		assertFalse(v.hasBeenEmphasised());

		scaleGraphPastInteractionThreshold();
		twinkle(v);
		assertTrue(v.hasBeenEmphasised());
	}

	@Test
	public void testSetVertexFocused() throws Exception {

		Collection<AbstractTestVertex> vertices = graph.getVertices();
		AbstractTestVertex v = CollectionUtils.any(vertices);

		swing(() -> graphComponent.setVertexFocused(v));
		assertTrue(swing(() -> v.isFocused()));
	}

	@Test
	public void testVertexLocationsGetInitialized() {

		//
		// This test will fail if the vertex locations are not set (usually done by the layout)
		// 

		Collection<AbstractTestVertex> vertices = graph.getVertices();
		AbstractTestVertex v = CollectionUtils.any(vertices);
		Point2D p = v.getLocation();
		assertNotNull(p);

		if (Double.compare(p.getX(), 0d) == 0) {
			if (Double.compare(p.getY(), 0d) == 0) {
				fail("Vertex location not initialized");
			}
		}
	}

	@Test
	public void testEdgeSizesGetInitialized() {

		//
		// This test will fail if the vertex locations are not set (usually done by the layout)
		// 

		Collection<TestEdge> edges = graph.getEdges();
		TestEdge e = CollectionUtils.any(edges);
		Shape edgeShape =
			GraphViewerUtils.getEdgeShapeInGraphSpace(graphComponent.getPrimaryViewer(), e);
		Rectangle bounds = edgeShape.getBounds();
		assertTrue("Edge width not initialized - width: " + bounds.width, bounds.width > 1);
		assertTrue("Edge height not initialized - height: " + bounds.height, bounds.height > 1);
	}

	@Test
	public void testSetGraphPerspective() throws Exception {

		// store off a vertex location
		Collection<AbstractTestVertex> vertices = graph.getVertices();
		AbstractTestVertex v = CollectionUtils.any(vertices);
		Point2D startPoint = v.getLocation();

		double startZoom = GraphViewerUtils.getGraphScale(graphComponent.getPrimaryViewer());
		RenderContext<AbstractTestVertex, TestEdge> renderContext =
			graphComponent.getRenderContext();
		GraphPerspectiveInfo<AbstractTestVertex, TestEdge> startPerspective =
			new GraphPerspectiveInfo<>(renderContext, startZoom);

		//
		// Change some of the attributes stored in the perspective
		//

		// change the zoom
		setZoom(.5);

		// move the view		
		moveVertexToCenter(v);

		// now, set the perspective and make sure the values are restored
		swing(() -> graphComponent.setGraphPerspective(startPerspective));

		// verify the vertex location is restored
		assertVertexAt(v, startPoint);
		assertCurrentZoomIs(startZoom);
	}

	@Test
	public void testKeyEventDelivery() {
		//
		// Tests that key events are correctly delivered to focused vertices
		//

		// make sure not vertices focused
		assertNoFocusedVertex();

		// type some keys
		String text = "Zowee Mama!";
		typeInGraph(text);

		// verify no vertices updated
		assertEditableVerticesDoNotContains(text);

		// focus an editable vertex
		focusEditableVertex();

		// type some keys
		text = "Zowee Mama 2!";
		typeInGraph(text);

		// verify vertex contents updated
		assertFocusedVertexTextUpdated(text);
	}

	@Test
	public void testMouseEvent_HeaderDragEditableVertex() throws Exception {
		//
		// Test that a vertex with a drag area (editable vertices for this test) can be 
		// dragged by the header.  Clicking in the body of that vertex will not trigger a drag, 
		// but should instead trigger a selection.
		//

		TextAreaTestVertex v = pickEditableVertex();

		int yOffset = 0; // header
		doTestDrag(v, yOffset);
	}

	@Test
	public void testMouseEvent_InternalDragEditableVertex() throws Exception {
		//
		// Test that a vertex with a drag area (editable vertices for this test) can be 
		// dragged by the header.  Clicking in the body of that vertex will not trigger a drag, 
		// but should instead trigger a selection.
		//

		// GraphViewer<AbstractTestVertex, TestEdge> viewer = graphComponent.getPrimaryViewer();
		// capture(viewer, "initial.png");

		hideSatellite();
		TextAreaTestVertex v = pickEditableVertex();
		ensureVertexVisible(v);

		// capture(viewer, "step1.png");

		Point startPoint = getViewLocation(v);

		int yOffset = 25; // past header; in body
		clickVertex(v, 10, yOffset);
		dragMouse(v, yOffset, 20);

		// capture(viewer, "step2.png");

		Point endPoint = getViewLocation(v);
		assertPointsAreAboutEqual("Editable vertex was moved when the mouse event should have " +
			"been delivered to the vertex", startPoint, endPoint);
		assertVertexHasTextSelection(v);
	}

	@Override
	public void capture(Component c, String name) throws Exception {

		waitForAnimation();
		super.capture(c, name);
	}

	@Test
	public void testDragNonEditableVertex() throws Exception {

		AbstractTestVertex v = pickNonEditableVertex();

		doTestDrag(v, 0);
	}

	@Test
	public void testRefreshButton() {

		swing(() -> graphComponent.setGraphViewStale(true));
		assertGraphStaleViewVisible();

		press("refresh.button");

		assertGraphStaleViewHidden();
	}

	@Test
	public void testShowSatelliteButton() {
		//
		// When the satellite is undocked, the button is visible.   Pressing it will show the
		// satellite window.
		//

		swing(() -> graphComponent.setSatelliteDocked(false));
		assertUndockedSatelliteVisible();

		press("show.satellite.button");
		assertUndockedSatelliteVisible();

		hideSatellite();

		press("show.satellite.button");
		assertUndockedSatelliteVisible();

		// 
		// When the satellite is docked, the button is present, but hidden behind the 
		// satellite viewer.  The user cannot press it, but if they could, it should have 
		// the effect of showing the docked satellite, which is already there; it should *not*
		// show the undocked satellite.
		//

		swing(() -> graphComponent.setSatelliteDocked(true));
		assertDockedSatelliteVisible();

		press("show.satellite.button");
		assertDockedSatelliteVisible();

		hideSatellite();

		press("show.satellite.button");
		assertDockedSatelliteVisible();
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertVertexHasTextSelection(TextAreaTestVertex v) {
		JTextArea textArea = v.getTextArea();
		String selectedText = swing(() -> textArea.getSelectedText());
		assertNotNull(selectedText);
	}

	// the y offset allows us to move from the header at the top, to the body in the middle, 
	// where appropriate
	private void doTestDrag(AbstractTestVertex v, int yOffset) throws Exception {

		ensureVertexVisible(v);

		Point startViewPoint = getViewLocation(v);
		int inABit = 2; // be sure we are inside the vertex
		int x1 = startViewPoint.x + inABit;
		int y1 = startViewPoint.y + inABit + yOffset;

		int distance = 10;
		int x2 = x1 + distance;
		int y2 = y1 + distance;

		// click the header
		focusVertex(v);

		// we don't need to loop, but it helped visualize the action
		for (int i = 0; i < 5; i++) {

			drag(x1, y1, x2, y2);

			Point newViewPoint = getViewLocation(v);
			assertPointsAreAboutEqual("Location is not as expected; drag failed\nstartd at " +
				startViewPoint + "; last point was: " + newViewPoint, new Point(x2, y2),
				newViewPoint);

			x1 = x2;
			y1 = y2;
			x2 = x1 + distance;
			y2 = y1 + distance;

			// Thread.sleep(100); // this lets you watch the drag
		}
	}

	private void press(String name) {
		AbstractGenericTest.pressButtonByName(graphComponent.getComponent(), name, true);
	}

	private AbstractTestVertex pickNonEditableVertex() {
		Collection<AbstractTestVertex> vertices = graph.getVertices();
		for (AbstractTestVertex v : vertices) {
			if (v instanceof TextAreaTestVertex) {
				continue;
			}
			return v;
		}

		fail("Unable to locate a non-editable vertex");
		return null;
	}

	private void focusEditableVertex() {
		Set<TextAreaTestVertex> editables = getEditableVertices();
		TextAreaTestVertex v = CollectionUtils.any(editables);
		swing(() -> graphComponent.setVertexFocused(v));
		assertEquals(v, graph.getFocusedVertex());
	}

	private void assertFocusedVertexTextUpdated(String expected) {
		AbstractTestVertex v = graph.getFocusedVertex();
		assertTrue(v instanceof TextAreaTestVertex);
		TextAreaTestVertex tav = (TextAreaTestVertex) v;
		String vertexText = swing(() -> tav.getText());
		assertThat("Vertex text not updated after typing text", vertexText,
			containsString(expected));
	}

	private void assertEditableVerticesDoNotContains(String text) {
		Set<TextAreaTestVertex> editables = getEditableVertices();
		for (TextAreaTestVertex v : editables) {
			String vertexText = v.getText();
			assertFalse(vertexText.contains(text));
		}
	}

	private Set<TextAreaTestVertex> getEditableVertices() {
		Collection<AbstractTestVertex> vertices = graph.getVertices();

		//@formatter:off
		return vertices
				.stream()
				.filter(v -> v instanceof TextAreaTestVertex)
				.map(v -> (TextAreaTestVertex) v)
				.collect(Collectors.toSet())
				;
		//@formatter:on
	}

	private TextAreaTestVertex pickEditableVertex() {
		return CollectionUtils.any(getEditableVertices());
	}

	private void typeInGraph(String text) {
		AbstractDockingTest.triggerText(graphComponent.getPrimaryViewer(), text);
	}

	private void assertNoFocusedVertex() {
		AbstractTestVertex focused = swing(() -> graph.getFocusedVertex());
		assertNull(focused);
	}

	private void assertCurrentZoomIs(double startZoom) {
		double fudge = .01;
		assertEquals(startZoom, GraphViewerUtils.getGraphScale(graphComponent.getPrimaryViewer()),
			fudge);
	}

	private void assertVertexAt(AbstractTestVertex v, Point2D startPoint) {
		Point2D currentPoint = v.getLocation();
		assertPointsAreAboutEqual("Vertex location not restored by setting the perspective",
			startPoint, currentPoint);
	}

	private void moveVertexToCenter(AbstractTestVertex v) {
		VisualGraphViewUpdater<AbstractTestVertex, TestEdge> updater =
			graphComponent.getViewUpdater();
		swing(() -> updater.moveVertexToCenterWithAnimation(v));
		waitForAnimation();
	}

	private void twinkle(AbstractTestVertex v) {
		swing(() -> graphComponent.twinkleVertex(v));
		waitForAnimation();
	}

	private void assertGraphStaleViewHidden() {
		assertFalse(swing(() -> graphComponent.isGraphViewStale()));
		assertStatusMessage(null);
	}

	private void assertGraphStaleViewVisible() {
		assertTrue(swing(() -> graphComponent.isGraphViewStale()));
		assertStatusMessage("Graph is stale");
	}

	private void assertStatusMessage(String expected) {
		Object paintable = TestUtils.getInstanceField("messagePaintable", graphComponent);
		String message = (String) TestUtils.getInstanceField("message", paintable);
		assertEquals(expected, message);
	}

	private void assertNoUndockedProvider() {
		Window window =
			AbstractDockingTest.getWindowByTitleContaining(null, SATELLITE_VIEWER_TITLE);
		assertNull(window);
	}

	private void assertSatelliteHidden() {
		assertFalse(isSatelliteVisible());
	}

	private void assertDockedSatelliteVisible() {
		assertTrue(isSatelliteVisible());
		assertFalse(isSatelliteUndocked());
	}

	private void assertUndockedSatelliteVisible() {
		assertTrue(satelliteVisibleSpy.get());
		assertFalse(satelliteDockedSpy.get());
	}
}
