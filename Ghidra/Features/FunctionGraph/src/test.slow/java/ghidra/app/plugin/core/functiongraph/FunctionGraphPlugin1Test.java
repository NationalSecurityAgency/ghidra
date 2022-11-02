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
package ghidra.app.plugin.core.functiongraph;

import static ghidra.graph.viewer.GraphViewerUtils.*;
import static org.junit.Assert.*;

import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.Transferable;
import java.awt.geom.Point2D;
import java.util.*;
import java.util.List;
import java.util.stream.Collectors;

import org.junit.*;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.dnd.GClipboard;
import edu.uci.ics.jung.algorithms.layout.Layout;
import edu.uci.ics.jung.visualization.VisualizationModel;
import edu.uci.ics.jung.visualization.VisualizationViewer;
import edu.uci.ics.jung.visualization.util.Caching;
import generic.test.TestUtils;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.nav.LocationMemento;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.core.colorizer.ColorizingPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.services.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.task.TaskMonitor;

public class FunctionGraphPlugin1Test extends AbstractFunctionGraphTest {

	public FunctionGraphPlugin1Test() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());

		waitForGraphToLoad();
	}

//	public void testCodeBlockSpeed() throws CancelledException {
////		ProgramDB cppProgram = env.getProgram("msvidctl.dll_MFCAnalysis");
//		ProgramDB cppProgram = env.getProgram("winword.exe");
//
//		FunctionManager functionManager = cppProgram.getFunctionManager();
////		Function function = functionManager.getFunctionAt(getAddress("5a1f903e"));
//		Function function = functionManager.getFunctionAt(getAddress("3036d629"));
//
//		long startTime = System.nanoTime();
//		BasicBlockModel blockModel = new BasicBlockModel(cppProgram, false);
//		CodeBlockIterator iterator =
//			blockModel.getCodeBlocksContaining(function.getBody(), TaskMonitorAdapter.DUMMY_MONITOR);
//		while (iterator.hasNext()) {
//			iterator.next();
//		}
//		long endTime = System.nanoTime();
//		double totalTime = (endTime - startTime) / 1000000000d;
//		System.err.println("total time: " + totalTime);
//	}

	@Test
	public void testLocationChanged() {
		// get the graph contents
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation location = getLocationForAddressString(startAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		// locate vertex with cursor
		FGVertex focusedVertex = getFocusVertex(functionGraph);
		assertNotNull("We did not start with a focused vertex", focusedVertex);

		// change the location
		String newLocationString = "01004192";
		goToAddress(newLocationString);

		// locate vertex with cursor
		graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation newLocation = getLocationForAddressString(newLocationString);
		assertTrue(graphData.containsLocation(newLocation));

		functionGraph = graphData.getFunctionGraph();
		FGVertex newFocusedVertex = functionGraph.getFocusedVertex();
		assertTrue(newFocusedVertex.containsProgramLocation(newLocation));

		// make sure the two vertices are not the same
		assertTrue("Changing locations in the code browser did not move the cursor location to " +
			"a new graph vertex", !focusedVertex.equals(newFocusedVertex));
	}

	@Test
	public void testProgramSelectionAcrossVerticesFromCodeBrowser() {
		FGData graphData = getFunctionGraphData();// make sure the graph gets loaded
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());

		ProgramSelection ps = makeMultiVertexSelectionInCodeBrowser();

		// this address is in a different vertex than the start address                
		ProgramLocation location = getLocationForAddressString("0x01004192");
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		FGVertex startVertex = functionGraph.getVertexForAddress(location.getAddress());

		// locate vertex with cursor
		assertNotNull("We did not start with a focused vertex", startVertex);
		assertTrue(startVertex.containsProgramLocation(location));

		// make a selection starting at the current location
		ProgramSelection firstSelection = startVertex.getProgramSelection();
		assertTrue("A selection too big for one vertex has fit into a start vertex",
			!ps.equals(firstSelection));

		Address address = getAddress("0x01004196");
		FGVertex secondVertex = functionGraph.getVertexForAddress(address);
		ProgramSelection secondSelection = secondVertex.getProgramSelection();
		assertTrue(!secondSelection.isEmpty());

		assertTrue(ps.getMinAddress().equals(firstSelection.getMinAddress()));
		assertTrue(ps.getMaxAddress().equals(secondSelection.getMaxAddress()));
	}

	@Test
	public void testGraphWithCloseAndReopenProgram_ForSCR_7813() {
		//
		// This test is meant to ensure that graph contents are properly disposed and that no
		// exceptions happen while switching programs.
		//
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());

		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, true);

		// should have empty data after closing the program
		graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Graph data should be empty after closing the program", !graphData.hasResults());

		pm.openProgram(program.getDomainFile());
		program.flushEvents();

		// we should have some sort of non-null data--either real or empty
		graphData = getFunctionGraphData();
		assertNotNull(graphData);

		goToAddress(startAddressString);

		// verify we can still graph data
		graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
	}

// note: unreliable--garbage collection works differently across platforms (sad face)	
//	public void testClearCacheAndMemoryLeak() {
//		//
//		// Test that when we clear the cache of a graph the vertices of that graph will be 
//		// garbage collected
//		//
//		WeakSet<FunctionGraphVertex> weakSet =
//			WeakDataStructureFactory.createSingleThreadAccessWeakSet();
//
//		FunctionGraphData graphData = getFunctionGraphData();
//		assertNotNull(graphData);
//		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
//
//		FunctionGraph graph = graphData.getFunctionGraph();
//		FunctionGraphVertex rootVertex = graph.getRootVertex();
//		assertNotNull(rootVertex);
//
//		weakSet.add(rootVertex);
//		assertTrue(weakSet.iterator().hasNext());
//
//		// move to a new function so that we the FG will not be holding a reference to the 
//		// originally graphed function
//		String address = "01002239";
//		goToAddress(address);
//
//		FunctionGraphData newGraphData = getFunctionGraphData();
//		assertNotNull(newGraphData);
//		assertTrue("Unexpectedly received an empty FunctionGraphData", newGraphData.hasResults());
//
//		assertTrue(
//			"Function Graph did not graph a new function as expected at address: " + address,
//			!graphData.equals(newGraphData));
//
//		triggerGraphDisposal(graphData);
//
//		rootVertex = null;
//		graph = null;
//		graphData = null;
//
//		// let (force) the Garbage Collector run
//		System.gc();
//		sleep(100);
//		System.gc();
//		sleep(100);
//		System.gc();
//		sleep(100);
//
//		boolean isNotCollected = weakSet.iterator().hasNext();
//		assertFalse(isNotCollected);
//	}
//
//	private void triggerGraphDisposal(FunctionGraphData dataToDispose) {
//		Object controller = getInstanceField("controller", graphProvider);
//		LRUMap<?, ?> cache = (LRUMap<?, ?>) getInstanceField("graphCache", controller);
//		cache.clear();
//		dataToDispose.dispose();
//	}

	@Test
	public void testSaveVertexPositions() {
		//
		// Test that we can move a node, load a new graph, reload the original graph and have 
		// the moved node return to the moved position
		//

		FGData originalGraphData = getFunctionGraphData();
		assertNotNull(originalGraphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData",
			originalGraphData.hasResults());

		FunctionGraph graph = originalGraphData.getFunctionGraph();
		final FGVertex rootVertex = graph.getRootVertex();
		assertNotNull(rootVertex);

		Point2D originalPoint = rootVertex.getLocation();

		double dx = originalPoint.getX() + 100;
		double dy = originalPoint.getY() + 100;

		Point2D newPoint = new Point2D.Double(dx, dy);
		final Layout<FGVertex, FGEdge> primaryLayout = getPrimaryLayout();
		final Point2D finalNewPoint = newPoint;
		runSwing(() -> primaryLayout.setLocation(rootVertex, finalNewPoint));

		// we have to wait for the paint to take place, as the rendering will change the vertex
		// locations
		FGPrimaryViewer primaryGraphViewer = getPrimaryGraphViewer();
		primaryGraphViewer.repaint();
		waitForSwing();

		// now that we have changed the data, load a new graph and then come back to the start
		// graph so that we can see that the settings have been re-applied
		String address = "01002239";
		goToAddress(address);

		FGData newGraphData = getFunctionGraphData();
		assertNotNull(newGraphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", newGraphData.hasResults());
		assertTrue(!newGraphData.equals(originalGraphData));

		// ...now go back and check the position
		goToAddress(startAddressString);

		newGraphData = getFunctionGraphData();
		assertNotNull(newGraphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", newGraphData.hasResults());

		graph = newGraphData.getFunctionGraph();
		FGVertex newRootVertex = graph.getRootVertex();
		assertNotNull(newRootVertex);

		waitForSwing();

		// Note: we can't test for exact equality based upon the location we set, as the values
		// are updated based upon other factors, like screen location and size.  We want to make
		// sure that the value is not the default.
		Point2D reloadedPoint = newRootVertex.getLocation();
		assertTrue("Vertex location not restored after regraphing a function",
			!originalPoint.equals(reloadedPoint));
	}

	@Test
	public void testRelayout() throws Exception {
		doTestRelayout(false);
	}

	@Test
	public void testReload() throws Exception {
		doTestRelayout(true);
	}

	@Test
	public void testLabelChangeAtVertexEntryUpdatesTitle() {
		int txID = -1;
		try {
			txID = program.startTransaction("Test: " + testName.getMethodName());
			doTestLabelChangeAtVertexEntryUpdatesTitle();
		}
		finally {
			program.endTransaction(txID, false);
		}
	}

	@Test
	public void testChangeFormat() throws Exception {
		//
		// Test that we can change the view's format.  As part of this test verify:
		// -That each graph gets the view changes
		// -Test reset format
		// -That view changes are persisted
		//
		FGController primaryController = getFunctionGraphController();
		waitForBusyRunManager(primaryController);

		FGData functionGraphData = getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();

		// Be sure to pick a vertex that will get bigger when a new field is added.  The
		// root vertex is already so wide (due to the function signature), that adding a small
		// field does not change its width.
		FGVertex vertex = functionGraph.getVertexForAddress(getAddress("1004178"));
		Rectangle originalBounds = vertex.getBounds();

		// Also, be sure that we are not on the function signature field, as that does not have
		// the 'Bytes' field.
		goTo("1004179");

		addBytesFormatFieldFactory();

		// 
		// Verify the vertex size has change (due to the format getting larger)
		//
		FGPrimaryViewer viewer = getPrimaryGraphViewer();
		viewer.repaint();
		waitForSwing();

		Rectangle updatedBounds = vertex.getBounds();
		assertTrue("bounds not updated - was: " + originalBounds + "; is now: " + updatedBounds,
			originalBounds.width < updatedBounds.width);

		performResetFormatAction();

		viewer.repaint();
		waitForSwing();

		Rectangle newNewBounds = vertex.getBounds();
		assertTrue(updatedBounds.width > newNewBounds.width);
	}

	@Test
	public void testCopyKeyBinding() throws Exception {
		//
		// Make a program selection and test that executing the copy keybinding will copy the 
		// selection (across vertices).
		//

		// 
		// Initialize the clipboard with known data
		//
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		systemClipboard.setContents(DUMMY_TRANSFERABLE, null);
		waitForSwing();

		//
		// Verify our initial state
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation location = getLocationForAddressString(startAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		// locate vertex with cursor
		FGVertex focusedVertex = getFocusVertex(functionGraph);
		assertNotNull("We did not start with a focused vertex", focusedVertex);

		//
		// Create a selection that we will copy from the executing the action 
		//
		AddressSetView addresses = focusedVertex.getAddresses();
		Address address = addresses.getMinAddress();
		ProgramSelection selection =
			new ProgramSelection(program.getAddressFactory(), address, address.add(8));
		tool.firePluginEvent(new ProgramSelectionPluginEvent("Test", selection, program));

		//
		// Validate and execute the action
		//
		DockingAction copyAction = getCopyAction();
		FGController controller = getFunctionGraphController();
		ComponentProvider provider = controller.getProvider();
		assertTrue(copyAction.isEnabledForContext(provider.getActionContext(null)));

		performAction(copyAction, provider, false);

		waitForTasks();

		Transferable contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
	}

	@Test
	public void testCopyAction() {
		//
		// Put the cursor in a vertex on a field with text and make sure that the copy action
		// is enabled.
		//

		// 
		// Initialize the clipboard with known data
		//
		Clipboard systemClipboard = GClipboard.getSystemClipboard();
		systemClipboard.setContents(DUMMY_TRANSFERABLE, null);
		waitForSwing();

		//
		// Verify our initial state
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation location = getLocationForAddressString(startAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		// locate vertex with cursor
		FGVertex focusedVertex = getFocusVertex(functionGraph);
		assertNotNull("We did not start with a focused vertex", focusedVertex);

		//
		// Put the cursor on a copyable thing
		//
		codeBrowser.goToField(getAddress("0x01004196"), "Mnemonic", 0, 0, 2, true);
		waitForSwing();

		// sanity check
		DockingAction copyAction = getCopyAction();
		assertClipboardServiceAddress(copyAction, "0x01004196");

		//
		// Validate and execute the action
		//		
		FGController controller = getFunctionGraphController();
		ComponentProvider provider = controller.getProvider();
		ActionContext actionContext = provider.getActionContext(null);
		boolean isEnabled = copyAction.isEnabledForContext(actionContext);
		debugAction(copyAction, actionContext);
		assertTrue(isEnabled);
		performAction(copyAction, actionContext, true);

		Transferable contents = systemClipboard.getContents(systemClipboard);
		assertNotNull(contents);
		assertTrue("Contents not copied into system clipboard", (contents != DUMMY_TRANSFERABLE));
	}

	@Test
	public void testSatelliteViewIsResizedToFit() {
		//
		// Test that the satellite view zoomed to fit completely in the window if the window
		// is resized or the graph is made bigger via dragging a vertex.
		//
		showSatellite();// make sure it is on

		FGController controller = getFunctionGraphController();
		waitForBusyRunManager(controller);
		FGView view = controller.getView();
		VisualizationViewer<FGVertex, FGEdge> satelliteViewer = view.getSatelliteViewer();
		Double originalGraphScale = getGraphScale(satelliteViewer);

		// 
		// window size change test
		//
		final Window window = windowForComponent(graphProvider.getComponent());
		final Dimension originalSize = window.getSize();
		final Dimension newSize = new Dimension(originalSize.width >> 1, originalSize.height >> 1);
		runSwing(() -> window.setSize(newSize));
		waitForSwing();
		waitForBusyGraph();

		Double newGraphScale = getGraphScale(satelliteViewer);
		Assert.assertNotEquals("The graph's scale did not change after resizing the window",
			originalGraphScale, newGraphScale);

		runSwing(() -> window.setSize(originalSize));
		waitForSwing();
		waitForBusyGraph();

		newGraphScale = getGraphScale(satelliteViewer);
		assertEquals(originalGraphScale, newGraphScale);

		// 
		// graph size change test
		//
		FGData functionGraphData = getFunctionGraphData();
		FunctionGraph functionGraph = functionGraphData.getFunctionGraph();
		VisualizationViewer<FGVertex, FGEdge> primaryGraphViewer = view.getPrimaryGraphViewer();
		VisualizationModel<FGVertex, FGEdge> model = primaryGraphViewer.getModel();
		final Layout<FGVertex, FGEdge> graphLayout = model.getGraphLayout();
		final FGVertex vertex = functionGraph.getRootVertex();
		final Point2D startPoint = graphLayout.apply(vertex);

		final Point2D newPoint = new Point2D.Double(startPoint.getX() + 2000, startPoint.getY());
		runSwing(() -> {
			Caching cachingLayout = (Caching) graphLayout;
			cachingLayout.clear();
			graphLayout.setLocation(vertex, newPoint);
		});
		waitForSwing();

		Double scaleAfterDragging = getGraphScale(satelliteViewer);
		Assert.assertNotEquals(newGraphScale, scaleAfterDragging);

		// put the vertex back and make sure the scale is reverted
		runSwing(() -> {
			Caching cachingLayout = (Caching) graphLayout;
			cachingLayout.clear();
			graphLayout.setLocation(vertex, startPoint);
		});
		waitForSwing();

		scaleAfterDragging = getGraphScale(satelliteViewer);
		assertEquals(newGraphScale, scaleAfterDragging);
	}

	public void TODO_testPersistence() {
		// 	
		// This wants to test that graph perspective info is saved between Ghidra sessions.  In
		// other words, is my graph location and zoom level the same between Ghidra runs.  We 
		// also want to test that colors and vertex locations are persisted between sessions.
		// 
		//

		// Note: This is probably too hard to worry about.  To test this, we have to setup a
		//       Ghidra environment with varied values.  Then, close down Ghidra, relaunch Ghidra,
		//       and test the changed values for sameness
	}

	public void TODO_testEdgeHover() {
		// hover should show information about the connected nodes in a tooltip?

		// should hover highlight the same edge in the satellite?

		//
		// Note: these are GUI intensive tests--low reward/benefit ratios
		//
	}

	@Test
	public void testGraphNodesCreated() throws Exception {
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Collection<FGVertex> vertices = functionGraph.getVertices();

		BlockModelService blockService = tool.getService(BlockModelService.class);
		CodeBlockModel blockModel = blockService.getActiveBlockModel(program);
		FunctionManager functionManager = program.getFunctionManager();
		Function function = functionManager.getFunctionContaining(getAddress(startAddressString));
		CodeBlockIterator iterator =
			blockModel.getCodeBlocksContaining(function.getBody(), TaskMonitor.DUMMY);

		// we should have one vertex for each code block
		Set<Address> vertexAddresses = new HashSet<>();
		for (FGVertex vertex : vertices) {
			AddressSetView addresses = vertex.getAddresses();
			vertexAddresses.add(addresses.getMinAddress());
		}

		for (; iterator.hasNext();) {
			CodeBlock codeBlock = iterator.next();
			assertTrue(vertexAddresses.contains(codeBlock.getMinAddress()));
		}
	}

	@Test
	public void testClearColorAction() throws Exception {
		tool.addPlugin(ColorizingPlugin.class.getName());

		FGVertex focusedVertex = getFocusedVertex();
		ColorizingService colorizingService = tool.getService(ColorizingService.class);
		Color appliedBackgroundColor =
			colorizingService.getBackgroundColor(focusedVertex.getVertexAddress());

		Color testColor = Color.RED;
		assertTrue("Unexpected start color--must change the test!",
			!testColor.equals(appliedBackgroundColor));

		chooseColor(focusedVertex, testColor);

		Color newVertexBackgroundColor = focusedVertex.getUserDefinedColor();
		assertEquals("Background color not set", testColor, newVertexBackgroundColor);

		DockingAction clearColorAction = getClearColorAction(focusedVertex);
		performAction(clearColorAction, graphProvider, true);

		Color userDefinedColor = focusedVertex.getUserDefinedColor();
		assertNull(userDefinedColor);

		Color serviceBackgroundColor =
			colorizingService.getBackgroundColor(focusedVertex.getVertexAddress());
		assertNull("Clear action did not clear the service's applied color",
			serviceBackgroundColor);
	}

	// test that navigating a vertex updates the code browser's location
	@Test
	public void testNavigationFromVertexToCodeBrowser() {

		//
		// This test covers navigation, which relies on the provider being focused to work
		//
		setProviderAlwaysFocused();

		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation location = getLocationForAddressString(startAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		// locate vertex with cursor
		FGVertex focusedVertex = getFocusVertex(functionGraph);
		assertNotNull("We did not start with a focused vertex", focusedVertex);

		Collection<FGVertex> vertices = functionGraph.getVertices();
		FGVertex otherVertex = null;
		for (FGVertex vertex : vertices) {
			if (vertex != focusedVertex) {
				otherVertex = vertex;
				break;
			}
		}
		assertNotNull(otherVertex);

		Address address = otherVertex.getAddresses().getMinAddress();
		final ProgramLocation newVertexLocation = new ProgramLocation(program, address);
		final FGController controller =
			(FGController) TestUtils.getInstanceField("controller", graphProvider);

		runSwing(() -> controller.display(program, newVertexLocation));

		// we must 'fake out' the listing to generate a location event from within the listing
		pressRightArrowKey(otherVertex);
		waitForSwing();

		ProgramLocation codeBrowserLocation = runSwing(() -> codeBrowser.getCurrentLocation());
		ProgramLocation actualVertexLocation = otherVertex.getProgramLocation();
		assertEquals(newVertexLocation.getAddress(), actualVertexLocation.getAddress());
		assertEquals(actualVertexLocation.getAddress(), codeBrowserLocation.getAddress());
	}

	@Test
	public void testFullyZoomedOutOption() throws Exception {
		// 
		// Test the default option that fits the entire graph into the window.  Then toggle the 
		// option and test that a new graph starts fully zoomed-in.
		//

		hideSatellite();// for readability
		setGraphWindowSize(300, 300);// make window small for easier testing
		setZoomOutOption(true);

		assertZoomedOut();

		setZoomOutOption(false);

		assertZoomedIn();
	}

	@Test
	public void testNavigationHistory_VertexChangesOption() throws Exception {

		setNavigationHistoryOption(NavigationHistoryChoices.VERTEX_CHANGES);

		FGData graphData = getFunctionGraphData();
		FunctionGraph graph = graphData.getFunctionGraph();
		Collection<FGVertex> vertices = graph.getVertices();

		FGVertex start = getFocusedVertex();

		Iterator<FGVertex> it = vertices.iterator();
		FGVertex v1 = it.next();
		pickVertex(v1);

		FGVertex v2 = it.next();
		pickVertex(v2);

		FGVertex v3 = it.next();
		pickVertex(v3);

		assertInHistory(start, v1, v2);
	}

	@Test
	public void testNavigationHistory_NavigationEventsOption() throws Exception {

		setNavigationHistoryOption(NavigationHistoryChoices.NAVIGATION_EVENTS);

		clearHistory();

		FGVertex v1 = vertex("01004178");
		pickVertex(v1);

		FGVertex v2 = vertex("01004192");
		pickVertex(v2);

		FGVertex v3 = vertex("010041a4");
		pickVertex(v3);

		// in this navigation mode, merely selecting nodes does *not* put previous nodes in history
		assertNotInHistory(v1, v2);

		//
		// Perform a navigation action (e.g., goTo()) and verify the old function is in the history
		//
		Address ghidra = getAddress("0x01002cf5");
		goTo(ghidra);
		assertInHistory(v3.getVertexAddress());

		Address foo = getAddress("0x01002339");
		goTo(foo);
		assertInHistory(v3.getVertexAddress(), ghidra);
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private void assertNotInHistory(FGVertex... vertices) {

		List<Address> vertexAddresses =
			Arrays.stream(vertices)
					.map(v -> v.getVertexAddress())
					.collect(Collectors.toList());
		assertNotInHistory(vertexAddresses);
	}

	private void assertNotInHistory(List<Address> addresses) {

		List<LocationMemento> locations = getNavigationHistory();
		List<Address> actualAddresses =
			locations.stream()
					.map(memento -> memento.getProgramLocation().getAddress())
					.collect(Collectors.toList());

		for (Address a : addresses) {
			assertFalse("Vertex address should not be in the history list: " + a + ".\nHistory: " +
				actualAddresses + "\nNavigated vertices: " + Arrays.asList(addresses),
				actualAddresses.contains(a));
		}
	}

	private void clearHistory() {
		GoToService goTo = tool.getService(GoToService.class);
		Navigatable navigatable = goTo.getDefaultNavigatable();

		NavigationHistoryService service = tool.getService(NavigationHistoryService.class);
		service.clear(navigatable);
	}

	private List<LocationMemento> getNavigationHistory() {

		GoToService goTo = tool.getService(GoToService.class);
		Navigatable navigatable = goTo.getDefaultNavigatable();

		NavigationHistoryService service = tool.getService(NavigationHistoryService.class);
		List<LocationMemento> locations = service.getPreviousLocations(navigatable);
		return locations;
	}

	private void assertInHistory(FGVertex... vertices) {

		List<Address> vertexAddresses =
			Arrays.stream(vertices)
					.map(v -> v.getVertexAddress())
					.collect(Collectors.toList());
		assertInHistory(vertexAddresses);
	}

	private void assertInHistory(Address... addresses) {
		assertInHistory(Arrays.asList(addresses));
	}

	private void assertInHistory(List<Address> expectedAddresses) {

		List<LocationMemento> actualLocations = getNavigationHistory();
		assertTrue(
			"Vertex address should be in the history list: " + expectedAddresses + ".\nHistory: " +
				actualLocations + "\nNavigated vertices: " + expectedAddresses,
			expectedAddresses.size() <= actualLocations.size());

		List<Address> actualAddresses =
			actualLocations.stream()
					.map(memento -> memento.getProgramLocation().getAddress())
					.collect(Collectors.toList());

		for (Address a : expectedAddresses) {

			assertTrue("Vertex address should be in the history list: " + a + ".\nActual: " +
				actualAddresses + "\nExpected: " + expectedAddresses,
				actualAddresses.contains(a));
		}
	}

	private void setNavigationHistoryOption(NavigationHistoryChoices choice) throws Exception {
		FGController controller = getFunctionGraphController();
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		runSwing(() -> setInstanceField("navigationHistoryChoice", options, choice));
		waitForSwing();
	}

	private void doTestLabelChangeAtVertexEntryUpdatesTitle() {
		// get the graph contents
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());

		// locate vertex with cursor
		Address vertexAddressWithDefaultLabel = getAddress("01004178");
		FunctionGraph graph = graphData.getFunctionGraph();
		FGVertex vertex = graph.getVertexForAddress(vertexAddressWithDefaultLabel);
		String originalTitle = vertex.getTitle();

		// add a label in the listing
		String labelName = testName.getMethodName();
		AddLabelCmd addCmd =
			new AddLabelCmd(vertexAddressWithDefaultLabel, labelName, SourceType.USER_DEFINED);
		addCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();

		// make sure the label appears in the vertex
		String updatedTitle = vertex.getTitle();
		Assert.assertNotEquals(originalTitle, updatedTitle);
		assertTrue(updatedTitle.indexOf(testName.getMethodName()) != -1);
	}

	private void doTestRelayout(boolean fullReload) throws Exception {

		//
		// This test covers navigation, which relies on the provider being focused to work
		//
		setProviderAlwaysFocused();

		//
		// Test that we can move a node, call relayout and that the moved node will not be 
		// at the moved position.
		//

		FGData originalGraphData = getFunctionGraphData();
		assertNotNull(originalGraphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData",
			originalGraphData.hasResults());

		//
		// Unusual Code: The initial load values may not be exactly the same as the values
		//               set during a relayout.  To make sure that we are comparing apples-to-apples,
		//               we want to record the initial values after performing a relayout.  Then,
		//               we change a node's position, relayout again, and check the final values
		//               with that after the first relayout.
		//		
		if (fullReload) {
			performReload();
		}
		else {
			performRelayout();
		}

		originalGraphData = getFunctionGraphData();
		FunctionGraph graph = originalGraphData.getFunctionGraph();
		final FGVertex rootVertex = graph.getRootVertex();
		assertNotNull(rootVertex);

		Point2D originalPoint = rootVertex.getLocation();

		double dx = originalPoint.getX() + 100;
		double dy = originalPoint.getY() + 100;

		Point2D newPoint = new Point2D.Double(dx, dy);
		final Layout<FGVertex, FGEdge> primaryLayout = getPrimaryLayout();
		final Point2D finalNewPoint = newPoint;
		runSwing(() -> primaryLayout.setLocation(rootVertex, finalNewPoint));

		assertEquals("Vertex location not correctly set", newPoint, rootVertex.getLocation());

		// we have to wait for the paint to take place, as the rendering will change the vertex
		// locations
		FGPrimaryViewer primaryGraphViewer = getPrimaryGraphViewer();
		primaryGraphViewer.repaint();
		waitForSwing();

		// move the location a bit, for later testing the sync between the listing and the graph
		goToAddress("1004196");

		// relayout
		if (fullReload) {
			performReload();
		}
		else {
			performRelayout();
		}

		FGData newGraphData = getFunctionGraphData();
		assertNotNull(newGraphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", newGraphData.hasResults());

		FunctionGraph newGraph = newGraphData.getFunctionGraph();
		FGVertex newRootVertex = newGraph.getRootVertex();
		assertNotNull(newRootVertex);

		waitForSwing();

		// Note: we can't test for exact equality based upon the location we set, as the values
		// are updated based upon other factors, like screen location and size.  We want to make
		// sure that the value is not the default.
		Point2D reloadedPoint = newRootVertex.getLocation();
		assertTrue(
			"Vertex location not restored to default after performing a relayout " +
				"original point: " + originalPoint + " - reloaded point: " + reloadedPoint,
			pointsAreSimilar(originalPoint, reloadedPoint));

		//
		// Make sure the CodeBrowser's location matches ours after the relayout (the location should
		// get broadcast to the CodeBrowser)
		//

		// Note: there is a timing failure that happens for this check; the event broadcast 
		//       only happens if the FG provider has focus; in parallel batch mode focus is 
		//       unreliable
		if (!BATCH_MODE) {
			assertTrue(graphAddressMatchesCodeBrowser(newGraph));
		}
	}

	private boolean graphAddressMatchesCodeBrowser(FunctionGraph graph) {
		FGVertex focusedVertex = runSwing(() -> graph.getFocusedVertex());
		ProgramLocation graphLocation = focusedVertex.getProgramLocation();
		ProgramLocation codeBrowserLocation = runSwing(() -> codeBrowser.getCurrentLocation());
		return graphLocation.getAddress().equals(codeBrowserLocation.getAddress());
	}
}
