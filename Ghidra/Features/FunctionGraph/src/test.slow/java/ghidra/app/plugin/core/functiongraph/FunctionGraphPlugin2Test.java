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

import static ghidra.graph.viewer.GraphViewerUtils.getGraphScale;
import static ghidra.graph.viewer.GraphViewerUtils.getPointInViewSpaceForVertex;
import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.Point;
import java.util.*;

import javax.swing.JComponent;

import org.junit.*;

import docking.action.DockingActionIf;
import edu.uci.ics.jung.graph.Graph;
import generic.test.TestUtils;
import ghidra.app.cmd.label.AddLabelCmd;
import ghidra.app.cmd.label.DeleteLabelCmd;
import ghidra.app.cmd.refs.AddMemRefCmd;
import ghidra.app.cmd.refs.RemoveReferenceCmd;
import ghidra.app.plugin.core.colorizer.ColorizingPlugin;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.vertex.*;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin;
import ghidra.app.plugin.core.navigation.NextPrevAddressPlugin;
import ghidra.app.util.viewer.listingpanel.ListingPanel;
import ghidra.graph.viewer.GraphPerspectiveInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.symbol.*;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

public class FunctionGraphPlugin2Test extends AbstractFunctionGraphTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		tool.addPlugin(GoToAddressLabelPlugin.class.getName());
		tool.addPlugin(NextPrevAddressPlugin.class.getName());

		waitForGraphToLoad();
	}

	@Test
	public void testSelectionFromCodeBrowser() {
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation location = getLocationForAddressString(startAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		// locate vertex with cursor
		FGVertex focusedVertex = getFocusVertex(functionGraph);
		assertNotNull("We did not start with a focused vertex", focusedVertex);
		assertTrue(focusedVertex.containsProgramLocation(location));

		// make a selection starting at the current location
		ProgramSelection ps = makeSingleVertexSelectionInCodeBrowser();
		ProgramSelection vertexSelection = focusedVertex.getProgramSelection();
		assertTrue(!ps.isEmpty());
		assertEquals("A selection from the code browser that is completely contained in the " +
			"tested vertex is not in the vertex", ps, vertexSelection);
	}

	@Test
	public void testRedockSatellite() {

		showSatellite();// make sure it is on

		undockSatellite();
		redockSatellite();
		assertNoUndockedProvider();
		assertSatelliteVisible(true);
	}

	@Test
	public void testUndockSatellite() {

		showSatellite();// make sure it is on

		assertNoUndockedProvider();

		undockSatellite();

		assertSatelliteVisible(true);
		assertUndockedProviderShowing();
	}

	@Test
	public void testShowSatelliteButtonWhenDocked() {
		showSatellite();// make sure it is on

		toggleSatalliteVisible(false);
		assertSatelliteVisible(false);

		pressShowSatelliteButton();

		assertSatelliteVisible(true);
		assertNoUndockedProvider();
	}

	@Test
	public void testShowSatelliteButtonWhenUnDocked() {
		showSatellite();// make sure it is on

		undockSatellite();
		assertUndockedProviderShowing();

		closeUndockedProvider();
		assertUndockedProviderNotShowing();

		pressShowSatelliteButton();

		assertUndockedProviderShowing();
		assertSatelliteVisible(true);
	}

	@Test
	public void testUndockWhileInvisible() {

		toggleSatalliteVisible(false);
		assertSatelliteVisible(false);

		undockSatellite();
		assertUndockedProviderShowing();

		redockSatellite();

		// note: redocking the satellite will make it visible again
		assertSatelliteVisible(true);
	}

	@Test
	public void testSnapshotWithUndockedSatellite() {

		undockSatellite();

		FGController newController = cloneGraph();
		assertUndockedProviderShowing(newController.getProvider());
		isSatelliteVisible(newController);
	}

	@SuppressWarnings("unchecked")
	// list cast
	@Test
	public void testSnapshot() {
		List<FGProvider> disconnectedProviders =
			(List<FGProvider>) getInstanceField("disconnectedProviders", graphPlugin);
		assertTrue(disconnectedProviders.isEmpty());

		FGController primaryController = getFunctionGraphController();
		waitForBusyRunManager(primaryController);
		ProgramLocation location = graphProvider.getLocation();
		GraphPerspectiveInfo<FGVertex, FGEdge> primaryPerspective =
			primaryController.getGraphPerspective(location);

		DockingActionIf snapshotAction =
			getAction(tool, graphPlugin.getName(), "Function Graph Clone");
		performAction(snapshotAction, true);

		assertEquals(1, disconnectedProviders.size());
		FGProvider providerClone = disconnectedProviders.get(0);
		FGController controllerClone = (FGController) getInstanceField("controller", providerClone);
		waitForBusyRunManager(controllerClone);
		ProgramLocation cloneLocation = providerClone.getLocation();
		GraphPerspectiveInfo<FGVertex, FGEdge> clonePerspective =
			controllerClone.getGraphPerspective(cloneLocation);

		double primaryPerspectiveZoom = primaryPerspective.getZoom();
		double clonePerspectiveZoom = clonePerspective.getZoom();
		assertEquals(primaryPerspectiveZoom, clonePerspectiveZoom, .001);

		Point primaryPoint = primaryPerspective.getLayoutTranslateCoordinates();
		Point clonePoint = clonePerspective.getLayoutTranslateCoordinates();

		assertPointsAreAboutEqual("Cloned graph view info does not match the source graph",
			primaryPoint, clonePoint);
	}

	@Test
	public void testZoom() {
		setZoom(0.5d);

		waitForAnimation();

		FGPrimaryViewer primaryGraphViewer = getPrimaryGraphViewer();
		Double originalGraphScale = getGraphScale(primaryGraphViewer);
		Msg.debug(this, "original scale: " + originalGraphScale);

		// zoom at code level
		Msg.debug(this, "zooming in...");
		zoomInCompletely();
		Double zoomedInGraphScale = getGraphScale(primaryGraphViewer);
		Msg.debug(this, "new scale: " + zoomedInGraphScale);

		Assert.assertNotEquals(originalGraphScale, zoomedInGraphScale);
	}

	@Test
	public void testSplitAndMergeNodesOnStaleGraph_ForReference() {
		int txID = -1;
		try {
			txID = program.startTransaction("Test: " + testName.getMethodName());
			doTestSplitAndMergeNodesOnStaleGraph_ForReference();
		}
		finally {
			program.endTransaction(txID, false);
		}
	}

	@Test
	public void testSplitAndMergeNodesOnStaleGraph_ForSymbol() {
		int txID = -1;
		try {
			txID = program.startTransaction("Test: " + testName.getMethodName());
			doTestSplitAndMergeNodesOnStaleGraph_ForSymbol();
		}
		finally {
			program.endTransaction(txID, false);
		}
	}

	@Test
	public void testSetVertexColor() {
		FGVertex focusedVertex = getFocusedVertex();

		JComponent panel = focusedVertex.getComponent();
		ListingPanel listingPanel =
			(ListingPanel) TestUtils.getInstanceField("listingPanel", panel);
		Color startBackgrond = listingPanel.getTextBackgroundColor();
		Color testColor = Color.RED;
		assertTrue("Unexpected start color--must change the test!",
			!testColor.equals(startBackgrond));

		chooseColor(focusedVertex, testColor);

		Color newBackground = listingPanel.getTextBackgroundColor();
		assertTrue(!startBackgrond.equals(newBackground));
	}

	@Test
	public void testSharedColorExperience() throws Exception {
		//
		// Tests the new way of coloring vertices, by way of the ColorizerService, which will
		// set the color in both the vertex and the listing (really just in the listing, but 
		// the vertex displays this color.
		//

		// install ColorizerPlugin
		tool.addPlugin(ColorizingPlugin.class.getName());

		FGVertex vertex = getFocusedVertex();
		ColorizingService colorizingService = tool.getService(ColorizingService.class);
		Color appliedBackgroundColor =
			colorizingService.getBackgroundColor(vertex.getVertexAddress());

		Color testColor = Color.RED;
		assertTrue("Unexpected start color--must change the test!",
			!testColor.equals(appliedBackgroundColor));

		chooseColor(vertex, testColor);

		// make sure the service is also cognizant of the color change
		appliedBackgroundColor = colorizingService.getBackgroundColor(vertex.getVertexAddress());
		assertEquals(testColor, appliedBackgroundColor);

		Color vBg = vertex.getBackgroundColor();
		assertEquals(appliedBackgroundColor, vBg);

		// 
		// Reload and make sure the color is re-applied to the vertex (this was broken)
		//
		Address vertexAddress = vertex.getVertexAddress();
		performReload();
		FGVertex reloadedVertex = vertex(vertexAddress);
		assertNotSame(vertex, reloadedVertex);
		vBg = reloadedVertex.getBackgroundColor();
		assertEquals(appliedBackgroundColor, vBg);
	}

	@Test
	public void testSetMostRecentColorAction() throws Exception {
		//
		// Test that the 'set most recent color' action will set the color of the vertex *and* 
		// in the Listing.
		//
		// install ColorizerPlugin
		tool.addPlugin(ColorizingPlugin.class.getName());

		FGVertex focusedVertex = getFocusedVertex();
		ColorizingService colorizingService = tool.getService(ColorizingService.class);
		Color startBackgroundColor =
			colorizingService.getBackgroundColor(focusedVertex.getVertexAddress());

		FGController controller = getFunctionGraphController();
		Color mostRecentColor = controller.getMostRecentColor();

		Assert.assertNotEquals(
			"Test environment not setup correctly--should have default backgrond " +
				"colors applied",
			startBackgroundColor, mostRecentColor);

		SetVertexMostRecentColorAction setRecentColorAction =
			getSetMostRecentColorAction(focusedVertex);
		performAction(setRecentColorAction, graphProvider, true);

		Color newVertexBackgroundColor = focusedVertex.getBackgroundColor();
		assertEquals("'Set Most Recent Color' action did not apply that color to the vertex",
			mostRecentColor, newVertexBackgroundColor);

		Color newBackgroundColor =
			colorizingService.getBackgroundColor(focusedVertex.getVertexAddress());
		assertEquals("'Set Most Recent Color' action did not apply that color to the color service",
			mostRecentColor, newBackgroundColor);
	}

	// TODO: see SCR 9208 - we don't currently support this, although we could
	public void dont_testNavigatingBackwardsRestoresPerspectiveInfo_ZoomOutOn() throws Exception {
		//
		// Test, that with the default 'zoomed-out' option *on* for new graphs, we will restore the 
		// user's previous graph perspective data when they navigate back to a function that 
		// were examining (instead of zooming back out to the full view).
		//

		hideSatellite();// for readability
		setGraphWindowSize(300, 300);// make window small for easier testing

		setZoomOutOption(true);

		// zoom in to a vertex (pick something beside the entry point)
		goTo("1004196");
		zoomInCompletely();

		// move that vertex off center
		moveView(10);
		FGVertex v = getFocusedVertex();
		Point originalLocation = getPointInViewSpaceForVertex(getPrimaryGraphViewer(), v);

		// 'go to' a new function to change the graph
		goTo("01002239");

		// trigger a back navigation
		navigateBack();

		// make sure that the zoom is restored (note: the point information reflects both
		// location and zoom)
		Point restoredLocation = getPointInViewSpaceForVertex(getPrimaryGraphViewer(), v);
		assertEquals(originalLocation, restoredLocation);
	}

	// not sure how to trigger a selection from a node via the GUI...if we use the API method,
	// as it does now, the CodeBrowser does not get the callback, because that's how the system works.
	// If it is worth testing, and we can do it from the mouse, then have at it
	public void dont_testSelectionFromGraphToCodeBrowser() {
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
		ProgramLocation location = getLocationForAddressString(startAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		// locate vertex with cursor
		FGVertex focusedVertex = getFocusVertex(functionGraph);
		assertNotNull("We did not start with a focused vertex", focusedVertex);

		AddressSetView addresses = focusedVertex.getAddresses();
		Address address = addresses.getMinAddress();
		focusedVertex.setProgramSelection(new ProgramSelection(address, address));

		// make sure the code browser now contains a matching selection
		ProgramSelection firstSelection = focusedVertex.getProgramSelection();
		ListingPanel listingPanel = codeBrowser.getListingPanel();
		ProgramSelection codeBrowserSelection = listingPanel.getProgramSelection();
		assertTrue(!firstSelection.isEmpty());
		assertEquals("Selecting text in the vertex did not select text in the code browser",
			firstSelection, codeBrowserSelection);

		Collection<FGVertex> vertices = functionGraph.getVertices();
		FGVertex otherVertex = null;
		for (FGVertex vertex : vertices) {
			if (vertex != focusedVertex) {
				otherVertex = vertex;
				break;
			}
		}
		assertNotNull(otherVertex);

		Address otherAddress = otherVertex.getAddresses().getMinAddress();
		otherVertex.setProgramSelection(new ProgramSelection(otherAddress, otherAddress));
		ProgramSelection secondSelection = otherVertex.getProgramSelection();
		assertTrue(!secondSelection.isEmpty());

		codeBrowserSelection = listingPanel.getProgramSelection();

		// the new code browser selection should have both of our vertex selections
		assertTrue(codeBrowserSelection.getMinAddress().equals(firstSelection.getMinAddress()));
		assertTrue(codeBrowserSelection.getMaxAddress().equals(secondSelection.getMaxAddress()));
	}

	// TODO: see SCR 9208 - we don't currently support this, although we could
	public void dontTestNavigatingBackwardsRestoresPerspectiveInfo_ZoomOutOff() throws Exception {
		//
		// Test, that with the default 'zoomed-out' option *off* for new graphs, we will restore the 
		// user's previous graph perspective data when they navigate back to a function that 
		// were examining (instead of zooming back out to the full view).
		//

		hideSatellite();// for readability
		setGraphWindowSize(300, 300);// make window small for easier testing

		setZoomOutOption(false);

		// zoom in to a vertex (pick something beside the entry point)
		goTo("1004196");
		zoomInCompletely();

		// move that vertex off center
		moveView(10);
		FGVertex v = getFocusedVertex();
		Point originalLocation = getPointInViewSpaceForVertex(getPrimaryGraphViewer(), v);

		// 'go to' a new function to change the graph
		goTo("01002239");

		// trigger a back navigation
		navigateBack();

		// make sure that the zoom is restored (note: the point information reflects both
		// location and zoom)
		Point restoredLocation = getPointInViewSpaceForVertex(getPrimaryGraphViewer(), v);
		assertEquals(originalLocation, restoredLocation);
	}

	//
	// TODO:  I have changed the groups such that you can group a single node, which lets you
	//        replace the view of the node with user-defined text.
	//
	//	      This tests verifies that a group will not be created if there is only one vertex
	//        found upon restoring settings.  If we want to put that code back, then this test
	//        is again valid.
	// 
	@Override
	public void dontTestRestoringWhenCodeBlocksHaveChanged_DoesntRegroup() {
		int transactionID = -1;
		try {
			transactionID = program.startTransaction(testName.getMethodName());
			doTestRestoringWhenCodeBlocksHaveChanged_DoesntRegroup();
		}
		finally {
			program.endTransaction(transactionID, false);
		}
	}

	public void doTestSplitAndMergeNodesOnStaleGraph_ForReference() {
		//
		// Test that we can split a node into two for reference operations:
		// 1) Adding a reference splits a node 
		// 2) Removing a reference merges a node
		// 2) The above actions do not take place with automatic updates on
		//
		// Edges cases:
		// 1) Adding a reference to a location already containing a symbol does not split the node
		// 2) Removing a reference with other references at the vertex entry point does not merge nodes
		// 

		// Find a good test function.
		goToAddress("01002cf5");

		// Find a node to manipulate
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());

		String vertexAddressString = "01002d2b";
		Address vertexAddress = getAddress(vertexAddressString);
		ProgramLocation location = getLocationForAddressString(vertexAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		FGVertex initialVertex = functionGraph.getVertexForAddress(vertexAddress);

		// Find a location within that node to which we will add a label
		String referenceFromAddress = "01002d3d";
		String referenceToAddress = "01002d47";
		Address fromAddress = getAddress(referenceFromAddress);
		Address toAddress = getAddress(referenceToAddress);

		//
		// Start with case 1 -- adding a reference
		//
		// Verify the graph is not stale
		FGController controller = getFunctionGraphController();
		FGView view = controller.getView();
		assertTrue(!view.isGraphViewStale());

		// Add a reference
		AddMemRefCmd addCmd =
			new AddMemRefCmd(fromAddress, toAddress, RefType.DATA, SourceType.USER_DEFINED, -1);
		addCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();

		waitForAnimation();

		// Verify the edited node has been split--the old vertex is gone; two new vertices exist
		assertTrue(!graph.containsVertex(initialVertex));
		FGVertex newParentVertex = functionGraph.getVertexForAddress(fromAddress);
		assertNotNull(newParentVertex);

		FGVertex newChildVertex = functionGraph.getVertexForAddress(toAddress);
		assertNotNull(newChildVertex);

		Collection<FGEdge> parentOutEdges = graph.getOutEdges(newParentVertex);
		assertTrue(parentOutEdges.size() == 1);
		assertEquals(newChildVertex, parentOutEdges.iterator().next().getEnd());

		// Verify the graph is stale
		assertTrue(view.isGraphViewStale());

		// Now remove the reference
		ReferenceManager referenceManager = program.getReferenceManager();
		Reference reference = referenceManager.getReference(fromAddress, toAddress, -1);
		assertNotNull(reference);
		RemoveReferenceCmd deleteCmd = new RemoveReferenceCmd(reference);
		deleteCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();
		waitForAnimation();

		// Verify the new nodes have been merged
		assertTrue(!graph.containsVertex(newParentVertex));
		assertTrue(!graph.containsVertex(newChildVertex));

		FGVertex newOldVertex = functionGraph.getVertexForAddress(vertexAddress);
		assertNotNull(newParentVertex);

		FGVertex newOldChildVertex = functionGraph.getVertexForAddress(toAddress);
		assertNotNull(newChildVertex);

		assertEquals(newOldVertex, newOldChildVertex);// this should be the same after the merge

		// 
		// Edge Cases
		//

		// Relayout to put the graph in a known good state
		performRelayout();

		// Find a node to manipulate (one that already has a reference)
		referenceFromAddress = "01002d29";
		referenceToAddress = "01002d52";
		fromAddress = getAddress(referenceFromAddress);
		toAddress = getAddress(referenceToAddress);
		FGVertex fromVertex = functionGraph.getVertexForAddress(vertexAddress);
		assertTrue(graph.containsVertex(fromVertex));

		// Add a reference to the entry point of the node
		addCmd =
			new AddMemRefCmd(fromAddress, toAddress, RefType.DATA, SourceType.USER_DEFINED, -1);
		addCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();
		waitForAnimation();

		// Verify the node was not split
		assertTrue(graph.containsVertex(fromVertex));

		// Now remove the reference we added 
		reference = referenceManager.getReference(fromAddress, toAddress, -1);
		assertNotNull(reference);
		deleteCmd = new RemoveReferenceCmd(reference);
		deleteCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();
		waitForAnimation();

		// Verify the node was not merged
		assertTrue(graph.containsVertex(fromVertex));
	}

	protected void doTestRestoringWhenCodeBlocksHaveChanged_DoesntRegroup() {
		// 
		// Tests the behavior of how group vertices are restored when one or more of the vertices 
		// inside of the grouped vertex is no longer available when the graph attempts to restore
		// the group vertex user settings (i.e., when restarting Ghidra, the previously grouped
		// vertices should reappear).  
		//
		// In this test, we will be mutating a group of 2 nodes such
		// that one of the nodes has been split into two.  This leaves only one vertex to 
		// be found by the regrouping algorithm.  Furthermore, the regrouping will not take place
		// if at least two vertices cannot be found.
		//

		// 
		// Pick a function and group some nodes.
		//
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d11" /* LAB_01002d11 */, "01002cf5" /* ghidra */);

		group(ungroupedVertices);

		// 5 edges expected: 
		// -01002cf5: 2 out 
		// -01002cf5: 2 in, 1 out
		int expectedGroupedEdgeCount = 5;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		AddressSetView addresses = groupedVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();

		//
		// Ideally, we would like to save, close and re-open the program so that we can get 
		// a round-trip saving and reloading.  However, in the test environment, we cannot save 
		// our programs.  So, we will instead just navigate away from the current function, clear
		// the cache (to make sure that we read the settings again), and then verify that the 
		// data saved in the program has been used to re-group.
		//
		graphFunction("0100415a");
		clearCache();

		//
		// Add a label to trigger a code block change
		//
		createLabel("01002d18");// in the middle of the LAB_01002d11 code block

		//
		// Relaunch the graph, which will use the above persisted group settings...
		//
		graphData = graphFunction("01002cf5");
		waitForAnimation();// the re-grouping may be using animation, which runs after the graph is loaded
		functionGraph = graphData.getFunctionGraph();
		FGVertex expectedGroupVertex = functionGraph.getVertexForAddress(minAddress);
		assertFalse(expectedGroupVertex instanceof GroupedFunctionGraphVertex);
	}

	protected void doTestSplitAndMergeNodesOnStaleGraph_ForSymbol() {
		//
		// Test that we can split a node into two for symbol operations:
		// 1) Adding a symbol splits a node 
		// 2) Removing a symbol merges a node
		// 2) The above actions do not take place with automatic updates on
		//
		// Edges cases:
		// 1) Adding a symbol to a location already containing a symbol does not split the node
		// 2) Removing a symbol with other symbols at the vertex entry point does not merge nodes
		// 

		// Find a good test function.
		goToAddress("01002cf5");

		// Find a node to manipulate
		FGData graphData = getFunctionGraphData();
		assertNotNull(graphData);
		assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());

		String vertexAddressString = "01002d2b";
		Address vertexAddress = getAddress(vertexAddressString);
		ProgramLocation location = getLocationForAddressString(vertexAddressString);
		assertTrue(graphData.containsLocation(location));
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		FGVertex initialVertex = functionGraph.getVertexForAddress(vertexAddress);

		// Find a location within that node to which we will add a label
		String labelAddressString = "01002d47";
		Address labelAddress = getAddress(labelAddressString);

		//
		// Start with case 1 -- adding a symbol
		//
		// Verify the graph is not stale
		FGController controller = getFunctionGraphController();
		FGView view = controller.getView();
		assertTrue(!view.isGraphViewStale());

		// Add a label
		String labelName = testName.getMethodName();
		AddLabelCmd addCmd = new AddLabelCmd(labelAddress, labelName, SourceType.USER_DEFINED);
		addCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();
		waitForAnimation();

		// Verify the edited node has been split--the old vertex is gone; two new vertices exist
		assertTrue(!graph.containsVertex(initialVertex));
		FGVertex newParentVertex = functionGraph.getVertexForAddress(vertexAddress);
		assertNotNull(newParentVertex);

		FGVertex newChildVertex = functionGraph.getVertexForAddress(labelAddress);
		assertNotNull(newChildVertex);

		Collection<FGEdge> parentOutEdges = graph.getOutEdges(newParentVertex);
		assertTrue(parentOutEdges.size() == 1);
		assertEquals(newChildVertex, parentOutEdges.iterator().next().getEnd());

		// Verify the graph is stale
		assertTrue(view.isGraphViewStale());

		// Now remove the label
		DeleteLabelCmd deleteCmd = new DeleteLabelCmd(labelAddress, labelName);
		deleteCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();
		waitForAnimation();

		// Verify the new nodes have been merged
		assertTrue(!graph.containsVertex(newParentVertex));
		assertTrue(!graph.containsVertex(newChildVertex));

		FGVertex newOldVertex = functionGraph.getVertexForAddress(vertexAddress);
		assertNotNull(newParentVertex);

		FGVertex newOldChildVertex = functionGraph.getVertexForAddress(labelAddress);
		assertNotNull(newChildVertex);

		assertEquals(newOldVertex, newOldChildVertex);// this should be the same after the merge

		// Verify the graph is still stale
		assertTrue(view.isGraphViewStale());

		// 
		// Edge Cases
		//

		// Relayout to put the graph in a known good state
		performRelayout();

		// Find a node to manipulate (one that already has a label)
		FGVertex vertexWithLabel = functionGraph.getVertexForAddress(vertexAddress);

		// Add a label to the entry point of the node
		labelName = testName.getMethodName() + "2";
		addCmd = new AddLabelCmd(vertexAddress, labelName, SourceType.USER_DEFINED);
		addCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();
		waitForAnimation();

		// Verify the node was not split
		assertTrue(graph.containsVertex(vertexWithLabel));

		// Verify the graph is stale
		assertTrue(view.isGraphViewStale());

		// Now remove the label we added 
		deleteCmd = new DeleteLabelCmd(vertexAddress, labelName);
		deleteCmd.applyTo(program);
		program.flushEvents();
		waitForSwing();
		waitForAnimation();

		// Verify the node was not merged
		assertTrue(graph.containsVertex(vertexWithLabel));
	}

	// note: unreliable--garbage collection works differently across platforms (sad face)	
//		public void testClearCacheAndMemoryLeak() {
//			//
//			// Test that when we clear the cache of a graph the vertices of that graph will be 
//			// garbage collected
//			//
//			WeakSet<FunctionGraphVertex> weakSet =
//				WeakDataStructureFactory.createSingleThreadAccessWeakSet();
	//
//			FunctionGraphData graphData = getFunctionGraphData();
//			assertNotNull(graphData);
//			assertTrue("Unexpectedly received an empty FunctionGraphData", graphData.hasResults());
	//
//			FunctionGraph graph = graphData.getFunctionGraph();
//			FunctionGraphVertex rootVertex = graph.getRootVertex();
//			assertNotNull(rootVertex);
	//
//			weakSet.add(rootVertex);
//			assertTrue(weakSet.iterator().hasNext());
	//
//			// move to a new function so that we the FG will not be holding a reference to the 
//			// originally graphed function
//			String address = "01002239";
//			goToAddress(address);
	//
//			FunctionGraphData newGraphData = getFunctionGraphData();
//			assertNotNull(newGraphData);
//			assertTrue("Unexpectedly received an empty FunctionGraphData", newGraphData.hasResults());
	//
//			assertTrue(
//				"Function Graph did not graph a new function as expected at address: " + address,
//				!graphData.equals(newGraphData));
	//
//			triggerGraphDisposal(graphData);
	//
//			rootVertex = null;
//			graph = null;
//			graphData = null;
	//
//			// let (force) the Garbage Collector run
//			System.gc();
//			sleep(100);
//			System.gc();
//			sleep(100);
//			System.gc();
//			sleep(100);
	//
//			boolean isNotCollected = weakSet.iterator().hasNext();
//			assertFalse(isNotCollected);
//		}
	//
//		private void triggerGraphDisposal(FunctionGraphData dataToDispose) {
//			Object controller = getInstanceField("controller", graphProvider);
//			LRUMap<?, ?> cache = (LRUMap<?, ?>) getInstanceField("graphCache", controller);
//			cache.clear();
//			dataToDispose.dispose();
//		}

}
