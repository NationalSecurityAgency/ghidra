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

import static org.junit.Assert.*;

import java.awt.Color;
import java.awt.geom.Point2D;
import java.util.*;

import org.apache.commons.collections4.IterableUtils;
import org.junit.*;

import docking.ActionContext;
import docking.action.DockingActionIf;
import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.clear.ClearPlugin;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.framework.plugintool.util.PluginException;
import ghidra.graph.viewer.options.RelayoutOption;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import util.CollectionUtils;

public class FunctionGraphGroupVertices1Test extends AbstractFunctionGraphTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		disableAnimation();
	}

	@Test
	public void testGroupAndUngroupVertices() {
		doTestGroupAndUngroupVertices();
	}

	@Test
	public void testGroupAndUngroupWithAutomaticRelayoutOff() {
		FGController controller = getFunctionGraphController();
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		setInstanceField("relayoutOption", options, RelayoutOption.NEVER);

		doTestGroupAndUngroupVertices();
	}

	@Test
	public void testGroupingPersistence() throws Exception {
		//
		// Round-trip test to ensure that a grouped graph will be restored after re-opening a
		// program.
		//

		//
		// Pick a function and group some nodes.
		//
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);

		group(ungroupedVertices);

		// -1 because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);
		Point2D location = getLocation(groupedVertex);
		AddressSetView addresses = groupedVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();
		Address maxAddress = addresses.getMaxAddress();

		// Record the edges for later validation.  Note: we have to keep the string form, as the
		// toString() on the edges will call back to its vertices, which will later have been
		// disposed.
		Collection<FGEdge> oringalGroupedEdges = new HashSet<>(graph.getEdges());// copy so they don't get cleared
		List<String> originalEdgeStrings = new ArrayList<>(oringalGroupedEdges.size());
		for (FGEdge edge : oringalGroupedEdges) {
			originalEdgeStrings.add(edge.toString());
		}

		// debug
		capture(getPrimaryGraphViewer(), "graph.grouping.before.reload");
		graphData = triggerPersistenceAndReload("01002cf5");

		waitForAnimation();// the re-grouping may be using animation, which runs after the graph is loaded
		functionGraph = graphData.getFunctionGraph();
		graph = functionGraph;
		FGVertex vertex = functionGraph.getVertexForAddress(minAddress);
		assertTrue(vertex instanceof GroupedFunctionGraphVertex);
		assertEquals(maxAddress, vertex.getAddresses().getMaxAddress());

		Point2D newLocation = getLocation(vertex);

		// TODO debug - this has failed; suspected timing issue
		waitForCondition(() -> pointsAreSimilar(location, newLocation));

		capture(getPrimaryGraphViewer(), "graph.grouping.after.reload");
		assertTrue(
			"Vertex location not restored to default after performing a relayout " +
				"original point: " + location + " - reloaded point: " + newLocation,
			pointsAreSimilar(location, newLocation));

		Collection<FGEdge> newGroupedEdges = graph.getEdges();
		List<String> newEdgeStrings = new ArrayList<>(newGroupedEdges.size());
		for (FGEdge edge : newGroupedEdges) {
			newEdgeStrings.add(edge.toString());
		}

		assertSameEdges("Edges not correctly restored after persisting", originalEdgeStrings,
			newEdgeStrings);
	}

	/**
	 * Tests that the app will recognize the case where the entry point to a function is invalid,
	 * and generate the appropriate error message when trying to create a function graph.
	 *
	 * Step 1: Make sure the function graph window is closed.
	 * Step 2: Clear the entry point bytes
	 * Step 3: Open the function graph window to generate the graph again.
	 * Step 4: Check the error message.
	 */
	public void testInvalidFunctionEntryPoint() {

		// First thing we need to do is close the function graph window.  It's opened on
		// startup by default in this test suite but we want it closed until we clear the
		// function code bytes.
		this.getFunctionGraphController().getProvider().closeComponent();

		// Set up some additional plugins we need.
		try {
			tool.addPlugin(CodeBrowserPlugin.class.getName());
			tool.addPlugin(ClearPlugin.class.getName());
		}
		catch (PluginException e) {
			e.printStackTrace();
			return;
		}
		FunctionGraphPlugin fgp = getPlugin(tool, FunctionGraphPlugin.class);
		ClearPlugin cp = getPlugin(tool, ClearPlugin.class);
		CodeBrowserPlugin cb = env.getPlugin(CodeBrowserPlugin.class);

		// Clear the entry point instruction.
		DockingActionIf clearAction;
		clearAction = getAction(cp, "Clear Code Bytes");
		cb.goToField(program.getAddressFactory().getAddress("01002cf5"), "Address", 0, 0);
		final ActionContext context = cb.getProvider().getActionContext(null);
		runSwing(() -> clearAction.actionPerformed(context));
		waitForBusyTool(tool);

		// Open the window; the tool will try to generate a new graph but should fail and generate
		// an error message.
		DockingActionIf openGraphAction;
		openGraphAction = getAction(fgp, "Display Function Graph");
		runSwing(() -> openGraphAction.actionPerformed(context));
		waitForBusyTool(tool);

		// Assert that the graph has generated the correct error message and stored it in
		// the function graph data.
		FGController controller = getFunctionGraphController();
		FGData data = controller.getFunctionGraphData();
		assertTrue(data.getMessage().contains("No instruction at function entry point"));
	}

	@Test
	public void testGroupAndUngroup_WhenOneOfTheGroupIsAGroup() {
		//
		// This test seeks to ensure that you can group a selection of vertices when one of
		// those vertices is itself a group.
		//

		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);

		group(ungroupedVertices);

		// -1 because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);
		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);

		//
		// Now group the group vertex with another vertex
		//
		Set<FGVertex> secondUngroupedVertices = selectVertices(functionGraph,
			"01002d0f" /* LAB_01002d0f */, "01002d1f" /* Grouped Vertex */);
		Set<FGEdge> secondUngroupedEdges = getEdges(graph, secondUngroupedVertices);

		group(secondUngroupedVertices);

		// 5 edges expected:
		// -ungrouped vertex: 1 in, 1 out
		// -grouped vertex  : 1 in, 2 out
		expectedGroupedEdgeCount = 5;
		GroupedFunctionGraphVertex secondGroupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, secondUngroupedVertices, expectedGroupedEdgeCount);
		assertVerticesRemoved(graph, secondUngroupedVertices);
		assertEdgesRemoved(graph, secondUngroupedEdges);

		//
		// Ungrouping the first time should restore the previous grouped vertices, including the
		// group vertex.
		//

		ungroup(secondGroupedVertex);

		assertVertexRemoved(graph, secondGroupedVertex);
		assertVerticesAdded(graph, secondUngroupedVertices);
		assertEdgesAdded(functionGraph, secondUngroupedEdges);
		assertSelected(secondUngroupedVertices);

		ungroup(groupedVertex);

		assertVertexRemoved(graph, groupedVertex);
		assertVerticesAdded(graph, ungroupedVertices);
		assertEdgesAdded(functionGraph, ungroupedEdges);
		assertSelected(ungroupedVertices);
	}

	@Test
	public void testGroupingPersistence_WhenOneOfTheGroupIsAGroup() throws Exception {
		//
		// This test seeks to ensure that groups within groups are persisted and restored.
		//

		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);

		//printEdges(ungroupedEdges);
		group(ungroupedVertices);

		// -1 because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex innerGroupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);
		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);

		AddressSetView addresses = innerGroupedVertex.getAddresses();
		Address innerMinAddress = addresses.getMinAddress();
		Address innerMaxAddress = addresses.getMaxAddress();

		//
		// Now group the group vertex with another vertex
		//
		Set<FGVertex> outerUngroupedVertices = selectVertices(functionGraph,
			"01002d0f" /* LAB_01002d0f */, "01002d1f" /* Grouped Vertex */);
		Set<FGEdge> outerUngroupedEdges = getEdges(graph, outerUngroupedVertices);

		//printEdges(outerUngroupedEdges);
		group(outerUngroupedVertices);

		// 5 edges expected:
		// -ungrouped vertex: 1 in, 1 out
		// -grouped vertex  : 1 in, 2 out
		expectedGroupedEdgeCount = 5;
		GroupedFunctionGraphVertex outerGroupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, outerUngroupedVertices, expectedGroupedEdgeCount);
		assertVerticesRemoved(graph, outerUngroupedVertices);
		assertEdgesRemoved(graph, outerUngroupedEdges);

		AddressSetView outerAddresses = outerGroupedVertex.getAddresses();
		Address secondMinAddress = outerAddresses.getMinAddress();
		Address secondMaxAddress = outerAddresses.getMaxAddress();

		graphData = triggerPersistenceAndReload("01002cf5");

		waitForAnimation();// the re-grouping may be using animation, which runs after the graph is loaded
		functionGraph = graphData.getFunctionGraph();
		graph = functionGraph;
		FGVertex vertex = functionGraph.getVertexForAddress(secondMinAddress);
		assertTrue(vertex instanceof GroupedFunctionGraphVertex);
		assertEquals(secondMaxAddress, vertex.getAddresses().getMaxAddress());
		outerGroupedVertex = (GroupedFunctionGraphVertex) vertex;

//		outerUngroupedVertices =
//			selectVertices(functionGraph, "01002d0f" /* LAB_01002d0f */, "01002d1f" /* Grouped Vertex */);
//		outerUngroupedEdges = getEdges(graph, outerUngroupedVertices);

		//printEdges(outerUngroupedEdges);
		ungroup(outerGroupedVertex);

		vertex = functionGraph.getVertexForAddress(innerMinAddress);
		assertTrue(vertex instanceof GroupedFunctionGraphVertex);
		assertEquals(innerMaxAddress, vertex.getAddresses().getMaxAddress());
		innerGroupedVertex = (GroupedFunctionGraphVertex) vertex;

		//printEdges(outerUngroupedEdges);
		assertEdgesAdded(functionGraph, outerUngroupedEdges);

		ungroup(innerGroupedVertex);

		assertEdgesAdded(functionGraph, ungroupedEdges);
	}

	@Test
	public void testRestoringWhenCodeBlocksHaveChanged_WillRegroup() {
		int transactionID = -1;
		try {
			transactionID = program.startTransaction(testName.getMethodName());
			doTestRestoringWhenCodeBlocksHaveChanged_WillRegroup();
		}
		finally {
			program.endTransaction(transactionID, false);
		}
	}

	@Test
	public void testSymbolAddedWhenGrouped_SymbolInsideOfGroupNode() {
		int transactionID = -1;
		try {
			transactionID = program.startTransaction(testName.getMethodName());
			doTestSymbolAddedWhenGrouped_SymbolInsideOfGroupNode();
		}
		finally {
			program.endTransaction(transactionID, false);
		}
	}

	@Test
	public void testUngroupAll() {
		//
		// Group some vertices and then group that vertex with some vertices to create a
		// recursively/nested grouping.  Also create a second top-level group.  Make sure the
		// ungroup all action will restore the original graph.
		//

		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
		Set<FGVertex> originalVertices = new HashSet<>(graph.getVertices());

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		group(ungroupedVertices);

		Set<FGVertex> outerUngroupedVertices = selectVertices(functionGraph,
			"01002d0f" /* LAB_01002d0f */, "01002d1f" /* Grouped Vertex */);
		group(outerUngroupedVertices);

		Set<FGVertex> secondUngroupedVertices =
			selectVertices(functionGraph, "01002d11" /* LAB_01002d11*/, "01002d06" /* 01002d06 */);
		group(secondUngroupedVertices);

		Assert.assertNotEquals(originalVertices.size(), graph.getVertices().size());

		ungroupAll();

		// don't use assertEQuals() with the different sets, as the sets may be of differing types
		// that do not correctly compare as equal
		Collection<FGVertex> vertices = graph.getVertices();
		assertEquals(originalVertices.size(), vertices.size());
		for (FGVertex originalVertex : originalVertices) {
			assertTrue("Original vertex not in ungrouped group: " + originalVertex,
				vertices.contains(originalVertex));
		}
	}

	@Test
	public void testSetUserText_WithPersistence() {
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);
		assertEquals("Did not grab all known edges for vertices", 4, ungroupedEdges.size());

		String groupVertexText = "Test Text";
		group(ungroupedVertices, groupVertexText);

		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);

		// -1 because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);
		AddressSetView addresses = groupedVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();
		Address maxAddress = addresses.getMaxAddress();

		graphData = triggerPersistenceAndReload("01002cf5");

		waitForAnimation();// the re-grouping may be using animation, which runs after the graph is loaded
		functionGraph = graphData.getFunctionGraph();
		graph = functionGraph;
		FGVertex vertex = functionGraph.getVertexForAddress(minAddress);
		assertTrue(vertex instanceof GroupedFunctionGraphVertex);
		assertEquals(maxAddress, vertex.getAddresses().getMaxAddress());

		groupedVertex = (GroupedFunctionGraphVertex) vertex;
		assertEquals("User-defined grouped vertex text was not restored after graph reload",
			groupVertexText, groupedVertex.getUserText());
	}

	@Test
	public void testGroupColoring_WithNoColorsInGroupedVertices() {
		//
		// The coloring algorithm:
		// 1) If the grouped vertices are not colored, then use the default group color
		// 2) If the grouped vertices are colored, but not all the same color,
		//    then use the default group color=
		// 3) If all grouped vertices share the same color, then make the group that color
		//
		// This test is for 1)

		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");
		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Test the group node color
		//
		verifyDefaultColor(group);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		verifyDefaultColor(v1, v2);
	}

	@Test
	public void testGroupColoring_WithMixedColorsInGroupedVertices() {
		//
		// The coloring algorithm:
		// 1) If the grouped vertices are not colored, then use the default group color
		// 2) If the grouped vertices are colored, but not all the same color,
		//    then use the default group color=
		// 3) If all grouped vertices share the same color, then make the group that color
		//
		// This test is for 2)

		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");

		// color just one of the vertices
		Color newColor = Color.RED;
		color(v1, newColor);

		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Test the group node color
		//
		verifyDefaultColor(group);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		verifyColor(v1, newColor);
		verifyDefaultColor(v2);
	}

	@Test
	public void testGroupColoring_WithUniformColorsInGroupedVertices() {
		//
		// The coloring algorithm:
		// 1) If the grouped vertices are not colored, then use the default group color
		// 2) If the grouped vertices are colored, but not all the same color,
		//    then use the default group color=
		// 3) If all grouped vertices share the same color, then make the group that color
		//
		// This test is for 3)

		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");

		// color just one of the vertices
		Color newColor = Color.RED;
		color(v1, newColor);
		color(v2, newColor);

		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Test the group node color
		//
		verifyColor(group, newColor);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		verifyColor(v1, newColor);
		verifyColor(v2, newColor);
	}

	@Test
	public void testGroupColoring_WithNoColorsInGroupedVertices_ChangeWhileGroupedChangesInternalVertices() {
		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");
		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Change the group color
		//
		Color newGroupColor = Color.CYAN;
		color(group, newGroupColor);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		verifyColor(v1, newGroupColor);
		verifyColor(v2, newGroupColor);
	}

	@Test
	public void testGroupColoring_WithMixedColorsInGroupedVertices_ChangeWhileGroupedChangesInternalVertices() {

		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");

		// color just one of the vertices
		Color newColor = Color.RED;
		color(v1, newColor);

		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Change the group color
		//
		Color newGroupColor = Color.CYAN;
		color(group, newGroupColor);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		verifyColor(v1, newGroupColor);
		verifyColor(v2, newGroupColor);
	}

	@Test
	public void testGroupColoring_WithUniformColorsInGroupedVertices_ChangeWhileGroupedChangesInternalVertices() {
		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");

		// color just one of the vertices
		Color newColor = Color.RED;
		color(v1, newColor);
		color(v2, newColor);

		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Change the group color
		//
		Color newGroupColor = Color.CYAN;
		color(group, newGroupColor);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		verifyColor(v1, newGroupColor);
		verifyColor(v2, newGroupColor);
	}

	@Test
	public void testGroupColorChangesGroupedVertexColors_AfterPeristence() {
		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");
		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Change the group color
		//
		Color newGroupColor = Color.CYAN;
		color(group, newGroupColor);

		//
		// Trigger persistence
		//
		Address groupAddress = group.getVertexAddress();
		FGData graphData = triggerPersistenceAndReload("01002cf5");

		//
		// Retrieve the group and make sure its color is restored
		//
		group = getGroupVertex(graphData.getFunctionGraph(), groupAddress);
		verifyColor(group, newGroupColor);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		v1 = vertex("01002d06");
		v2 = vertex("01002d0f");
		verifyColor(v1, newGroupColor);
		verifyColor(v2, newGroupColor);
	}

	@Test
	public void testNoGroupColorChange_GroupedVertexColorsStillDefault_AfterPeristence() {
		graphFunction("01002cf5");

		//
		// Group a node
		//
		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");
		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Trigger persistence
		//
		Address groupAddress = group.getVertexAddress();
		FGData graphData = triggerPersistenceAndReload("01002cf5");

		//
		// Retrieve the group and make sure its color is restored
		//
		group = getGroupVertex(graphData.getFunctionGraph(), groupAddress);
		verifyDefaultColor(group);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		v1 = vertex("01002d06");
		v2 = vertex("01002d0f");
		verifyDefaultColor(v1, v2);
	}

	@Test
	public void testNoGroupColorChange_GroupedVertexColorsNonDefault_AfterPeristence() {
		graphFunction("01002cf5");

		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");

		//
		// Color just one of the vertices
		//
		Color newColor = Color.RED;
		color(v1, newColor);

		//
		// Group a node
		//
		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Trigger persistence
		//
		Address groupAddress = group.getVertexAddress();
		FGData graphData = triggerPersistenceAndReload("01002cf5");

		//
		// Retrieve the group and make sure its color is restored
		//
		group = getGroupVertex(graphData.getFunctionGraph(), groupAddress);
		verifyDefaultColor(group);

		//
		// Ungroup
		//
		ungroup(group);

		//
		// Test the grouped vertices colors
		//
		v1 = vertex("01002d06");
		v2 = vertex("01002d0f");
		verifyColor(v1, newColor);
		verifyDefaultColor(v2);
	}

	@Test
	public void testNoGroupColorChange_GroupedVertexColorsNonDefault_AfterReset() {
		graphFunction("01002cf5");

		FGVertex v1 = vertex("01002d06");
		FGVertex v2 = vertex("01002d0f");

		//
		// Color just one of the vertices
		//
		Color newColor = Color.RED;
		color(v1, newColor);

		//
		// Group a node
		//
		GroupedFunctionGraphVertex group = group("A", v1, v2);

		//
		// Trigger reset
		//
		Address groupAddress = group.getVertexAddress();
		FGData graphData = reset();

		//
		// Make sure the group is gone
		//
		FGVertex vertex = graphData.getFunctionGraph().getVertexForAddress(groupAddress);
		assertFalse(vertex instanceof GroupedFunctionGraphVertex);// the group has been removed

		//
		// Test the grouped vertices colors
		//
		v1 = vertex("01002d06");
		v2 = vertex("01002d0f");
		verifyColor(v1, newColor);
		verifyDefaultColor(v2);
	}

	@Test
	public void testEdgeDefaultAlphaPersistsAfterGrouping() {

		graphFunction("01002cf5");

		FGVertex v1 = vertex("01002cf5");
		FGVertex v2 = vertex("01002d0f");

		FunctionGraph graph = getFunctionGraph();
		Iterable<FGEdge> edges = graph.getEdges(v1, v2);
		assertEquals(1, IterableUtils.size(edges));
		FGEdge edge = CollectionUtils.any(edges);

		Double alpha = edge.getAlpha();
		assertTrue(alpha < 1.0); // this is the default flow 

		GroupedFunctionGraphVertex group = group("A", v1, v2);
		ungroup(group);

		edges = graph.getEdges(v1, v2);
		assertEquals(1, IterableUtils.size(edges));
		edge = CollectionUtils.any(edges);

		Double alphAfterGroup = edge.getAlpha();
		assertEquals(alpha, alphAfterGroup);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	// @formatter:off
	@Override
	protected void doTestGroupAndUngroupVertices() {
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Set<FGVertex> ungroupedVertices = selectVertices( functionGraph,
																	"01002d2b" /* Another Local*/,
																	"01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);
		assertEquals("Did not grab all known edges for vertices", 4, ungroupedEdges.size());

		group(ungroupedVertices);

		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);

		// -1 because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex =
			validateNewGroupedVertexFromVertices(functionGraph, ungroupedVertices,
				expectedGroupedEdgeCount);

		ungroup(groupedVertex);

		assertVertexRemoved(graph, groupedVertex);
		assertVerticesAdded(graph, ungroupedVertices);
		assertEdgesAdded(functionGraph, ungroupedEdges);
		assertSelected(ungroupedVertices);

	}

	@Override
	protected void doTestRestoringWhenCodeBlocksHaveChanged_WillRegroup() {
		//
		// Tests the behavior of how group vertices are restored when one or more of the vertices
		// inside of the grouped vertex is no longer available when the graph attempts to restore
		// the group vertex user settings (i.e., when restarting Ghidra, the previously grouped
		// vertices should reappear).
		//
		// In this test, we will be mutating a group of 3 nodes such
		// that one of the nodes has been split into two.  This leaves 2 vertices to
		// be found by the regrouping algorithm.  Furthermore, the regrouping *will* still
		// take place, as at least two vertices cannot be found.
		//

		//
		// Pick a function and group some nodes.
		//
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();

		Set<FGVertex> ungroupedVertices = selectVertices(functionGraph,
			"01002d11" /* LAB_01002d11 */, "01002cf5" /* ghidra */, "01002d1f" /* MyLocal */);

		group(ungroupedVertices);

		// 5 edges expected:
		// -01002cf5: 2 out
		// -01002d11: 2 in, (1 out that was removed)
		// -01002d1f: 2 out (1 in that was removed)
		int expectedGroupedEdgeCount = 6;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		AddressSetView addresses = groupedVertex.getAddresses();
		Address minAddress = addresses.getMinAddress();
		Address maxAddress = addresses.getMaxAddress();

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
		Address labelAddress = createLabel("01002d18");// in the middle of the LAB_01002d11 code block

		//
		// Relaunch the graph, which will use the above persisted group settings...
		//
		graphData = graphFunction("01002cf5");
		waitForAnimation();// the re-grouping may be using animation, which runs after the graph is loaded
		functionGraph = graphData.getFunctionGraph();
		FGVertex expectedGroupVertex = functionGraph.getVertexForAddress(minAddress);
		assertTrue(expectedGroupVertex instanceof GroupedFunctionGraphVertex);
		assertEquals(maxAddress, expectedGroupVertex.getAddresses().getMaxAddress());

		// ...we expect that the two original grouped vertices have again been grouped...
		FGVertex splitVertex =
			functionGraph.getVertexForAddress(getAddress("01002d11") /* LAB_01002d11 */);
		assertTrue("The split vertex should not have been regrouped",
			!(splitVertex instanceof GroupedFunctionGraphVertex));

		FGVertex unchangedVertex =
			functionGraph.getVertexForAddress(getAddress("01002cf5") /* ghidra */);
		assertTrue("An unchanged vertex should have been regrouped: " + unchangedVertex,
			(unchangedVertex instanceof GroupedFunctionGraphVertex));

		unchangedVertex = functionGraph.getVertexForAddress(getAddress("01002d1f") /* MyLocal */);
		assertTrue("An unchanged vertex should have been regrouped: " + unchangedVertex,
			(unchangedVertex instanceof GroupedFunctionGraphVertex));

		// ...but the newly created code block has not
		FGVertex newlyCreatedVertex = functionGraph.getVertexForAddress(labelAddress);
		assertNotNull(newlyCreatedVertex);
	}

	@Override
	protected void doTestSymbolAddedWhenGrouped_SymbolInsideOfGroupNode() {
		//
		// By default, if the FunctionGraph detects a symbol addition to one of the code blocks
		// in the graph, then it will split the affected vertex (tested elsewhere).
		// However, if the affected vertex is grouped, then the FG will not split the node, but
		// should still show the 'stale' indicator.
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

		//
		// Add a label to trigger a code block change
		//
		Address labelAddress = createLabel("01002d18");// in the middle of the LAB_01002d11 code block

		//
		// Make sure the newly created code block does not have a corresponding vertex
		//
		FGVertex exisingVertex = functionGraph.getVertexForAddress(labelAddress);
		assertEquals("Grouped vertex does not contain the address of the newly created label",
			groupedVertex, exisingVertex);
	}
}
