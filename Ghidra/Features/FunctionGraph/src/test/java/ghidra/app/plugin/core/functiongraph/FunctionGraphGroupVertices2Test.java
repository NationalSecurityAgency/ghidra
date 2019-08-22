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

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.*;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.FGController;
import ghidra.app.plugin.core.functiongraph.mvc.FGData;
import ghidra.graph.viewer.edge.VisualGraphPathHighlighter;
import ghidra.program.model.symbol.RefType;
import util.CollectionUtils;

public class FunctionGraphGroupVertices2Test extends AbstractFunctionGraphTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		disableAnimation();
	}

	@Test
	public void testResetClearsGroups() {
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		// @formatter:off
		Set<FGVertex> ungroupedVertices = selectVertices(functionGraph, 
														 "01002d2b" /* Another Local*/, 
														 "01002d1f" /* MyLocal */);
		// @formatter:on
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);
		assertEquals("Did not grab all known edges for vertices", 4, ungroupedEdges.size());

		group(ungroupedVertices);

		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);

		// -1 because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		FGData newGraphData = reset();

		functionGraph = newGraphData.getFunctionGraph();
		graph = functionGraph;

		assertVertexRemoved(graph, groupedVertex);
		assertVerticesAdded(graph, ungroupedVertices);
		assertEdgesAdded(functionGraph, ungroupedEdges);
	}

	@Test
	public void testSnapshotGetsGroupedVertices() {

		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;

		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);
		assertEquals("Did not grab all known edges for vertices", 4, ungroupedEdges.size());

		group(ungroupedVertices);

		// (size - 1) because one one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);

		//
		// Clone the graph
		//
		FGController clonedController = cloneGraph();
		FGData clonedData = clonedController.getFunctionGraphData();
		FunctionGraph clonedFunctionGraph = clonedData.getFunctionGraph();

		FGVertex clonedVertexAtGroupAddress =
			clonedFunctionGraph.getVertexForAddress(groupedVertex.getVertexAddress());
		assertTrue(clonedVertexAtGroupAddress instanceof GroupedFunctionGraphVertex);

		GroupedFunctionGraphVertex clonedGroupVertex =
			(GroupedFunctionGraphVertex) clonedVertexAtGroupAddress;
		Set<FGVertex> clonedGroupedVertices = clonedGroupVertex.getVertices();

		// check that the original ungrouped vertices are equal to the vertices inside of
		// the group vertex inside of the cloned graph
		Object[] v1 = ungroupedVertices.toArray();
		Object[] v2 = clonedGroupedVertices.toArray();
		assertArraysEqualUnordered("The grouped vertices are not the same in the cloned graph", v1,
			v2);

		Set<FGEdge> clonedUngroupedEdges = new HashSet<>();
		clonedUngroupedEdges.addAll(clonedGroupVertex.getUngroupedEdges());
		assertFalse("Cloned vertex does not have any edges", clonedUngroupedEdges.isEmpty());

		ungroup(clonedGroupVertex);

		Graph<FGVertex, FGEdge> clonedGraph = clonedFunctionGraph;
		assertVertexRemoved(clonedGraph, clonedGroupVertex);
		assertVerticesAdded(clonedGraph, clonedGroupedVertices);
		assertEdgesAdded(clonedFunctionGraph, clonedUngroupedEdges);
	}

	@Test
	public void testRedoUncollapsedVertices() {
		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex groupA = group("A", v1, v2);

		uncollapse(groupA);

		assertUncollapsed(v1, v2);

		regroup(v1);

		assertGrouped(v1, v2);
	}

	@Test
	public void testRedoActionRemovedWhenVertexAddedToNewGroup() {
		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");
		FGVertex v3 = vertex("1004192");

		GroupedFunctionGraphVertex groupA = group("A", v1, v2, v3);

		uncollapse(groupA);

		assertUncollapsed(v1, v2, v3);

		// new groupB with v3, which will remove it from groupA
		FGVertex v4 = vertex("1004196");
		group("B", v3, v4);

		assertNotUncollapsed(v1, v2);
	}

	@Test
	public void testRedoUncollapsedVertexFromASubgroupVertex() {
		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");

		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);

		assertUncollapsed(innerGroup, v3, v4);
		assertVerticesRemoved(outerGroup);

		regroup(innerGroup);

		assertNotUncollapsed(innerGroup);
	}

	@Test
	public void testUncollapsedGroupRemovalOfOneVertex() {
		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex groupA = group("A", v1, v2);

		uncollapse(groupA);

		assertUncollapsed(v1, v2);

		removeFromUncollapsedGroup(v1);

		assertNotUncollapsed(v1);
	}

	@Test
	public void testUncollapsedGroupRemovalWithUncollapsedNestedGroupWithMixedSelection() {
		//
		// This odd beast is meant to test the condition where we 
		// -Create a group A
		// -Create a group B from A and other vertices
		// -Uncollapse all groups
		// -Select A's vertices and one from B
		// -Execute the 'Remove from Group' action
		// -No exceptions should take place
		//
		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");

		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);
		uncollapse(innerGroup);
		assertUncollapsed(v1, v2, v3, v4);

		removeFromUncollapsedGroup(v1, v2, v3);

		assertNotUncollapsed(v1, v2);
	}

	@Test
	public void testRemovingLastGroupMemberClearsHistory() {
		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");
		GroupedFunctionGraphVertex groupA = group("A", v1, v2);

		uncollapse(groupA);
		assertUncollapsed(v1, v2);

		removeFromUncollapsedGroup(v1, v2);
		assertNotUncollapsed(v1, v2);

		FunctionGraph functionGraph = getFunctionGraph();
		assertNull(functionGraph.getGroupHistory(v1));
		assertNull(functionGraph.getGroupHistory(v2));
	}

	@Test
	public void testRedoUncollapsedGroupWithInnerUncollapsedGroup() {
		//
		// Special case:  
		// 1) Create a group "Inner Group"
		// 2) Create a second Group "Outer Group", which contains Group A
		// 3) Ungroup B
		// 4) Ungroup A
		// 5) Regroup from a vertex that was in B
		//

		//
		// This test has two main objectives: 
		// 1) Make sure you can uncollapse an internal group and then regroup,
		//
		// 2) Make sure the state of the outer group's internal vertices remain however they 
		//    were the last time they were regrouped.  To do this:
		//
		// 		A) Make sure that, after step 1), you can then uncollapse the outer group and the
		//    		inner vertices will be in the same previously uncollapsed state,
		// 		B) Regroup the inner group, regroup the outer group, uncollapse the outer group and 
		//    		the inner vertices should still be grouped.
		//

		//
		// 1) 
		//

		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");

		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);
		uncollapse(innerGroup);
		assertUncollapsed(v1, v2, v3, v4);
		assertVerticesRemoved(innerGroup, outerGroup);

		regroup(v4);
		assertVerticesRemoved(v1, v2, v3, v4);

		// 
		// 2) A)
		//
		uncollapse(outerGroup);
		assertUncollapsed(v1, v2, v3, v4);// this was the previous state

		// 
		// 2) B)
		//
		regroup(v1);
		assertVerticesRemoved(v1, v2);

		regroup(v4);
		assertVerticesRemoved(v1, v2, v3, v4);

		uncollapse(outerGroup);
		assertVerticesRemoved(v1, v2);// this was the previous state
		assertUncollapsed(v3, v4, innerGroup);
	}

	@Test
	public void testRedoUncollapsedGroupWithInnerUncollapsedGroupAfterMovingNestedVertexToNewGroup() {
		//
		// Tests the scenario where uncollapsed, nested groups have their structure altered and 
		// how the parent group is regrouped afterwards.
		//
		// Nested, uncollapsed groups that have children put into new groups are disbanded.  We
		// want to make sure that any parents of the disbanded group are updated.
		//
		// Basic Steps:
		// -Create a nested group situation
		// -Uncollapse the outer group
		// -Uncollapse the inner group
		// -Regroup a member of inner group
		// -Regroup the outer group
		// 

		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");

		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);

		uncollapse(innerGroup);

		group("New Group", v1);// v1 was inside of 
		assertNotUncollapsed(v2);// no longer in group with v1

		// these two vertices were in the "Outer Group", but that was disbanded, due to the 
		// regrouping of v2
		assertNotUncollapsed(v3, v4);
	}

	@Test
	public void testRedoUncollapsedGroupWithInnerUncollapsedGroupAfterRemovingNestedVertex() {
		//
		// Tests that we can remove a vertex from a nested group and that when the outer group
		// is regrouped the removed vertex will not be put back into any group.
		//
		// Basic Steps:
		// -Create a nested group situation
		// -Uncollapse the outer group
		// -Uncollapse the inner group
		// -Regroup a member of outer group
		// -Verify removed vertex is not grouped

		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");

		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);

		uncollapse(innerGroup);

		removeFromUncollapsedGroup(v1);
		assertNotUncollapsed(v1);
		assertUncollapsed(v2);// still collapsed after removal

		regroup(v4);

		assertNotGrouped(v1);
		assertInGroup(v2, v3, v4);
	}

	@Test
	public void testFindForwardScopedFlowWhenGroupRemovesSourceNode() {

		//
		// Test the case that grouping the entry node will create a group that has incoming 
		// edges.  In this case, there is no source node in the graph.  This will cause an 
		// exception if the code does not create a fake source node before passing the graph
		// the the algorithm for calculating dominance.
		//

		create12345GraphWithTransaction();

		FGVertex entry = vertex("100415a");
		FGVertex v2 = vertex("1004178");
		FGVertex v3 = vertex("1004192");

		FunctionGraph graph = getFunctionGraph();
		FGEdgeImpl edge = new FGEdgeImpl(v3, v2, RefType.UNCONDITIONAL_JUMP, graph.getOptions());
		graph.addEdge(edge);

		FGComponent graphComponent = getGraphComponent();
		VisualGraphPathHighlighter<FGVertex, FGEdge> pathHighlighter =
			graphComponent.getPathHighlighter();
		pathHighlighter.setHoveredVertex(entry);
		waitForPathHighligter();

		Collection<FGEdge> edges = graph.getEdges();
		assertHovered(edges);

		pathHighlighter.setHoveredVertex(null);
		assertHovered(Collections.emptySet());

		GroupedFunctionGraphVertex group = group("Entry in Group", entry, v2);

		pathHighlighter.setHoveredVertex(group);
		waitForPathHighligter();
		assertHovered(edges);
	}

	@Test
	public void testFindForwardScopedFlow_WithoutGroup_IncomingEdgeToRoot() {

		//
		// Test the case that an ungrouped graph does not throw an exception if the root node
		// is hovered when it has incoming edges.
		//

		create12345GraphWithTransaction();

		FGVertex entry = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		FunctionGraph graph = getFunctionGraph();
		FGEdgeImpl edge = new FGEdgeImpl(v2, entry, RefType.UNCONDITIONAL_JUMP, graph.getOptions());
		graph.addEdge(edge);

		FGComponent graphComponent = getGraphComponent();
		VisualGraphPathHighlighter<FGVertex, FGEdge> pathHighlighter =
			graphComponent.getPathHighlighter();
		pathHighlighter.setHoveredVertex(entry);
		waitForPathHighligter();

		Collection<FGEdge> edges = graph.getEdges();
		assertHovered(edges);

		pathHighlighter.setHoveredVertex(null);
		assertHovered(Collections.emptySet());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertHovered(Collection<FGEdge> edges) {

		FunctionGraph graph = getFunctionGraph();
		Set<FGEdge> nonHoveredEdges = new HashSet<>(graph.getEdges());
		Set<FGEdge> expectedEdges = CollectionUtils.asSet(edges);
		nonHoveredEdges.removeAll(expectedEdges);

		for (FGEdge e : expectedEdges) {
			boolean isHovered = swing(() -> e.isInHoveredVertexPath());
			assertTrue("Edge was not hovered: " + e, isHovered);
		}

		for (FGEdge e : nonHoveredEdges) {
			boolean isHovered = swing(() -> e.isInHoveredVertexPath());
			assertFalse("Edge hovered when it should not have been: " + e, isHovered);
		}
	}

	private void waitForPathHighligter() {
		waitForSwing();
		FGComponent graphComponent = getGraphComponent();
		VisualGraphPathHighlighter<FGVertex, FGEdge> highlighter =
			graphComponent.getPathHighlighter();
		waitForCondition(() -> !highlighter.isBusy(), "Timed-out waiting for Path Highlighter");
		// waitForAnimation(); don't need to do this, as the edges are hovered while animating
		waitForSwing();
	}

}
