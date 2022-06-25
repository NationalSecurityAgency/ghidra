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

import java.util.Collection;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import edu.uci.ics.jung.graph.Graph;
import ghidra.app.plugin.core.functiongraph.graph.FGEdge;
import ghidra.app.plugin.core.functiongraph.graph.FunctionGraph;
import ghidra.app.plugin.core.functiongraph.graph.vertex.FGVertex;
import ghidra.app.plugin.core.functiongraph.graph.vertex.GroupedFunctionGraphVertex;
import ghidra.app.plugin.core.functiongraph.mvc.*;
import ghidra.graph.viewer.options.RelayoutOption;

public class FunctionGraphGroupVertices3Test extends AbstractFunctionGraphTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		disableAnimation();
	}

	@Test
	public void testAddingToGroup() {
		doTestAddingToGroup();
	}

	@Test
	public void testAddingToGroupWithAutomaticRelayoutOff() {
		FGController controller = getFunctionGraphController();
		FunctionGraphOptions options = controller.getFunctionGraphOptions();
		setInstanceField("relayoutOption", options, RelayoutOption.NEVER);

		doTestAddingToGroup();
	}

	@Test
	public void testForMissingEdgesWhenAddingToGroupBug() {
		//
		// Found a condition in a particular function when adding to a group node triggered the
		// loss of an edge.
		//
		graphFunction("0100415a");

		FGVertex v1 = vertex("0100415a");
		FGVertex v2 = vertex("01004178");
		FGVertex v3 = vertex("01004192");
		FGVertex v4 = vertex("01004196");
		FGVertex v5 = vertex("0100419c");

		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v1, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);

		GroupedFunctionGraphVertex group = group("A", v1, v2);

		verifyEdge(group, v3);
		verifyEdge(group, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);

		group = addToGroup(group, v3);

		verifyEdge(group, v4);
		verifyEdge(group, v5);

		ungroupAll();

		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v1, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);
	}

	@Test
	public void testGroupingProperlyTranslatesEdgesFromGroupedVerticesToRealVertices() {
		int transactionID = -1;
		try {
			transactionID = program.startTransaction(testName.getMethodName());
			doTestGroupingProperlyTranslatesEdgesFromGroupedVerticesToRealVertices();
		}
		finally {
			program.endTransaction(transactionID, true);
		}
	}

	@Test
	public void testGroupHistoryPersistence() {

		String functionAddress = "01002cf5";
		graphFunction(functionAddress);

		String a1 = "1002d11";
		String a2 = "1002d06";

		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);
		GroupedFunctionGraphVertex groupA = group("A", v1, v2);
		uncollapse(groupA);
		assertUncollapsed(v1, v2);

		triggerPersistenceAndReload(functionAddress);
		waitForBusyGraph();// the re-grouping may be using animation, which runs after the graph is loaded

		v1 = vertex(a1);
		v2 = vertex(a2);
		assertUncollapsed(v1, v2);// group history restored

		// make sure it still works correctly
		regroup(v1);
		assertNotUncollapsed(v1, v2);
	}

	@Test
	public void testGroupHistoryPersistenceWithOtherGroup() {
		//
		// Tests that we persist history correctly when there is also a group persisted.
		//
		String functionAddress = "01002cf5";
		graphFunction(functionAddress);

		String a1 = "1002d11";
		String a2 = "1002d06";

		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);
		GroupedFunctionGraphVertex groupA = group("A", v1, v2);
		uncollapse(groupA);
		assertUncollapsed(v1, v2);

		// new group
		String a3 = "1002d1f";
		String a4 = "1002d66";
		FGVertex v3 = vertex(a3);
		FGVertex v4 = vertex(a4);

		group("B", v3, v4);

		assertUncollapsed(v1, v2);// sanity check--still uncollapsed

		triggerPersistenceAndReload(functionAddress);
		waitForBusyGraph();// the re-grouping may be using animation, which runs after the graph is loaded

		v1 = vertex(a1);
		v2 = vertex(a2);
		assertUncollapsed(v1, v2);// group history restored
		assertGrouped(v3, v4);// group restored
	}

	@Test
	public void testGroupHistoryPersistenceWithSubGroup() {
		//
		// Tests that we persist history correctly when there a group in the uncollapsed set.
		//
		String functionAddress = "01002cf5";
		graphFunction(functionAddress);

		String a1 = "1002d11";
		String a2 = "1002d06";

		FGVertex v1 = vertex(a1);
		FGVertex v2 = vertex(a2);
		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		// new group
		String a3 = "1002d1f";
		String a4 = "1002d66";
		FGVertex v3 = vertex(a3);
		FGVertex v4 = vertex(a4);
		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);
		assertUncollapsed(innerGroup, v3, v4);

		triggerPersistenceAndReload(functionAddress);
		waitForBusyGraph();// the re-grouping may be using animation, which runs after the graph is loaded

		v1 = vertex(a1);
		v2 = vertex(a2);
		assertTrue(v1 instanceof GroupedFunctionGraphVertex);
		assertTrue(v2 instanceof GroupedFunctionGraphVertex);

		v3 = vertex(a3);
		v4 = vertex(a4);

		assertUncollapsed(v3, v4);// group history restored

		// v1 and v2 should both be represented by a group
		innerGroup = (GroupedFunctionGraphVertex) v1;
		assertUncollapsed(innerGroup);
	}

	@Test
	public void testHistoryUpdatesWhenGroupUserTextChanges() {
		//
		// The group history can hang around for a while, which means that the history's 
		// description can be out-of-sync with the current state of the group unless we update it.
		// This method tests that we correctly update the history.
		//
		// Basic Steps:
		// -Create a nested group situation
		// -Uncollapse the outer group
		// -Change the text of the inner group
		// -Uncollapse the inner group
		// -Regroup the inner group
		// -Make sure the text is the last set text
		//

		create12345GraphWithTransaction();

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");

		GroupedFunctionGraphVertex innerGroup = group("Inner Group", v1, v2);

		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");

		GroupedFunctionGraphVertex outerGroup = group("Outer Group", innerGroup, v3, v4);

		uncollapse(outerGroup);

		// ungroup and regroup (this creates a history entry)
		uncollapse(innerGroup);
		regroup(v1);// regroup the inner group

		// change the text
		String newText = "New Inner Group Text";
		setGroupText(innerGroup, newText);

		// ungroup and regroup (make sure the history entry is not stale)
		uncollapse(innerGroup);
		regroup(v1);// regroup the inner group

		assertGroupText(innerGroup, newText);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	protected void doTestAddingToGroup() {
		FGData graphData = graphFunction("01002cf5");
		FunctionGraph functionGraph = graphData.getFunctionGraph();
		Graph<FGVertex, FGEdge> graph = functionGraph;
	
		Collection<FGEdge> originalEdges = graph.getEdges();
	
		Set<FGVertex> ungroupedVertices =
			selectVertices(functionGraph, "01002d2b" /* Another Local*/, "01002d1f" /* MyLocal */);
		Set<FGEdge> ungroupedEdges = getEdges(graph, ungroupedVertices);
		assertEquals("Did not grab all known edges for vertices", 4, ungroupedEdges.size());
	
		group(ungroupedVertices);
	
		assertVerticesRemoved(graph, ungroupedVertices);
		assertEdgesRemoved(graph, ungroupedEdges);
	
		// -1 because one of the edges was between two of the vertices being grouped
		int expectedGroupedEdgeCount = ungroupedEdges.size() - 1;
		GroupedFunctionGraphVertex groupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);
	
		//
		// Pick another vertex to add to the current group
		//
		Set<FGVertex> newUngroupedVertices =
			selectVertices(functionGraph, "01002d66" /* LAB_01002d66 */);
		Set<FGEdge> newUngroupedEdges = getEdges(graph, newUngroupedVertices);
	
		addToGroup(groupedVertex, newUngroupedVertices);
	
		assertVerticesRemoved(graph, newUngroupedVertices);
		assertEdgesRemoved(graph, newUngroupedEdges);
	
		expectedGroupedEdgeCount = 3;
		GroupedFunctionGraphVertex updatedGroupedVertex = validateNewGroupedVertexFromVertices(
			functionGraph, ungroupedVertices, expectedGroupedEdgeCount);
		assertNotEquals(groupedVertex, updatedGroupedVertex);
		Set<FGVertex> originalVertices = groupedVertex.getVertices();
		Set<FGVertex> newVertices = updatedGroupedVertex.getVertices();
		assertTrue(newVertices.containsAll(originalVertices));
	
		//
		//  Ungroup and make sure all edges and vertices return
		//
	
		ungroup(updatedGroupedVertex);
	
		assertVertexRemoved(graph, updatedGroupedVertex);
	
		assertVerticesAdded(graph, ungroupedVertices);
		assertEdgesAdded(functionGraph, originalEdges);
	
		ungroupedVertices.addAll(newUngroupedVertices);
		assertSelected(ungroupedVertices);
	}

	protected void doTestGroupingProperlyTranslatesEdgesFromGroupedVerticesToRealVertices() {
		//
		//	WARNING!!!  WARNING!!!  WARNING!!!  WARNING!!!  WARNING!!!  WARNING!!!  
		// This is not a junit test in that it is long, involved, hidden and complicated.  We 
		// need to test this functionality, but we don't have a jComplicatedTest, so we will do
		// it here.
		//

		//
		// Desired Behavior: We want to be able to group vertices, group grouped vertices and then
		//                   ungroup them in any order.  For us to be able to do this, our group
		//                   vertices must store enough edge information to be able to ungroup 
		//                   and find vertices for edges *whether or now those vertices have been
		//                   grouped or ungrouped*
		// 
		// Original Bug: We had a bug loosely described here: 
		// 0) Start with a directed graph of vertices.
		// 1) Create two separate group vertices (A and B), such that A has an edge to B.
		// 2) Create a third group vertex (Z) that contains a non-grouped vertex (B) *and* one 
		//    of the other groups.
		// 3) Now, ungroup the 1 remaining originally grouped vertex (A).
		// 4) **At this point, the code could not determine which endpoint to pick for the edge 
		//      that used to be from Z->A.  Which vertex inside of A represented the connection
		//      pointing into Z (by way of B).
		// 
		// The fix is mentioned in the Desired Behavior section.  
		//

		/*
		 
		 0) Initial Graph
		 
		 1 -> 2 -> 3 -> 4
		           |
		           *
		           5
		           
		*/

		create12345Graph();

		//
		// Our graph maps from number to address like so:
		//

		FGVertex v1 = vertex("100415a");
		FGVertex v2 = vertex("1004178");
		FGVertex v3 = vertex("1004192");
		FGVertex v4 = vertex("1004196");
		FGVertex v5 = vertex("100419c");

		// verify initial graph 
		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);
		verifyEdgeCount(4);

		/*
		 1) Create two separate group vertices (A and B), such that A has an edge to B.
		            
		 A (v:{1,2} e:{1->2, 2->3}) -> B (v:{3,4} e:{2->3,3->4,3->5})
		                               |
		                               *
		                               5
		                               		 
		 */

		GroupedFunctionGraphVertex groupA = group("A", v1, v2);
		GroupedFunctionGraphVertex groupB = group("B", v3, v4);

		verifyEdge(groupA, groupB);
		verifyEdge(groupB, v5);
		verifyEdgeCount(2);// no other edges

		/*
		 2) Create a third group vertex (Z) that contains a non-grouped vertex *and* one 
		    of the other groups (B).
		    
		 A (v:{1,2} e:{1->2, 2->3}) -> Z (
		 									v:{B (v:{3,4} e:{2->3,3->4,3->5}), 5}
		 									e:{2->3, 3->5}
		 								  )          
		
		*/

		GroupedFunctionGraphVertex groupZ = group("Z", groupB, v5);

		verifyEdge(groupA, groupZ);
		verifyEdgeCount(1);

		/*
		 3) Now, ungroup the 1 remaining originally grouped vertex (A).
		 
		 1 -> 2 -> Z (
						v:{B (v:{3,4} e:{2->3,3->4,3->5}), 5}
						e:{2->3, 3->5}
					  )   
		 
		 */

		ungroup(groupA);

		verifyEdge(v1, v2);
		verifyEdge(v2, groupZ);
		verifyEdgeCount(2);

		/*
		 
		 4) Now, ungroup Z and go back to having one remaining group vertex (B)
		 
		 1 -> 2 -> -> B (v:{3,4} e:{2->3,3->4,3->5})
		              |
		              *
		              5
		            		  
		*/

		ungroup(groupZ);

		verifyEdge(v1, v2);
		verifyEdge(v2, groupB);
		verifyEdge(groupB, v5);
		verifyEdgeCount(3);

		/*
		 5) Finally, ungroup the last group and make sure the graph is restored
		              
		 1 -> 2 -> 3 -> 4
		           |
		           *
		           5		
		  
		 */

		ungroup(groupB);

		verifyEdge(v1, v2);
		verifyEdge(v2, v3);
		verifyEdge(v3, v4);
		verifyEdge(v3, v5);
		verifyEdgeCount(4);

	}
}
