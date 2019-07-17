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
package ghidra.graph.graphs;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static util.CollectionUtils.asList;

import java.util.Collection;

import org.junit.Before;
import org.junit.Test;

import edu.uci.ics.jung.graph.util.EdgeType;
import edu.uci.ics.jung.graph.util.Pair;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import util.CollectionUtils;

public class FilteredVisualGraphTest extends AbstractFilteringVisualGraphTest {

	@Before
	public void setUp() {

		graph = new FilteringVisualGraph<AbstractTestVertex, TestEdge>() {

			@Override
			public VisualGraphLayout<AbstractTestVertex, TestEdge> getLayout() {
				// we don't need these for this test
				return null;
			}

			@Override
			public DefaultVisualGraph<AbstractTestVertex, TestEdge> copy() {
				// we don't need these for this test
				return null;
			}
		};

		/*

		 		v1
		 		 |
		 		v2
		 		/\
		 	  v3  v4
		 	   \  /
		 	    v5
		 	    |
		 	    v6
		 	    |
		 	    v7

		 */

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v3 = vertex("3");
		AbstractTestVertex v4 = vertex("4");
		AbstractTestVertex v5 = vertex("5");
		AbstractTestVertex v6 = vertex("6");
		AbstractTestVertex v7 = vertex("7");
		TestEdge e12 = edge(v1, v2);
		TestEdge e23 = edge(v2, v3);
		TestEdge e24 = edge(v2, v4);
		TestEdge e35 = edge(v3, v5);
		TestEdge e45 = edge(v4, v5);
		TestEdge e56 = edge(v5, v6);
		TestEdge e67 = edge(v6, v7);

		// sanity check
		assertTrue(graph.containsEdge(e12));
		assertTrue(graph.containsEdge(e23));
		assertTrue(graph.containsEdge(e24));
		assertTrue(graph.containsEdge(e35));
		assertTrue(graph.containsEdge(e45));
		assertTrue(graph.containsEdge(e56));
		assertTrue(graph.containsEdge(e67));
	}

	@Test
	public void testFilterVertex() {

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		TestEdge e = edge(v1, v2);

		graph.filterVertices(CollectionUtils.asList(v1));

		//
		// Ensure that the vertex and it's edge are no longer in the graph; all others remain
		//
		assertFiltered(v1);
		assertFiltered(e);
	}

	@Test
	public void testFilterVertexMaintainsRemovedContent() {

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		TestEdge e = edge(v1, v2);
		graph.filterVertices(asList(v1));

		assertFiltered(v1);
		assertFiltered(e);
	}

	@Test
	public void testClearFilter() {

		AbstractTestVertex v1 = vertex("1");
		graph.filterVertices(asList(v1));

		assertFiltered(v1);

		graph.clearFilter();

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
	}

	@Test
	public void testFilterEdge() {

		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v3 = vertex("3");
		TestEdge e = edge(v2, v3);

		graph.filterEdges(CollectionUtils.asList(e));

		assertNoVerticesFiltered();
		assertFiltered(e);
	}

	@Test
	public void testFilterEdgeMaintainsRemovedContent() {

		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v3 = vertex("3");
		TestEdge e = edge(v2, v3);
		graph.filterEdges(CollectionUtils.asList(e));

		assertFiltered(e);
	}

	@Test
	public void testRemoveVertexUpdatesFilterCache() {
		//
		// Test that removing a vertex from the graph will update any vertex that has been
		// filtered.
		//

		AbstractTestVertex v1 = vertex("1");
		graph.filterVertices(asList(v1));

		graph.removeVertex(v1);

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
		assertNotInGraph(v1);
	}

	@Test
	public void testRemoveEdgeUpdatesFilterCache() {
		//
		// Test that removing a vertex from the graph will update any vertex that has been
		// filtered.
		//

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		TestEdge e12 = edge(v1, v2);

		graph.filterVertices(asList(v1));

		graph.removeEdge(e12);

		assertFiltered(v1);
		assertNoEdgesFiltered();
		assertNotInGraph(e12);
	}

	@Test
	public void testRemoveUnrelatedVertexDoesNotUpdateFilterCache() {
		//
		// Test that removing a vertex from the graph will update any vertex that has been
		// filtered.
		//

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v4 = vertex("4");
		TestEdge e = edge(v1, v2);
		graph.filterVertices(asList(v1));

		graph.removeVertex(v4);

		assertFiltered(v1);
		assertFiltered(e);
		assertNotInGraph(v4);
	}

	@Test
	public void testRemoveUnrelatedEdgeDoesNotUpdateFilterCache() {
		//
		// Test that removing a vertex from the graph will update any vertex that has been
		// filtered.
		//

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v4 = vertex("4");
		TestEdge e12 = edge(v1, v2);
		TestEdge e24 = edge(v2, v4);
		graph.filterVertices(asList(v1));

		graph.removeEdge(e24);

		assertFiltered(v1);
		assertFiltered(e12);
		assertNotInGraph(e24);
	}

	@Test
	public void testRemoveVerticesUpdatesFilterCache_RemoveFilteredVertex() {

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v3 = vertex("3");
		AbstractTestVertex v4 = vertex("4");
		TestEdge e12 = edge(v1, v2);
		TestEdge e23 = edge(v2, v3);
		TestEdge e24 = edge(v2, v4);

		graph.filterVertices(asList(v1, v2));

		assertFiltered(v1, v2);
		assertFiltered(e12, e23, e24);

		graph.removeVertices(asList(v1));

		assertFiltered(v2);
		assertFiltered(e23, e24);
		assertNotInGraph(v1);
		assertNotInGraph(e12);
	}

	@Test
	public void testRemoveEdgesUpdatesFilterCache_RemoveFilteredEdges() {

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v3 = vertex("3");
		AbstractTestVertex v4 = vertex("4");
		TestEdge e12 = edge(v1, v2);
		TestEdge e23 = edge(v2, v3);
		TestEdge e24 = edge(v2, v4);

		graph.filterVertices(asList(v1, v2));

		assertFiltered(v1, v2);
		assertFiltered(e12, e23, e24);

		graph.removeEdge(e12);

		assertFiltered(v1, v2);
		assertFiltered(e23, e24);
		assertNotInGraph(e12);
	}

	@Test
	public void testRemoveVerticesUpdatesFilterCache_RemoveNonFilteredVertex() {

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		AbstractTestVertex v3 = vertex("3");
		AbstractTestVertex v4 = vertex("4");
		TestEdge e12 = edge(v1, v2);
		TestEdge e23 = edge(v2, v3);
		TestEdge e24 = edge(v2, v4);

		graph.filterVertices(asList(v1, v2));

		assertFiltered(v1, v2);
		assertFiltered(e12, e23, e24);

		graph.removeVertices(asList(v3));

		assertFiltered(v1, v2);
		assertFiltered(e12, e24);
		assertNotInGraph(v3);
	}

	@Test
	public void testRestoreVertices_DoesNotAddForeignVerticesOrEdges_WhileNotFiltered() {

		AbstractTestVertex v100 = new LabelTestVertex("100");

		graph.unfilterVertices(asList(v100));

		assertNotInGraph(v100);
		assertFalse(graph.isFiltered());
	}

	@Test
	public void testRestoreVertices_DoesNotAddForeignVerticesOrEdges_WhileFiltered() {

		AbstractTestVertex v1 = vertex("1");
		graph.filterVertices(asList(v1));

		AbstractTestVertex v100 = new LabelTestVertex("100");
		graph.unfilterVertices(asList(v100));

		assertNotInGraph(v100);
		assertFiltered(v1);
		assertFiltered(edge(v1, vertex("2")));
		assertTrue(graph.isFiltered());
	}

	@Test
	public void testRestoreEdges_DoesNotAddForeignVerticesOrEdges_WhileNotFiltered() {

		AbstractTestVertex v100 = new LabelTestVertex("100");
		AbstractTestVertex v101 = new LabelTestVertex("101");
		TestEdge e = new TestEdge(v100, v101);

		graph.unfilterEdges(asList(e));

		assertNotInGraph(v100, v101);
		assertNotInGraph(e);
		assertFalse(graph.isFiltered());
	}

	@Test
	public void testRestoreEdges_DoesNotAddForeignVerticesOrEdges_WhileFiltered() {

		AbstractTestVertex v1 = vertex("1");
		graph.filterVertices(asList(v1));

		AbstractTestVertex v100 = new LabelTestVertex("100");
		AbstractTestVertex v101 = new LabelTestVertex("101");
		TestEdge e = new TestEdge(v100, v101);

		graph.unfilterEdges(asList(e));

		assertFiltered(v1);
		assertFiltered(edge(v1, vertex("2")));
		assertNotInGraph(v100, v101);
		assertNotInGraph(e);
		assertTrue(graph.isFiltered());
	}

	// TODO testRemoveVertexUpdatesFilter
	// TODO testRemoveEdgeUpdatesFilter

	// TODO test edge cache updated on remove

	// TODO testUnfilterVertex()
	// -restores/moves edges that cannot be put back

	// TODO test adding vertex does not update graph, but updates filter cache
	// TODO test adding edge does not update graph, but updates filter cache

	@Test
	public void testUnfilterEdge() {

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		TestEdge e = edge(v1, v2);

		graph.filterEdges(asList(e));

		assertNoVerticesFiltered();
		assertFiltered(e);

		graph.unfilterEdges(asList(e));

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
	}

	@Test
	public void testUnfilterEdge_DoesNotWorkIfVertexHasBeenFiltered() {

		AbstractTestVertex v1 = vertex("1");
		AbstractTestVertex v2 = vertex("2");
		TestEdge e = edge(v1, v2);

		graph.filterVertices(asList(v1));

		assertFiltered(v1);
		assertFiltered(e);

		graph.unfilterEdges(asList(e));

		// no change
		assertFiltered(v1);
		assertFiltered(e);
	}

	@Test
	public void testUnfilterEdge_DoesNotWorkIfOnlyOneVertexHasBeenRestored() {

		// see setUp() for how the graph is constructed
		AbstractTestVertex v5 = vertex("5");
		AbstractTestVertex v6 = vertex("6");
		AbstractTestVertex v7 = vertex("7");
		TestEdge e56 = edge(v5, v6);
		TestEdge e67 = edge(v6, v7);

		graph.filterVertices(asList(v6, v7));

		// any edges connected to 6 and 7 will also get filtered
		assertFiltered(v6, v7);
		assertFiltered(e56, e67);

		graph.unfilterVertices(asList(v6));

		// when we restored v6, the v5->v6 edge should have been restored
		assertFiltered(v7);
		assertFiltered(e67);

		graph.unfilterEdges(asList(e67));

		// no change--the edge cannot be restored because one of its vertices is not in the graph
		assertFiltered(v7);
		assertFiltered(e67);
	}

	@Test
	public void testUnfilterVertices_EdgeIsRestored() {

		// see setUp() for how the graph is constructed
		AbstractTestVertex v5 = vertex("5");
		AbstractTestVertex v6 = vertex("6");
		AbstractTestVertex v7 = vertex("7");
		TestEdge e56 = edge(v5, v6);
		TestEdge e67 = edge(v6, v7);

		graph.filterVertices(asList(v6, v7));

		// any edges connected to 6 and 7 will also get filtered
		assertFiltered(v6, v7);
		assertFiltered(e56, e67);

		graph.unfilterVertices(asList(v6));

		assertFiltered(v7);
		assertFiltered(e67);

		graph.unfilterVertices(asList(v7));

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
	}

	@Test
	public void testDispose_Unfiltered() {

		graph.dispose();

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
		assertTrue(graph.getVertices().isEmpty());
		assertTrue(graph.getEdges().isEmpty());
	}

	@Test
	public void testDispose_Filtered() {

		AbstractTestVertex v1 = vertex("1");

		graph.filterVertices(asList(v1));

		graph.dispose();

		assertNoVerticesFiltered();
		assertNoEdgesFiltered();
		assertTrue(graph.getVertices().isEmpty());
		assertTrue(graph.getEdges().isEmpty());
	}

	@Test
	public void testAddEdge_WhileUnfiltered() {

		doTestAddEdge_WhenUnfiltered((e, v1, v2) -> graph.addEdge(e));
	}

	@Test
	public void testAddEdge_WhileFiltered() {

		doTestAddEdge_WhenFiltered((e, v1, v2) -> graph.addEdge(e));
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Collection_WhenUnfiltered() {

		doTestAddEdge_WhenUnfiltered((e, v1, v2) -> {

			Collection<AbstractTestVertex> vertices = asList(v1, v2);
			graph.addEdge(e, vertices);
		});
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Collection_WhenFiltered() {

		doTestAddEdge_WhenFiltered((e, v1, v2) -> {

			Collection<AbstractTestVertex> vertices = asList(v1, v2);
			graph.addEdge(e, vertices);
		});
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Collection_Type_WhenUnfiltered() {

		doTestAddEdge_WhenUnfiltered((e, v1, v2) -> {

			Collection<AbstractTestVertex> vertices = asList(v1, v2);
			graph.addEdge(e, vertices, EdgeType.DIRECTED);
		});
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Collection_Type_WhenFiltered() {

		doTestAddEdge_WhenFiltered((e, v1, v2) -> {

			Collection<AbstractTestVertex> vertices = asList(v1, v2);
			graph.addEdge(e, vertices, EdgeType.DIRECTED);
		});
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Vertex_Vertex_WhenUnfiltered() {

		doTestAddEdge_WhenUnfiltered((e, v1, v2) -> graph.addEdge(e, v1, v2));
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Vertex_Vertex_WhenFiltered() {

		doTestAddEdge_WhenFiltered((e, v1, v2) -> graph.addEdge(e, v1, v2));
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Pair_WhenUnfiltered() {

		doTestAddEdge_WhenUnfiltered((e, v1, v2) -> graph.addEdge(e, new Pair<>(v1, v2)));
	}

	@Test
	public void testAddEdge_Overloaded_Edge_Pair_WhenFiltered() {

		doTestAddEdge_WhenFiltered((e, v1, v2) -> graph.addEdge(e, new Pair<>(v1, v2)));
	}
//==================================================================================================
// Private Methods
//==================================================================================================

	// 'addEdgeFunction' is one of the various 'addEdge' functions on graph
	private void doTestAddEdge_WhenUnfiltered(AddEdgeConsumer addEdgeFunction) {

		// The action should:
		// -update the filtered cache
		// -update the active graph
		//

		// Users vertices and edges not yet in the graph
		AbstractTestVertex v100 = new LabelTestVertex("100");
		AbstractTestVertex v101 = new LabelTestVertex("101");
		TestEdge e = new TestEdge(v100, v101);

		addEdgeFunction.doAddEdge(e, v100, v101);

		assertUnfiltered(v100, v101);
		assertUnfiltered(e);
	}

	private void doTestAddEdge_WhenFiltered(AddEdgeConsumer addEdgeFunction) {

		//
		// The action should:
		// -update the filtered cache
		// -not update the active graph
		//

		AbstractTestVertex v100 = new LabelTestVertex("100");
		AbstractTestVertex v101 = new LabelTestVertex("101");
		TestEdge e = new TestEdge(v100, v101);

		graph.filterVertices(asList(vertex("1")));

		addEdgeFunction.doAddEdge(e, v100, v101);

		assertFiltered(v100);
		assertFiltered(v101);
		assertFiltered(e);
	}

	private interface AddEdgeConsumer {
		public void doAddEdge(TestEdge e, AbstractTestVertex v1, AbstractTestVertex v2);
	}
}
