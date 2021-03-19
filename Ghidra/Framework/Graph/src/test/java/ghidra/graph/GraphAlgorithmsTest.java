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

import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.util.*;
import java.util.concurrent.TimeUnit;

import org.junit.Assert;
import org.junit.Test;

import ghidra.graph.algo.*;
import ghidra.util.Msg;
import ghidra.util.datastruct.ListAccumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.TimeoutException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;

public class GraphAlgorithmsTest extends AbstractGraphAlgorithmsTest {

	@Override
	protected GDirectedGraph<TestV, TestE> createGraph() {
		return GraphFactory.createDirectedGraph();
	}

	@Test
	public void testGetSources() {
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);

		g.addVertex(v1);
		g.addVertex(v2);
		g.addVertex(v3);

		Set<TestV> sources = GraphAlgorithms.getSources(g);
		assertEquals(3, sources.size());

		g.addEdge(edge(v1, v2));
		g.addEdge(edge(v1, v3));

		sources = GraphAlgorithms.getSources(g);
		assertEquals(1, sources.size());
		assertEquals("1", id(sources.iterator().next()));

		g.addEdge(edge(v2, v1));
		g.addEdge(edge(v3, v1));

		sources = GraphAlgorithms.getSources(g);
		assertEquals(0, sources.size());
	}

	@Test
	public void testGetDescendants() {
		//   v1 -> v2 -> v3
		//    |
		//   v4 -> v5 -> v6

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		edge(v1, v2);
		edge(v2, v3);
		edge(v1, v4);
		edge(v4, v5);
		edge(v5, v6);

		Set<TestV> descendants = GraphAlgorithms.getDescendants(g, set(v1));
		assertContainsExactly(descendants, v1, v2, v3, v4, v5, v6);

		descendants = GraphAlgorithms.getDescendants(g, set(v3));
		assertTrue(descendants.isEmpty());

		descendants = GraphAlgorithms.getDescendants(g, set(v2, v5));
		assertContainsExactly(descendants, v2, v3, v5, v6);
	}

	@Test
	public void testSubGraph() {
		//   v1 -> v2 -> v3 <----
		//    |	                 |
		//   v4 -> v5 -> v6      |
		//    |                  |
		//    |->---->----->-----|

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v1, v4);
		edge(v4, v5);
		edge(v5, v6);
		edge(v4, v3);

		GDirectedGraph<TestV, TestE> subGraph = GraphAlgorithms.createSubGraph(g, set(v1, v2, v3));
		Collection<TestV> vertices = subGraph.getVertices();
		assertContainsExactly(vertices, v1, v2, v3);

	}

	@Test
	public void testStronglyConnected() {
		//   V1 <- V4
		//    |     ^
		//    v     |
		//   V2 -> V3 -> V5 <--> V6
		//
		//   V7

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		g.addVertex(v7);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v3, v5);
		edge(v5, v6);
		edge(v6, v5);
		edge(v4, v1);

		Set<Set<TestV>> stronglyConnectedComponents =
			GraphAlgorithms.getStronglyConnectedComponents(g);
		assertEquals(3, stronglyConnectedComponents.size());

		assertStrongGraph(stronglyConnectedComponents, v1, v2, v3, v4);
		assertStrongGraph(stronglyConnectedComponents, v5, v6);
		assertStrongGraph(stronglyConnectedComponents, v7);
	}

	@Test
	public void testStronglyConnected2() {
		//   V1 <- V4 <--------
		//    |     ^          ^
		//    v     |          |
		//   V2 -> V3 -> V5 -> V6

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v3, v5);
		edge(v5, v6);
		edge(v6, v4);
		edge(v4, v1);

		Set<Set<TestV>> stronglyConnectedComponents =
			GraphAlgorithms.getStronglyConnectedComponents(g);
		assertEquals(1, stronglyConnectedComponents.size());

		assertStrongGraph(stronglyConnectedComponents, v1, v2, v3, v4, v5, v6);
	}

	@Test
	public void testDominance_GetDominators_Empty() {

		try {
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);
			Assert.fail("Expected exception getting dominators from vertex not in graph");
		}
		catch (Exception e) {
			// expected
		}
	}

	@Test
	public void testDominance_GetDominators_NoSources() {
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		edge(v1, v2);
		edge(v2, v1);

		try {
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

			Assert.fail("Expected exception getting dominators from vertex not in graph");
		}
		catch (Exception e) {
			// expected
		}
	}

	@Test
	public void testDominance_GetDominators() throws CancelledException {

		/*
		 		v1->.
		 		 |  |
		 		v2  |
		 		 |  |
		 		v3  |
		 		 |  |
		 		v4--<
		 */
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v1, v4);

		ChkDominanceAlgorithm<TestV, TestE> algo =
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		assertContainsExactly(algo.getDominators(v1), v1);
		assertContainsExactly(algo.getDominators(v2), v1, v2);
		assertContainsExactly(algo.getDominators(v3), v1, v2, v3);
		assertContainsExactly(algo.getDominators(v4), v1, v4);
	}

	@Test
	public void testDominance_GetDominators_WithTwoPathsFromRoot() throws CancelledException {
		//
		//          v1->.
		//           |  |
		// 			v2  |
		//		     |  \/
		//           |  |
		//      	 |  v3
		//           |  |
		//           |  \/
		//          v4--<
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v1, v4);

		ChkDominanceAlgorithm<TestV, TestE> dominanceAlgorithm =
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		assertContainsExactly(dominanceAlgorithm.getDominators(v1), v1);
		assertContainsExactly(dominanceAlgorithm.getDominators(v2), v1, v2);
		assertContainsExactly(dominanceAlgorithm.getDominators(v3), v1, v2, v3);
		assertContainsExactly(dominanceAlgorithm.getDominators(v4), v1, v4);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testDominance_GetDominatorGraph() throws CancelledException {
		//
		//          v1->.
		//           |  |
		// 			v2  |
		//		     |  \/
		//           |  |
		//      	    v3  |
		//           |  |
		//           |  \/
		//          v4--<
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v1, v4);

		GDirectedGraph<TestV, GEdge<TestV>> dg =
			GraphAlgorithms.findDominanceTree(g, TaskMonitor.DUMMY);

		//@formatter:off
		assertContainsEdgesExactly(dg,
								   resultEdge(v1, v2),
								   resultEdge(v1, v2),
								   resultEdge(v2, v3),
								   resultEdge(v1, v4));
		//@formatter:on

	}

	@Test
	public void testDominance_GetDominators_Complicated() throws CancelledException {

		//@formatter:off
		/*
				v1
			 	 |
				v2
			 	 |
	sink   v3 <- v4
		   /\	 |
		   	|	 v5
			| 	/  \
			| v6   v7
		    |  |\   |
		    | v8  \ |
		    |   \   |
		    |     \ |
		    |      v9
			|	   / \
		    |     /   \
		    .<--v11-->v10	sink

		*/
		//@formatter:on

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);
		TestV v11 = vertex(11);

		edge(v1, v2);
		edge(v2, v4);
		edge(v4, v3);
		edge(v4, v5);

		edge(v5, v6);
		edge(v5, v7);
		edge(v6, v8);
		edge(v6, v9);
		edge(v7, v9);
		edge(v8, v9);
		edge(v9, v10);
		edge(v9, v11);
		edge(v11, v3);
		edge(v11, v10);

		ChkDominanceAlgorithm<TestV, TestE> dominanceAlgorithm =
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		assertContainsExactly(dominanceAlgorithm.getDominators(v1), v1);
		assertContainsExactly(dominanceAlgorithm.getDominators(v2), v1, v2);
		assertContainsExactly(dominanceAlgorithm.getDominators(v3), v1, v2, v4, v3);
		assertContainsExactly(dominanceAlgorithm.getDominators(v4), v1, v2, v4);
		assertContainsExactly(dominanceAlgorithm.getDominators(v5), v1, v2, v4, v5);
		assertContainsExactly(dominanceAlgorithm.getDominators(v6), v1, v2, v4, v5, v6);
		assertContainsExactly(dominanceAlgorithm.getDominators(v7), v1, v2, v4, v5, v7);
		assertContainsExactly(dominanceAlgorithm.getDominators(v8), v1, v2, v4, v5, v6, v8);
		assertContainsExactly(dominanceAlgorithm.getDominators(v9), v1, v2, v4, v5, v9);
		assertContainsExactly(dominanceAlgorithm.getDominators(v10), v1, v2, v4, v5, v9, v10);
		assertContainsExactly(dominanceAlgorithm.getDominators(v11), v1, v2, v4, v5, v9, v11);
	}

	@Test
	public void testDominance_GetDominators_WithTwoPathsFromSecondNode() throws CancelledException {
		//
		//          v1
		//           |
		// 			v2
		//		   / |
		//        /  |
		//      v3   v4
		//       \   |
		//        \  |
		//         - v5
		//           |
		//           |
		//           v6
		//
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v3, v5);
		edge(v4, v5);
		edge(v5, v6);

		ChkDominanceAlgorithm<TestV, TestE> algo =
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		assertContainsExactly(algo.getDominators(v1), v1);
		assertContainsExactly(algo.getDominators(v2), v1, v2);
		assertContainsExactly(algo.getDominators(v3), v1, v2, v3);
		assertContainsExactly(algo.getDominators(v4), v1, v2, v4);
		assertContainsExactly(algo.getDominators(v5), v1, v2, v5);
		assertContainsExactly(algo.getDominators(v6), v1, v2, v5, v6);
	}

	@Test
	public void testDominance_GetDominated_WithTwoPathsFromSecondNode() throws CancelledException {
		//
		//          v1
		//           |
		// 			v2
		//		   / |
		//        /  |
		//      v3   v4
		//       \   |
		//        \  |
		//         - v5
		//           |
		//           |
		//           v6
		//
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v3, v5);
		edge(v4, v5);
		edge(v5, v6);

		ChkDominanceAlgorithm<TestV, TestE> algo =
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		// all paths go through v1
		//@formatter:off
		Collection<TestE> dominated = findDominance(v1, algo);
		assertContainsExactly(dominated, edge(v1, v2),
									  	 edge(v2, v3),
									  	 edge(v2, v4),
									  	 edge(v3, v5),
									  	 edge(v4, v5),
									  	 edge(v5, v6));
		//@formatter:on

		// all paths, but v1, are dominated by v2
		//@formatter:off
		dominated = findDominance(v2, algo);
		assertContainsExactly(dominated, edge(v2, v3),
									  	 edge(v2, v4),
									  	 edge(v3, v5),
									  	 edge(v4, v5),
									  	 edge(v5, v6));
		//@formatter:on

		// v3/v4 are two ways through the graph; they do not dominate
		dominated = findDominance(v3, algo);
		assertTrue(dominated.isEmpty());
		dominated = findDominance(v4, algo);
		assertTrue(dominated.isEmpty());

		dominated = findDominance(v5, algo);
		assertContainsExactly(dominated, edge(v5, v6));

		// v6 is the exit; it dominates nothing
		dominated = findDominance(v6, algo);
		assertTrue(dominated.isEmpty());
	}

	@Test
	public void testPostDominance_GetDominators() throws CancelledException {

		/*
		 		v1->.
		 		 |  |
		 		v2  |
		 		 |  |
		 		v3  |
		 		 |  |
		 		v4--<
		 */
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v1, v4);

		ChkPostDominanceAlgorithm<TestV, TestE> algo =
			new ChkPostDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		assertContainsExactly(algo.getDominators(v1), v1, v4);
		assertContainsExactly(algo.getDominators(v2), v2, v3, v4);
		assertContainsExactly(algo.getDominators(v3), v3, v4);
		assertContainsExactly(algo.getDominators(v4), v4);
	}

	@Test
	public void testPostDominance_GetDominators_WithLoopBack() throws CancelledException {

		//@formatter:off
		/*
		 		v1
		 		 |
		 		v2 <-.
		 		 |   |
		 		v3   |
		 	   / |   |
	   sink  v4  v5->|

		 */
		//@formatter:on
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v3, v5);
		edge(v5, v2);

		ChkPostDominanceAlgorithm<TestV, TestE> algo =
			new ChkPostDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		assertContainsExactly(algo.getDominators(v1), v1, v2, v3, v4);
		assertContainsExactly(algo.getDominators(v2), v2, v3, v4);
		assertContainsExactly(algo.getDominators(v3), v3, v4);
		assertContainsExactly(algo.getDominators(v4), v4);
		assertContainsExactly(algo.getDominators(v5), v2, v3, v4, v5);
	}

	@Test
	public void testPostDominated() throws CancelledException {

		//
		//          v1
		//           |
		// 			v2
		//		   / |
		//        /  |
		//      v3   v4
		//       \   |
		//        \  |
		//         - v5
		//           |
		//           |
		//           v6
		//
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v3, v5);
		edge(v4, v5);
		edge(v5, v6);

		ChkPostDominanceAlgorithm<TestV, TestE> algo =
			new ChkPostDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		// v1 is the entry; it is not post-dominated by anything
		Collection<TestE> dominated = findPostDominance(v1, algo);
		assertTrue("The start vertex is the root--it should not post dominate any nodes.  " +
			"Found: " + dominated, dominated.isEmpty());

		dominated = findPostDominance(v2, algo);
		assertContainsExactly(dominated, edge(v1, v2));

		// v3/v4 are two ways through the graph; they do not post-dominate
		dominated = findPostDominance(v3, algo);
		assertTrue(dominated.isEmpty());
		dominated = findPostDominance(v4, algo);
		assertTrue(dominated.isEmpty());

		//@formatter:off
		dominated = findPostDominance(v5, algo);
		assertContainsExactly(dominated, edge(v1, v2),
									  	 edge(v2, v3),
									  	 edge(v2, v4),
									  	 edge(v3, v5),
									  	 edge(v4, v5));
		//@formatter:on

		// all paths go through v6
		//@formatter:off
		dominated = findPostDominance(v6, algo);
		assertContainsExactly(dominated, edge(v1, v2),
									  	 edge(v2, v3),
									  	 edge(v2, v4),
									  	 edge(v3, v5),
									  	 edge(v4, v5),
									  	 edge(v5, v6));
		//@formatter:on

	}

	@Test
	public void testPostDominated_ChkAlgorithm() {

		//
		//          v1
		//           |
		// 			v2
		//		   / |
		//        /  |
		//      v3   v4
		//       \   |
		//        \  |
		//         - v5
		//           |
		//           |
		//           v6
		//
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v3, v5);
		edge(v4, v5);
		edge(v5, v6);

		// v1 is the entry; it is not post-dominated by anything
		Collection<TestE> dominated = findPostDominance(v1);
		assertTrue("The start vertex is the root--it should not post dominate any nodes.  " +
			"Found: " + dominated, dominated.isEmpty());

		dominated = findPostDominance(v2);
		assertContainsExactly(dominated, edge(v1, v2));

		// v3/v4 are two ways through the graph; they do not post-dominate
		dominated = findPostDominance(v3);
		assertTrue(dominated.isEmpty());
		dominated = findPostDominance(v4);
		assertTrue(dominated.isEmpty());

		//@formatter:off
		dominated = findPostDominance(v5);
		assertContainsExactly(dominated, edge(v1, v2),
									  	 edge(v2, v3),
									  	 edge(v2, v4),
									  	 edge(v3, v5),
									  	 edge(v4, v5));
		//@formatter:on

		// all paths go through v6
		//@formatter:off
		dominated = findPostDominance(v6);
		assertContainsExactly(dominated, edge(v1, v2),
									  	 edge(v2, v3),
									  	 edge(v2, v4),
									  	 edge(v3, v5),
									  	 edge(v4, v5),
									  	 edge(v5, v6));
		//@formatter:on

	}

	@Test
	public void testDominated_MultipleSources() throws CancelledException {
		/*
		source 		v1
			 		 |
		source 	v2	v3
			 	 |	 |
			 	v4	v5
			 	 \   |
			 	  \  |
			 	   -v6
		             |
		 			v7
				   / |
		          /  |
		        v8   v9
		         \   |
		          \  |
		           - v10
		             |
		             |
		            v11
		
		*/

		TestV v1 = vertex(1);  // Root
		TestV v2 = vertex(2);  // Root
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);
		TestV v11 = vertex(11);

		edge(v1, v3);
		edge(v3, v5);
		edge(v5, v6);

		edge(v2, v4);
		edge(v4, v6);

		edge(v6, v7);
		edge(v7, v8);
		edge(v7, v9);
		edge(v8, v10);
		edge(v9, v10);
		edge(v10, v11);

		ChkDominanceAlgorithm<TestV, TestE> algo =
			new ChkDominanceAlgorithm<>(g, TaskMonitor.DUMMY);

		//@formatter:off
		Collection<TestE> dominated = findDominance(v1, algo);
		assertContainsExactly(dominated, edge(v1, v3),
									  	 edge(v3, v5));
		//@formatter:on

		dominated = findDominance(v2, algo);
		assertContainsExactly(dominated, edge(v2, v4));

		dominated = findDominance(v3, algo);
		assertContainsExactly(dominated, edge(v3, v5));

		dominated = findDominance(v4, algo);
		assertTrue(dominated.isEmpty());

		dominated = findDominance(v5, algo);
		assertTrue(dominated.isEmpty());

		//@formatter:off
		dominated = findDominance(v6, algo);
		assertContainsExactly(dominated, edge(v6, v7),
									  	 edge(v7, v8),
									  	 edge(v7, v9),
									  	 edge(v8, v10),
									  	 edge(v9, v10),
									  	 edge(v10, v11));

		dominated = findDominance(v7, algo);
		assertContainsExactly(dominated, edge(v7, v8),
									  	 edge(v7, v9),
									  	 edge(v8, v10),
									  	 edge(v9, v10),
									  	 edge(v10, v11));
		//@formatter:on

		dominated = findDominance(v8, algo);
		assertTrue(dominated.isEmpty());

		dominated = findDominance(v9, algo);
		assertTrue(dominated.isEmpty());

		dominated = findDominance(v10, algo);
		assertContainsExactly(dominated, edge(v10, v11));

	}

	@Test
	public void testPostDominated_MultipleSources() {
		/*
		source 		v1
			 		 |
		source 	v2	v3
			 	 |	 |
			 	v4	v5
			 	 \   |
			 	  \  |
			 	   -v6
		             |
		 			v7
				   / |
		          /  |
		        v8   v9
		         \   |
		          \  |
		           - v10
		             |
		             |
		            v11
		
		*/

		TestV v1 = vertex(1);  // Root
		TestV v2 = vertex(2);  // Root
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);
		TestV v11 = vertex(11);

		edge(v1, v3);
		edge(v3, v5);
		edge(v5, v6);

		edge(v2, v4);
		edge(v4, v6);

		edge(v6, v7);
		edge(v7, v8);
		edge(v7, v9);
		edge(v8, v10);
		edge(v9, v10);
		edge(v10, v11);

		Collection<TestE> dominated = findPostDominance(v1);
		assertTrue("The start vertex is the root--it should not post dominate any nodes.  " +
			"Found: " + dominated, dominated.isEmpty());

		dominated = findPostDominance(v2);
		assertTrue("The start vertex is the root--it should not post dominate any nodes.  " +
			"Found: " + dominated, dominated.isEmpty());

		dominated = findPostDominance(v3);
		assertContainsExactly(dominated, edge(v1, v3));

		dominated = findPostDominance(v4);
		assertContainsExactly(dominated, edge(v2, v4));

		//@formatter:off
		dominated = findPostDominance(v5);
		assertContainsExactly(dominated, edge(v1, v3),
										 edge(v3, v5));

		dominated = findPostDominance(v6);
		assertContainsExactly(dominated, edge(v1, v3),
										 edge(v3, v5),
										 edge(v5, v6),
										 edge(v2, v4),
										 edge(v4, v6));

		dominated = findPostDominance(v7);
		assertContainsExactly(dominated, edge(v1, v3),
										 edge(v3, v5),
										 edge(v5, v6),
										 edge(v2, v4),
										 edge(v4, v6),
										 edge(v6, v7));

		dominated = findPostDominance(v8);
		assertTrue(dominated.isEmpty());

		dominated = findPostDominance(v9);
		assertTrue(dominated.isEmpty());

		dominated = findPostDominance(v10);
		assertContainsExactly(dominated, edge(v1, v3),
										 edge(v3, v5),
										 edge(v5, v6),
										 edge(v2, v4),
										 edge(v4, v6),
										 edge(v6, v7),
										 edge(v7, v8),
										 edge(v7, v9),
										 edge(v8, v10),
										 edge(v9, v10));

		dominated = findPostDominance(v11);
		assertContainsExactly(dominated, edge(v1, v3),
										 edge(v3, v5),
										 edge(v5, v6),
										 edge(v2, v4),
										 edge(v4, v6),
										 edge(v6, v7),
										 edge(v7, v8),
										 edge(v7, v9),
										 edge(v8, v10),
										 edge(v9, v10),
										 edge(v10, v11));
		//@formatter:on
	}

	@Test
	public void testPostDominated_MultipleSinks() {
		/*
		 		    v1
			 	   / |
		sink ->  v2 v3
		             |
		 			v4
				   / |\
		          /  | \
		        v5   v6 v7  <- sink
		         \   |
		          \  |
		           - v8
		             |
		             |
		             v9		 <- sink
		
		*/

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);  // sink
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);  // sink
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);  // sink

		edge(v1, v2);
		edge(v1, v3);
		edge(v3, v4);
		edge(v4, v5);
		edge(v4, v6);
		edge(v4, v7);
		edge(v5, v8);
		edge(v6, v8);
		edge(v8, v9);

		Collection<TestE> dominated = findPostDominance(v1);
		assertTrue("The start vertex is the root--it should not post dominate any nodes.  " +
			"Found: " + dominated, dominated.isEmpty());

		dominated = findPostDominance(v2);
		assertTrue(dominated.isEmpty()); // v1 can be visited via v3

		dominated = findPostDominance(v3);
		assertTrue(dominated.isEmpty()); // v1 can be visited via v2

		//@formatter:off
		dominated = findPostDominance(v4);
		assertContainsExactly(dominated, edge(v3, v4));

		dominated = findPostDominance(v5);
		assertTrue(dominated.isEmpty()); // there are 3 paths at this level

		dominated = findPostDominance(v6);
		assertTrue(dominated.isEmpty());  // there are 3 paths at this level

		dominated = findPostDominance(v7);
		assertTrue(dominated.isEmpty());  // there are 3 paths at this level

		dominated = findPostDominance(v8);
		assertContainsExactly(dominated, edge(v5, v8),
			 							 edge(v6, v8));

		dominated = findPostDominance(v9);
		assertContainsExactly(dominated, edge(v5, v8),
			 							 edge(v6, v8),
			 							 edge(v8, v9));
		//@formatter:on
	}

	@Test
	public void testDominanceEquality() throws CancelledException {
		//
		// Regression test for https://github.com/NationalSecurityAgency/ghidra/issues/2836
		// Make sure that Object.equals() is used, not ==.
		//
		// Note: this tests uses multiple vertices that are equal() to expose the issue with
		//       using '=='.   Previously it was up to clients to ensure they not duplicate nodes.
		//       With this change duplicate nodes are acceptable as long as the client correctly
		//       implements equals().
		//
		edge(vertex(1), vertex(2));
		edge(vertex(1), vertex(3));

		GraphAlgorithms.findDominanceTree(g, TaskMonitor.DUMMY);
	}

	@Test
	public void testDepthFirstPostOrder() {
		//   V1 -> V3 -> V6
		//    |     |
		//    v     v
		//   V2 -> V4 -> V5

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v1, v3);
		edge(v2, v6);
		edge(v2, v4);
		edge(v4, v5);
		edge(v3, v4);

		List<TestV> postOrder = DepthFirstSorter.postOrder(g);
		assertEquals(6, postOrder.size());

		assertOrder(postOrder, v5, v4);
		assertOrder(postOrder, v4, v2);
		assertOrder(postOrder, v4, v3);
		assertOrder(postOrder, v2, v1);
		assertOrder(postOrder, v3, v1);
		assertOrder(postOrder, v6, v2);
	}

	@Test
	public void testDepthFirstPreOrder() {
		//   V1 -> V3 -> V6
		//    |     |
		//    v     v
		//   V2 -> V4 -> V5

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v1, v3);
		edge(v2, v6);
		edge(v2, v4);
		edge(v4, v5);
		edge(v3, v4);

		List<TestV> preOrder = DepthFirstSorter.preOrder(g);
		assertEquals(6, preOrder.size());

		assertOrder(preOrder, v1, v2);
		assertOrder(preOrder, v1, v3);
		assertOrder(preOrder, v1, v4);
		assertOrder(preOrder, v1, v5);
		assertOrder(preOrder, v1, v6);
		assertOrder(preOrder, v2, v6);

	}

	@Test
	public void testDepthFirstPreOrder_MiddleAlternatingPaths() {
		/*
		
		 		v1
		 		 |
		 		v2
		 		/\
		 	   /  \
		 	  v3  v4
		 	   \ /
		 	    v5
		 	     |
		 	    v6
		
		 */

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v3, v5);
		edge(v4, v5);
		edge(v5, v6);

		List<TestV> preOrder = DepthFirstSorter.preOrder(g);
		assertEquals(6, preOrder.size());

		assertListEqualsOneOf(preOrder, Arrays.asList(v1, v2, v3, v5, v6, v4),
			Arrays.asList(v1, v2, v4, v5, v6, v3));
	}

	@Test
	public void testDepthFirstPostOrder_MiddleAlternatingPaths() {
		/*
		
		 		v1
		 		 |
		 		v2
		 		/\
		 	   /  \
		 	  v3  v4
		 	   \ /
		 	    v5
		 	     |
		 	    v6
		
		 */

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v3, v5);
		edge(v4, v5);
		edge(v5, v6);

		List<TestV> postOrder = DepthFirstSorter.postOrder(g);
		assertEquals(6, postOrder.size());

		assertListEqualsOneOf(postOrder, Arrays.asList(v6, v5, v3, v4, v2, v1),
			Arrays.asList(v6, v5, v4, v3, v2, v1));
	}

	@Test
	public void testDepthFirstPostOrderWithCycle() {
		//   V1 -> V3 -> V6
		//    |     |
		//    v     v
		//   V2 -> V4 -> V5
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		edge(v1, v2);
		edge(v1, v3);
		edge(v2, v6);
		edge(v2, v4);
		edge(v4, v5);
		edge(v3, v4);
		edge(v5, v6);

		List<TestV> postOrder = DepthFirstSorter.postOrder(g);
		assertEquals(6, postOrder.size());

		assertOrder(postOrder, v5, v4);
		assertOrder(postOrder, v4, v2);
		assertOrder(postOrder, v2, v1);
		assertOrder(postOrder, v3, v1);
		assertOrder(postOrder, v6, v2);
	}

	@Test
	public void testDepthFirstPostOrderMultipleSources() {
		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);

		edge(v1, v3);
		edge(v2, v3);
		edge(v2, v4);

		List<TestV> postOrder = DepthFirstSorter.postOrder(g);
		assertEquals(4, postOrder.size());

		assertOrder(postOrder, v3, v1);
		assertOrder(postOrder, v3, v2);
		assertOrder(postOrder, v4, v2);
	}

	@Test
	public void testDepthFirstPostOrderWithDisjointCycle() {
		//   V1 --> V2
		//    |     |
		//    v     |
		//   V3 <----
		//    |
		//    v
		//   V4 <-> V5

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v4, v5);
		edge(v5, v4);

		List<TestV> postOrder = DepthFirstSorter.postOrder(g);
		assertEquals(5, postOrder.size());

		assertOrder(postOrder, v3, v1);
		assertOrder(postOrder, v3, v2);
		assertOrder(postOrder, v4, v3);
		assertOrder(postOrder, v5, v4);
	}

	@Test
	public void testJohnsonsCircuits() throws CancelledException {

		g = GraphFactory.createDirectedGraph();
		generateCompletelyConnectedGraph(4);
		List<List<TestV>> circuits = GraphAlgorithms.findCircuits(g, TaskMonitor.DUMMY);
		assertEquals(20, circuits.size());

		g = GraphFactory.createDirectedGraph();
		generateCompletelyConnectedGraph(5);
		circuits = GraphAlgorithms.findCircuits(g, TaskMonitor.DUMMY);
		assertEquals(84, circuits.size());

	}

	@Test
	public void testJohnsonsCircuitsNotCompletelyConnected() throws CancelledException {
		//
		//
		//         <----------
		//         |          |
		//   1 --> 2 --> 3 --> 4
		//         |      |
		//         |       --> 5 ----> 7 ---> (back to 3)
		//         |           ^\
		//         |           | \
		//          -----------   6
		//
		//
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v5);
		edge(v3, v4);
		edge(v3, v5);
		edge(v4, v2);
		edge(v5, v7);
		edge(v5, v6);
		edge(v7, v3);

		List<List<TestV>> circuits = GraphAlgorithms.findCircuits(g, TaskMonitor.DUMMY);
		assertEquals(3, circuits.size());
	}

	@Test
	public void testJohnsonsCircuits_TimeoutReached() throws CancelledException {

		startMemoryMonitorThread(false);

		g = GraphFactory.createDirectedGraph();
		generateCompletelyConnectedGraph(30); // this takes a while

		int timeout = 250;
		TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(timeout, TimeUnit.MILLISECONDS);

		try {
			GraphAlgorithms.findCircuits(g, monitor);
			fail("Did not timeout in " + timeout + " ms");
		}
		catch (TimeoutException e) {
			// good
		}

		assertTrue(monitor.didTimeout());
	}

	@Test
	public void testFindPaths() throws CancelledException {
		//
		//
		//         <----------
		//         |          |
		//   1 --> 2 --> 3 --> 4
		//         |      |
		//         |      --> 5 ----> 7 ---> (back to 3)
		//         |           ^\
		//         |           | \
		//          -----------   6
		//
		//
		//

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);

		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v5);
		edge(v3, v4);
		edge(v3, v5);
		edge(v4, v2);
		edge(v5, v7);
		edge(v5, v6);
		edge(v7, v3);

		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();
		GraphAlgorithms.findPaths(g, v2, v4, accumulator, TaskMonitor.DUMMY);

		List<List<TestV>> paths = accumulator.asList();
		assertEquals(2, paths.size());
		List<TestV> shortestPath = paths.get(0).size() == 3 ? paths.get(0) : paths.get(1);
		List<TestV> longestPath = paths.get(0).size() == 3 ? paths.get(1) : paths.get(0);
		assertContainsExactly(shortestPath, v2, v3, v4);
		assertContainsExactly(longestPath, v2, v5, v7, v3, v4);
	}

	@Test
	public void testFindPaths_FullyConnected() throws CancelledException {

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);

		edge(v1, v2);
		edge(v1, v3);

		edge(v2, v3);
		edge(v2, v1);

		edge(v3, v2);
		edge(v3, v1);

		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();
		GraphAlgorithms.findPaths(g, v1, v2, accumulator, TaskMonitor.DUMMY);

		List<List<TestV>> paths = accumulator.asList();
		assertPathExists(paths, v1, v2);
		assertPathExists(paths, v1, v3, v2);
	}

	@Test
	public void testFindPaths_FullyConnected2() throws CancelledException {

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);

		edge(v1, v2);
		edge(v1, v3);
		edge(v1, v4);
		edge(v1, v5);

		edge(v2, v1);
		edge(v2, v3);
		edge(v2, v4);
		edge(v2, v5);

		edge(v3, v1);
		edge(v3, v2);
		edge(v3, v4);
		edge(v3, v5);

		edge(v4, v1);
		edge(v4, v2);
		edge(v4, v3);
		edge(v4, v5);

		edge(v5, v1);
		edge(v5, v2);
		edge(v5, v3);
		edge(v5, v4);

		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();
		GraphAlgorithms.findPaths(g, v1, v5, accumulator, TaskMonitor.DUMMY);

		List<List<TestV>> paths = accumulator.asList();
		assertEquals(16, paths.size());
		assertPathExists(paths, v1, v5);

		assertPathExists(paths, v1, v2, v5);
		assertPathExists(paths, v1, v3, v5);
		assertPathExists(paths, v1, v4, v5);

		assertPathExists(paths, v1, v2, v3, v5);
		assertPathExists(paths, v1, v2, v4, v5);
		assertPathExists(paths, v1, v3, v2, v5);
		assertPathExists(paths, v1, v3, v4, v5);
		assertPathExists(paths, v1, v4, v2, v5);
		assertPathExists(paths, v1, v4, v3, v5);

		assertPathExists(paths, v1, v2, v3, v4, v5);
		assertPathExists(paths, v1, v2, v4, v3, v5);
		assertPathExists(paths, v1, v3, v2, v4, v5);
		assertPathExists(paths, v1, v3, v4, v2, v5);
		assertPathExists(paths, v1, v4, v2, v3, v5);
		assertPathExists(paths, v1, v4, v3, v2, v5);
	}

	@Test
	public void testFindPaths_MultiPaths() throws CancelledException {

		/*
		 		v1
		 	   /  \
		 	 v2    v3
			  |   / | \
			  |  v4 v5 v6
			  |   * |  |
			  |     |  v7
			  |     |  | \
			  |     |  v8 v9
			  |     |   * |
			   \    |    /
			     \  |  /
			       \|/
			        v10
		
		
			 Paths:
			 	v1, v2, v10
			 	v1, v3, v5, v10
			 	v1, v3, v6, v7, v9, v10
		 */

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);

		edge(v1, v2);
		edge(v1, v3);

		edge(v2, v10);

		edge(v3, v4);
		edge(v3, v5);
		edge(v3, v6);

		edge(v5, v10);

		edge(v6, v7);
		edge(v7, v8);
		edge(v7, v9);

		edge(v9, v10);

		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();
		GraphAlgorithms.findPaths(g, v1, v10, accumulator, TaskMonitor.DUMMY);

		List<List<TestV>> paths = accumulator.asList();
		assertEquals(3, paths.size());
		assertPathExists(paths, v1, v2, v10);
		assertPathExists(paths, v1, v3, v5, v10);
		assertPathExists(paths, v1, v3, v6, v7, v9, v10);

		accumulator = new ListAccumulator<>();
		GraphAlgorithms.findPaths(g, v1, v10, accumulator, TaskMonitor.DUMMY);

	}

	@Test
	public void testFindPathsNew_MultiPaths_BackFlows() throws CancelledException {

		/*
		   --> v1
		   |  /  \
		   -v2    v3
			    /  | \
			   v4  v5 v6 <--
			    *  |  |     |
			       |  v7    |
			       |  | \   |
			       |  v8 v9 -
			       |   *
			       |
			      v10
		
		
			Paths: v1, v3, v5, v10
		*/

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);

		edge(v1, v2);
		edge(v1, v3);

		edge(v2, v1); // back edge

		edge(v3, v4);
		edge(v3, v5);
		edge(v3, v6);

		edge(v5, v10);

		edge(v6, v7);

		edge(v7, v8);
		edge(v7, v9);

		edge(v9, v6); // back edge

		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();

		GraphAlgorithms.findPaths(g, v1, v10, accumulator, TaskMonitor.DUMMY);

		List<List<TestV>> paths = accumulator.asList();
		assertEquals(1, paths.size());
		assertPathExists(paths, v1, v3, v5, v10);
	}

	@Test
	public void testFindPathsNew_MultiPaths_LongDeadEnd() throws CancelledException {

		/*
			   v1
			  /  \
			v2    v3
			|   /  | \
			|  v4  v5 v6
			|   |  |  |
			|  v11 |  v7
			|   |  |  | \
			|  v12 |  v8 v9
			|   *  |   * |
			 \     |    /
			   \   |  /
			     \ |/
			      v10
		
		
			Paths:
			v1, v2, v10
			v1, v3, v5, v10
			v1, v3, v6, v7, v9, v10
		*/

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);
		TestV v11 = vertex(11);
		TestV v12 = vertex(12);

		edge(v1, v2);
		edge(v1, v3);

		edge(v2, v10);

		edge(v3, v4);
		edge(v3, v5);
		edge(v3, v6);

		edge(v4, v11);

		edge(v11, v12);

		edge(v5, v10);

		edge(v6, v7);
		edge(v7, v8);
		edge(v7, v9);

		edge(v9, v10);

		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();

		GraphAlgorithms.findPaths(g, v1, v10, accumulator, TaskMonitor.DUMMY);

		List<List<TestV>> paths = accumulator.asList();
		assertEquals(3, paths.size());
		assertPathExists(paths, v1, v2, v10);
		assertPathExists(paths, v1, v3, v5, v10);
		assertPathExists(paths, v1, v3, v6, v7, v9, v10);
	}

	@Test
	public void testFindPathsNew_MultiPaths() throws CancelledException {

		/*
		 		v1
		 	   /  \
		 	 v2    v3
			  |   / | \
			  |  v4 v5 v6
			  |   * |  |
			  |     |  v7
			  |     |  | \
			  |     |  v8 v9
			  |     |   * |
			   \    |    /
			     \  |  /
			       \|/
			        v10
		
		
			 Paths:
			 	v1, v2, v10
			 	v1, v3, v5, v10
			 	v1, v3, v6, v7, v9, v10
		 */

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);
		TestV v10 = vertex(10);

		edge(v1, v2);
		edge(v1, v3);

		edge(v2, v10);

		edge(v3, v4);
		edge(v3, v5);
		edge(v3, v6);

		edge(v5, v10);

		edge(v6, v7);
		edge(v7, v8);
		edge(v7, v9);

		edge(v9, v10);

		ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();

		GraphAlgorithms.findPaths(g, v1, v10, accumulator, TaskMonitor.DUMMY);

		List<List<TestV>> paths = accumulator.asList();
		assertEquals(3, paths.size());
		assertPathExists(paths, v1, v2, v10);
		assertPathExists(paths, v1, v3, v5, v10);
		assertPathExists(paths, v1, v3, v6, v7, v9, v10);

		accumulator = new ListAccumulator<>();
		GraphAlgorithms.findPaths(g, v4, v10, accumulator, TaskMonitor.DUMMY);
		paths = accumulator.asList();
		assertTrue(paths.isEmpty());
	}

	@Test
	public void testFindPaths_TimeoutReached() throws CancelledException {

		startMemoryMonitorThread(false);

		g = GraphFactory.createDirectedGraph();
		TestV[] vertices = generateCompletelyConnectedGraph(15);

		int timeout = 250;
		TimeoutTaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(timeout, TimeUnit.MILLISECONDS);

		TestV start = vertices[0];
		TestV end = vertices[vertices.length - 1];
		try {
			ListAccumulator<List<TestV>> accumulator = new ListAccumulator<>();
			GraphAlgorithms.findPaths(g, start, end, accumulator, monitor);

			Msg.debug(this, "Found paths " + accumulator.size());
			fail("Did not timeout in " + timeout + " ms");
		}
		catch (TimeoutException e) {
			// good
		}

		assertTrue(monitor.didTimeout());
	}

	@Test
	public void testGetEdgesFrom_StartToBottom() {
		//   v1 -> v2 -> v3
		//          |
		//         v4 -> v5 -> v6

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v4, v5);
		edge(v5, v6);

		//@formatter:off
		Set<TestE> edges = GraphAlgorithms.getEdgesFrom(g, v1, true);
		assertContainsExactly(edges, edge(v1, v2),
									 edge(v2, v3),
									 edge(v2, v4),
									 edge(v4, v5),
									 edge(v5, v6));
		//@formatter:on

		edges = GraphAlgorithms.getEdgesFrom(g, v6, true);
		assertTrue(edges.isEmpty());
	}

	@Test
	public void testGetEdgesFrom_BottomToTop() {
		//   v1 -> v2 -> v3
		//          |
		//         v4 -> v5 -> v6

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v4, v5);
		edge(v5, v6);

		//@formatter:off
		Set<TestE> edges = GraphAlgorithms.getEdgesFrom(g, v6, false);
		assertContainsExactly(edges, edge(v5, v6),
									 edge(v4, v5),
									 edge(v2, v4),
									 edge(v1, v2));
		//@formatter:on

		edges = GraphAlgorithms.getEdgesFrom(g, v1, false);
		assertTrue(edges.isEmpty());
	}

	@Test
	public void testGetEdgesFrom_MiddleOut_Upwards() {
		//   v1 -> v2 -> v3
		//          |
		//         v4 -> v5 -> v6

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v4, v5);
		edge(v5, v6);

		//@formatter:off
		Set<TestE> edges = GraphAlgorithms.getEdgesFrom(g, v5, false);
		assertContainsExactly(edges, edge(v4, v5),
									 edge(v2, v4),
									 edge(v1, v2));

		edges = GraphAlgorithms.getEdgesFrom(g, v4, false);
		assertContainsExactly(edges, edge(v2, v4),
									 edge(v1, v2));

		edges = GraphAlgorithms.getEdgesFrom(g, v3, false);
		assertContainsExactly(edges, edge(v2, v3),
									 edge(v1, v2));
		//@formatter:on

		edges = GraphAlgorithms.getEdgesFrom(g, v1, false);
		assertTrue(edges.isEmpty());
	}

	@Test
	public void testGetEdgesFrom_MiddleOut_Downwards() {
		//   v1 -> v2 -> v3
		//          |
		//         v4 -> v5 -> v6

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		edge(v1, v2);
		edge(v2, v3);
		edge(v2, v4);
		edge(v4, v5);
		edge(v5, v6);

		//@formatter:off
		Set<TestE> edges = GraphAlgorithms.getEdgesFrom(g, v2, true);
		assertContainsExactly(edges, edge(v2, v4),
									 edge(v2, v3),
									 edge(v4, v5),
									 edge(v5, v6));

		edges = GraphAlgorithms.getEdgesFrom(g, v4, true);
		assertContainsExactly(edges, edge(v4, v5),
									 edge(v5, v6));

		edges = GraphAlgorithms.getEdgesFrom(g, v5, true);
		assertContainsExactly(edges, edge(v5, v6));
		//@formatter:on

		edges = GraphAlgorithms.getEdgesFrom(g, v3, true);
		assertTrue(edges.isEmpty());
	}

	@Test
	public void testGetEntryPoints() {
		/*
		 	 One large graph; each box represents a strong component; v8/v9
		 	 have no entry point, as that component has an incoming edge
		
		 		v1 -> v2 -> v3
		
		 		 __
		 		|v4|
		 	    ----
		 		 __________      _________
		 		|v5 -> v6 -|--> |v8 <-> v9|
		 		|^      |  |    -----------
		 		| \     |  |
		 		|   v7 <-  |
		 		------------
		
		 */

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		TestV v8 = vertex(8);
		TestV v9 = vertex(9);

		edge(v1, v2);
		edge(v2, v3);

		g.addVertex(v4);

		edge(v5, v6);
		edge(v6, v7);
		edge(v7, v5);

		edge(v6, v8);
		edge(v8, v9);
		edge(v9, v8);

		Set<TestV> entries = GraphAlgorithms.getEntryPoints(g);

		assertThat(entries.size(), is(3));
		assertThat(entries, hasItems(v1, v4));
		assertThat(entries, hasItem(isOneOf(v5, v6, v7)));

	}

	@Test
	public void testGetComplexityDepth() {

		g = GraphFactory.createDirectedGraph();

		//   V1 <- V4
		//    |     ^
		//    v     |
		//   V2 -> V3 -> V5 <--> V6
		//
		//   V7

		TestV v1 = vertex(1);
		TestV v2 = vertex(2);
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);
		TestV v7 = vertex(7);
		g.addVertex(v7);

		edge(v1, v2);
		edge(v2, v3);
		edge(v3, v4);
		edge(v3, v5);
		edge(v5, v6);
		edge(v6, v5);
		edge(v4, v1);

		// make an arbitrary root
		TestV root = vertex("root");
		g.addEdge(edge(root, v1));

		Map<TestV, Integer> depths = GraphAlgorithms.getComplexityDepth(g);
		assertEquals(g.getVertexCount(), depths.size());

		assertEquals(4, (int) depths.get(v1));
		assertEquals(3, (int) depths.get(v2));
		assertEquals(2, (int) depths.get(v3));
		assertEquals(0, (int) depths.get(v4));
		assertEquals(1, (int) depths.get(v5));
		assertEquals(0, (int) depths.get(v6));
		assertEquals(0, (int) depths.get(v7));
	}
}
