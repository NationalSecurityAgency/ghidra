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

import java.util.Collection;

import org.junit.Test;

public class MutableGDirectedGraphWrapperTest extends AbstractGraphAlgorithmsTest {

	@Override
	protected GDirectedGraph<TestV, TestE> createGraph() {
		return GraphFactory.createDirectedGraph();
	}

	@Test
	public void testCreateGraph() {
		/*		 
			 		v1
			 		 |
			 	v2	v3
			 	 |	 |
			 	v4	v5
			 	 \   |
			 	  \  |
			 	    v6
			 	    
					||
					||
					\/
		
		
				  Fake Vertex
		Fake Edge	|\	  Fake Edge
					| \
				--------------------		
					|   \    Original Graph
				 	|	v1
				 	|	 |
				 	v2	v3
				 	 |	 |
				 	v4	v5
				 	 \   |
				 	  \  |
				 	    v6		 	   
		 */

		TestV v1 = vertex(1);  // Root
		TestV v2 = vertex(2);  // Root
		TestV v3 = vertex(3);
		TestV v4 = vertex(4);
		TestV v5 = vertex(5);
		TestV v6 = vertex(6);

		TestE e1 = edge(v1, v3);
		TestE e2 = edge(v3, v5);
		TestE e3 = edge(v5, v6);

		TestE e4 = edge(v2, v4);
		TestE e5 = edge(v4, v6);

		//
		// Now create the second graph above using a mutable wrapper
		//
		MutableGDirectedGraphWrapper<TestV, TestE> wrapper = new MutableGDirectedGraphWrapper<>(g);
		TestV fakeRoot = vertex("Fake Root");
		TestE fakeEdge1 = new TestE(fakeRoot, v1);
		TestE fakeEdge2 = new TestE(fakeRoot, v2);

		wrapper.addEdge(fakeEdge1);
		wrapper.addEdge(fakeEdge2);

		//@formatter:off
		assertContainsEdgesExactly(wrapper,
								   e1, e2, e3, e4, e5,
								   fakeEdge1, fakeEdge2);
		
		assertContainsExactly(wrapper.getVertices(), v1, v2, v3, v4, v5, v6, fakeRoot);
		assertContainsExactly(g.getVertices(), v1, v2, v3, v4, v5, v6);
		//@formatter:on

		//
		// Exercise various methods that will call the new graph and the original graph
		//
		Collection<TestE> edges = wrapper.getOutEdges(fakeRoot);
		assertContainsExactly(edges, fakeEdge1, fakeEdge2);

		// check the out edges for a few nodes from the original graph
		edges = wrapper.getOutEdges(v1);
		assertContainsExactly(edges, e1);
		edges = wrapper.getOutEdges(v2);
		assertContainsExactly(edges, e4);

		edges = wrapper.getInEdges(fakeRoot);
		assertContainsExactly(edges);

		// check the out edges for a few nodes from the original graph
		edges = wrapper.getInEdges(v1);
		assertContainsExactly(edges, fakeEdge1);
		edges = wrapper.getInEdges(v2);
		assertContainsExactly(edges, fakeEdge2);
	}
}
