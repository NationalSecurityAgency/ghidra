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
package ghidra.service.graph;

import static org.junit.Assert.*;

import java.util.Set;

import org.junit.Before;
import org.junit.Test;

public class AttributedGraphTest {

	private AttributedGraph graph;

	@Before
	public void setup() {
		graph = new AttributedGraph("Test", new EmptyGraphType());
	}

	@Test
	public void testAddVertex() {
		AttributedVertex v = graph.addVertex();
		assertTrue(graph.containsVertex(v));
		assertEquals(1, graph.getVertexCount());
	}

	@Test
	public void testAddVertexTwice() {
		AttributedVertex v = graph.addVertex();
		assertFalse(graph.addVertex(v));
		assertEquals(1, graph.getVertexCount());
	}

	@Test
	public void testAddVertexWithId() {
		AttributedVertex v = graph.addVertex("A");
		assertTrue(graph.containsVertex(v));
		assertEquals(1, graph.getVertexCount());
		assertEquals("A", v.getId());
		assertEquals("A", v.getName());
	}

	@Test
	public void testAddVertexWithIdAndName() {
		AttributedVertex v = graph.addVertex("A", "Bob");
		assertTrue(graph.containsVertex(v));
		assertEquals(1, graph.getVertexCount());
		assertEquals("A", v.getId());
		assertEquals("Bob", v.getName());
	}

	@Test
	public void testAddVertexWithExistingVertex() {
		AttributedVertex v = new AttributedVertex("A");
		graph.addVertex(v);
		assertTrue(graph.containsVertex(v));
		assertEquals(1, graph.getVertexCount());
		assertEquals("A", v.getId());
	}

	@Test
	public void testAddDuplicateVertex() {
		AttributedVertex v1 = graph.addVertex("A");
		AttributedVertex v2 = graph.addVertex("A");

		assertEquals(1, graph.getVertexCount());
		assertTrue(v1 == v2);
	}

	@Test
	public void testAddDuplicateVertexWithDifferentName() {
		AttributedVertex v1 = graph.addVertex("A", "Bob");
		AttributedVertex v2 = graph.addVertex("A", "Joe");

		assertEquals(1, graph.getVertexCount());
		assertTrue(v1 == v2);
		assertEquals("Joe", v2.getName());
	}

	@Test
	public void testAddEdge() {
		AttributedVertex v1 = graph.addVertex("A", "Bob");
		AttributedVertex v2 = graph.addVertex("B", "Joe");
		AttributedEdge e = graph.addEdge(v1, v2);
		assertEquals(1, graph.getEdgeCount());
		assertEquals(v1, graph.getEdgeSource(e));
		assertEquals(v2, graph.getEdgeTarget(e));
	}

	@Test
	public void testAddExistingEdge() {
		AttributedVertex v1 = graph.addVertex("A", "Bob");
		AttributedVertex v2 = graph.addVertex("B", "Joe");
		AttributedEdge e = new AttributedEdge("E1");
		assertTrue(graph.addEdge(v1, v2, e));

		assertEquals(1, graph.getEdgeCount());
		assertEquals(v1, graph.getEdgeSource(e));
		assertEquals(v2, graph.getEdgeTarget(e));
	}

	@Test
	public void testAddEdgeWithId() {
		AttributedVertex v1 = graph.addVertex("A", "Bob");
		AttributedVertex v2 = graph.addVertex("B", "Joe");
		AttributedEdge e = graph.addEdge(v1, v2, "X");

		assertEquals(1, graph.getEdgeCount());
		assertEquals(v1, graph.getEdgeSource(e));
		assertEquals(v2, graph.getEdgeTarget(e));
		assertEquals("X", e.getId());
	}

	@Test
	public void testCanAddEdgeWithVerticesNotInGraph() {
		AttributedVertex v1 = new AttributedVertex("A", "Bob");
		AttributedVertex v2 = new AttributedVertex("B", "Joe");

		AttributedEdge e = graph.addEdge(v1, v2);

		assertEquals(2, graph.getVertexCount());
		assertEquals(1, graph.getEdgeCount());

		assertTrue(graph.containsVertex(v1));
		assertTrue(graph.containsVertex(v2));
	}

	@Test
	public void testGetVertexById() {

		// create a vertex with all the possible ways
		AttributedVertex v1 = graph.addVertex("A");
		AttributedVertex v2 = graph.addVertex("B", "NAME");
		AttributedVertex v3 = graph.addVertex();
		AttributedVertex v4 = new AttributedVertex("C");
		graph.addVertex(v4);

		Set<AttributedVertex> vertexSet = graph.vertexSet();
		assertEquals(4, vertexSet.size());

		// make sure all vertices were added to the id to vertex map
		assertEquals(v1, graph.getVertex("A"));
		assertEquals(v2, graph.getVertex("B"));
		assertEquals(v3, graph.getVertex(v3.getId()));
		assertEquals(v4, graph.getVertex("C"));

	}

	@Test
	public void testCollapseDuplicateEdges() {
		AttributedVertex v1 = graph.addVertex("A");
		AttributedVertex v2 = graph.addVertex("B");

		graph.addEdge(v1, v2);
		graph.addEdge(v1, v2);
		graph.addEdge(v1, v2);

		assertEquals(1, graph.getEdgeCount());

		assertEquals("3", graph.getEdge(v1, v2).getAttribute("Weight"));
	}

	@Test
	public void testCollapseDuplicateEdgesWithSuppliedEdges() {
		AttributedVertex v1 = graph.addVertex("A");
		AttributedVertex v2 = graph.addVertex("B");

		graph.addEdge(v1, v2, new AttributedEdge("1"));
		graph.addEdge(v1, v2, new AttributedEdge("2"));
		graph.addEdge(v1, v2, new AttributedEdge("3"));

		assertEquals(1, graph.getEdgeCount());

		AttributedEdge edge = graph.getEdge(v1, v2);
		assertEquals("3", edge.getAttribute("Weight"));
		assertEquals("1", edge.getId());
	}

	@Test
	public void testNonCollapsingEdges() {
		graph = new AttributedGraph("Test", new EmptyGraphType(), "Test", false);

		AttributedVertex v1 = graph.addVertex("A");
		AttributedVertex v2 = graph.addVertex("B");

		graph.addEdge(v1, v2);
		graph.addEdge(v1, v2);
		graph.addEdge(v1, v2, new AttributedEdge("x"));

		assertEquals(3, graph.getEdgeCount());
	}

	@Test
	public void testReverseEdgesDontCollapse() {
		AttributedVertex v1 = graph.addVertex("A");
		AttributedVertex v2 = graph.addVertex("B");

		graph.addEdge(v1, v2);
		graph.addEdge(v2, v1);

		assertEquals(2, graph.getEdgeCount());
	}

}
