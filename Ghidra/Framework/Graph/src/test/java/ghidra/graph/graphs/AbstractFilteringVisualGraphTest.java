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

import static org.junit.Assert.*;

import java.util.*;

import util.CollectionUtils;

public abstract class AbstractFilteringVisualGraphTest {

	protected FilteringVisualGraph<AbstractTestVertex, TestEdge> graph;

	protected void assertNoEdgesFiltered() {
		assertEquals(0, sizeOf(getFilteredEdges()));
	}

	protected void assertNoVerticesFiltered() {
		assertEquals(0, sizeOf(getFilteredVertices())); // no vertices were filtered
	}

	protected void assertFiltered(TestEdge... edges) {
		for (TestEdge e : edges) {
			assertTrue("Edge is should have been filtered: " + e, getFilteredEdges().contains(e));
			assertTrue("Edge is not in the unfiltered graph: " + e, getAllEdges().contains(e));
		}
	}

	protected void assertUnfiltered(TestEdge... edges) {

		Collection<TestEdge> filteredEdges = getFilteredEdges();
		Collection<TestEdge> allEdges = getAllEdges();
		for (TestEdge e : edges) {
			assertFalse("Edge should not have been filtered: " + e, filteredEdges.contains(e));
			assertTrue("Edge is not in the unfiltered graph: " + e, allEdges.contains(e));
		}
	}

	protected void assertFiltered(AbstractTestVertex... vertices) {

		Collection<AbstractTestVertex> filteredVertices = getFilteredVertices();
		Collection<AbstractTestVertex> allVertices = getAllVertices();
		for (AbstractTestVertex v : vertices) {
			assertTrue("Vertex is should have been filtered: " + v, filteredVertices.contains(v));
			assertTrue("Vertex is not in the unfiltered graph: " + v, allVertices.contains(v));
		}
	}

	protected void assertOnlyTheseAreFiltered(AbstractTestVertex... vertices) {

		Collection<AbstractTestVertex> filteredVertices = getFilteredVertices();
		Collection<AbstractTestVertex> allVertices = getAllVertices();
		assertEquals(vertices.length, filteredVertices.size());
		for (AbstractTestVertex v : vertices) {
			assertTrue("Vertex is should have been filtered: " + v, filteredVertices.contains(v));
			assertTrue("Vertex is not in the unfiltered graph: " + v, allVertices.contains(v));
		}
	}

	protected void assertOnlyTheseAreFiltered(TestEdge... edges) {

		Collection<TestEdge> filteredEdges = getFilteredEdges();
		Collection<TestEdge> allEdges = getAllEdges();
		assertEquals(edges.length, filteredEdges.size());
		for (TestEdge e : edges) {

			assertTrue("Edge is should have been filtered: " + e, filteredEdges.contains(e));
			assertTrue("Edge is not in the unfiltered graph: " + e, allEdges.contains(e));
		}
	}

	protected void assertUnfiltered(AbstractTestVertex... vertices) {
		for (AbstractTestVertex v : vertices) {
			assertTrue("Vertex should not have been filtered: " + v,
				getUnfilteredVertices().contains(v));
			assertTrue("Vertex is not in the unfiltered graph: " + v, getAllVertices().contains(v));
		}
	}

	protected void assertNotInGraph(AbstractTestVertex... vertices) {
		for (AbstractTestVertex v : vertices) {
			assertFalse("Vertex should not be in the graph at all: " + v,
				getAllVertices().contains(v));
		}
	}

	protected void assertNotInGraph(TestEdge... edges) {
		for (TestEdge e : edges) {
			assertFalse("Edge should not be in the graph at all: " + e, getAllEdges().contains(e));
		}
	}

	protected Set<AbstractTestVertex> getFilteredVertices() {
		return CollectionUtils.asSet(graph.getFilteredVertices());
	}

	protected Set<AbstractTestVertex> getUnfilteredVertices() {
		return CollectionUtils.asSet(graph.getUnfilteredVertices());
	}

	protected Set<AbstractTestVertex> getAllVertices() {
		return CollectionUtils.asSet(graph.getAllVertices());
	}

	protected Set<TestEdge> getFilteredEdges() {
		return CollectionUtils.asSet(graph.getFilteredEdges());
	}

	protected Set<TestEdge> getUnfilteredEdges() {
		return CollectionUtils.asSet(graph.getUnfilteredEdges());
	}

	protected Set<TestEdge> getAllEdges() {
		return CollectionUtils.asSet(graph.getAllEdges());
	}

	protected AbstractTestVertex vertex(String id) {
		LabelTestVertex v = new LabelTestVertex(id);
		List<AbstractTestVertex> allVertices = CollectionUtils.asList(graph.getAllVertices());
		int index = allVertices.indexOf(v);
		if (index >= 0) {
			// always prefer the existing vertices
			return allVertices.get(index);
		}

		graph.addVertex(v);
		return v;
	}

	protected TestEdge edge(AbstractTestVertex start, AbstractTestVertex end) {
		List<TestEdge> allEdges = CollectionUtils.asList(graph.getAllEdges());
		TestEdge e = new TestEdge(start, end);
		int index = allEdges.indexOf(e);
		if (index >= 0) {
			// always prefer the existing edges
			return allEdges.get(index);
		}

		graph.addEdge(e);
		return e;
	}

	protected int sizeOf(Collection<?> c) {
		return c.size();
	}

}
