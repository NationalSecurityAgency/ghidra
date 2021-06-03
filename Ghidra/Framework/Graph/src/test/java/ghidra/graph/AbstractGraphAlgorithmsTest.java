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

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.*;

import org.junit.Assert;
import org.junit.Before;

import generic.test.AbstractGenericTest;
import ghidra.graph.algo.ChkDominanceAlgorithm;
import ghidra.graph.algo.ChkPostDominanceAlgorithm;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractGraphAlgorithmsTest extends AbstractGenericTest {

	protected GDirectedGraph<TestV, TestE> g;

	@Before
	public void setUp() throws Exception {
		g = createGraph();
	}

	protected abstract GDirectedGraph<TestV, TestE> createGraph();

	@SuppressWarnings("unchecked") // no heap violation
	protected <V, E extends GEdge<V>> void assertContainsEdgesExactly(GDirectedGraph<V, E> dg,
			E... edges) {

		Collection<E> dominanceEdges = dg.getEdges();
		assertContainsExactly(dominanceEdges, edges);

	}

	@SuppressWarnings("unchecked")
	protected <V, E extends GEdge<V>> E resultEdge(TestV v1, TestV v2) {
		return (E) new DefaultGEdge<>(v1, v2);
	}

	protected void startMemoryMonitorThread(boolean doIt) {

		if (!doIt) {
			return;
		}

		Thread t = new Thread(() -> {

			while (true) {

				sleep(1000);
				printMemory();
			}

		}, "Memory Monitor");

		t.setDaemon(true);
		t.start();
	}

	protected TestV[] generateSimplyConnectedGraph(int nVertices) {
		TestV[] vertices = new TestV[nVertices];
		for (int i = 0; i < nVertices; i++) {
			vertices[i] = vertex(i);
		}
		for (int i = 0; i < nVertices - 1; i++) {
			edge(vertices[i], vertices[i + 1]);
		}
		return vertices;
	}

	protected TestV[] generateCompletelyConnectedGraph(int nVertices) {
		TestV[] vertices = new TestV[nVertices];
		for (int i = 0; i < nVertices; i++) {
			vertices[i] = vertex(i);
		}
		for (int i = 0; i < nVertices; i++) {
			for (int j = 0; j < nVertices; j++) {
				if (i != j) {
					edge(vertices[i], vertices[j]);
				}
			}
		}
		return vertices;
	}

	protected TestV[] generateHalflyConnectedGraph(int nVertices) {
		TestV[] vertices = new TestV[nVertices];
		for (int i = 0; i < nVertices; i++) {
			vertices[i] = vertex(i);
		}

		// at least one straight line through the graph
		for (int i = 0; i < nVertices - 1; i++) {
			edge(vertices[i], vertices[i + 1]);
		}

		// extra connections
		int n = (nVertices / 2) + (nVertices / 4);
		for (int i = 0; i < nVertices; i++) {
			for (int j = 0; j < n; j++) {
				if (i != j) {
					edge(vertices[i], vertices[j]);
				}
			}
		}
		return vertices;
	}

	protected TestV[] generateHalflyConnectedGraphNoBacktracking(int nVertices) {
		TestV[] vertices = new TestV[nVertices];
		for (int i = 0; i < nVertices; i++) {
			vertices[i] = vertex(i);
		}

		// at least one straight line through the graph
		for (int i = 0; i < nVertices - 1; i++) {
			edge(vertices[i], vertices[i + 1]);
		}

		// extra connections
		int n = (nVertices / 2) + (nVertices / 4);
		for (int i = 0; i < nVertices; i++) {
			for (int j = i; j < n; j++) {
				if (i != j) {
					edge(vertices[i], vertices[j]);
				}
			}
		}
		return vertices;
	}

	protected void assertOrder(List<TestV> postOrder, TestV v1, TestV v2) {
		int index1 = postOrder.indexOf(v1);
		int index2 = postOrder.indexOf(v2);
		assertTrue("Expected " + v1 + " before " + v2, index1 < index2);
	}

	protected void assertStrongGraph(Collection<Set<TestV>> stronglyConnectedComponents,
			TestV... vertices) {
		int size = vertices.length;
		for (Set<TestV> set : stronglyConnectedComponents) {
			if (set.size() == size) {
				assertContainsExactly(set, vertices);
				return;
			}
		}

		Assert.fail("Unexpected set size");
	}

	protected TestV vertex(int id) {
		return new TestV(id);
	}

	protected TestV vertex(String id) {
		return new TestV(id);
	}

	protected TestE edge(TestV start, TestV end) {
		TestE e = new TestE(start, end);
		g.addEdge(e);
		return e;
	}

	protected String id(TestV v) {
		return v.id;
	}

	protected Set<TestV> set(TestV... vertices) {
		HashSet<TestV> set = new HashSet<>();
		for (TestV v : vertices) {
			set.add(v);
		}
		return set;
	}

	// returns those nodes dominated by 'from'
	protected Collection<TestE> findDominance(TestV from,
			ChkDominanceAlgorithm<TestV, TestE> algo) {
		Set<TestV> dominated = algo.getDominated(from);
		Set<TestE> filtered = GraphAlgorithms.retainEdges(g, dominated);
		return filtered;
	}

	// returns those nodes dominated by 'from'
	protected Collection<TestE> findPostDominance(TestV from,
			ChkPostDominanceAlgorithm<TestV, TestE> algo) {
		Set<TestV> dominated = algo.getDominated(from);
		Set<TestE> filtered = GraphAlgorithms.retainEdges(g, dominated);
		return filtered;
	}

	// returns those nodes post-dominated by 'from'
	protected Collection<TestE> findPostDominance(TestV from) {

		try {
			Set<TestV> postDominated =
				GraphAlgorithms.findPostDominance(g, from, TaskMonitor.DUMMY);
			Set<TestE> filtered = GraphAlgorithms.retainEdges(g, postDominated);
			return filtered;
		}
		catch (CancelledException e) {
			// can't happen; dummy monitor
			fail("Someone changed my monitor!!");
		}

		return null;
	}

	protected void assertPathExists(List<List<TestV>> paths, TestV... vertices) {

		List<TestV> expectedPath = List.of(vertices);
		for (List<TestV> path : paths) {
			if (path.equals(expectedPath)) {
				return;
			}
		}
		fail("List of paths does not contain: " + expectedPath + "\n\tactual paths: " + paths);
	}

	@SafeVarargs
	protected final <V> void assertListEqualsOneOf(List<V> actual, List<V>... expected) {

		StringBuilder buffy = new StringBuilder();
		for (List<V> list : expected) {
			if (areListsEquals(actual, list)) {
				return;
			}
			buffy.append(list.toString());
		}
		fail("Expected : " + buffy + "\nActual: " + actual);
	}

	private <V> boolean areListsEquals(List<V> l1, List<V> l2) {
		return l1.equals(l2);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================	

	protected static class TestV {

		private String id;

		public TestV(String id) {
			this.id = id;
		}

		public TestV(int id) {
			this.id = Integer.toString(id);
		}

		@Override
		public String toString() {
			return id;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((id == null) ? 0 : id.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}
			if (obj == null) {
				return false;
			}
			if (getClass() != obj.getClass()) {
				return false;
			}

			TestV other = (TestV) obj;
			if (!Objects.equals(id, other.id)) {
				return false;
			}
			return true;
		}
	}

	protected static class TestE extends DefaultGEdge<TestV> {

		public TestE(TestV start, TestV end) {
			super(start, end);
		}
	}
}
