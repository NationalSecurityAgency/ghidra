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

import static org.junit.Assert.assertEquals;

import java.util.*;

import org.junit.Test;

import ghidra.graph.algo.DijkstraShortestPathsAlgorithm;
import ghidra.graph.jung.JungDirectedGraph;

public class DijkstraShortestPathsAlgorithmTest {
	private TestEdge AB;
	private TestEdge BC;
	private TestEdge AC;
	private TestGImplicitDirectedGraph<String, TestEdge> graph;

	private static class TestEdge implements GEdge<String> {
		private String start;
		private String end;

		public TestEdge(String start, String end) {
			this.start = start;
			this.end = end;
		}

		@Override
		public String getStart() {
			return start;
		}

		@Override
		public String getEnd() {
			return end;
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((end == null) ? 0 : end.hashCode());
			result = prime * result + ((start == null) ? 0 : start.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof TestEdge)) {
				return false;
			}
			TestEdge that = (TestEdge) obj;
			if (!this.start.equals(that.start)) {
				return false;
			}
			if (!this.end.equals(that.end)) {
				return false;
			}
			return true;
		}

		@Override
		public String toString() {
			return "(" + start + " -> " + end + ")";
		}
	}

	private static class TestWeightedEdge extends TestEdge implements GWeightedEdge<String> {
		private double weight;

		public TestWeightedEdge(String start, String end, double weight) {
			super(start, end);
			this.weight = weight;
		}

		@Override
		public double getWeight() {
			return weight;
		}
	}

	private static class TestGImplicitDirectedGraph<V, E extends GEdge<V>>
			extends JungDirectedGraph<V, E> implements GImplicitDirectedGraph<V, E> {
		// This class provides the default concrete graph, along with the interface the
		// algorithm under test needs
	}

	protected void constructThreeGraphUnweighted() {
		graph = new TestGImplicitDirectedGraph<>();
		graph.addVertex("A");
		graph.addVertex("B");
		graph.addVertex("C");

		AB = new TestEdge("A", "B");
		BC = new TestEdge("B", "C");
		AC = new TestEdge("A", "C");
		graph.addEdge(AB);
		graph.addEdge(BC);
		graph.addEdge(AC);
	}

	protected void constructThreeGraphWeighted() {
		graph = new TestGImplicitDirectedGraph<>();
		graph.addVertex("A");
		graph.addVertex("B");
		graph.addVertex("C");

		AB = new TestWeightedEdge("A", "B", 1);
		BC = new TestWeightedEdge("B", "C", 1);
		AC = new TestWeightedEdge("A", "C", 2);
		graph.addEdge(AB);
		graph.addEdge(BC);
		graph.addEdge(AC);
	}

	protected Set<Deque<TestEdge>> makePaths(TestEdge[]... paths) {
		Set<Deque<TestEdge>> result = new HashSet<>();
		for (TestEdge[] path : paths) {
			Deque<TestEdge> p = new LinkedList<>();
			for (TestEdge e : path) {
				p.add(e);
			}
			result.add(p);
		}
		return result;
	}

	@Test
	public void testExplicitGraphNoMaxUnit() {
		constructThreeGraphUnweighted();
		DijkstraShortestPathsAlgorithm<String, TestEdge> dijkstra =
			new DijkstraShortestPathsAlgorithm<>(graph, GEdgeWeightMetric.unitMetric());

		assertEquals(makePaths(new TestEdge[] { AC }), dijkstra.computeOptimalPaths("A", "C"));
		assertEquals(makePaths(), dijkstra.computeOptimalPaths("C", "A"));
	}

	@Test(expected = ClassCastException.class)
	public void testUnweightedNoMetricError() {
		constructThreeGraphUnweighted();
		DijkstraShortestPathsAlgorithm<String, TestEdge> dijkstra =
			new DijkstraShortestPathsAlgorithm<>(graph);

		dijkstra.computeOptimalPaths("A", "C");
	}

	@Test
	public void testExplicitWeightedMultiple() {
		constructThreeGraphWeighted();
		DijkstraShortestPathsAlgorithm<String, TestEdge> dijkstra =
			new DijkstraShortestPathsAlgorithm<>(graph);

		assertEquals(makePaths(new TestEdge[] { AC }, new TestEdge[] { AB, BC }),
			dijkstra.computeOptimalPaths("A", "C"));
	}

	@Test
	public void testExplicitWeightedMax() {
		constructThreeGraphWeighted();
		DijkstraShortestPathsAlgorithm<String, TestEdge> dijkstra =
			new DijkstraShortestPathsAlgorithm<>(graph, 1d);

		assertEquals(makePaths(), dijkstra.computeOptimalPaths("A", "C"));
		assertEquals(makePaths(new TestEdge[] { AB }), dijkstra.computeOptimalPaths("A", "B"));
		assertEquals(makePaths(new TestEdge[] { BC }), dijkstra.computeOptimalPaths("B", "C"));
		assertEquals(makePaths(), dijkstra.computeOptimalPaths("C", "A"));
	}

	public enum CollatzOp {
		INV_DIV2, INV_MUL3_ADD1, SQR /* Not really Collatz, but provides multiple paths */;
	}

	public class CollatzEdge implements GEdge<Integer> {
		private int start;
		private int end;
		private CollatzOp op;

		public CollatzEdge(int start, CollatzOp op, int end) {
			this.start = start;
			this.end = end;
			this.op = op;
		}

		@Override
		public Integer getStart() {
			return start;
		}

		@Override
		public Integer getEnd() {
			return end;
		}

		@Override
		public String toString() {
			return op.name() + "(" + start + ")=" + end;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == null) {
				return false;
			}
			return this.toString().equals(obj.toString());
		}

		@Override
		public int hashCode() {
			return this.toString().hashCode();
		}
	}

	/**
	 * A silly infinite graph based loosely on the Collatz conjecture
	 */
	public class CollatzGraph implements GImplicitDirectedGraph<Integer, CollatzEdge> {
		@Override
		public Collection<CollatzEdge> getInEdges(Integer v) {
			throw new UnsupportedOperationException();
		}

		@Override
		public Collection<CollatzEdge> getOutEdges(Integer v) {
			Set<CollatzEdge> result = new HashSet<>();
			int r = v * 2;
			if (r >= 0) {
				result.add(new CollatzEdge(v, CollatzOp.INV_DIV2, v * 2));
			}
			r = v * v;
			if (r >= 0) {
				result.add(new CollatzEdge(v, CollatzOp.SQR, v * v));
			}
			r = v - 1;
			if (r % 3 == 0) {
				result.add(new CollatzEdge(v, CollatzOp.INV_MUL3_ADD1, r / 3));
			}
			return result;
		}

		@Override
		public GDirectedGraph<Integer, CollatzEdge> copy() {
			throw new UnsupportedOperationException();
		}
	}

	protected Set<Deque<CollatzEdge>> makeCollatzPaths(int start, CollatzOp[]... paths) {
		Set<Deque<CollatzEdge>> result = new HashSet<>();
		for (CollatzOp[] path : paths) {
			int cur = start;
			Deque<CollatzEdge> p = new LinkedList<>();
			for (CollatzOp op : path) {
				int next = 0;
				switch (op) {
					case INV_DIV2:
						next = cur * 2;
						break;
					case INV_MUL3_ADD1:
						next = (cur - 1) / 3;
						break;
					case SQR:
						next = cur * cur;
				}
				p.add(new CollatzEdge(cur, op, next));
				cur = next;
			}
			result.add(p);
		}
		return result;
	}

	@Test
	public void testImplicit() {
		DijkstraShortestPathsAlgorithm<Integer, CollatzEdge> dijkstra =
			new DijkstraShortestPathsAlgorithm<>(new CollatzGraph(), 10d,
				GEdgeWeightMetric.unitMetric());
		Collection<Deque<CollatzEdge>> opt = dijkstra.computeOptimalPaths(1, 10);
		Collection<Deque<CollatzEdge>> exp = makeCollatzPaths(1, //
			new CollatzOp[] { CollatzOp.INV_DIV2, CollatzOp.INV_DIV2, CollatzOp.SQR,
				CollatzOp.INV_MUL3_ADD1, CollatzOp.INV_DIV2 }, //
			new CollatzOp[] { CollatzOp.INV_DIV2, CollatzOp.SQR, CollatzOp.SQR,
				CollatzOp.INV_MUL3_ADD1, CollatzOp.INV_DIV2 });
		assertEquals(exp, opt);
	}
}
