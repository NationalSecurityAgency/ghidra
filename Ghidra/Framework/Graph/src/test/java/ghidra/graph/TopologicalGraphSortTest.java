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

import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import org.junit.Test;

public class TopologicalGraphSortTest extends AbstractGraphAlgorithmsTest {
	private Comparator<TestE> edgeComparator = (e1, e2) -> e1.toString().compareTo(e2.toString());

	@Override
	protected GDirectedGraph<TestV, TestE> createGraph() {
		return GraphFactory.createDirectedGraph();
	}

	@Test
	public void testSimpleGraph() {
		//   v1 -> v2 -> v3
		//    |
		//   v4 -> v5 -> v6

		TestV v1 = v(1);
		TestV v2 = v(2);
		TestV v3 = v(3);
		TestV v4 = v(4);
		TestV v5 = v(5);
		TestV v6 = v(6);
		e(v1, v2);
		e(v2, v3);
		e(v1, v4);
		e(v4, v5);
		e(v5, v6);

		List<TestV> sorted = GraphAlgorithms.topologicalSort(g, v1, edgeComparator);
		assertList(sorted, v1, v2, v3, v4, v5, v6);
	}

	@Test
	public void testGraphWithLoop() {
		//   v1 -> v2 -> v3 <----
		//    |	                 |
		//   v4 -> v5 -> v6      |
		//    |                  |
		//    |->---->----->-----|

		TestV v1 = v(1);
		TestV v2 = v(2);
		TestV v3 = v(3);
		TestV v4 = v(4);
		TestV v5 = v(5);
		TestV v6 = v(6);

		e(v1, v2);
		e(v2, v3);
		e(v1, v4);
		e(v4, v5);
		e(v5, v6);
		e(v4, v3);

		List<TestV> sorted = GraphAlgorithms.topologicalSort(g, v1, edgeComparator);
		assertList(sorted, v1, v2, v4, v3, v5, v6);

	}

	@Test
	public void testDoubleLoop() {
		//   V1 <- V4 <--------
		//    |     ^          ^
		//    v     |          |
		//   V2 -> V3 -> V5 -> V6

		TestV v1 = v(1);
		TestV v2 = v(2);
		TestV v3 = v(3);
		TestV v4 = v(4);
		TestV v5 = v(5);
		TestV v6 = v(6);

		e(v1, v2);
		e(v2, v3);
		e(v3, v4);
		e(v3, v5);
		e(v5, v6);
		e(v6, v4);
		e(v4, v1);

		List<TestV> sorted = GraphAlgorithms.topologicalSort(g, v1, edgeComparator);
		assertList(sorted, v1, v2, v3, v5, v6, v4);
	}

	@Test
	public void testInterleavedBranching() {

		/*
		 	 .<-v1->.
		 	 |   |  |
		 	 |  v4  |
		 	 |   |  |
		 	 >--v3  |
		 		 |  |
		 		v2--<
		 */
		TestV v1 = v(1);
		TestV v2 = v(2);
		TestV v3 = v(3);
		TestV v4 = v(4);

		e(v1, v3);
		e(v1, v4);
		e(v1, v2);
		e(v4, v3);
		e(v3, v2);

		List<TestV> sorted = GraphAlgorithms.topologicalSort(g, v1, edgeComparator);
		assertList(sorted, v1, v4, v3, v2);
	}

	@Test
	public void testMixedGraph() {

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

		TestV v1 = v(1);
		TestV v2 = v(2);
		TestV v3 = v(3);
		TestV v4 = v(4);
		TestV v5 = v(5);
		TestV v6 = v(6);
		TestV v7 = v(7);
		TestV v8 = v(8);
		TestV v9 = v(9);
		TestV v10 = v(10);
		TestV v11 = v(11);

		e(v1, v2);
		e(v2, v4);
		e(v4, v3);
		e(v4, v5);

		e(v5, v6);
		e(v5, v7);
		e(v6, v8);
		e(v6, v9);
		e(v7, v9);
		e(v8, v9);
		e(v9, v10);
		e(v9, v11);
		e(v11, v3);
		e(v11, v10);

		List<TestV> sorted = GraphAlgorithms.topologicalSort(g, v1, edgeComparator);
		assertList(sorted, v1, v2, v4, v5, v6, v8, v7, v9, v11, v10, v3);

	}

	private void assertList(List<TestV> sorted, TestV... vertices) {
		if (vertices.length != sorted.size()) {
			failed(sorted, vertices);
		}
		assertEquals(vertices.length, sorted.size());
		for (int i = 0; i < vertices.length; i++) {
			if (vertices[i] != sorted.get(i)) {
				failed(sorted, vertices);
			}
		}
	}

	private void failed(List<TestV> sorted, TestV[] vertices) {
		String expected =
			Arrays.stream(vertices).map(v -> v.toString()).collect(Collectors.joining(", "));
		String actual = sorted.stream().map(v -> v.toString()).collect(Collectors.joining(", "));
		fail("expected: \"" + expected + "\", but got: \"" + actual + "\"");
	}
}
