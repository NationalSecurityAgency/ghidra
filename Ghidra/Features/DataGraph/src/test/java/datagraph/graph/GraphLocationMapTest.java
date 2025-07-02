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
package datagraph.graph;

import static org.junit.Assert.*;

import java.awt.Point;

import org.junit.Test;

import datagraph.graph.explore.GraphLocationMap;

public class GraphLocationMapTest {

	private GraphLocationMap<TestVertex> map1;
	private GraphLocationMap<TestVertex> map2;

	@Test
	public void testInitialState() {
		TestVertex v = new TestVertex("A");
		assertEquals("A", v.getName());
		map1 = new GraphLocationMap<>(v, 10, 20);

		assertEquals(10, map1.getWidth());
		assertEquals(20, map1.getHeight());
		assertEquals(p(0, 0), map1.get(v));
	}

	@Test
	public void testMergeRight() {
		TestVertex a = new TestVertex("A");
		TestVertex b = new TestVertex("B");

		map1 = new GraphLocationMap<>(a, 10, 20);
		map2 = new GraphLocationMap<>(b, 100, 50);

		// merge maps left to right, shifting map2 by 1000
		map1.merge(map2, 1000, 0);

		assertEquals(1055, map1.getWidth());  // width of both maps + the gap
		assertEquals(50, map1.getHeight());	// height of the tallest map
		assertEquals(p(0, 0), map1.get(a)); // point in first map doesn't move
		assertEquals(p(1000, 0), map1.get(b));// point in second map moved by shift
	}

	@Test
	public void testMergeBottom() {
		TestVertex a = new TestVertex("A");
		TestVertex b = new TestVertex("B");

		map1 = new GraphLocationMap<>(a, 10, 20);
		map2 = new GraphLocationMap<>(b, 100, 50);

		// merge maps left to right, shifting map2 by 1000
		map1.merge(map2, 0, 1000);

		assertEquals(100, map1.getWidth());  // width of both maps + the gap
		assertEquals(1035, map1.getHeight());	// height of the tallest map
		assertEquals(p(0, 0), map1.get(a)); // point in first map doesn't move
		assertEquals(p(0, 1000), map1.get(b));// point in second map moved by shift
	}

	private Point p(int x, int y) {
		return new Point(x, y);
	}

	private class TestVertex {
		private String name;

		TestVertex(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}
	}
}
