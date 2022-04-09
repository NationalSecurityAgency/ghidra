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

import org.junit.Before;
import org.junit.Test;

public class GraphPathTest {

	private GraphPath<Integer> graphPath;

	/**
	 * Setup to have a new GraphPath instance for every test that is filled with 21 vertices.
	 */
	@Before
	public void setUp() {
		graphPath = new GraphPath<>();
		for (int i = 0; i <= 20; i++) {
			graphPath.add(i);
		}
	}

	/**
	 * Test to verify if copy() function works correctly. Reinitializes the GraphPath object and
	 * adds three vertices to it. GraphPath is then copied and with assertions the test checks if
	 * all three vertices exist in the copy, and that they are the only vertices in the GraphPath.
	 */
	@Test
	public void testCopy() {
		graphPath = new GraphPath<>();

		graphPath.add(1);
		graphPath.add(2);
		graphPath.add(3);

		GraphPath<Integer> graphPathCopy = graphPath.copy();

		assertTrue(graphPathCopy.contains(1));
		assertTrue(graphPathCopy.contains(2));
		assertTrue(graphPathCopy.contains(3));
		assertEquals(3, graphPathCopy.size());
	}

	/**
	 * Test to verify if startsWith() function works correctly. A smaller GraphPath is given as an
	 * argument in this test. Asserts check if the startsWith() function returns true, when the
	 * GraphPath actually starts with the GraphPath passed in the parameter. Also check if false
	 * is returned with a GraphPath that the GraphPath object does not start with.
	 */
	@Test
	public void testStartsWith_SmallerGraphPath() {
		GraphPath<Integer> graphPathStart = new GraphPath<>();
		for (int i = 0; i < 5; i++) {
			graphPathStart.add(i);
		}

		assertTrue(graphPath.startsWith(graphPathStart));
		assertFalse(graphPath.startsWith(new GraphPath<>(6)));
	}

	/**
	 * Test to verify if startsWith() function works correctly. A larger GraphPath is given as an
	 * argument in this test. Asserts check if the startsWith() function returns false, when the
	 * GraphPath in the argument is larger than the GraphPath object.
	 */
	@Test
	public void testStartsWith_LargerGraphPath() {
		GraphPath<Integer> largerGraphPath = new GraphPath<>();
		for (int i = 0; i < 25; i++) {
			largerGraphPath.add(i);
		}

		assertFalse(graphPath.startsWith(largerGraphPath));
	}

	/**
	 * Test to verify if getCommonStartPath() function works correctly.
	 */
	@Test
	public void testGetCommonStartPath() {
		GraphPath<Integer> sharedStartPath = new GraphPath<>();
		for (int i = 0; i < 10; i++) {
			sharedStartPath.add(i);
		}

		GraphPath<Integer> differentPath = sharedStartPath.copy();
		for (int i = 90; i < 100; i++) {
			differentPath.add(i);
		}

		GraphPath<Integer> commonStartPathResult =
			sharedStartPath.getCommonStartPath(differentPath);
		for (int i = 0; i < commonStartPathResult.size(); i++) {
			assertEquals(sharedStartPath.get(i), commonStartPathResult.get(i));
		}

		assertEquals(sharedStartPath.size(), commonStartPathResult.size());
	}

	@Test
	public void testSize() {
		graphPath = new GraphPath<>();
		graphPath.add(1);
		graphPath.add(2);
		graphPath.add(3);

		assertEquals(3, graphPath.size());
	}

	@Test
	public void testContains() {
		Random r = new Random();
		int randomInt = r.nextInt(1000);
		graphPath.add(randomInt);
		assertTrue(graphPath.contains(randomInt));
		assertFalse(graphPath.contains(1001));

		randomInt = r.nextInt(1000);
		graphPath.add(randomInt);
		assertTrue(graphPath.contains(randomInt));
		assertFalse(graphPath.contains(1001));
	}

	/**
	 * Test to verify if getLast() function works correctly. At setUp() a GraphPath is created
	 * containing 21 vertices, with the last vertex having integer 20. Assert checks if getLast()
	 * function returns 20, since it is the last vertex in the GraphPath.
	 */
	@Test
	public void testGetLast() {
		assertEquals(20, (int) graphPath.getLast());
	}

	/**
	 * Test to verify if depth() function works correctly. At setUp() a GraphPath is created
	 * containing 21 vertices, with the last vertex having integer 20. A random vertex is selected
	 * from the GraphPath. Since in the test cases the depth is equal to the vertex its integer,
	 * an assertEquals with the two is performed.
	 */
	@Test
	public void testDepth() {
		Random r = new Random();
		int randomInt = r.nextInt(graphPath.size());
		assertEquals(randomInt, graphPath.depth(randomInt));
	}

	/**
	 * Test to verify if get() function works correctly. At setUp() a GraphPath is created
	 * containing 21 vertices, with the last vertex having integer 20. A random vertex is selected
	 * from the GraphPath. Since in the test cases the index is equal to the vertex its integer,
	 * an assertEquals with the two is performed.
	 */
	@Test
	public void testGet() {
		Random r = new Random();
		int randomInt = r.nextInt(graphPath.size());
		assertEquals(randomInt, (int) graphPath.get(randomInt));
	}

	/**
	 * Test to verify if removeLast() function works correctly. At setUp() a GraphPath is created
	 * containing 21 vertices, with the last vertex having integer 20. Assert checks if this is the
	 * case. Second assert checks if 20 is again returned when removeLast() is called. Final assert
	 * checks if now getLast() returns 19, to check if removeLast() actually worked.
	 */
	@Test
	public void tetRemoveLast() {
		assertEquals(20, (int) graphPath.getLast());
		assertEquals(20, (int) graphPath.removeLast());
		assertEquals(19, (int) graphPath.getLast());
	}

	/**
	 * Test to verify if getPredecessors() function works correctly. At setUp() a GraphPath is
	 * created containing 21 vertices, with the last vertex having integer 20. This test creates a
	 * new set with integers 0-10. Then assertEquals checks if the set returned by
	 * getPredecessors() is equal as this set.
	 */
	@Test
	public void testGetPredecessors() {
		Set<Integer> predecessors = new HashSet<>();
		for (int i = 0; i <= 10; i++) {
			predecessors.add(i);
		}

		Set<Integer> predecessorsSet = graphPath.getPredecessors(10);
		assertEquals(predecessors, predecessorsSet);
	}

	/**
	 * Test to verify if getPredecessors() function works correctly. At setUp() a GraphPath is
	 * created containing 21 vertices, with the last vertex having integer 20. Assert checks if
	 * getPredecessors() returns an empty HashSet whenever it is called with a larger index than
	 * the amount of vertices contained in the GraphPath.
	 */
	@Test
	public void testGetPredecessors_LargerIndex() {
		Set<Integer> predecessorsSet = graphPath.getPredecessors(21);
		assertEquals(0, predecessorsSet.size());
	}

	/**
	 * Test to verify if getSuccessors() function works correctly. At setUp() a GraphPath is
	 * created containing 21 vertices, with the last vertex having integer 20. This test creates a
	 * new set with integers 10-20. Then assertEquals checks if the set returned by
	 * getSuccessors() is the same as this set.
	 */
	@Test
	public void testGetSuccessors() {
		Set<Integer> successors = new HashSet<>();
		for (int i = 10; i <= 20; i++) {
			successors.add(i);
		}

		Set<Integer> successorsSet = graphPath.getSuccessors(10);
		assertEquals(successors, successorsSet);
	}

	/**
	 * Test to verify if getPredecessors() function works correctly. At setUp() a GraphPath is
	 * created containing 21 vertices, with the last vertex having integer 20. Assert checks if
	 * getSuccessors() returns an empty HashSet whenever it is called with a larger index than
	 * the amount of vertices contained in the GraphPath.
	 */
	@Test
	public void testGetSuccessors_LargerIndex() {
		Set<Integer> successorsSet = graphPath.getSuccessors(graphPath.size());
		assertEquals(0, successorsSet.size());
	}
}
