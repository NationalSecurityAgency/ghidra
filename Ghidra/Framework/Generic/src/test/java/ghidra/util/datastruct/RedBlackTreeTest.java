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
package ghidra.util.datastruct;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class RedBlackTreeTest extends AbstractGenericTest {
	RedBlackTree<Integer, String> tree;

	public RedBlackTreeTest() {
		super();
	}

    @Before
    public void setUp() throws Exception {
		tree = new RedBlackTree<Integer, String>();

		tree.put(5, "five");
		tree.put(10, "ten");
		tree.put(3, "three");
		tree.put(7, "seven");
		tree.put(1, "one");
		tree.put(9, "nine");
		tree.put(2, "two");
		tree.put(6, "six");
		tree.put(4, "four");

	}

@Test
    public void testSize() {
		assertEquals(9, tree.size());
	}

@Test
    public void testContains() {
		assertTrue(tree.containsKey(1));
		assertTrue(tree.containsKey(2));
		assertTrue(tree.containsKey(3));
		assertTrue(tree.containsKey(4));
		assertTrue(tree.containsKey(5));
		assertTrue(tree.containsKey(6));
		assertTrue(tree.containsKey(7));
		assertTrue(tree.containsKey(9));
		assertTrue(tree.containsKey(10));

		assertTrue(!tree.containsKey(0));
		assertTrue(!tree.containsKey(11));
		assertTrue(!tree.containsKey(8));

	}

@Test
    public void testGetFirstLast() {
		RedBlackEntry<Integer, String> node = tree.getFirst();
		assertEquals(1, (int) node.getKey());

		node = tree.getLast();
		assertEquals(10, (int) node.getKey());

	}

//
//	public void testGetPrevious() {
//		RedBlackNode<Integer, String> node = tree.getPrevious(12);
//		assertEquals(10, (int) node.getKey());
//		node = tree.getPrevious(9);
//		assertEquals(7, (int) node.getKey());
//		node = tree.getPrevious(8);
//		assertEquals(7, (int) node.getKey());
//
//		node = tree.getPrevious(3);
//		assertEquals(2, (int) node.getKey());
//
//		node = tree.getPrevious(1);
//		assertEquals(null, node);
//		node = tree.getPrevious(-5);
//		assertEquals(null, node);
//
//		node = treeWithDups.getPrevious(12);
//		assertEquals(10, (int) node.getKey());
//		node = treeWithDups.getPrevious(9);
//		assertEquals(7, (int) node.getKey());
//		node = treeWithDups.getPrevious(8);
//		assertEquals(7, (int) node.getKey());
//
//		node = treeWithDups.getPrevious(3);
//		assertEquals(2, (int) node.getKey());
//
//		node = treeWithDups.getPrevious(1);
//		assertEquals(null, node);
//		node = treeWithDups.getPrevious(-5);
//		assertEquals(null, node);
//
//	}

@Test
    public void testGetNextNode() {
		RedBlackEntry<Integer, String> node = tree.getFirst();
		assertEquals("one", node.value);
		node = node.getSuccessor();
		assertEquals("two", node.value);
		node = node.getSuccessor();
		assertEquals("three", node.value);
		node = node.getSuccessor();
		assertEquals("four", node.value);
		node = node.getSuccessor();
		assertEquals("five", node.value);
		node = node.getSuccessor();
		assertEquals("six", node.value);
		node = node.getSuccessor();
		assertEquals("seven", node.value);
		node = node.getSuccessor();
		assertEquals("nine", node.value);
		node = node.getSuccessor();
		assertEquals("ten", node.value);
		node = node.getSuccessor();
		assertNull(node);

	}

@Test
    public void testRemove() {
		assertEquals(9, tree.size());
		tree.remove(5);
		assertEquals(8, tree.size());

	}

@Test
    public void testDepth() {
		tree = new RedBlackTree<Integer, String>();
		tree.put(1, "one");
		tree.put(2, "two");
		tree.put(3, "three");
		tree.put(4, "four");
		tree.put(5, "five");
		tree.put(6, "six");
		tree.put(7, "seven");
		tree.put(8, "eight");
		tree.put(9, "nine");
		tree.put(10, "ten");

		assertEquals(4, getTreeDepth(tree));

		tree = new RedBlackTree<Integer, String>();
		tree.put(10, "ten");
		tree.put(9, "nine");
		tree.put(8, "eight");
		tree.put(7, "seven");
		tree.put(6, "six");
		tree.put(5, "five");
		tree.put(4, "four");
		tree.put(3, "three");
		tree.put(2, "two");
		tree.put(1, "one");

		assertEquals(4, getTreeDepth(tree));

	}

	private int getTreeDepth(RedBlackTree<Integer, String> rbTree) {
		int treeDepth = 0;
		RedBlackEntry<Integer, String> node = rbTree.getFirst();
		while (node != null) {
			int nodeDepth = getNodeDepth(node);
			if (nodeDepth > treeDepth) {
				treeDepth = nodeDepth;
			}
			node = node.getSuccessor();
		}
		return treeDepth;
	}

	private int getNodeDepth(RedBlackEntry<Integer, String> node) {
		int nodeDepth = 0;
		while (node.parent != null) {
			nodeDepth++;
			node = node.parent;
		}
		return nodeDepth;
	}
}
