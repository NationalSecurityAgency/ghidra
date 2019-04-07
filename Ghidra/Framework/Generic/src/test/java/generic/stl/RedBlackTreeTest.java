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
package generic.stl;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class RedBlackTreeTest extends AbstractGenericTest {
	RedBlackTree<Integer, String> tree;
	RedBlackTree<Integer, String> treeWithDups;

	public RedBlackTreeTest() {
		super();
	}
	
    @Before
    public void setUp() throws Exception {
		tree = new RedBlackTree<Integer, String>(new SelfComparator<Integer>(), false);
		treeWithDups = new RedBlackTree<Integer, String>(new SelfComparator<Integer>(), true);
		
		tree.put(5, "five");
		tree.put(10, "ten");
		tree.put(3, "three");
		tree.put(7, "seven");
		tree.put(1, "one");
		tree.put(9, "nine");
		tree.put(2, "two");
		tree.put(6, "six");
		tree.put(4, "four");
		

		treeWithDups.put(5, "five");
		treeWithDups.put(10, "ten");
		treeWithDups.put(3, "three");
		treeWithDups.put(7, "seven");
		treeWithDups.put(1, "one");
		treeWithDups.put(9, "nine");
		treeWithDups.put(2, "two");
		treeWithDups.put(6, "six");
		treeWithDups.put(4, "four");

		treeWithDups.put(1, "one-a");
		treeWithDups.put(1, "one-b");
		treeWithDups.put(5, "five-a");
		treeWithDups.put(7, "seven-a");
		treeWithDups.put(1, "one-c");
		treeWithDups.put(5, "five-b");
		treeWithDups.put(5, "five-c");
		
	}
@Test
    public void testSize() {
		assertEquals(9, tree.size());
		assertEquals(16, treeWithDups.size());
	}
	
@Test
    public void testPut() {
		Pair<RedBlackNode<Integer, String>, Boolean> result = tree.put( 5, "five - dup" );
		assertTrue( !result.second );
		
		result = tree.put( 3, "three - dup" );
		assertTrue( !result.second );
		
		result = tree.put( 200, "two hundred" );
		assertTrue( result.second );
		
		treeWithDups.put( 5, "five - dup" );
		assertTrue( result.second );
		
		result = treeWithDups.put( 200, "two hundred" );
		assertTrue( result.second );
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
		
		assertTrue(treeWithDups.containsKey(1));
		assertTrue(treeWithDups.containsKey(2));
		assertTrue(treeWithDups.containsKey(3));
		assertTrue(treeWithDups.containsKey(4));
		assertTrue(treeWithDups.containsKey(5));
		assertTrue(treeWithDups.containsKey(6));
		assertTrue(treeWithDups.containsKey(7));
		assertTrue(treeWithDups.containsKey(9));
		assertTrue(treeWithDups.containsKey(10));

		assertTrue(!treeWithDups.containsKey(0));
		assertTrue(!treeWithDups.containsKey(11));
		assertTrue(!treeWithDups.containsKey(8));
		
	}
@Test
    public void testGetFirstLast() {
		RedBlackNode<Integer,String> node = tree.getFirst();
		assertEquals(1, (int)node.getKey());
		
		node = treeWithDups.getFirst();
		assertEquals(1, (int)node.getKey());

		node = tree.getLast();
		assertEquals(10, (int)node.getKey());
		node = treeWithDups.getLast();
		assertEquals(10, (int)node.getKey());

	}
	
@Test
    public void testUpperBound() {
		RedBlackNode<Integer,String> node = tree.upperBound(-1);
		assertEquals(1, (int)node.getKey());
		node = tree.upperBound(2);
		assertEquals(3, (int)node.getKey());
		node = tree.upperBound(7);
		assertEquals(9, (int)node.getKey());
		
		node = tree.upperBound(8);
		assertEquals(9, (int)node.getKey());

		node = tree.upperBound(10);
		assertEquals(null, node);
		node = tree.upperBound(20);
		assertEquals(null, node);

		
		node = treeWithDups.upperBound(-1);
		assertEquals(1, (int)node.getKey());
		node = treeWithDups.upperBound(2);
		assertEquals(3, (int)node.getKey());
		node = treeWithDups.upperBound(7);
		assertEquals(9, (int)node.getKey());
		
		node = treeWithDups.upperBound(4);
		assertEquals(5, (int)node.getKey());
		assertEquals("five", node.getValue());
		
		node = treeWithDups.upperBound(8);
		assertEquals(9, (int)node.getKey());

		node = treeWithDups.upperBound(10);
		assertEquals(null, node);
		node = treeWithDups.upperBound(20);
		assertEquals(null, node);
		
	}
@Test
    public void testLowerBound() {
		RedBlackNode<Integer,String> node = tree.lowerBound(12);
		assertNull(node);
		node = tree.lowerBound(9);
		assertEquals(9, (int)node.getKey());
		node = tree.lowerBound(8);
		assertEquals(9, (int)node.getKey());
		
		node = tree.lowerBound(3);
		assertEquals(3, (int)node.getKey());

		node = tree.lowerBound(1);
		assertEquals(1, (int)node.getKey());
		node = tree.lowerBound(-5);
		assertEquals(1, (int)node.getKey());

		node = treeWithDups.lowerBound(12);
		assertNull(node);
		node = treeWithDups.lowerBound(9);
		assertEquals(9, (int)node.getKey());
		node = treeWithDups.lowerBound(8);
		assertEquals(9, (int)node.getKey());

		node = treeWithDups.lowerBound(5);
		assertEquals(5, (int)node.getKey());
		assertEquals("five", node.getValue());
		
		node = treeWithDups.lowerBound(3);
		assertEquals(3, (int)node.getKey());

		node = treeWithDups.lowerBound(1);
		assertEquals(1, (int)node.getKey());
		assertEquals("one", node.getValue());
		
		node = treeWithDups.lowerBound(-5);
		assertEquals(1, (int)node.getKey());
		assertEquals("one", node.getValue());
		
	}
@Test
    public void testFindFirst() {
		RedBlackNode<Integer,String> node = tree.findFirstNode(7);
		assertNotNull(node);
		assertEquals(7, (int)node.key);
		
		node = tree.findFirstNode(8);
		assertNull(node);
			
		node = treeWithDups.findFirstNode(7);
		assertNotNull(node);
		assertEquals(7, (int)node.key);
		
		node = tree.findFirstNode(8);
		assertNull(node);
		
		node = tree.findFirstNode(5);
		assertNotNull(node);
		assertEquals("five", node.getValue());

	}
@Test
    public void testFindLast() {
		RedBlackNode<Integer,String> node = tree.findLastNode(7);
		assertNotNull(node);
		assertEquals(7, (int)node.key);
		assertEquals("seven", node.value);
		
		node = tree.findLastNode(8);
		assertNull(node);
			
		node = treeWithDups.findLastNode(7);
		assertNotNull(node);
		assertEquals(7, (int)node.key);
		assertEquals("seven-a", node.value);
		
		node = treeWithDups.findLastNode(8);
		assertNull(node);
		
		node = treeWithDups.findLastNode(5);
		assertNotNull(node);
		assertEquals("five-c", node.getValue());

	}	
@Test
    public void testGetNextNode() {
		RedBlackNode<Integer,String> node = tree.getFirst();
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

	
		node = treeWithDups.getFirst();
		assertEquals("one", node.value);
		node = node.getSuccessor();
		assertEquals("one-a", node.value);
		node = node.getSuccessor();
		assertEquals("one-b", node.value);
		node = node.getSuccessor();
		assertEquals("one-c", node.value);
		node = node.getSuccessor();

		
		assertEquals("two", node.value);
		node = node.getSuccessor();
		assertEquals("three", node.value);
		node = node.getSuccessor();
		assertEquals("four", node.value);
		node = node.getSuccessor();
		assertEquals("five", node.value);
		node = node.getSuccessor();
		assertEquals("five-a", node.value);
		node = node.getSuccessor();
		assertEquals("five-b", node.value);
		node = node.getSuccessor();
		assertEquals("five-c", node.value);
		node = node.getSuccessor();
		assertEquals("six", node.value);
		node = node.getSuccessor();
		assertEquals("seven", node.value);
		node = node.getSuccessor();
		assertEquals("seven-a", node.value);
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

		assertEquals(16, treeWithDups.size());
		assertEquals("five",treeWithDups.remove(5));
		assertEquals(15, treeWithDups.size());
		assertEquals("five-a",treeWithDups.remove(5));
		assertEquals(14, treeWithDups.size());
		assertEquals("five-b",treeWithDups.remove(5));
		assertEquals(13, treeWithDups.size());
		assertEquals("five-c",treeWithDups.remove(5));
		assertEquals(12, treeWithDups.size());
		assertNull(treeWithDups.remove(5));
		assertEquals(12, treeWithDups.size());

	}
@Test
    public void testDeleteEntry() {
		RedBlackNode<Integer, String> node = treeWithDups.findFirstNode(5);
		node = node.getSuccessor();
		treeWithDups.deleteEntry(node);
		node = treeWithDups.findFirstNode(5);
		node = node.getSuccessor();
		assertEquals("five-b", node.value);
	}
	
@Test
    public void testDepth() {
		tree = new RedBlackTree<Integer, String>(new SelfComparator<Integer>(), false);
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

		tree = new RedBlackTree<Integer, String>(new SelfComparator<Integer>(), false);
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
		RedBlackNode<Integer, String> node = rbTree.getFirst();
		while(node != null) {
			int nodeDepth = getNodeDepth(node);
			if (nodeDepth > treeDepth) {
				treeDepth = nodeDepth;
			}
			node = node.getSuccessor();
		}
		return treeDepth;
	}
	private int getNodeDepth(RedBlackNode<Integer, String> node) {
		int nodeDepth = 0;
		while (node.parent != null) {
			nodeDepth++;
			node = node.parent;
		}
		return nodeDepth;
	}
}
