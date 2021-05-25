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
package docking.widgets.tree.support;

import static org.junit.Assert.*;

import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.tree.*;
import generic.test.AbstractGenericTest;

/**
 * Class to test the {@link DepthFirstIterator} and {@link BreadthFirstIterator} classes for
 * iterator through the {@link GTree} nodes.
 */
public class TreeIteratorTest {
	private GTreeNode root;
	private GTreeNode node0;
	private GTreeNode node1;
	private GTreeNode node2;
	private GTreeNode node0_0;
	private GTreeNode node0_1;
	private GTreeNode node1_0;

	@Before
	public void setUp() {
		root = new GTestNode("root");
		node0 = new GTestNode("Node0");
		node1 = new GTestNode("Node1");
		node2 = new GTestNode("Node2");
		node0_0 = new GTestNode("Node0_0");
		node0_1 = new GTestNode("Node0_1");
		node1_0 = new GTestNode("Node1_0");

		AbstractGenericTest.runSwing(() -> {
			root.addNode(node0);
			root.addNode(node1);
			root.addNode(node2);
			node0.addNode(node0_0);
			node0.addNode(node0_1);
			node1.addNode(node1_0);
		});
	}

	@Test
	public void testDepthFirst() {
		Iterator<GTreeNode> it = new DepthFirstIterator(root);
		assertTrue(it.hasNext());
		assertEquals(root, it.next());
		assertTrue(it.hasNext());
		assertEquals(node0, it.next());
		assertTrue(it.hasNext());
		assertEquals(node0_0, it.next());
		assertTrue(it.hasNext());
		assertEquals(node0_1, it.next());
		assertTrue(it.hasNext());
		assertEquals(node1, it.next());
		assertTrue(it.hasNext());
		assertEquals(node1_0, it.next());
		assertTrue(it.hasNext());
		assertEquals(node2, it.next());

		assertFalse(it.hasNext());
	}

	@Test
	public void testBreadthFirst() {
		Iterator<GTreeNode> it = new BreadthFirstIterator(root);
		assertTrue(it.hasNext());
		assertEquals(root, it.next());
		assertTrue(it.hasNext());
		assertEquals(node0, it.next());
		assertTrue(it.hasNext());
		assertEquals(node1, it.next());
		assertTrue(it.hasNext());
		assertEquals(node2, it.next());
		assertTrue(it.hasNext());
		assertEquals(node0_0, it.next());
		assertTrue(it.hasNext());
		assertEquals(node0_1, it.next());
		assertTrue(it.hasNext());
		assertEquals(node1_0, it.next());

		assertFalse(it.hasNext());
	}
}
