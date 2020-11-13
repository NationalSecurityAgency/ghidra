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
package docking.widgets.tree;

import static org.junit.Assert.*;

import java.util.*;
import java.util.stream.Collectors;

import javax.swing.tree.TreePath;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;
import docking.widgets.tree.support.GTreeFilter;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Note: This test does not extend {@link AbstractDockingTest}.  Extending that class sets up
 * {@link Swing#runNow(Runnable)} methods so that they actually run on the swing thread; otherwise
 * they run on the calling thread.  Normally GTreeNode test would need that because the fire event
 * calls normally check that the events are being sent on the swing thread.  In this file, all the
 * tests use {@link TestNode} or {@link LazyTestNode} which override the event sending methods to
 * instead put the events in a list so that the test can check that the correct events were generated.
 * Since the methods that check for being on the swing thread are overridden, we can get away with
 * not extending {@link AbstractDockingTest} and this allows the test to run about 100 times faster.
 */

public class GTreeNodeTest {
	private List<TestEvent> events = new ArrayList<>();
	private GTreeNode root;
	private GTreeNode node0;
	private GTreeNode node1;
	private GTreeNode node2;
	private GTreeNode node0_0;
	private GTreeNode node0_1;
	private GTreeNode node1_0;

	@Before
	public void setUp() {
		root = new TestNode("root");
		node0 = new TestNode("Node0");
		node1 = new TestNode("Node1");
		node2 = new TestNode("Node2");
		node0_0 = new TestNode("Node0_0");
		node0_1 = new TestNode("Node0_1");
		node1_0 = new TestNode("Node1_0");
		root.addNode(node0);
		root.addNode(node1);
		root.addNode(node2);
		node0.addNode(node0_0);
		node0.addNode(node0_1);
		node1.addNode(node1_0);
		events.clear();
	}

	@Test
	public void testClone() throws CloneNotSupportedException {
		GTreeNode clone = node0.clone();

		assertTrue(node0.equals(clone));
		assertNull(clone.getParent());
		assertFalse(clone.isLoaded());
	}

	@Test
	public void testGetParent() {
		assertEquals(root, node0.getParent());
		assertEquals(node0, node0_0.getParent());

		root.setParent(new GTreeRootParentNode(null));
		assertEquals(null, root.getParent());
	}

	@Test
	public void testRemovingNodeClearsParent() {
		root.removeNode(node0);
		assertNull(node0.getParent());
		assertNotNull(node0_0.getParent());
	}

	@Test
	public void testRemovingAllClearsParent() {
		root.removeAll();
		assertNull(node0.getParent());
		assertNull(node1.getParent());
		assertNull(node2.getParent());
	}

	@Test
	public void testCompareTo() {
		TestNode nodeFoo = new TestNode("Foo");
		TestNode nodefoo = new TestNode("foo");
		TestNode nodeBar = new TestNode("Bar");
		assertEquals(0, nodeFoo.compareTo(nodefoo));
		assertEquals(0, nodefoo.compareTo(nodeFoo));
		assertEquals(0, nodeFoo.compareTo(nodeFoo));
		assertTrue(nodeFoo.compareTo(nodeBar) > 0);
		assertTrue(nodeBar.compareTo(nodeFoo) < 0);
		assertTrue(nodefoo.compareTo(nodeBar) > 0);
	}

	@Test
	public void testIterator() {

		Iterator<GTreeNode> iterator = root.getChildren().iterator();
		assertTrue(iterator.hasNext());
		assertEquals(node0, iterator.next());
		assertTrue(iterator.hasNext());
		assertEquals(node1, iterator.next());
		assertTrue(iterator.hasNext());
		assertEquals(node2, iterator.next());
		assertFalse(iterator.hasNext());
	}

	@Test
	public void testAddNode() {
		int originalRootCount = root.getChildCount();

		TestNode child = new TestNode("child");
		root.addNode(child);

		assertEquals(originalRootCount + 1, root.getChildCount());

		assertEquals(root, child.getParent());
		assertEquals(child, root.getChild(originalRootCount));

		assertEquals(1, events.size());
		TestEvent event = events.get(0);
		assertEquals(EventType.NODE_ADDED, event.type);
		assertEquals(root, event.parent);
		assertEquals(child, event.node);
	}

	@Test
	public void testAddNodeAtIndex() {
		int originalRootCount = root.getChildCount();

		TestNode child = new TestNode("child");

		root.addNode(1, child);

		assertEquals(originalRootCount + 1, root.getChildCount());
		assertEquals(root, child.getParent());
		assertEquals(child, root.getChild(1));
		assertEquals(node0, root.getChild(0));
		assertEquals(node1, root.getChild(2));

		assertEquals(1, events.size());

		TestEvent event = events.get(0);
		assertEquals(EventType.NODE_ADDED, event.type);
		assertEquals(root, event.parent);
		assertEquals(child, event.node);
	}

	@Test
	public void testAddNodes() {
		int originalRootCount = root.getChildCount();

		TestNode child1 = new TestNode("child1");
		TestNode child2 = new TestNode("child2");
		List<GTreeNode> list = new ArrayList<GTreeNode>();
		list.add(child1);
		list.add(child2);

		root.addNodes(list);

		assertEquals(root, child1.getParent());
		assertEquals(root, child2.getParent());

		assertEquals(originalRootCount + 2, root.getChildCount());

		assertEquals(child1, root.getChild(originalRootCount));
		assertEquals(child2, root.getChild(originalRootCount + 1));

		assertEquals(1, events.size());
		TestEvent event = events.get(0);
		assertEquals(EventType.STRUCTURE_CHANGED, event.type);
		assertEquals(root, event.node);
	}

	@Test
	public void testGetChildren() {
		List<GTreeNode> children = root.getChildren();
		assertEquals(3, children.size());
		assertEquals(node0, children.get(0));
		assertEquals(node1, children.get(1));
		assertEquals(node2, children.get(2));
	}

	@Test
	public void testGetChildrenIsImmutable() {
		List<GTreeNode> children = root.getChildren();
		try {
			children.add(new TestNode("test"));
			fail("Should not have been able to modify list return from getChildren()");
		}
		catch (Exception e) {
			// expected
		}
	}

	@Test
	public void testGetChildCount() {
		assertEquals(3, root.getChildCount());
	}

	@Test
	public void testGetChild() {
		assertEquals(node0, root.getChild(0));
	}

	@Test
	public void testGetChildByName() {
		assertEquals(node1, root.getChild("Node1"));
		assertNull(root.getChild("foo"));
	}

	@Test
	public void testGetNodeCount() {
		assertEquals(3, node0.getNodeCount()); // node0 has 2 children
		assertEquals(2, node1.getNodeCount()); // node1 has 1 child
		assertEquals(1, node2.getNodeCount()); // node2 has no children
		assertEquals(7, root.getNodeCount());  // one more that the total of the children count
	}

	@Test
	public void testGetLeafCount() {
		assertEquals(2, node0.getLeafCount()); // node0 has 2 children
		assertEquals(1, node1.getLeafCount()); // node1 has 1 child
		assertEquals(1, node2.getLeafCount()); // node2 so it is a leaf
		assertEquals(4, root.getLeafCount());  // the total of all its children
	}

	@Test
	public void testGetLeafCountOnLazyNodes() throws CancelledException {
		LazyGTestNode node = new LazyGTestNode("Test", 3);
		assertEquals(1, node.getLeafCount());
		node.getChildren();// force load
		assertEquals(3, node.getLeafCount());
		node.loadAll(TaskMonitor.DUMMY);
		assertEquals(27, node.getLeafCount());
	}

	@Test
	public void testGetIndexInParent() {
		assertEquals(0, node0.getIndexInParent());
		assertEquals(1, node1.getIndexInParent());
		assertEquals(2, node2.getIndexInParent());
		assertEquals(0, node0_0.getIndexInParent());

		// test that unattached node doesn't blow up.
		assertEquals(-1, new TestNode("test").getIndexInParent());
	}

	@Test
	public void testGetIndexOfChild() throws CloneNotSupportedException {
		assertEquals(0, root.getIndexOfChild(node0));
		assertEquals(1, root.getIndexOfChild(node1));
		assertEquals(2, root.getIndexOfChild(node2));

		assertEquals(-1, root.getIndexOfChild(node0_0));

		assertEquals(0, root.getIndexOfChild(node0.clone()));
	}

	@Test
	public void testGetTreePath() {
		TreePath path = node0_0.getTreePath();
		assertEquals(node0_0, path.getLastPathComponent());
		assertEquals(node0, path.getParentPath().getLastPathComponent());
		assertEquals(root, path.getParentPath().getParentPath().getLastPathComponent());
		assertNull(path.getParentPath().getParentPath().getParentPath());
	}

	@Test
	public void testRemoveAll() {
		root.removeAll();
		assertEquals(0, root.getChildCount());
		assertEquals(1, events.size());
		TestEvent event = events.get(0);
		assertEquals(EventType.STRUCTURE_CHANGED, event.type);
		assertEquals(root, event.node);
	}

	@Test
	public void testRemoveNode() {
		root.removeNode(node1);
		assertEquals(2, root.getChildCount());
		assertNull(node1.getParent());
		assertEquals(1, events.size());
		TestEvent event = events.get(0);
		assertEquals(EventType.NODE_REMOVED, event.type);
		assertEquals(root, event.parent);
	}

	@Test
	public void testRemoveNonExistingNode() {
		root.removeNode(new TestNode("Test"));
		assertEquals(3, root.getChildCount());
		assertTrue(events.isEmpty());
	}

	@Test
	public void testSetChildren() {
		List<GTreeNode> list = new ArrayList<GTreeNode>();
		TestNode child1 = new TestNode("child1");
		TestNode child2 = new TestNode("child2");
		list.add(child1);
		list.add(child2);

		root.setChildren(list);
		assertEquals(2, root.getChildCount());
		assertEquals(child1, root.getChild(0));
		assertEquals(child2, root.getChild(1));
		assertNull(node0.getParent());
		assertNull(node1.getParent());
		assertNull(node2.getParent());
	}

	@Test
	public void testSetChildrenNull() {
		root.setChildren(null);
		assertFalse(root.isLoaded());
		assertEquals(0, root.getChildCount());
		assertTrue(root.isLoaded());
	}

	@Test
	public void isAncestor() {
		assertTrue(root.isAncestor(node0_0));
		assertFalse(node0_0.isAncestor(root));
	}

	@Test
	public void testGetRoot() {
		assertEquals(root, node0_1.getRoot());
		assertEquals(root, root.getRoot());
		TestNode testNode = new TestNode("test");
		assertEquals(testNode, testNode.getRoot());
	}

	@Test
	public void testIsRoot() {
		assertTrue(root.isRoot());
		assertFalse(node0_1.isRoot());
	}

	@Test
	public void testDispose() {
		root.dispose();
		assertFalse(root.isLoaded());
		assertNull(node1.getParent());
		assertNull(node1_0.getParent());
		assertFalse(node1.isLoaded());
	}

	@Test
	public void testFilter() throws CancelledException, CloneNotSupportedException {
		GTreeNode filtered = root.filter(new TestFilter("0_0"), TaskMonitor.DUMMY);
		assertEquals(3, filtered.getNodeCount());
		assertEquals(root, filtered);
		assertEquals(1, filtered.getChildCount());
		GTreeNode node = filtered.getChild(0);
		assertEquals(node0, node);
		assertEquals(1, node.getChildCount());
		assertEquals(node0_0, node.getChild(0));
	}

	@Test
	public void testFilterNoMatch() throws CancelledException, CloneNotSupportedException {
		GTreeNode filtered = root.filter(new TestFilter("xxxxxxx"), TaskMonitor.DUMMY);
		assertNotNull(filtered);
		assertEquals(root, filtered);
		assertEquals(0, filtered.getChildCount());
	}

	@Test
	public void testLoadAllOnSimpleTree() throws CancelledException {
		assertEquals(7, root.loadAll(TaskMonitor.DUMMY));
	}

	@Test
	public void testLoadAllOnLazyTree() throws CancelledException {
		GTreeNode node = new LazyTestNode("test", 2);
		assertEquals(13, node.loadAll(TaskMonitor.DUMMY));
	}

	@Test
	public void testUnloadOnLazyNode() throws CancelledException {
		GTreeLazyNode node = new LazyTestNode("test", 2);
		node.loadAll(TaskMonitor.DUMMY);
		assertTrue(node.isLoaded());

		events.clear();
		node.unloadChildren();
		assertFalse(node.isLoaded());

		assertEquals(1, events.size());
		TestEvent event = events.get(0);
		assertEquals(EventType.STRUCTURE_CHANGED, event.type);
		assertEquals(node, event.node);
	}

	@Test
	public void testStreamDepthFirst() {
		List<GTreeNode> collect = root.stream(true).collect(Collectors.toList());
		assertEquals(7, collect.size());
		assertEquals(root, collect.get(0));
		assertEquals(node0, collect.get(1));
		assertEquals(node0_0, collect.get(2));
		assertEquals(node0_1, collect.get(3));
		assertEquals(node1, collect.get(4));
		assertEquals(node1_0, collect.get(5));
		assertEquals(node2, collect.get(6));
	}

	@Test
	public void testStreamBreadthFirst() {
		List<GTreeNode> collect = root.stream(false).collect(Collectors.toList());
		assertEquals(7, collect.size());
		assertEquals(root, collect.get(0));
		assertEquals(node0, collect.get(1));
		assertEquals(node1, collect.get(2));
		assertEquals(node2, collect.get(3));
		assertEquals(node0_0, collect.get(4));
		assertEquals(node0_1, collect.get(5));
		assertEquals(node1_0, collect.get(6));
	}

	@Test
	public void testEqualsAndHashCode() {
		GTreeNode nodeA = new TestNode("AAA");
		GTreeNode nodeB = new TestNode("BBB");
		GTreeNode nodeAA = new TestNode("AAA");
		assertEquals(nodeA, nodeAA);
		assertNotEquals(nodeA, nodeB);
		assertEquals(nodeA.hashCode(), nodeAA.hashCode());
		assertNotEquals(nodeA.hashCode(), nodeB.hashCode());
	}

	@Test
	public void testCantAddNodeTwice() {
		node0 = new TestNode("No Dups");

		int childCount = root.getChildCount();
		root.addNode(node0);
		assertEquals(childCount + 1, root.getChildCount());

		// now make sure the count doesn't grow again
		root.addNode(node0);
		assertEquals(childCount + 1, root.getChildCount());

		// try adding it with an index, still shouldn't get added
		root.addNode(0, node0);
		assertEquals(childCount + 1, root.getChildCount());

	}

	@Test
	public void testCloneEquals() throws CloneNotSupportedException {
		GTreeNode nodeA = new TestNode("AAA");
		assertEquals(nodeA, nodeA.clone());
		assertEquals(nodeA.hashCode(), nodeA.clone().hashCode());
	}

	private class TestFilter implements GTreeFilter {

		private String text;

		TestFilter(String text) {
			this.text = text;
		}

		@Override
		public boolean acceptsNode(GTreeNode node) {
			return node.getDisplayText().contains(text);
		}

		@Override
		public boolean showFilterMatches() {
			return false;
		}

	}

	private class LazyTestNode extends LazyGTestNode {

		LazyTestNode(String name, int depth) {
			super(name, depth);
		}

		@Override
		public void doFireNodeStructureChanged() {
			events.add(new TestEvent(EventType.STRUCTURE_CHANGED, null, this, -1));
		}

		@Override
		public void doFireNodeChanged() {
			events.add(new TestEvent(EventType.NODE_CHANGED, getParent(), this, -1));
		}

		@Override
		protected void doFireNodeAdded(GTreeNode newNode) {
			events.add(new TestEvent(EventType.NODE_ADDED, this, newNode, -1));
		}

		@Override
		protected void doFireNodeRemoved(GTreeNode removedNode, int index) {
			events.add(new TestEvent(EventType.NODE_REMOVED, this, removedNode, -1));
		}
	}

	private class TestNode extends GTestNode {
		TestNode(String name) {
			super(name);
		}

		@Override
		public void doFireNodeStructureChanged() {
			events.add(new TestEvent(EventType.STRUCTURE_CHANGED, null, this, -1));
		}

		@Override
		public void doFireNodeChanged() {
			events.add(new TestEvent(EventType.NODE_CHANGED, getParent(), this, -1));
		}

		@Override
		protected void doFireNodeAdded(GTreeNode newNode) {
			events.add(new TestEvent(EventType.NODE_ADDED, this, newNode, -1));
		}

		@Override
		protected void doFireNodeRemoved(GTreeNode removedNode, int index) {
			events.add(new TestEvent(EventType.NODE_REMOVED, this, removedNode, -1));
		}
	}

	enum EventType {
		STRUCTURE_CHANGED, NODE_CHANGED, NODE_ADDED, NODE_REMOVED
	}

	private class TestEvent {
		EventType type;
		GTreeNode parent;
		GTreeNode node;
		int index;

		TestEvent(EventType type, GTreeNode parent, GTreeNode node, int index) {
			this.type = type;
			this.parent = parent;
			this.node = node;
			this.index = index;
		}
	}

}
