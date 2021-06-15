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

import java.util.ArrayList;
import java.util.List;

import javax.swing.Icon;
import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;
import javax.swing.tree.TreePath;

import org.junit.Before;
import org.junit.Test;

import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;
import ghidra.test.DummyTool;

public class GTreeEventTest extends AbstractDockingTest {

	private GTree gTree;

	private List<TreeEvent> events = new ArrayList<>();

	@Before
	public void setUp() throws Exception {
		GTreeNode root = new TestRootNode();
		gTree = new GTree(root);
		gTree.getModel().addTreeModelListener(new TestTreeModelListener());

		DockingWindowManager winMgr = new DockingWindowManager(new DummyTool(), null);
		winMgr.addComponent(new TestTreeComponentProvider(gTree));
		winMgr.setVisible(true);

		waitForTree();
	}

	@Test
	public void testNodeAdded() {
		GTreeNode root = gTree.getModelRoot();
		root.addNode(new LeafNode("NEW ABC"));
		assertEquals(1, events.size());
		TreeEvent treeEvent = events.get(0);
		assertEquals(EventType.INSERTED, treeEvent.eventType);
	}

	@Test
	public void testChangingParentNodeWhileFiltered() {

		//
		// This tests a bug where the tree model was not firing a structure changed event for a 
		// changed parent node when a filter was in place.
		//

		TestRootNode modelRoot = new TestRootNode();
		gTree.setRootNode(modelRoot);

		createNodes(modelRoot, "A");
		createNodes(modelRoot, "B");
		createNodes("B", "B1", "B2", "B3");

		setFilterText("B");

		//
		// Note: we are changing the children of the 'B' node that is not in the view now that we
		//       have filtered.   The 'B' node in the filtered view should also be updated and we
		//       should receive a structure changed event
		//
		events.clear();
		GTreeNode B4 = new LeafNode("B4");
		GTreeNode modelB = findNode(modelRoot, "B");
		setChildren(modelB, B4);

		GTreeNode viewRoot = gTree.getViewRoot();
		GTreeNode viewB = findNode(viewRoot, "B");
		assertEvent(viewB, EventType.STRUCTURE_CHANGED);
	}

	private void assertEvent(GTreeNode viewB, EventType eventType) {

		assertTrue(events.size() > 0);
		TreeEvent event = events.get(0);
		assertEquals(eventType, event.eventType);
		TreePath path = event.getTreePath();
		assertNotNull(path);
		assertEquals(viewB, path.getLastPathComponent());
	}

	private void setChildren(GTreeNode parent, GTreeNode... children) {
		parent.setChildren(List.of(children));
		waitForTree();
	}

	private void createNodes(String parent, String... children) {
		GTreeNode parentNode = findNode(parent);
		createNodes(parentNode, children);
	}

	private void createNodes(GTreeNode parentNode, String... children) {

		waitForTree();

		List<GTreeNode> list = new ArrayList<>();
		list.addAll(parentNode.getChildren());
		for (String name : children) {
			NamedNode node = new NamedNode(name);
			list.add(node);
		}

		parentNode.setChildren(list);
		waitForTree();
	}

	private GTreeNode findNode(String name) {
		GTreeNode rootNode = gTree.getViewRoot();
		return findNode(rootNode, name);
	}

	private GTreeNode findNode(GTreeNode node, String name) {
		if (node.getName().equals(name)) {
			return node;
		}

		List<GTreeNode> children = node.getChildren();
		for (GTreeNode child : children) {
			if (child.getName().startsWith(name)) {
				return child;
			}

			GTreeNode grandChild = findNode(child, name);
			if (grandChild != null) {
				return grandChild;
			}
		}

		return null;
	}

	private void setFilterText(final String text) {
		runSwing(() -> gTree.setFilterText(text));
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(gTree);
	}

	private class NamedNode extends GTreeNode {

		private final String name;

		NamedNode(String name) {
			this.name = name;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return false;
		}
	}

	enum EventType {
		CHANGED, INSERTED, REMOVED, STRUCTURE_CHANGED
	}

	static class TreeEvent {
		TreeModelEvent event;
		EventType eventType;

		public TreeEvent(EventType type, TreeModelEvent event) {
			this.eventType = type;
			this.event = event;
		}

		TreePath getTreePath() {
			return event.getTreePath();
		}
	}

	class TestTreeModelListener implements TreeModelListener {

		@Override
		public void treeNodesChanged(TreeModelEvent e) {
			events.add(new TreeEvent(EventType.CHANGED, e));
		}

		@Override
		public void treeNodesInserted(TreeModelEvent e) {
			events.add(new TreeEvent(EventType.INSERTED, e));
		}

		@Override
		public void treeNodesRemoved(TreeModelEvent e) {
			events.add(new TreeEvent(EventType.REMOVED, e));
		}

		@Override
		public void treeStructureChanged(TreeModelEvent e) {
			events.add(new TreeEvent(EventType.STRUCTURE_CHANGED, e));
		}

	}
}
