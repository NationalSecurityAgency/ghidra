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

import javax.swing.event.TreeModelEvent;
import javax.swing.event.TreeModelListener;

import org.junit.Before;
import org.junit.Test;

import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;
import ghidra.test.DummyTool;

public class GTreeEventTest extends AbstractDockingTest {

	private GTree gTree;

	private DockingWindowManager winMgr;

	private List<TreeEvent> events = new ArrayList<>();
	private GTreeNode root;

	@Before
	public void setUp() throws Exception {
		root = new TestRootNode();
		gTree = new GTree(root);
		gTree.getModel().addTreeModelListener(new TestTreeModelListener());
//		filterField = (FilterTextField) gTree.getFilterField();

		winMgr = new DockingWindowManager(new DummyTool(), null);
		winMgr.addComponent(new TestTreeComponentProvider(gTree));
		winMgr.setVisible(true);

		waitForTree();
	}

	@Test
	public void testNodeAdded() {
		root.addNode(new LeafNode("NEW ABC"));
		assertEquals(1, events.size());
		TreeEvent treeEvent = events.get(0);
		assertEquals(EventType.INSERTED, treeEvent.eventType);
	}

	private void waitForTree() {
		waitForTree(gTree);
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
