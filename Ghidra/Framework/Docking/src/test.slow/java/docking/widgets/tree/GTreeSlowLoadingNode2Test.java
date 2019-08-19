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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import javax.swing.*;

import org.junit.*;

import docking.test.AbstractDockingTest;
import docking.widgets.filter.FilterTextField;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class GTreeSlowLoadingNode2Test extends AbstractDockingTest {

	private static final int MAX_DEPTH = 4;
	private static final int MIN_CHILD_COUNT = 3;
	private static final int MAX_CHILD_COUNT = 3;

	private volatile boolean pauseChildLoading = false;

	private JFrame frame;
	private GTree gTree;
	private FilterTextField filterField;

	@Before
	public void setUp() throws Exception {

		gTree = new GTree(new EmptyRootNode());
		filterField = (FilterTextField) gTree.getFilterField();

		frame = new JFrame("GTree Test");
		frame.getContentPane().add(gTree);
		frame.setSize(400, 400);
		frame.setVisible(true);

		waitForTree();

	}

	@After
	public void tearDown() throws Exception {
		gTree.dispose();
		frame.dispose();
	}

	@Test
	public void testBasicLoading() {
		gTree.setRootNode(new TestRootNode(0));
		waitForTree();
		// make sure we have some children
		GTreeRootNode rootNode = gTree.getRootNode();
		List<GTreeNode> allChildren = rootNode.getAllChildren();
		typeFilterText("Many B1");
		clearFilterText();
		List<GTreeNode> allChildren2 = rootNode.getAllChildren();
		assertEquals("Children were reloaded instead of being reused", allChildren, allChildren2);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void typeFilterText(String text) {
		JTextField textField = (JTextField) getInstanceField("textField", filterField);
		triggerText(textField, text);
		waitForTree();
	}

	private void setFilterText(final String text) {
		runSwing(() -> filterField.setText(text));
		waitForTree();
	}

	private void clearFilterText() {
		setFilterText("");
	}

	private void waitForTree() {
		waitForTree(gTree);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class EmptyRootNode extends AbstractGTreeRootNode {

		EmptyRootNode() {
			setChildren(new ArrayList<GTreeNode>());
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return "Empty Test GTree Root Node";
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}
	}

	private class TestRootNode extends TestSlowLoadingNode implements GTreeRootNode {
		private GTree tree;

		TestRootNode(int loadDelayMillis) {
			super(loadDelayMillis, 3);
		}

		@Override
		public void setGTree(GTree tree) {
			this.tree = tree;
		}

		@Override
		public GTree getGTree() {
			return tree;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return "Test GTree Root Node";
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

	private class TestSlowLoadingNode extends GTreeSlowLoadingNode {

		private final long loadDelayMillis;
		private final int depth;

		TestSlowLoadingNode(long loadDelayMillis, int depth) {
			this.loadDelayMillis = loadDelayMillis;
			this.depth = depth;
		}

		@Override
		public List<GTreeNode> generateChildren(TaskMonitor monitor) throws CancelledException {

			if (depth > MAX_DEPTH) {
				return new ArrayList<>();
			}

			if (monitor.isCancelled()) {
				return new ArrayList<>();
			}

			sleep(loadDelayMillis);

			while (pauseChildLoading) {
				sleep(100);
			}

			int childCount = getRandomInt(MIN_CHILD_COUNT, MAX_CHILD_COUNT);
			List<GTreeNode> children = new ArrayList<>();
			for (int i = 0; i < childCount; i++) {
				if (monitor.isCancelled()) {
					return new ArrayList<>();
				}
				children.add(new TestSlowLoadingNode(0, depth + 1));
			}
			return children;
		}

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return getClass().getSimpleName();
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

	private class TestLeafNode extends AbstractGTreeNode {

		private String name = getClass().getSimpleName() + getRandomString();

		@Override
		public Icon getIcon(boolean expanded) {
			return null;
		}

		@Override
		public String getName() {
			return name;
		}

		@Override
		public String getToolTip() {
			return null;
		}

		@Override
		public boolean isLeaf() {
			return true;
		}

	}
}
