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
import static org.junit.Assert.assertNull;

import java.util.*;

import javax.swing.Icon;
import javax.swing.tree.TreePath;

import org.junit.Before;
import org.junit.Test;

import docking.test.AbstractDockingTest;

public class GTreeAllPathsIteratorTest extends AbstractDockingTest {

	private static class TestRootNode extends AbstractGTreeRootNode {
		protected String name;

		public TestRootNode(String name, List<GTreeNode> children) {
			this.name = name;
			setChildren(children);
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

	private static class TestNode extends AbstractGTreeNode {
		protected String name;

		public TestNode(String name, List<GTreeNode> children) {
			this.name = name;
			setChildren(children);
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

	@Before
	public void setUp() throws Exception {

	}

	/**
	 * R
	 */
	@Test
    public void testRootOnly() {
		List<GTreeNode> children = Collections.emptyList();
		AbstractGTreeNode root = new TestRootNode("Root", children);

		TreePath path;
		Iterator<TreePath> it = root.allPaths().iterator();

		path = it.next();
		assertEquals("The path should consist only of the root", "[Root]", path.toString());

		path = it.next();
		assertNull("There should only be one path", path);
	}

	/**
	 * A
	 * `-B
	 *   `-C
	 */
	@Test
    public void testChainOfThree() {
		List<GTreeNode> childrenC = Collections.emptyList();
		AbstractGTreeNode nodeC = new TestNode("C", childrenC);
		AbstractGTreeNode nodeB = new TestNode("B", Collections.singletonList((GTreeNode) nodeC));
		AbstractGTreeNode rootA =
			new TestRootNode("A", Collections.singletonList((GTreeNode) nodeB));

		Iterator<TreePath> it = rootA.allPaths().iterator();

		assertEquals("Path 1 incorrect", "[A]", it.next().toString());
		assertEquals("Path 2 incorrect", "[A, B]", it.next().toString());
		assertEquals("Path 3 incorrect", "[A, B, C]", it.next().toString());
		assertNull("There should be only 3 paths", it.next());
	}

	/**
	 * A
	 * |-B
	 * | |-C
	 * | `-D
	 * `-E
	 *   |-F
	 *   `-G
	 */
	@Test
    public void testTwoByTwo() {
		List<GTreeNode> empty = Collections.emptyList();
		AbstractGTreeNode nodeG = new TestNode("G", empty);
		AbstractGTreeNode nodeF = new TestNode("F", empty);
		AbstractGTreeNode nodeE =
			new TestNode("E", Arrays.asList(new GTreeNode[] { nodeF, nodeG }));
		AbstractGTreeNode nodeD = new TestNode("D", empty);
		AbstractGTreeNode nodeC = new TestNode("C", empty);
		AbstractGTreeNode nodeB =
			new TestNode("B", Arrays.asList(new GTreeNode[] { nodeC, nodeD }));
		AbstractGTreeNode rootA =
			new TestRootNode("A", Arrays.asList(new GTreeNode[] { nodeB, nodeE }));

		Iterator<TreePath> it = rootA.allPaths().iterator();

		assertEquals("Path 1 incorrect", "[A]", it.next().toString());
		assertEquals("Path 2 incorrect", "[A, B]", it.next().toString());
		assertEquals("Path 3 incorrect", "[A, B, C]", it.next().toString());
		assertEquals("Path 4 incorrect", "[A, B, D]", it.next().toString());
		assertEquals("Path 5 incorrect", "[A, E]", it.next().toString());
		assertEquals("Path 6 incorrect", "[A, E, F]", it.next().toString());
		assertEquals("Path 7 incorrect", "[A, E, G]", it.next().toString());
		assertNull("There should be only 7 paths", it.next());
	}
}
