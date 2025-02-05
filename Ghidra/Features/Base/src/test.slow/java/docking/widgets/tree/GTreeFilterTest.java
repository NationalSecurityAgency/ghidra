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

import java.util.List;

import javax.swing.tree.TreePath;

import org.jdom.Element;
import org.junit.*;

import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;
import docking.widgets.filter.*;
import ghidra.test.DummyTool;
import ghidra.util.StringUtilities;

public class GTreeFilterTest extends AbstractDockingTest {

	private DummyTool tool;
	private TestTreeComponentProvider provider;
	private GTree gTree;
	private FilterTextField filterField;

	private DockingWindowManager winMgr;

	@Before
	public void setUp() throws Exception {

		tool = new DummyTool();
		winMgr = new DockingWindowManager(tool, null);
		winMgr.setVisible(true);

		buildTree();
	}

	private void buildTree() {
		GTreeNode root = new TestRootNode();
		gTree = new GTree(root);

		filterField = (FilterTextField) gTree.getFilterField();
		provider = new TestTreeComponentProvider(tool, gTree);
		winMgr.addComponent(provider);

		waitForTree();
	}

	@After
	public void tearDown() throws Exception {
		winMgr.dispose();
	}

	@Test
	public void testContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("ABC");
		assertEquals("Expected 4 of nodes to be in filtered tree!", 4, viewRoot().getChildCount());

		checkContainsNode("ABC");
		checkContainsNode("XABC");
		checkContainsNode("ABCX");
		checkContainsNode("XABCX");

		setFilterText("MMM");
		assertEquals("Expected 4 of nodes to be in filtered tree!", 0, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testMultiWordContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ' ',
			MultitermEvaluationMode.AND);

		setFilterText("CX AB");
		assertEquals(2, viewRoot().getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ' ', MultitermEvaluationMode.OR);

		setFilterText("CX AB");
		assertEquals(4, viewRoot().getChildCount());

		checkContainsNode("ABCX");
		checkContainsNode("XABCX");

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testMultiWordContainsDelimiters() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			setFilterText("CX" + delim + "AB");
			assertEquals(2, viewRoot().getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delim + "AB");
			assertEquals(4, viewRoot().getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
		}

	}

	@Test
	public void testMultiWordContainsDelimitersWithLeadingSpaces() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		String delimPad = StringUtilities.pad("", ' ', 1);

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			String delimStr = delimPad + delim;

			setFilterText("CX" + delimStr + "AB");
			assertEquals(2, viewRoot().getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delimStr + "AB");
			assertEquals(4, viewRoot().getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());

		}
	}

	@Test
	public void testMultiWordContainsDelimitersWithTrailingSpaces() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		String delimPad = StringUtilities.pad("", ' ', 1);

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			String delimStr = delim + delimPad;

			setFilterText("CX" + delimStr + "AB");
			assertEquals(2, viewRoot().getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delimStr + "AB");
			assertEquals(4, viewRoot().getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());

		}
	}

	@Test
	public void testMultiWordContainsDelimitersWithBoundingSpaces() {

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		String delimPad = StringUtilities.pad("", ' ', 1);

		for (char delim : FilterOptions.VALID_MULTITERM_DELIMITERS.toCharArray()) {
			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.AND);

			String delimStr = delimPad + delim + delimPad;

			setFilterText("CX" + delimStr + "AB");
			assertEquals(2, viewRoot().getChildCount());

			setFilterOptions(TextFilterStrategy.CONTAINS, false, true, delim,
				MultitermEvaluationMode.OR);

			setFilterText("CX" + delimStr + "AB");
			assertEquals(4, viewRoot().getChildCount());

			checkContainsNode("ABCX");
			checkContainsNode("XABCX");

			setFilterText("");
			assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());

		}
	}

	@Test
	public void testInvertedContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, true);

		assertEquals(5, viewRoot().getChildCount());

		setFilterText("ABC");
		assertEquals(1, viewRoot().getChildCount());

		checkDoesNotContainsNode("ABC");
		checkDoesNotContainsNode("XABC");
		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");

		setFilterText("MMM");
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testInvertedMultiWordContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, true, true, ' ', MultitermEvaluationMode.AND);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("CX AB");

		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");
		assertEquals(3, viewRoot().getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, true, true, ' ', MultitermEvaluationMode.OR);
		setFilterText("");
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("CX AB");

		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");
		assertEquals(1, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testStartsWith() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("ABC");
		checkContainsNode("ABC");
		checkContainsNode("ABCX");
		assertEquals(2, viewRoot().getChildCount());

		setFilterText("MMM");
		assertEquals(0, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testInvertedStartsWith() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH, true);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("ABC");
		checkDoesNotContainsNode("ABC");
		checkDoesNotContainsNode("ABCX");
		assertEquals(3, viewRoot().getChildCount());

		setFilterText("MMM");
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testExactMatch() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("ABC");
		checkContainsNode("ABC");
		assertEquals(1, viewRoot().getChildCount());

		setFilterText("MMM");
		assertEquals(0, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testInvertedExactMatch() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, true);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("ABC");
		checkDoesNotContainsNode("ABC");
		assertEquals(4, viewRoot().getChildCount());

		setFilterText("MMM");
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testRegExMatch() {
		setFilterOptions(TextFilterStrategy.REGULAR_EXPRESSION, false);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("^ABC$");
		checkContainsNode("ABC");
		assertEquals("Expected 1 node match exacly match ABC!", 1, viewRoot().getChildCount());

		setFilterText("ABC");
		checkContainsNode("ABC");
		checkContainsNode("XABC");
		checkContainsNode("ABCX");
		checkContainsNode("XABCX");
		assertEquals("Expected 4 of nodes that contain the text ABC!", 4,
			viewRoot().getChildCount());

		setFilterText("XA.{0,2}X");
		checkContainsNode("XABCX");
		assertEquals(1, viewRoot().getChildCount());

		setFilterText("X{0,1}A.{0,2}X");
		checkContainsNode("XABCX");
		checkContainsNode("ABCX");
		assertEquals(2, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testInvertedRegExMatch() {
		setFilterOptions(TextFilterStrategy.REGULAR_EXPRESSION, true);
		// no filter text - make sure all 5 nodes are there
		assertEquals(5, viewRoot().getChildCount());

		setFilterText("^ABC$");
		checkDoesNotContainsNode("ABC");
		assertEquals(4, viewRoot().getChildCount());

		setFilterText("ABC");
		checkDoesNotContainsNode("ABC");
		checkDoesNotContainsNode("XABC");
		checkDoesNotContainsNode("ABCX");
		checkDoesNotContainsNode("XABCX");
		assertEquals(1, viewRoot().getChildCount());

		setFilterText("XA.{0,2}X");
		checkDoesNotContainsNode("XABCX");
		assertEquals(4, viewRoot().getChildCount());

		setFilterText("X{0,1}A.{0,2}X");
		checkDoesNotContainsNode("XABCX");
		checkDoesNotContainsNode("ABCX");
		assertEquals(3, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	@Test
	public void testSwitchFilterTypes() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);
		setFilterText("ABC");
		checkContainsNode("ABC");
		checkContainsNode("ABCX");
		assertEquals(2, viewRoot().getChildCount());

		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false);
		checkContainsNode("ABC");
		assertEquals(1, viewRoot().getChildCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, false);
		assertEquals("Expected 4 of nodes to be in filtered tree!", 4, viewRoot().getChildCount());
		checkContainsNode("ABC");
		checkContainsNode("XABC");
		checkContainsNode("ABCX");
		checkContainsNode("XABCX");

	}

	@Test
	public void testFilterPersistence() {

		// default configuration
		assertFilterOptions(TextFilterStrategy.CONTAINS);

		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		setFilterText("ABC");
		assertNodesByName(viewRoot(), "ABC");

		setFilterOptions(TextFilterStrategy.STARTS_WITH);
		setFilterText("ABC");
		assertNodesByName(viewRoot(), "ABC", "ABCX");

		// close and reopen the tree so we know the preferences are saved
		triggerSaveAndReload();

		assertFilterOptions(TextFilterStrategy.STARTS_WITH);
		setFilterText("ABC");
		assertNodesByName(viewRoot(), "ABC", "ABCX");

		// put back, test, and then make sure the updated filter is restored
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		setFilterText("ABC");
		assertNodesByName(viewRoot(), "ABC");

		// close and reopen the tree to verify that the new tree uses the last used filter
		triggerSaveAndReload();

		assertFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		setFilterText("ABC");
		assertNodesByName(viewRoot(), "ABC");
	}

	@Test
	public void testFilterOptionsOverride() {

		//
		// This is testing the special case of setting preferred options on the 
		// DefaultGTreeFilterProvider.  When an API client sets the preferred options on that class,
		// we have chosen to not save or restore user preferences for that filter.  It is not clear
		// why we do that, but it is probably based on the assumption that the API client wants the
		// filter to always start in the preferred state.  The prevents filter from being restored
		// with a previous user filter that does not make sense for the general case.
		//

		// default configuration
		assertFilterOptions(TextFilterStrategy.CONTAINS);

		// 
		// Change the options and reload the tree so we know the preferences are saved
		//
		setFilterOptions(TextFilterStrategy.STARTS_WITH);
		triggerSaveAndReload();
		assertFilterOptions(TextFilterStrategy.STARTS_WITH);

		// set the filter settings manually via the API
		FilterOptions newOptions =
			new FilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false, false, false);
		rebuildTreeWithPreferredFilter(newOptions);

		// verify after building the tree with the preferred options that the previous persisted
		// options are not applied
		assertFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
	}

	private GTreeNode viewRoot() {
		return gTree.getViewRoot();
	}

	private void assertFilterOptions(TextFilterStrategy expectedStrategy) {

		GTreeFilterProvider filterProvider = runSwing(() -> gTree.getFilterProvider());
		DefaultGTreeFilterProvider defaultProvider =
			(DefaultGTreeFilterProvider) filterProvider;
		FilterOptions filterOptions = defaultProvider.getFilterOptions();
		TextFilterStrategy actualStrategy = filterOptions.getTextFilterStrategy();
		assertEquals(expectedStrategy, actualStrategy);
	}

	private void triggerSaveAndReload() {

		// trigger the window manager to save the table filter preferences to xml
		Element xml = new Element("TOOL");
		winMgr.saveToXML(xml);

		runSwing(() -> {
			winMgr.removeComponent(provider);
			gTree.dispose();
		});

		// put the state back in the window manager
		winMgr.restoreFromXML(xml);

		// load the new table and let it pull the preferences from the window manager
		buildTree();
	}

	private void rebuildTreeWithPreferredFilter(FilterOptions newOptions) {

		winMgr.removeComponent(provider);
		gTree.dispose();

		GTreeNode root = new TestRootNode();
		gTree = new GTree(root);

		setPreferredFilter(newOptions);

		filterField = (FilterTextField) gTree.getFilterField();
		provider = new TestTreeComponentProvider(tool, gTree);
		winMgr.addComponent(provider);

		waitForTree();
	}

	private void setPreferredFilter(FilterOptions newOptions) {
		runSwing(() -> {
			GTreeFilterProvider filterProvider = gTree.getFilterProvider();
			DefaultGTreeFilterProvider defaultProvider =
				(DefaultGTreeFilterProvider) filterProvider;
			defaultProvider.setPreferredFilterOptions(
				new FilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false, false, false));
		});
	}

	@Test
	public void testUsePath() {

		/*
		  Create a tree with the following nodes in order to test matching of a node name that 
		  exists at multiple levels.
		  
		  	Root/XYZ
		  	Root/folder1/XYZ
			Root/folder1/folder1_1/XYZ
			Root/folder1/folder1_1/folder1_1_1/XYZ
			Root/folder2/XYZ
		  
		 */

		String xyzName = "XYZ";
		GTreeNode root = new TestRootNode();
		TestNode folder1 = new TestNode("folder1");
		LeafNode leaf1 = new LeafNode(xyzName);
		folder1.addNode(leaf1);
		TestNode folder1_1 = new TestNode("folder1_1");
		LeafNode leaf1_1 = new LeafNode(xyzName);
		folder1_1.addNode(leaf1_1);
		TestNode folder1_1_1 = new TestNode("folder1_1_1");
		LeafNode leaf1_1_1 = new LeafNode(xyzName);
		folder1_1_1.addNode(leaf1_1_1);
		TestNode folder2 = new TestNode("folder2");
		LeafNode leaf2 = new LeafNode(xyzName);
		folder2.addNode(leaf2);

		folder1.addNode(folder1_1);
		folder1_1.addNode(folder1_1_1);

		root.addNode(folder1);
		root.addNode(folder2);

		gTree.setRootNode(root);
		waitForTree();

		setFilterOnPath(true);

		// name only; match all
		setFilterText(xyzName);
		//@formatter:off
		assertNodes(
			root.getChild(xyzName),
			leaf1,
			leaf1_1,
			leaf1_1_1,
			leaf2
		);
		//@formatter:on

		// folder1 and name; match all under folder1
		setFilterText("*folder1*" + xyzName);
		//@formatter:off
		assertNodes(
			// root.getChild(xyzName),  no match here
			leaf1,
			leaf1_1,
			leaf1_1_1
			// leaf2                    no match here
		);
		//@formatter:on

		// folder1_1 and name; match all under folder1_1
		setFilterText("*folder1_1*" + xyzName);
		//@formatter:off
		assertNodes(
			// root.getChild(xyzName),  no match here
			// leaf1,                   no match here
			leaf1_1,
			leaf1_1_1
			// leaf2                    no match here
		);
		//@formatter:on

		// folder1_1_1 and name; match only under folder1_1_1
		setFilterText("*folder1_1_1*" + xyzName);
		//@formatter:off
		assertNodes(
			// root.getChild(xyzName),  no match here
			// leaf1,                   no match here
			// leaf1_1,                 no match here
			leaf1_1_1
			// leaf2                    no match here
		);
		//@formatter:on

		// folder1_1_1 and name; match only under folder1_1_1
		setFilterText("Root/folder1/folder1_1/folder1_1_1/" + xyzName);
		//@formatter:off
		assertNodes(
			// root.getChild(xyzName),  no match here
			// leaf1,                   no match here
			// leaf1_1,                 no match here
			leaf1_1_1
			// leaf2                    no match here
		);
		//@formatter:on

		setFilterOnPath(false);
		// folder1_1_1 and name; match only under folder1_1_1
		setFilterText("*folder1_1_1*" + xyzName);
		assertNoMatches();
	}

	private void assertNoMatches() {
		assertEquals(0, viewRoot().getChildCount());
	}

	private void assertNodesByName(GTreeNode parent, String... nodes) {

		int count = 0;
		int rows = gTree.getRowCount();
		for (int i = 0; i < rows; i++) {
			TreePath path = gTree.getPathForRow(i);
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (node.isLeaf()) {
				if (node.isLeaf()) {
					count++;
				}
			}
		}

		assertEquals(nodes.length, count);
		for (String nodeName : nodes) {
			GTreeNode child = parent.getChild(nodeName);
			assertNotNull("No child found by name '%s'".formatted(nodeName), child);
		}
	}

	private void assertNodes(GTreeNode... nodes) {

		int count = 0;
		int rows = gTree.getRowCount();
		for (int i = 0; i < rows; i++) {
			TreePath path = gTree.getPathForRow(i);
			GTreeNode node = (GTreeNode) path.getLastPathComponent();
			if (node.isLeaf()) {
				if (node.isLeaf()) {
					count++;
				}
			}
		}

		assertEquals(nodes.length, count);
		for (GTreeNode node : nodes) {
			assertTrue(gTree.getRowForPath(node.getTreePath()) != -1);
		}
	}

	private void setFilterOnPath(boolean usePath) {
		runSwing(() -> {
			FilterOptions filterOptions =
				new FilterOptions(TextFilterStrategy.CONTAINS, true, false, false, usePath, false,
					FilterOptions.DEFAULT_DELIMITER, MultitermEvaluationMode.AND);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider())
					.setFilterOptions(filterOptions);
		});
		waitForTree();
	}

	private void checkContainsNode(String string) {
		List<GTreeNode> children = viewRoot().getChildren();
		for (GTreeNode gTreeNode : children) {
			if (gTreeNode.getName().equals(string)) {
				return;
			}
		}
		Assert.fail("Expected node " + string + " to be included in filter, but was not found!");
	}

	private void checkDoesNotContainsNode(String string) {
		List<GTreeNode> children = viewRoot().getChildren();
		for (GTreeNode gTreeNode : children) {
			if (gTreeNode.getName().equals(string)) {
				Assert.fail("Expected node " + string +
					" to be NOT be included in filter, but was not found!");
			}
		}
	}

	private void setFilterText(final String text) {
		runSwing(() -> {
			filterField.setText(text);
		});
		waitForTree();
	}

	private void setFilterOptions(final TextFilterStrategy filterStrategy) {
		setFilterOptions(filterStrategy, false);
	}

	private void setFilterOptions(final TextFilterStrategy filterStrategy, final boolean inverted) {

		runSwing(() -> {
			FilterOptions filterOptions = new FilterOptions(filterStrategy, false, false, inverted);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider())
					.setFilterOptions(filterOptions);
		});
		waitForTree();
	}

	private void setFilterOptions(TextFilterStrategy filterStrategy, boolean inverted,
			boolean multiTerm, char splitCharacter, MultitermEvaluationMode evalMode) {
		runSwing(() -> {
			FilterOptions filterOptions = new FilterOptions(filterStrategy, false, false, inverted,
				false, multiTerm, splitCharacter, evalMode);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider())
					.setFilterOptions(filterOptions);
		});
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(gTree);
	}

}
