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

import org.junit.*;

import docking.DockingWindowManager;
import docking.test.AbstractDockingTest;
import docking.widgets.filter.*;
import ghidra.test.DummyTool;
import ghidra.util.StringUtilities;

public class GTreeFilterTest extends AbstractDockingTest {

	private GTree gTree;
	private FilterTextField filterField;

	private DockingWindowManager winMgr;

	@Before
	public void setUp() throws Exception {
		GTreeNode root = new TestRootNode();
		gTree = new GTree(root);

		filterField = (FilterTextField) gTree.getFilterField();

		winMgr = new DockingWindowManager(new DummyTool(), null);
		winMgr.addComponent(new TestTreeComponentProvider(gTree));
		winMgr.setVisible(true);

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
		assertEquals("Expected 4 of nodes to be in filtered tree!", 4,
			viewRoot().getChildCount());

		checkContainsNode("ABC");
		checkContainsNode("XABC");
		checkContainsNode("ABCX");
		checkContainsNode("XABCX");

		setFilterText("MMM");
		assertEquals("Expected 4 of nodes to be in filtered tree!", 0, viewRoot().getChildCount());

		setFilterText("");
		assertEquals("Expected all 5 nodes to be back", 5, viewRoot().getChildCount());
	}

	private GTreeNode viewRoot() {
		return gTree.getViewRoot();
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
	public void testSavingSelectedFilterType() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false);
		setFilterText("ABC");
		checkContainsNode("ABC");
		assertEquals(1, viewRoot().getChildCount());

		Object originalValue = getInstanceField("uniquePreferenceKey", gTree);
		setInstanceField("preferenceKey", gTree.getFilterProvider(), "XYZ");
		setFilterOptions(TextFilterStrategy.STARTS_WITH, false);
		checkContainsNode("ABC");
		checkContainsNode("ABCX");
		assertEquals(2, viewRoot().getChildCount());

		setInstanceField("preferenceKey", gTree.getFilterProvider(), originalValue);
		setInstanceField("optionsSet", gTree.getFilterProvider(), false);
		restorePreferences();
		checkContainsNode("ABC");
		assertEquals(1, viewRoot().getChildCount());

	}

	private void restorePreferences() {
		runSwing(() -> {
			GTreeFilterProvider filterProvider = gTree.getFilterProvider();
			String key = (String) getInstanceField("uniquePreferenceKey", gTree);
			Class<?>[] classes = new Class[] { DockingWindowManager.class, String.class };
			Object[] objs = new Object[] { winMgr, key };
			invokeInstanceMethod("loadFilterPreference", filterProvider, classes, objs);
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

	private void setFilterOptions(final TextFilterStrategy filterStrategy, final boolean inverted) {

		runSwing(() -> {
			FilterOptions filterOptions = new FilterOptions(filterStrategy, false, false, inverted);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider()).setFilterOptions(
				filterOptions);
		});
		waitForTree();

	}

	private void setFilterOptions(TextFilterStrategy filterStrategy, boolean inverted,
			boolean multiTerm, char splitCharacter, MultitermEvaluationMode evalMode) {
		runSwing(() -> {
			FilterOptions filterOptions = new FilterOptions(filterStrategy, false, false, inverted,
				multiTerm, splitCharacter, evalMode);
			((DefaultGTreeFilterProvider) gTree.getFilterProvider()).setFilterOptions(
				filterOptions);
		});
		waitForTree();
	}

	private void waitForTree() {
		waitForTree(gTree);
	}

}
