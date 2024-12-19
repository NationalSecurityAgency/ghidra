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
package docking.widgets.table;

import static org.junit.Assert.*;

import java.awt.BorderLayout;
import java.util.List;

import javax.swing.JComponent;
import javax.swing.JPanel;

import org.jdom.Element;
import org.junit.*;

import docking.*;
import docking.widgets.filter.*;
import docking.widgets.table.model.DirData;
import docking.widgets.table.model.TestDataModel;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.DummyTool;
import ghidra.util.table.GhidraTable;

public class GhidraTableFilterTest extends AbstractGhidraHeadedIntegrationTest {
	private static final int TOTAL_TABLE_ROWS = 12;
	private TestDataModel model;
	private RowObjectTableModel<DirData> filteredModel;
	private GhidraTable table;
	private GTableFilterPanel<DirData> filterPanel;
	private DockingWindowManager winMgr;
	private DummyTool tool;
	private TestTableComponentProvider provider;

	@Before
	public void setUp() throws Exception {

		tool = new DummyTool();
		winMgr = new DockingWindowManager(tool, null);
		winMgr.setVisible(true);

		buildTable();
	}

	private void buildTable() throws Exception {

		runSwingWithException(() -> {
			model = new TestDataModel("filterTestDirList.txt");
			table = new GhidraTable(model);
			filterPanel = new GTableFilterPanel<>(table, model);
			filteredModel = filterPanel.getTableFilterModel();
			table.setAutoLookupColumn(4);
			provider = new TestTableComponentProvider(tool);
		});

		winMgr.addComponent(provider);
		waitForSwing();
	}

	@After
	public void tearDown() throws Exception {
		winMgr.dispose();
		filterPanel.dispose();
	}

	@Test
	public void testContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS);
		// no filter text - make sure all 5 nodes are there
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC");
		assertEquals(4, filteredModel.getRowCount());

		checkContainsName("ABC");
		checkContainsName("XABC");
		checkContainsName("ABCX");
		checkContainsName("XABCX");

		setFilterText("MMM");
		assertEquals(0, filteredModel.getRowCount());

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testInvertedContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, true);
		// no filter text - make sure all 5 nodes are there
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC");
		assertEquals(8, filteredModel.getRowCount());

		checkDoesNotContainsName("ABC");
		checkDoesNotContainsName("XABC");
		checkDoesNotContainsName("ABCX");
		checkDoesNotContainsName("XABCX");

		setFilterText("MMM");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testMultiWordContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ' ',
			MultitermEvaluationMode.AND);
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC 2002");
		assertEquals(2, filteredModel.getRowCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ' ', MultitermEvaluationMode.OR);

		setFilterText("ABC 2002");
		assertEquals(8, filteredModel.getRowCount());

		checkContainsName("ABC");
		checkContainsName("XABCX");

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testInvertedMultiWordContains() {
		setFilterOptions(TextFilterStrategy.CONTAINS, true, true, ' ', MultitermEvaluationMode.AND);

		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC 2002");
		assertEquals(10, filteredModel.getRowCount());

		setFilterOptions(TextFilterStrategy.CONTAINS, true, true, ' ', MultitermEvaluationMode.OR);
		assertEquals(4, filteredModel.getRowCount());

		checkDoesNotContainsName("ABC");
		checkDoesNotContainsName("XABCX");

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testStartsWith() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH);

		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC");
		checkContainsName("ABC");
		checkContainsName("ABCX");
		assertEquals(2, filteredModel.getRowCount());

		setFilterText("MMM");
		assertEquals(0, filteredModel.getRowCount());

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testInvertedStartsWith() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH, true);

		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC");
		checkDoesNotContainsName("ABC");
		checkDoesNotContainsName("ABCX");
		assertEquals(10, filteredModel.getRowCount());

		setFilterText("MMM");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testExactMatch() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC");
		checkContainsName("ABC");
		assertEquals(1, filteredModel.getRowCount());

		setFilterText("MMM");
		assertEquals(0, filteredModel.getRowCount());

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testInvertedExactMatch() {
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY, true);
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("ABC");
		checkDoesNotContainsName("ABC");
		assertEquals(11, filteredModel.getRowCount());

		setFilterText("MMM");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testRegExMatch() {
		setFilterOptions(TextFilterStrategy.REGULAR_EXPRESSION);

		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());

		setFilterText("^ABC$");
		checkContainsName("ABC");
		assertEquals(1, filteredModel.getRowCount());

		setFilterText("ABC");
		checkContainsName("ABC");
		checkContainsName("XABC");
		checkContainsName("ABCX");
		checkContainsName("XABCX");
		assertEquals(4, filteredModel.getRowCount());

		setFilterText("XA.{0,2}X");
		checkContainsName("XABCX");
		assertEquals(1, filteredModel.getRowCount());

		setFilterText("X{0,1}A.{0,2}X");
		checkContainsName("XABCX");
		checkContainsName("ABCX");
		checkContainsName("ABXC");
		assertEquals(3, filteredModel.getRowCount());

		setFilterText("");
		assertEquals(TOTAL_TABLE_ROWS, filteredModel.getRowCount());
	}

	@Test
	public void testSwitchFilterTypes() {
		setFilterOptions(TextFilterStrategy.STARTS_WITH);
		setFilterText("ABC");
		checkContainsName("ABC");
		checkContainsName("ABCX");
		assertEquals(2, filteredModel.getRowCount());

		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		checkContainsName("ABC");
		assertEquals(1, filteredModel.getRowCount());

		setFilterOptions(TextFilterStrategy.CONTAINS);
		assertEquals(4, filteredModel.getRowCount());
		checkContainsName("ABC");
		checkContainsName("XABC");
		checkContainsName("ABCX");
		checkContainsName("XABCX");

	}

	@Test
	public void testFilterPersistence() throws Exception {

		// default configuration
		assertFilterOptions(TextFilterStrategy.CONTAINS);

		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		setFilterText("ABC");
		setFilterText("ABC");

		setFilterOptions(TextFilterStrategy.STARTS_WITH);
		setFilterText("ABC");
		checkContainsName("ABC");
		checkContainsName("ABCX");

		// close and reopen the table to verify that the new tree uses the last used filter
		triggerSaveAndReload();

		assertFilterOptions(TextFilterStrategy.STARTS_WITH);
		setFilterText("ABC");
		checkContainsName("ABC");
		checkContainsName("ABCX");

		// put back, test, and then make sure the updated filter is restored
		setFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		setFilterText("ABC");
		checkContainsName("ABC");

		// close and reopen the table to verify that the new tree uses the last used filter
		triggerSaveAndReload();

		assertFilterOptions(TextFilterStrategy.MATCHES_EXACTLY);
		setFilterText("ABC");
		checkContainsName("ABC");
	}

	@Test
	public void testWhiteSpaceDelimiter() {
		waitForSwing();
		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ' ', MultitermEvaluationMode.OR);
		setFilterText("ABC");
		checkContainsName("ABC");
		assertEquals(4, filteredModel.getRowCount());

		setFilterText("ABC     export");
		assertEquals(5, filteredModel.getRowCount());

		setFilterText("ABC     export drivers");
		assertEquals(6, filteredModel.getRowCount());
	}

	@Test
	public void testCommaMultiTermFilter() {
		waitForSwing();
		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, ',', MultitermEvaluationMode.OR);
		setFilterText("ABC");
		checkContainsName("ABC");
		assertEquals(4, filteredModel.getRowCount());

		setFilterText("ABC,export");
		assertEquals(5, filteredModel.getRowCount());

		setFilterText("ABC ,export");
		assertEquals(5, filteredModel.getRowCount());

		setFilterText("ABC, export");
		assertEquals(5, filteredModel.getRowCount());

		setFilterText("ABC,export,drivers");
		assertEquals(6, filteredModel.getRowCount());
	}

	@Test
	public void testQuotedMultiTermFilter() {
		waitForSwing();
		setFilterOptions(TextFilterStrategy.CONTAINS, false, true, '-', MultitermEvaluationMode.OR);
		setFilterText("ABC");
		checkContainsName("ABC");
		assertEquals(4, filteredModel.getRowCount());

		setFilterText("ABC-export");
		assertEquals(5, filteredModel.getRowCount());

		setFilterText("\"a-\"");
		assertEquals(1, filteredModel.getRowCount());

		setFilterText("\"-test\"");
		assertEquals(2, filteredModel.getRowCount());

		setFilterText("\"-test\"-abc");
		assertEquals(6, filteredModel.getRowCount());

	}

	@Test
	public void testWithColumnOff() {
		GTableColumnModel columnModel = (GTableColumnModel) table.getColumnModel();

		// make sure that when the time column is on, one match is found
		setFilterText("12:00");
		assertEquals(1, filteredModel.getRowCount());

		// turn off the 'Time' column
		columnModel.setVisible(columnModel.getColumn(1), false);

		// make sure that when the column is off, no matches are found
		setFilterText("12:00");
		assertEquals(0, filteredModel.getRowCount());

		// make sure that the next column over (index-wise) still produces matches (this
		// was a bug we had)
		setFilterText("export");
		assertEquals(1, filteredModel.getRowCount());
	}

//=================================================================================================
// Private Methods
//=================================================================================================	

	private void triggerSaveAndReload() throws Exception {

		// trigger the window manager to save the table filter preferences to xml
		Element xml = new Element("TOOL");
		winMgr.saveToXML(xml);

		runSwing(() -> {
			winMgr.removeComponent(provider);
			filterPanel.dispose();
		});

		// put the state back in the window manager
		winMgr.restoreFromXML(xml);

		// load the new table and let it pull the preferences from the window manager
		buildTable();
	}

	private void assertFilterOptions(TextFilterStrategy expectedStrategy) {
		FilterOptions filterOptions = runSwing(() -> filterPanel.getFilterOptions());
		TextFilterStrategy actualStrategy = filterOptions.getTextFilterStrategy();
		assertEquals(expectedStrategy, actualStrategy);
	}

	private void setFilterOptions(TextFilterStrategy filterStrategy) {
		setFilterOptions(filterStrategy, false);
	}

	private void setFilterOptions(TextFilterStrategy filterStrategy, boolean inverted) {
		runSwing(() -> {
			filterPanel.setFilterOptions(new FilterOptions(filterStrategy, false, false, inverted));
		});
		waitForSwing();
	}

	private void setFilterOptions(TextFilterStrategy filterStrategy, boolean inverted,
			boolean multiTerm, char splitter, MultitermEvaluationMode evalMode) {
		filterPanel.setFilterOptions(new FilterOptions(filterStrategy, false, false, inverted,
			false, multiTerm, splitter, evalMode));
		waitForSwing();
	}

	private void checkContainsName(String string) {
		List<DirData> modelData = filteredModel.getModelData();
		for (DirData dirData : modelData) {
			if (dirData.getName().equals(string)) {
				return;
			}
		}
		Assert.fail(
			"Expected dir entry " + string + " to be included in filter, but was not found!");
	}

	private void checkDoesNotContainsName(String string) {
		List<DirData> modelData = filteredModel.getModelData();
		for (DirData dirData : modelData) {
			if (dirData.getName().equals(string)) {
				Assert.fail("Did not Expect dir entry " + string +
					" to be included in filter, but was found!");
			}
		}
	}

	private void setFilterText(final String text) {
		runSwing(() -> filterPanel.setFilterText(text));
		waitForSwing();
	}

	private class TestTableComponentProvider extends ComponentProvider {

		private JPanel panel;

		public TestTableComponentProvider(DummyTool tool) {
			super(tool, "Test", "Test");
			setDefaultWindowPosition(WindowPosition.STACK);
			setTabText("Test");

			panel = new JPanel(new BorderLayout());
			panel.add(table, BorderLayout.CENTER);
			panel.add(filterPanel, BorderLayout.SOUTH);
		}

		@Override
		public JComponent getComponent() {
			return panel;
		}

		@Override
		public String getTitle() {
			return "Test Tree";
		}
	}
}
