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
package ghidra.features.bsim.gui.search.dialog;

import static org.junit.Assert.*;

import java.sql.SQLException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.*;

import ghidra.features.bsim.gui.AbstractBSimPluginTest;
import ghidra.features.bsim.gui.filters.*;
import ghidra.features.bsim.query.SQLFunctionDatabase;
import ghidra.features.bsim.query.client.*;
import ghidra.features.bsim.query.facade.FunctionDatabaseTestDouble;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.program.database.symbol.FunctionSymbol;

/**
 * Tests the filtering components of BSim accessible from the UI. This will cover the 
 * following:
 * 
 * 	- loading default filters
 * 	- adding/removing/changing filters
 * 	- input validation
 * 	- proper construction of queries
 *
 */
public class BSimFilterPanelTest extends AbstractBSimPluginTest {

	private Set<FunctionSymbol> selectedFunctions = new HashSet<>();
	private BSimFilterPanel filterPanel;

	@Before
	public void setUp() throws Exception {
		super.setUp();
		goTo(FUN1_ADDR);
		performAction(searchAction, false);

		searchDialog = waitForDialogComponent(BSimSearchDialog.class);
		filterPanel = BSimSearchDialogTestHelper.getFilterPanel(searchDialog);
	}

	@After
	public void tearDown() throws Exception {
		close(searchDialog);
		env.dispose();
	}

	@Test
	public void testOneFilterInPanelByDefault() {
		List<FilterWidget> widgets = filterPanel.getFilterWidgets();
		assertEquals(1, widgets.size());
		FilterWidget widget = widgets.get(0);
		List<BSimFilterType> filterTypes = widget.getChoosableFilterTypes();
		List<BSimFilterType> baseFilters = BSimFilterType.getBaseFilters();

		// should have all the base filters plus 2 for date earler, date later and 3 for
		// function tags "KNOWN_LIBRARY", "HAS_UNIMPLEMENTED", and "HAS_BAD_DATA"
		assertTrue(filterTypes.containsAll(baseFilters));
		assertEquals(baseFilters.size() + 5, filterTypes.size());
	}

	@Test
	public void testAddFilter() {
		List<FilterWidget> widgets = filterPanel.getFilterWidgets();
		assertEquals(1, widgets.size());

		pressButtonByName(filterPanel, "Add Filter");

		widgets = filterPanel.getFilterWidgets();
		assertEquals(2, widgets.size());

		pressButtonByName(filterPanel, "Add Filter");

		widgets = filterPanel.getFilterWidgets();
		assertEquals(3, widgets.size());

	}

	@Test
	public void testRemoveFilter() {
		List<FilterWidget> widgets = filterPanel.getFilterWidgets();

		pressButtonByName(filterPanel, "Add Filter");

		widgets = filterPanel.getFilterWidgets();
		assertEquals(2, widgets.size());

		pressButtonByName(widgets.get(0), "Delete Filter");
		widgets = filterPanel.getFilterWidgets();
		assertEquals(1, widgets.size());
	}

	@Test
	public void testRemovingLastFilterLeavesItButIsBackToBlankFilter() {
		FilterWidget widget = filterPanel.getFilterWidgets().get(0);

		assertEquals(new BlankBSimFilterType(), widget.getSelectedFilter());
		ExecutableNameBSimFilterType exeFilter = new ExecutableNameBSimFilterType();
		setFilter(widget, exeFilter, "bob");

		assertEquals(exeFilter, widget.getSelectedFilter());
		assertEquals("bob", widget.getValues().get(0));

		pressButtonByName(widget, "Delete Filter");

		widget = filterPanel.getFilterWidgets().get(0);
		assertEquals(new BlankBSimFilterType(), widget.getSelectedFilter());

	}

	@Test
	public void testFilterValidation_MD5() {
		FilterWidget widget = filterPanel.getFilterWidgets().get(0);
		setFilter(widget, new Md5BSimFilterType(), "123");
		assertFalse(widget.hasValidValue());

		setFilter(widget, new Md5BSimFilterType(), "0123456789ABCDEF0123456789ABCEDF");
		assertTrue(hasValidValue(widget));
	}

	@Test
	public void testFilterValidation_Dates() {
		FilterWidget widget = filterPanel.getFilterWidgets().get(0);
		DateEarlierBSimFilterType dateFilter = new DateEarlierBSimFilterType("Ingest Date");
		setFilter(widget, dateFilter, "123");
		assertFalse(widget.hasValidValue());

		setFilter(widget, dateFilter, "09211974");
		assertFalse(hasValidValue(widget));

		setFilter(widget, dateFilter, "January 4th, 2006");
		assertFalse(hasValidValue(widget));

		setFilter(widget, dateFilter, "2001/07/11");
		assertTrue(hasValidValue(widget));

		setFilter(widget, dateFilter, "09/21/1974");
		assertTrue(hasValidValue(widget));

		setFilter(widget, dateFilter, "2001-01-01");
		assertTrue(hasValidValue(widget));
	}

	/**
	 * Tests that duplicate filters are correctly combined in the final
	 * query.
	 * 
	 * ie: (compiler_name = 0) OR (compiler_name = 1)
	 * @throws SQLException if there's a problem creating the query
	 */
	@Test
	public void testDuplicateFilters() throws SQLException {

		pressButtonByName(filterPanel, "Add Filter");
		List<FilterWidget> widgets = filterPanel.getFilterWidgets();

		setFilter(widgets.get(0), new CompilerBSimFilterType(), "gcc");
		setFilter(widgets.get(1), new CompilerBSimFilterType(), "gcc2");

		BSimSqlClause clause = getSqlClause();
		// Verify that we have two compiler clauses.
		String clause1 = "name_compiler=1";
		String clause2 = "name_compiler=0";
		assertTrue(clause.whereClause().contains(clause1));
		assertTrue(clause.whereClause().contains(clause2));

		// And verify that those two clauses are separated by an OR.
		String glue = getTextBetween(clause.whereClause(), clause1, clause2);
		assertTrue(glue.contains("OR"));
		assertTrue(!glue.contains("AND"));
	}

	/**
	 * Tests that multiple entries in a single filter are correctly parsed.
	 * 
	 * @throws SQLException if there's a problem creating the query
	 */
	@Test
	public void testCSVEntry() throws SQLException {
		List<FilterWidget> widgets = filterPanel.getFilterWidgets();

		setFilter(widgets.get(0), new CompilerBSimFilterType(), List.of("gcc", "gcc2", "gcc3"));

		BSimSqlClause clause = getSqlClause();

		// Verify that we have three clauses.
		String clause1 = "name_compiler=0";
		String clause2 = "name_compiler=1";
		String clause3 = "name_compiler=2";
		assertTrue(clause.whereClause().contains(clause1));
		assertTrue(clause.whereClause().contains(clause2));
		assertTrue(clause.whereClause().contains(clause3));

		// And verify that those two clauses are separated by an OR.
		String glue = getTextBetween(clause.whereClause(), clause1, clause2);
		assertTrue(glue.contains("OR"));
		assertTrue(!glue.contains("AND"));

	}

	/**
	 * Tests that multiple negative filters are correctly combined.
	 * 
	 * ie: (name != bob) && (name != john)
	 * 
	 * @throws SQLException if there's a problem creating the query
	 * 
	 */
	@Test
	public void testCombiningNegativeFilters() throws SQLException {
		pressButtonByName(filterPanel, "Add Filter");
		List<FilterWidget> widgets = filterPanel.getFilterWidgets();

		setFilter(widgets.get(0), new NotExecutableNameBSimFilterType(), "exename");
		setFilter(widgets.get(1), new NotExecutableNameBSimFilterType(), "othername");

		BSimSqlClause clause = getSqlClause();
		// Verify that we have two compiler clauses.
		String clause1 = "name_exec != 'exename'";
		String clause2 = "name_exec != 'othername'";
		assertTrue(clause.whereClause().contains(clause1));
		assertTrue(clause.whereClause().contains(clause2));

		// And verify that those two clauses are separated by an OR.
		String glue = getTextBetween(clause.whereClause(), clause1, clause2);
		assertTrue(!glue.contains("OR"));
		assertTrue(glue.contains("AND"));
	}

	/**
	 * Tests that multiple positive filters are correctly combined.
	 * 
	 * ie: (name == bob) || (name == john)
	 * 
	 * @throws SQLException if there's a problem creating the query
	 */
	@Test
	public void testCombiningPositiveFilters() throws SQLException {
		pressButtonByName(filterPanel, "Add Filter");
		List<FilterWidget> widgets = filterPanel.getFilterWidgets();

		setFilter(widgets.get(0), new CompilerBSimFilterType(), "gcc");
		setFilter(widgets.get(1), new ArchitectureBSimFilterType(), "x86:LE:64:default");

		BSimSqlClause clause = getSqlClause();
		// Verify that we have two compiler clauses.
		String clause1 = "name_compiler=0";
		String clause2 = "architecture=1";
		assertTrue(clause.whereClause().contains(clause1));
		assertTrue(clause.whereClause().contains(clause2));

		// And verify that those two clauses are separated by an OR.
		String glue = getTextBetween(clause.whereClause(), clause1, clause2);
		assertTrue(!glue.contains("OR"));
		assertTrue(glue.contains("AND"));
	}

	/**
	 * Generates a fake set of resolution IDs to be used in generating filter
	 * queries. For the purpose of this test suite, the value of the IDs isn't
	 * important; we just have to have valid objects to pass to the query.
	 * 
	 * @param exeFilter the BSim filter object
	 * @return the array of resolution IDs
	 */
	private IDSQLResolution[] createMockResolutionIDs(BSimFilter exeFilter) {

		IDSQLResolution[] idres = new IDSQLResolution[exeFilter.numAtoms()];
		for (int i = 0; i < idres.length; i++) {
			idres[i] = new IDSQLResolution.Compiler("something");
			idres[i].id1 = i;
		}

		return idres;
	}

	/**
	 * Uses regex to search a given string for all text between two substrings of
	 * that full string. The position of the two substrings relative to eachother
	 * is unimportant. ie: str1 + <some stuff> + str2 will work just as well as
	 * str2 + <some stuff> + str1. This method will figure out what the correct
	 * order is.
	 * 
	 * Note: This is used in this test suite to find out if two sql clauses are
	 * 		combined using AND's or OR's.
	 * 	
	 * @param fullString the full string containing str1 and str2
	 * @param str1 one side of the search
	 * @param str2 the other side of the search
	 * @return all text between str1 and str2
	 */
	private String getTextBetween(String fullString, String str1, String str2) {

		// First figure out which substring is on the left and which is on the right.
		int index1 = fullString.indexOf(str1);
		int index2 = fullString.indexOf(str2);
		if (index1 > index2) {
			String temp = str1;
			str1 = str2;
			str2 = temp;
		}

		String regex = Pattern.quote(str1) + "(.*?)" + Pattern.quote(str2);
		Pattern pattern = Pattern.compile(regex);
		Matcher matcher = pattern.matcher(fullString);
		while (matcher.find()) {
			return matcher.group(1);
		}

		return "";
	}

	private void setFilter(FilterWidget widget, BSimFilterType filter, String value) {
		setFilter(widget, filter, List.of(value));
	}

	private void setFilter(FilterWidget widget, BSimFilterType filter, List<String> values) {
		runSwing(() -> widget.setFilter(filter, values));
	}

	private boolean hasValidValue(FilterWidget widget) {
		return runSwing(() -> widget.hasValidValue());
	}

	private BSimSqlClause getSqlClause() throws SQLException {
		BSimFilter bSimFilter = runSwing(() -> filterPanel.getFilterSet().getBSimFilter());
		IDSQLResolution[] resolutionIds = createMockResolutionIDs(bSimFilter);
		SQLFunctionDatabase database = new FunctionDatabaseTestDouble();
		BSimSqlClause clause = SQLEffects.createFilter(bSimFilter, resolutionIds, database);
		return clause;
	}

}
