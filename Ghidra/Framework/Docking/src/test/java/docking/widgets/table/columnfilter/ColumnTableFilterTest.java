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
package docking.widgets.table.columnfilter;

import static org.junit.Assert.*;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.util.*;

import javax.swing.table.TableColumn;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.table.*;
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.MappedColumnConstraint;
import docking.widgets.table.constraint.dialog.*;
import docking.widgets.table.constraint.provider.*;
import ghidra.framework.options.SaveState;
import mockit.Mock;
import mockit.MockUp;

/**
 * This test performs operations on swing components in the test thread.  I believe this is ok
 * since in this test, the widgets are never realized and the swing thread in generally not
 * involved.  If this test has displays intermittent failures, then more work will be needed to
 * fix the threading when accessing swing components.
 */
public class ColumnTableFilterTest {
	private SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("MM/dd/yyyy");
	private RowObjectFilterModel<Integer> tableModel;
	private GTable gTable;
	private ColumnFilterDialogModel<Integer> filterModel;
	private List<ColumnConstraint<?>> allConstraints;

	@Before
	public void setup() {
		allConstraints = loadConstraints();
		// using a mock up to load discoverable column filters without performing a class search.
		new MockUp<DiscoverableTableUtils>() {
			@Mock
			public List<ColumnConstraint<?>> getColumnConstraints(Class<?> columnType) {
				List<ColumnConstraint<?>> matches = new ArrayList<>();
				for (ColumnConstraint<?> columnConstraint : allConstraints) {
					if (columnConstraint.getColumnType().equals(columnType)) {
						matches.add(columnConstraint);
					}
				}
				return matches;
			}
		};
		tableModel = createTableModel();
		gTable = new GTable(tableModel);
		filterModel = new ColumnFilterDialogModel<>(tableModel, gTable.getColumnModel(), null);
	}

	private RowObjectFilterModel<Integer> createTableModel() {
		TestTableModel testTableModel = new TestTableModel();

		testTableModel.addColumn("Name",
			new String[] { "Alice", "Bob", "Chuck", "Dave", "Ellen", "Frank" });

		testTableModel.addColumn("Age",
			new Byte[] { (byte) 1, (byte) 2, (byte) 3, (byte) 4, (byte) 5, (byte) 6 });

		testTableModel.addColumn("ID", new Short[] { (short) 100, (short) 200, (short) 300,
			(short) 400, (short) 500, (short) 600 });

		testTableModel.addColumn("Net Worth",
			new Integer[] { 600000, 500000, 400000, 300000, 200000, 100000 });

		testTableModel.addColumn("Long ID",
			new Long[] { 1000l, 2000l, 3000l, 4000l, 5000l, 10000000000l });

		testTableModel.addColumn("Birth Date", new Date[] { date("01/01/2010"), date("01/02/2010"),
			date("01/03/2010"), date("01/04/2010"), date("01/05/2010"), date("01/06/2010"), });

		return new TableModelWrapper<>(testTableModel);
	}

	private Date date(String dateString) {
		try {
			return DATE_FORMAT.parse(dateString);
		}
		catch (ParseException e) {
			fail("Can't parse date: " + dateString);
		}
		return null;
	}

	@Test
	public void testStringStartsWithColumnFilter() {
		addFirstFilter("Name", "Starts With", "C");

		applyFilter();

		assertEquals(1, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Chuck", tableModel.getValueAt(0, col));
	}

	@Test
	public void testStringDoesNotStartsWithColumnFilter() {
		addFirstFilter("Name", "Does Not Start With", "C");

		applyFilter();

		assertEquals(5, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Alice", tableModel.getValueAt(0, col));
		assertEquals("Bob", tableModel.getValueAt(1, col));
		assertEquals("Dave", tableModel.getValueAt(2, col));
		assertEquals("Ellen", tableModel.getValueAt(3, col));
		assertEquals("Frank", tableModel.getValueAt(4, col));
	}

	@Test
	public void testStringEndsWithColumnFilter() {
		addFirstFilter("Name", "Ends With", "e");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Alice", tableModel.getValueAt(0, col));
		assertEquals("Dave", tableModel.getValueAt(1, col));
	}

	@Test
	public void testStringContainsColumnFilter() {
		addFirstFilter("Name", "Contains", "l");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Alice", tableModel.getValueAt(0, col));
		assertEquals("Ellen", tableModel.getValueAt(1, col));
	}

	@Test
	public void testStringMatchesColumnFilter() {
		addFirstFilter("Name", "Matches Regex", ".*l.*e.*");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Alice", tableModel.getValueAt(0, col));
		assertEquals("Ellen", tableModel.getValueAt(1, col));
	}

	@Test
	public void testStringNotContainsColumnFilter() {
		addFirstFilter("Name", "Does Not Contain", "l");

		applyFilter();

		assertEquals(4, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Bob", tableModel.getValueAt(0, col));
		assertEquals("Chuck", tableModel.getValueAt(1, col));
		assertEquals("Dave", tableModel.getValueAt(2, col));
		assertEquals("Frank", tableModel.getValueAt(3, col));
	}

	@Test
	public void testByteAtLeastFilter() {
		addFirstFilter("Age", "At Least", "5");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Age");
		assertEquals((byte) 5, tableModel.getValueAt(0, col));
		assertEquals((byte) 6, tableModel.getValueAt(1, col));
	}

	@Test
	public void testByteAtMostFilter() {
		addFirstFilter("Age", "At Most", "2");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Age");
		assertEquals((byte) 1, tableModel.getValueAt(0, col));
		assertEquals((byte) 2, tableModel.getValueAt(1, col));
	}

	@Test
	public void testByteInRangeFilter() {
		addFirstFilter("Age", "In Range", "[2,4]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Age");
		assertEquals((byte) 2, tableModel.getValueAt(0, col));
		assertEquals((byte) 3, tableModel.getValueAt(1, col));
		assertEquals((byte) 4, tableModel.getValueAt(2, col));
	}

	@Test
	public void testByteNotInRangeFilter() {
		addFirstFilter("Age", "Not In Range", "[2,4]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Age");
		assertEquals((byte) 1, tableModel.getValueAt(0, col));
		assertEquals((byte) 5, tableModel.getValueAt(1, col));
		assertEquals((byte) 6, tableModel.getValueAt(2, col));
	}

	@Test
	public void testShortAtLeastFilter() {
		addFirstFilter("ID", "At Least", "500");

		applyFilter();

		int col = getColumn("ID");
		assertEquals(2, tableModel.getRowCount());
		assertEquals((short) 500, tableModel.getValueAt(0, col));
		assertEquals((short) 600, tableModel.getValueAt(1, col));
	}

	@Test
	public void testShortAtMostFilter() {
		addFirstFilter("ID", "At Most", "210");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("ID");
		assertEquals((short) 100, tableModel.getValueAt(0, col));
		assertEquals((short) 200, tableModel.getValueAt(1, col));
	}

	@Test
	public void testShortInRangeFilter() {
		addFirstFilter("ID", "In Range", "[200,400]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("ID");
		assertEquals((short) 200, tableModel.getValueAt(0, col));
		assertEquals((short) 300, tableModel.getValueAt(1, col));
		assertEquals((short) 400, tableModel.getValueAt(2, col));
	}

	@Test
	public void testShortNotInRangeFilter() {
		addFirstFilter("ID", "Not In Range", "[200,410]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("ID");

		assertEquals((short) 100, tableModel.getValueAt(0, col));
		assertEquals((short) 500, tableModel.getValueAt(1, col));
		assertEquals((short) 600, tableModel.getValueAt(2, col));
	}

	@Test
	public void testIntAtLeastFilter() {
		addFirstFilter("Net Worth", "At Least", "500000");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Net Worth");
		assertEquals(600000, tableModel.getValueAt(0, col));
		assertEquals(500000, tableModel.getValueAt(1, col));
	}

	@Test
	public void testIntAtMostFilter() {
		addFirstFilter("Net Worth", "At Most", "200000");

		applyFilter();

		int col = getColumn("Net Worth");
		assertEquals(2, tableModel.getRowCount());
		assertEquals(200000, tableModel.getValueAt(0, col));
		assertEquals(100000, tableModel.getValueAt(1, col));
	}

	@Test
	public void testIntInRangeFilter() {
		addFirstFilter("Net Worth", "In Range", "[200000,400000]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Net Worth");
		assertEquals(400000, tableModel.getValueAt(0, col));
		assertEquals(300000, tableModel.getValueAt(1, col));
		assertEquals(200000, tableModel.getValueAt(2, col));
	}

	@Test
	public void testIntNotInRangeFilter() {
		addFirstFilter("Net Worth", "Not In Range", "[200000,400000]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Net Worth");
		assertEquals(600000, tableModel.getValueAt(0, col));
		assertEquals(500000, tableModel.getValueAt(1, col));
		assertEquals(100000, tableModel.getValueAt(2, col));
	}

	@Test
	public void testLongAtLeastFilter() {
		addFirstFilter("Long ID", "At Least", "5000");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Long ID");
		assertEquals(5000l, tableModel.getValueAt(0, col));
		assertEquals(10000000000l, tableModel.getValueAt(1, col));
	}

	@Test
	public void testLongAtMostFilter() {
		addFirstFilter("Long ID", "At Most", "2000");

		applyFilter();

		int col = getColumn("Long ID");
		assertEquals(2, tableModel.getRowCount());
		assertEquals(1000l, tableModel.getValueAt(0, col));
		assertEquals(2000l, tableModel.getValueAt(1, col));
	}

	@Test
	public void testLongInRangeFilter() {
		addFirstFilter("Long ID", "In Range", "[2000,4000]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Long ID");
		assertEquals(2000l, tableModel.getValueAt(0, col));
		assertEquals(3000l, tableModel.getValueAt(1, col));
		assertEquals(4000l, tableModel.getValueAt(2, col));
	}

	@Test
	public void testLongNotInRangeFilter() {
		addFirstFilter("Long ID", "Not In Range", "[2000, 4000]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Long ID");
		assertEquals(1000l, tableModel.getValueAt(0, col));
		assertEquals(5000l, tableModel.getValueAt(1, col));
		assertEquals(10000000000l, tableModel.getValueAt(2, col));
	}

	@Test
	public void testDateAtLeastFilter() {
		addFirstFilter("Birth Date", "On or After Date", "01/05/2010");

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Birth Date");
		assertEquals(date("01/05/2010"), tableModel.getValueAt(0, col));
		assertEquals(date("01/06/2010"), tableModel.getValueAt(1, col));
	}

	@Test
	public void testDateAtMostFilter() {
		addFirstFilter("Birth Date", "On or Before Date", "01/02/2010");

		applyFilter();

		int col = getColumn("Birth Date");
		assertEquals(2, tableModel.getRowCount());
		assertEquals(date("01/01/2010"), tableModel.getValueAt(0, col));
		assertEquals(date("01/02/2010"), tableModel.getValueAt(1, col));
	}

	@Test
	public void testDateInRangeFilter() {

		addFirstFilter("Birth Date", "Between Dates", "[01/02/2010, 01/04/2010]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Birth Date");
		assertEquals(date("01/02/2010"), tableModel.getValueAt(0, col));
		assertEquals(date("01/03/2010"), tableModel.getValueAt(1, col));
		assertEquals(date("01/04/2010"), tableModel.getValueAt(2, col));
	}

	@Test
	public void testDateNotInRangeFilter() {
		addFirstFilter("Birth Date", "Not Between Dates", "[01/02/2010, 01/04/2010]");

		applyFilter();

		assertEquals(3, tableModel.getRowCount());

		int col = getColumn("Birth Date");
		assertEquals(date("01/01/2010"), tableModel.getValueAt(0, col));
		assertEquals(date("01/05/2010"), tableModel.getValueAt(1, col));
		assertEquals(date("01/06/2010"), tableModel.getValueAt(2, col));
	}

	@Test
	public void testTwoConditionsAnded() {
		addFirstFilter("Name", "Contains", "l");
		addAndFilter("Age", "At Least", "4");

		applyFilter();

		assertEquals(1, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Ellen", tableModel.getValueAt(0, col));
	}

	@Test
	public void testMultipleConditionsAnded() {
		addFirstFilter("Name", "Contains", "e");
		addAndFilter("Age", "At Least", "3");
		addAndFilter("Name", "Contains", "n");

		applyFilter();

		assertEquals(1, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Ellen", tableModel.getValueAt(0, col));
	}

	@Test
	public void testOrConditions() {
		addConstraints("Name", new String[] { "Contains", "Starts With" },
			new String[] { "Bo", "Ell" }, true);

		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Bob", tableModel.getValueAt(0, col));
		assertEquals("Ellen", tableModel.getValueAt(1, col));
	}

	@Test
	public void testAndOrConditions() {
		addConstraints("Name", new String[] { "Contains", "Starts With" },
			new String[] { "Bo", "Ell" }, true);

		addConstraints("Name", new String[] { "Ends With", "Contains" },
			new String[] { "ob", "ran" }, false);

		applyFilter();

		assertEquals(1, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Bob", tableModel.getValueAt(0, col));
	}

	@Test
	public void testSaveAndRestoreFilter() {
		addConstraints("Name", new String[] { "Contains", "Starts With" },
			new String[] { "Bo", "Ell" }, true);

		addConstraints("Name", new String[] { "Ends With", "Contains" },
			new String[] { "ob", "ran" }, false);

		ColumnBasedTableFilter<Integer> tableColumnFilter = filterModel.getTableColumnFilter();
		SaveState saveState = tableColumnFilter.save();
		ColumnBasedTableFilter<Integer> restoredFilter = new ColumnBasedTableFilter<>(tableModel);
		restoredFilter.restore(saveState, restoredFilter);
		assertEquals(tableColumnFilter.getHtmlRepresentation(),
			restoredFilter.getHtmlRepresentation());
	}

	@Test
	public void testLoadingFilterModelFromExistingFilter() {
		addConstraints("Name", new String[] { "Contains", "Starts With" },
			new String[] { "Bo", "Ell" }, true);

		addConstraints("Name", new String[] { "Ends With", "Contains" },
			new String[] { "ob", "ran" }, false);

		ColumnBasedTableFilter<Integer> tableColumnFilter = filterModel.getTableColumnFilter();
		ColumnFilterDialogModel<Integer> newModel =
			new ColumnFilterDialogModel<>(tableModel, gTable.getColumnModel(), tableColumnFilter);

		assertEquals(tableColumnFilter.getHtmlRepresentation(),
			newModel.getTableColumnFilter().getHtmlRepresentation());

	}

	@Test
	public void testIsValidAndGetErrorMessage() {
		assertTrue(filterModel.isValid());
		addAndFilter("Name", "Ends With", "");
		getEditorComponent();		// have to get editor component to trigger invalid state
		assertTrue(!filterModel.isValid());

	}

	@Test
	public void testOrCondition() {
		addFirstFilter("Name", "Starts With", "A"); // first one doesn't matter if it is AND or OR.
		addOrFilter("Name", "Starts With", "B");
		applyFilter();

		assertEquals(2, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Alice", tableModel.getValueAt(0, col));
		assertEquals("Bob", tableModel.getValueAt(1, col));
	}

	/**
	 * This tests the query ["Name starts with A" OR "Name starts With B" AND "Name ends with z"]
	 * is evaluated as ["Name starts with A" OR ("Name starts With B" AND "Name ends with z")]
	 * and not         [("Name starts with A" OR "Name starts With B") AND "Name ends with z"]
	 * Since no entries end with "z", if the OR had precedence, you would get no results.
	 */
	@Test
	public void testAndOrPrecedenceOrFirst() {
		addFirstFilter("Name", "Starts With", "A");
		addOrFilter("Name", "Starts With", "B");
		addAndFilter("Name", "Ends With", "z");
		applyFilter();

		assertEquals(1, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Alice", tableModel.getValueAt(0, col));
	}

	/**
	 * This tests that the query ["Name starts with A" AND "Name ends With z" OR "Name starts with B"]
	 * is evaluated as [("Name starts with A" AND "Name ends With z") OR "Name starts with B"]
	 * and not         ["Name starts with A" AND ("Name ends With z" OR "Name starts with B")]
	 * Since no entries end with "z", if the OR had precedence, you would get no results since the
	 * OR part would evaluate to "Bob" which  when ANDed with "starts with A" would not match "Bob"
	 * and therefore no results would be found.
	 */
	@Test
	public void testAndOrPrecedenceAndFirst() {
		addFirstFilter("Name", "Starts With", "A");
		addAndFilter("Name", "Ends With", "z");
		addOrFilter("Name", "Starts With", "B");
		applyFilter();

		assertEquals(1, tableModel.getRowCount());

		int col = getColumn("Name");
		assertEquals("Bob", tableModel.getValueAt(0, col));
	}

	private void getEditorComponent() {
		DialogFilterCondition<?> condition =
			filterModel.getFilterRows().get(0).getFilterConditions().get(0);
		condition.getInlineEditorComponent();
	}

	private int getColumn(String columnName) {
		TableColumn column = gTable.getColumn(columnName);
		return column.getModelIndex();
	}

	private void addFirstFilter(String columnName, String constraintName, String constraintValue) {
		// add it with And, but it doesn't matter what the Logic condition is for the first item
		// as they only determine how a filter combines with those before it.
		addFilter(columnName, constraintName, constraintValue, LogicOperation.AND, true);
	}

	private void addAndFilter(String columnName, String constraintName, String constraintValue) {
		addFilter(columnName, constraintName, constraintValue, LogicOperation.AND, false);
	}

	private void addOrFilter(String columnName, String constraintName, String constraintValue) {
		addFilter(columnName, constraintName, constraintValue, LogicOperation.OR, false);
	}

	private void addFilter(String columnName, String constraintName, String constraintValue,
			LogicOperation logicOperation, boolean first) {
		DialogFilterRow filterRow = createFilterRow(logicOperation, first);
		ColumnFilterData<?> columnData = getColumnFilterData(columnName);
		filterRow.setColumnData(columnData);
		List<DialogFilterCondition<?>> conditions = filterRow.getFilterConditions();
		DialogFilterCondition<?> condition = conditions.get(0);
		condition.setSelectedConstraint(constraintName);
		condition.setValue(constraintValue, null);

		// Many of the hasValidValue() implementations compare against a GUI component that
		// doesn't get built without these calls.
		condition.getInlineEditorComponent();
		condition.getDetailEditorComponent();
	}

	private DialogFilterRow createFilterRow(LogicOperation logicalOp, boolean first) {
		List<DialogFilterRow> filterRows = filterModel.getFilterRows();
		if (first && filterRows.size() == 1) {
			return filterRows.get(0);

		}
		return filterModel.createFilterRow(logicalOp);
	}

	private void applyFilter() {
		ColumnBasedTableFilter<Integer> tableColumnFilter = filterModel.getTableColumnFilter();
		tableModel.setTableFilter(tableColumnFilter);
	}

	private ColumnFilterData<?> getColumnFilterData(String columnName) {
		List<ColumnFilterData<?>> allData = filterModel.getAllColumnFilterData();
		for (ColumnFilterData<?> columnFilterData : allData) {
			if (columnFilterData.getName().equals(columnName)) {
				return columnFilterData;
			}
		}
		return null;
	}

	@SuppressWarnings("unchecked")
	private List<ColumnConstraint<?>> loadConstraints() {
		List<ColumnConstraint<?>> list = new ArrayList<>();
		list.addAll(new NumberColumnConstraintProvider().getColumnConstraints());
		list.addAll(new StringColumnConstraintProvider().getColumnConstraints());
		Collection<ColumnConstraint<?>> columnConstraints =
			new DateColumnConstraintProvider().getColumnConstraints();
		for (ColumnConstraint<?> c : columnConstraints) {
			list.add(new MappedColumnConstraint<>(new DateColumnTypeMapper(),
				(ColumnConstraint<LocalDate>) c));
		}
		return list;
	}

	private void addConstraints(String columnName, String[] constraintNames,
			String[] constraintValues, boolean first) {

		DialogFilterRow filterRow = createFilterRow(LogicOperation.AND, first);
		ColumnFilterData<?> columnData = getColumnFilterData(columnName);
		filterRow.setColumnData(columnData);

		// set the first one
		List<DialogFilterCondition<?>> conditions = filterRow.getFilterConditions();
		DialogFilterCondition<?> condition = conditions.get(0);
		condition.setSelectedConstraint(constraintNames[0]);
		condition.setValue(constraintValues[0], null);

		// Many of the hasValidValue() implementations compare against a GUI component that
		// doesn't get built without these calls.
		condition.getInlineEditorComponent();
		condition.getDetailEditorComponent();

		for (int i = 1; i < constraintNames.length; i++) {
			DialogFilterCondition<?> c = filterRow.addFilterCondition();
			c.setSelectedConstraint(constraintNames[i]);
			c.setValue(constraintValues[i], null);

			// Many of the hasValidValue() implementations compare against a GUI component that
			// doesn't get built without these calls.
			c.getInlineEditorComponent();
			c.getDetailEditorComponent();
		}
	}

}
