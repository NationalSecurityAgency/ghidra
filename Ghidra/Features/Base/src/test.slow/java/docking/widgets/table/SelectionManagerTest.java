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
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.*;
import javax.swing.table.TableModel;

import org.apache.logging.log4j.*;
import org.apache.logging.log4j.core.config.Configurator;
import org.junit.*;

import docking.widgets.filter.FilterOptions;
import docking.widgets.table.threaded.ThreadedTableModelStub;
import ghidra.docking.settings.Settings;
import ghidra.framework.LoggingInitialization;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SelectionManagerTest extends AbstractGhidraHeadedIntegrationTest {

	private static final int TEST_COLUMN_COUNT = 4;
	private static final int MIN_ROW_COUNT = 10;
	private static final int MAX_ROW_COUNT = 40;
	private static final int MAX_THREAD_SLEEP_DELAY = 100;

	private JFrame frame;
	private GTable table;
	private NonRowObjectFilterTestTableModel model;
	private ThreadedTestTableModel threadedModel;

	private Logger logger;

	public SelectionManagerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		LoggingInitialization.initializeLoggingSystem();
		logger = LogManager.getLogger(SelectionManager.class);
		Configurator.setLevel(logger.getName(), Level.DEBUG);

		logger.trace("\n\nsetUp(): " + testName.getMethodName());

		List<StringRowObject> data = createBasicData();
		model = new NonRowObjectFilterTestTableModel(data);

		// must created the threaded model in the swing thread (it's part of the contract)
		runSwing(() -> threadedModel = new ThreadedTestTableModel());
	}

	@After
	public void tearDown() throws Exception {
		threadedModel.dispose();
		frame.dispose();

		logger.trace("tearDown() - leaving: " + testName.getMethodName() + "\n\n");
	}

	@Test
	public void testRestoreSelectionAfterTableChanged() {
		doTestRestoreSelectionAfterTableChanged(false);
		doTestRestoreSelectionAfterTableChanged(true);
	}

	@Test
	public void testSelectionRestoreAfterSortingAndFilteringAndSorting() throws Exception {
		//
		// Sort.  Filter.  Make a selection.  Change the sort.
		// Make sure the same 'row object' is selected.
		// There was a bug found under these series of events (because the full dataset was
		// sorted differently than the filtered dataset)
		//
		createTable(true);
		assertEquals("Table unexpectedly has a selection by default for threaded model", 0,
			table.getSelectedRowCount());

		int startRow = 2; // start with an even row (odd will be filtered-out)
		selectRow(startRow);
		StringRowObject startObject = getSelectedObject();

		changeSort();

		setFilterText("even"); // filter out odd rows

		assertEquals("Incorrect object was re-selected", startObject, getSelectedObject());

		changeSort();

		assertEquals("Incorrect object was re-selected", startObject, getSelectedObject());
	}

	@Test
	public void testSelectionRestoreAfterFiltering_RowObjectMissing() throws Exception {
		//
		// Make a selection.  Filter the selection out.  Remove the filter.
		// Make sure the same 'row object' is selected.
		//
		String threadedDescription = "threaded model";
		createTable(true);
		assertEquals("Table unexpectedly has a selection by default for " + threadedDescription, 0,
			table.getSelectedRowCount());

		int row = 0;
		selectRow(row);

		setFilterText("garbledeegook");

		int selectedRow = getSelectedRow();
		assertEquals("Selection was not filtered out as expected", -1, selectedRow);

		setFilterText("");

		selectedRow = getSelectedRow();
		assertEquals("Selection was not restored", 0, selectedRow);
	}

	@Test
	public void testSelectionRestoreAfterFiltering_RowObjectPresent() throws Exception {
		//
		// Make a selection.  Add a filter.  Make sure the same 'row object' is selected.
		// Remove the filter.  Make sure the same 'row object' is selected.
		//

		createTable(true);
		assertEquals("Table unexpectedly has a selection by default for threaded model", 0,
			table.getSelectedRowCount());

		int startRow = 2; // start with an even row (odd will be filtered-out)
		selectRow(startRow);
		StringRowObject startObject = getSelectedObject();

		setFilterText("even"); // filter out odd rows

		assertEquals("Incorrect object was re-selected", startObject, getSelectedObject());

		setFilterText("");

		assertEquals("Incorrect object was re-selected", startObject, getSelectedObject());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void doTestRestoreSelectionAfterTableChanged(boolean isThreaded) {
		logger.trace("doTestRestoreSelectionAfterTableChanged - start");

		//
		// Make a selection.  Fire a tableDataChanged().  Make sure the selection returns.
		//
		String threadedDescription = isThreaded ? "threaded model" : "non-threaded model";
		createTable(isThreaded);
		assertEquals("Table unexpectedly has a selection by default for " + threadedDescription, 0,
			table.getSelectedRowCount());

		int row = 0;
		StringRowObject rowObject = getRowObject(row);
		selectRow(row);

		logger.trace("\tafter selected row...firing event");
		fireTableDataChanged();
		logger.trace("\tafter firing event...waiting for model");

		waitForTableModel();
		logger.trace("\tafter waiting for model");

		int selectedRow = getSelectedRow();
		if (selectedRow == -1) {
			Assert.fail("Selection not restored after sorting table");
		}

		StringRowObject newRowObject = getRowObject(selectedRow);
		assertEquals("Row not selected after a tableChanged() event for " + threadedDescription,
			rowObject, newRowObject);

		logger.trace("doTestRestoreSelectionAfterTableChanged - end");
	}

	@Test
	public void testDontRestoreSelectionAfterTableChangedAndNewSelection() {
		doTestDontRestoreSelectionAfterTableChangedAndNewSelection(false);
		doTestDontRestoreSelectionAfterTableChangedAndNewSelection(true);
	}

	private void doTestDontRestoreSelectionAfterTableChangedAndNewSelection(boolean isThreaded) {
		//
		// Make a selection.  Fire a tableDataChanged(). Somehow post a new selection before the
		// repair selection is executed on the swing thread.
		//
		String threadedDescription = isThreaded ? "threaded model" : "non-threaded model";
		createTable(isThreaded);
		assertEquals("Table unexpectedly has a selection by default for " + threadedDescription, 0,
			table.getSelectedRowCount());

		selectRow(0);

		int newRow = 1;
		fireTableDataChangedAndChangeSelection(newRow);

		// the tables current selection should remain the newest selection and not the original
		waitForTableModel();

		int selectedRow = getSelectedRow();
		assertEquals("Last selection made was not preserved", newRow, selectedRow);
	}

	@Test
	public void testRestoreSelectionWithMultipleRowsSelected() {
		doTestRestoreSelectionWithMultipleRowsSelected(false);
		doTestRestoreSelectionWithMultipleRowsSelected(true);
	}

	private void doTestRestoreSelectionWithMultipleRowsSelected(boolean isThreaded) {
		//
		// Make a multi-selection.  Fire a tableDataChanged().  Make sure the multi-selection returns.
		//
		String threadedDescription = isThreaded ? "threaded model" : "non-threaded model";
		createTable(isThreaded);
		assertEquals("Table unexpectedly has a selection by default for " + threadedDescription, 0,
			table.getSelectedRowCount());

		int row1 = 0;
		int row2 = 5;
		selectRows(row1, row2);

		fireTableDataChanged();

		waitForTableModel();

		int selectedRow = table.getSelectedRow();
		if (selectedRow == -1) {
			Assert.fail(
				"Now rows selected after a tableChanged() event for " + threadedDescription);
		}

		int[] selectedRows = table.getSelectedRows();
		assertEquals(2, selectedRows.length);
		assertEquals(row1, selectedRows[0]);
		assertEquals(row2, selectedRows[1]);
	}

	@Test
	public void testRestoreSelectionWithDuplicateRows() {
		doTestRestoreSelectionWithDuplicateRows(false);
		doTestRestoreSelectionWithDuplicateRows(true);
	}

	@SuppressWarnings("unchecked")
	private void doTestRestoreSelectionWithDuplicateRows(boolean isThreaded) {
		logger.trace("doTestRestoreSelectionWithDuplicateRows - start - threaded?: " + isThreaded);

		//
		// Test that normal selections are restored when multiple duplicate rows exist in the table
		//
		String[] data = { "Dup Col 1", "Dup Col 2", "Dup Col 3", "Dup Col 4" };
		StringRowObject duplicateRow1 = new StringRowObject(data);
		StringRowObject duplicateRow2 = new StringRowObject(data);
		StringRowObject duplicateRow3 = new StringRowObject(data);

		addRowToModel(duplicateRow1, isThreaded);
		addRowToModel(duplicateRow2, isThreaded);
		addRowToModel(duplicateRow3, isThreaded);
		createTable(isThreaded);
		fireTableDataChanged();
		waitForTableModel();

		String threadedDescription = isThreaded ? "threaded model" : "non-threaded model";
		createTable(isThreaded);
		assertEquals("Table unexpectedly has a selection by default for " + threadedDescription, 0,
			table.getSelectedRowCount());

		AbstractSortedTableModel<StringRowObject> abstractModel =
			(AbstractSortedTableModel<StringRowObject>) table.getModel();
		int dup1Index = abstractModel.getIndexForRowObject(duplicateRow1);
		int secondNonDuplicateRowIndex = getOtherNonDuplicateRowIndex(dup1Index, abstractModel);

		selectRows(dup1Index, secondNonDuplicateRowIndex);

		fireTableDataChanged();

		waitForTableModel();

		int selectedRow = getSelectedRow();
		if (selectedRow == -1) {
			Assert.fail(
				"Now rows selected after a tableChanged() event for " + threadedDescription);
		}

		int[] selectedRows = table.getSelectedRows();
		assertEquals(2, selectedRows.length);
		assertDuplicateRowSelection(duplicateRow1, dup1Index, selectedRows[0]);
		assertEquals(secondNonDuplicateRowIndex, selectedRows[1]);

		//
		// Same test, but now try when the duplicates themselves are selected
		//
		clearSelection();
		assertEquals("Selection not cleared!", 0, table.getSelectedRowCount());

		int dup3Index = dup1Index + 2;
		selectRows(dup1Index, dup3Index);

		fireTableDataChanged();

		waitForTableModel();

		selectedRow = getSelectedRow();
		if (selectedRow == -1) {
			logger.trace("\tpreparing to fail");
			Assert.fail(
				"Now rows selected after a tableChanged() event for " + threadedDescription);
		}

		selectedRows = table.getSelectedRows();
		assertEquals(2, selectedRows.length);
		assertDuplicateRowSelection(duplicateRow1, dup1Index, selectedRows[0]);
		assertDuplicateRowSelection(duplicateRow3, dup3Index, selectedRows[1]);

		logger.trace("doTestRestoreSelectionWithDuplicateRows - end");
	}

	/**
	 * Make sure that either the two given rows are an exact match, or that the row objects that
	 * represent each row are equal()
	 */
	private void assertDuplicateRowSelection(StringRowObject originalRowObject, int originalRow,
			int newRow) {
		if (originalRow == newRow) {
			return;// exact match--good!
		}

		StringRowObject rowObject = getRowObject(newRow);
		assertEquals("Equivalent row object not selected when selection was restored",
			originalRowObject, rowObject);
	}

	@Test
	public void testSelectionRestoreAfterSorting() {
		doTestSelectionRestoreAfterSorting(false);
		doTestSelectionRestoreAfterSorting(true);
	}

	private void doTestSelectionRestoreAfterSorting(boolean isThreaded) {
		//
		// Make a selection.  Change the sort.  Make sure the same 'row object' is selected.
		//
		String threadedDescription = isThreaded ? "threaded model" : "non-threaded model";
		createTable(isThreaded);
		assertEquals("Table unexpectedly has a selection by default for " + threadedDescription, 0,
			table.getSelectedRowCount());

		int startRow = 0;
		selectRow(startRow);
		StringRowObject startObject = getSelectedObject();

		changeSort();

		waitForTableModel();

		StringRowObject endObject = getSelectedObject();
		assertEquals("Incorrect object was re-selected", startObject, endObject);
	}

	@Test
	public void testSelectionRestoreAfterFiltering() throws Exception {
		//
		// Make a selection.  Change add a filter.  Make sure the same 'row object' is selected.
		//
		String threadedDescription = "threaded model";
		createTable(true);
		assertEquals("Table unexpectedly has a selection by default for " + threadedDescription, 0,
			table.getSelectedRowCount());
	}

	private int getSelectedRow() {
		AtomicInteger ref = new AtomicInteger(-1);
		runSwing(() -> {
			ref.set(table.getSelectedRow());
		});
		return ref.get();
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	@SuppressWarnings("unchecked")
	private StringRowObject getSelectedObject() {

		AtomicReference<StringRowObject> ref = new AtomicReference<>();
		runSwing(() -> {
			int row = table.getSelectedRow();
			TableModel tm = table.getModel();
			RowObjectTableModel<StringRowObject> rowModel =
				(RowObjectTableModel<StringRowObject>) tm;
			StringRowObject rowObject = rowModel.getRowObject(row);
			ref.set(rowObject);
		});
		return ref.get();
	}

	private void createTable(boolean isThreaded) {
		if (frame == null) {
			frame = new JFrame("GTree Test");
		}

		if (isThreaded) {
			table = new GTable(threadedModel);
		}
		else {
			table = new GTable(model);
		}

		Container contentPane = frame.getContentPane();
		contentPane.removeAll();
		contentPane.setLayout(new BorderLayout());
		frame.getContentPane().add(new JScrollPane(table), BorderLayout.CENTER);
		frame.setSize(1000, 400);
		frame.setVisible(true);

		waitForTableModel();
	}

	private void waitForTableModel() {
		if (table.getModel() instanceof ThreadedTestTableModel) {
			waitForTableModel(threadedModel);
		}
		else {
			waitForSwing();
		}
	}

	private void setFilterText(final String text) throws Exception {
		final DefaultTableTextFilterFactory<StringRowObject> factory =
			new DefaultTableTextFilterFactory<>(new FilterOptions());
		final DefaultRowFilterTransformer<StringRowObject> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		SwingUtilities.invokeAndWait(
			() -> threadedModel.setTableFilter(factory.getTableFilter(text, transformer)));

		waitForTableModel();
	}

	private int getOtherNonDuplicateRowIndex(int dup1Index,
			AbstractSortedTableModel<StringRowObject> tableModel) {
		int otherRow = dup1Index;
		while (otherRow == dup1Index) {
			otherRow = getRandomInt(0, table.getRowCount() - 1);
		}

		StringRowObject currentRowObject = tableModel.getRowObject(dup1Index);
		StringRowObject newRowObject = tableModel.getRowObject(otherRow);
		if (currentRowObject.equals(newRowObject)) {
			// try again--we want the new index to be for a row that is NOT a duplicate
			return getOtherNonDuplicateRowIndex(dup1Index, tableModel);
		}

		return otherRow;
	}

	private void changeSort() {
		AbstractSortedTableModel<?> abstractModel = (AbstractSortedTableModel<?>) table.getModel();
		TableSortState sortState = abstractModel.getTableSortState();
		int columnCount = abstractModel.getColumnCount();
		ColumnSortState columnSortState = null;
		for (int i = 0; i < columnCount; i++) {
			columnSortState = sortState.getColumnSortState(i);
			if (columnSortState != null) {
				break;
			}
		}
		assertNotNull("No sorted column!!?!?", columnSortState);

		ColumnSortState newColumnState = columnSortState.createFlipState();
		TableSortState newSortState = new TableSortState(newColumnState);
		abstractModel.setTableSortState(newSortState);

		waitForSwing();
		waitForTableModel();
	}

	@SuppressWarnings("unchecked")
	private StringRowObject getRowObject(int row) {
		AbstractSortedTableModel<StringRowObject> abstractModel =
			(AbstractSortedTableModel<StringRowObject>) table.getModel();

		return abstractModel.getRowObject(row);
	}

	private void addRowToModel(StringRowObject row, boolean isThreaded) {
		if (isThreaded) {
			threadedModel.addRow(row);
		}
		else {
			model.addRow(row);
		}
	}

	private void clearSelection() {
		runSwing(() -> table.clearSelection());
	}

	private void selectRow(final int row) {
		final ListSelectionModel selectionModel = table.getSelectionModel();
		runSwing(() -> selectionModel.setSelectionInterval(row, row));

		int selectedRow = getSelectedRow();
		assertEquals("Row not selected!", row, selectedRow);

		logger.trace("Selected row value: " + getRowObject(selectedRow));
	}

	private void selectRows(final int row1, final int row2) {
		logger.trace("SMT.selectRows(): " + row1 + " and " + row2);
		final ListSelectionModel selectionModel = table.getSelectionModel();
		runSwing(() -> {
			selectionModel.setSelectionInterval(row1, row1);
			selectionModel.addSelectionInterval(row2, row2);
		});

		int[] selectedRows = table.getSelectedRows();
		assertEquals(2, selectedRows.length);

		logger.trace("\tSMT.selectRows() - found selected rows: " + selectedRows[0] + " and " +
			selectedRows[1]);

		// We may be passed the rows in non-sorted order.  The selection manager will give us
		// results in ascending order.  Make sure to compare them correctly.
		if (row1 > row2) {
			assertEquals(row2, selectedRows[0]);
			assertEquals(row1, selectedRows[1]);
		}
		else {
			assertEquals(row1, selectedRows[0]);
			assertEquals(row2, selectedRows[1]);
		}

		logger.trace("Selected row value: " + getRowObject(row1));
		logger.trace("Selected row value: " + getRowObject(row2));
	}

	private void fireTableDataChanged() {
		runSwing(() -> {
			AbstractSortedTableModel<?> abstractModel =
				(AbstractSortedTableModel<?>) table.getModel();
			abstractModel.fireTableDataChanged();
		});
	}

	private void fireTableDataChangedAndChangeSelection(final int row) {
		runSwing(() -> {
			AbstractSortedTableModel<?> abstractModel =
				(AbstractSortedTableModel<?>) table.getModel();
			abstractModel.fireTableDataChanged();

			// change the selection here...we know that the SelectionManager will try to
			// repair selection in an invoke later, so if we change the selection here, then
			// it should invalidate the selection that is posted to be repaired as a result
			// of the preceding call to fireTableDataChanged()
			ListSelectionModel selectionModel = table.getSelectionModel();
			selectionModel.setSelectionInterval(row, row);
		});

	}

	private List<StringRowObject> createBasicData() {
		int rowCount = getRandomInt(MIN_ROW_COUNT, MAX_ROW_COUNT);
		List<StringRowObject> data = new ArrayList<>(rowCount);
		for (int i = 0; i < rowCount; i++) {
			String[] strings = new String[TEST_COLUMN_COUNT];
			for (int j = 0; j < TEST_COLUMN_COUNT; j++) {
				String oddity = (j % 2 == 0) ? " (even)" : " (odd)";
				strings[j] = getRandomString() + oddity;
			}
			data.add(new StringRowObject(strings));
		}
		return data;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class StringRowObject {
		private final String[] data;

		StringRowObject(String[] data) {
			this.data = data;
		}

		String get(int column) {
			return data[column];
		}

		@Override
		public String toString() {
			StringBuilder buildy = new StringBuilder();
			for (String string : data) {
				buildy.append(string).append(':');
			}
			return buildy.toString();
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj) {
				return true;
			}

			if (obj == null) {
				return false;
			}

			if (getClass() != obj.getClass()) {
				return false;
			}

			StringRowObject other = (StringRowObject) obj;
			for (int i = 0; i < data.length; i++) {
				// must be same data in same order
				if (!data[i].equals(other.data[i])) {
					return false;
				}
			}
			return true;
		}

		@Override
		public int hashCode() {
			int hashCode = 0;
			for (String element : data) {
				hashCode += element.hashCode();
			}
			return hashCode;
		}
	}

	private class NonRowObjectFilterTestTableModel
			extends AbstractSortedTableModel<StringRowObject> {

		private final List<StringRowObject> data;

		NonRowObjectFilterTestTableModel(List<StringRowObject> data) {
			this.data = data;
			fireTableDataChanged();// let our parent know our data has been set
		}

		@Override
		public String getName() {
			return "Test";
		}

		@Override
		public String getColumnValueForRow(StringRowObject t, int columnIndex) {
			return t.get(columnIndex);
		}

		void addRow(StringRowObject rowObject) {
			data.add(rowObject);
		}

		@Override
		public List<StringRowObject> getModelData() {
			return data;
		}

		@Override
		public boolean isSortable(int columnIndex) {
			return true;
		}

		@Override
		public int getColumnCount() {
			return TEST_COLUMN_COUNT;
		}

		@Override
		public int getRowCount() {
			return data.size();
		}
	}

	private class ThreadedTestTableModel extends ThreadedTableModelStub<StringRowObject> {

		List<StringRowObject> data;

		protected ThreadedTestTableModel() {
			super(ThreadedTestTableModel.class.getName(), null);
		}

		void addRow(StringRowObject rowObject) {
			super.addObject(rowObject);
		}

		@Override
		protected void doLoad(Accumulator<StringRowObject> accumulator, TaskMonitor monitor)
				throws CancelledException {
			data = createBasicData();
			accumulator.addAll(data);
			for (@SuppressWarnings("unused")
			StringRowObject rowObject : data) {
				sleep(getRandomInt(10, MAX_THREAD_SLEEP_DELAY));
			}
		}

		@Override
		protected TableColumnDescriptor<StringRowObject> createTableColumnDescriptor() {
			TableColumnDescriptor<StringRowObject> descriptor = new TableColumnDescriptor<>();

			descriptor.addVisibleColumn(new ATableColumn());
			descriptor.addVisibleColumn(new BTableColumn());
			descriptor.addVisibleColumn(new CTableColumn());
			descriptor.addVisibleColumn(new DTableColumn());

			return descriptor;
		}

		private class ATableColumn extends AbstractDynamicTableColumnStub<StringRowObject, String> {

			@Override
			public String getColumnName() {
				return "A";
			}

			@Override
			public String getValue(StringRowObject rowObject, Settings settings,
					ServiceProvider provider) throws IllegalArgumentException {
				return rowObject.get(0);
			}
		}

		private class BTableColumn extends AbstractDynamicTableColumnStub<StringRowObject, String> {

			@Override
			public String getColumnName() {
				return "B";
			}

			@Override
			public String getValue(StringRowObject rowObject, Settings settings,
					ServiceProvider provider) throws IllegalArgumentException {
				return rowObject.get(0);
			}
		}

		private class CTableColumn extends AbstractDynamicTableColumnStub<StringRowObject, String> {

			@Override
			public String getColumnName() {
				return "C";
			}

			@Override
			public String getValue(StringRowObject rowObject, Settings settings,
					ServiceProvider provider) throws IllegalArgumentException {
				return rowObject.get(0);
			}
		}

		private class DTableColumn extends AbstractDynamicTableColumnStub<StringRowObject, String> {

			@Override
			public String getColumnName() {
				return "D";
			}

			@Override
			public String getValue(StringRowObject rowObject, Settings settings,
					ServiceProvider provider) throws IllegalArgumentException {
				return rowObject.get(0);
			}
		}
	}
}
