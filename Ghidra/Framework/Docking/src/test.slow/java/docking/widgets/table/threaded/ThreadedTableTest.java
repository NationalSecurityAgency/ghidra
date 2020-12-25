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
package docking.widgets.table.threaded;

import static org.junit.Assert.*;

import java.awt.Component;
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.JComponent;
import javax.swing.event.TableModelEvent;

import org.junit.*;

import docking.DockingUtils;
import docking.widgets.AutoLookup;
import docking.widgets.filter.*;
import docking.widgets.table.*;
import docking.widgets.table.ColumnSortState.SortDirection;
import ghidra.docking.spy.SpyEventRecorder;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class ThreadedTableTest extends AbstractThreadedTableTest {

	private final Pattern SORT_SIZE_PATTERN = Pattern.compile(".*\\((\\d+) rows\\).*");

	private SpyEventRecorder recorder = new SpyEventRecorder(testName.getMethodName());
	private SpyTaskMonitor spyMonitor = new SpyTaskMonitor(recorder);
	private SpyTextFilter<Long> spyFilter;
	private SortListener spySortListener =
		sortState -> recorder.record("Swing - model sorted - sort state=" + sortState);
	private ThreadedTableModelListener spyLoadListener = new SpyTableModelLIstener();

	@Override
	@Before
	public void setUp() throws Exception {

		super.setUp();

		// must run in Swing so that we do not mutate listeners while events are broadcasting
		runSwing(() -> installListeners());

		waitForTableModel(model);
	}

	private void installListeners() {
		MouseListener[] mouseListeners = header.getMouseListeners();
		for (MouseListener l : mouseListeners) {
			if (!(l instanceof GTableMouseListener)) {
				continue;
			}

			header.removeMouseListener(l);
			header.addMouseListener(new SpyMouseListenerWrapper(l, recorder));
		}

		model.addSortListener(spySortListener);
		model.addThreadedTableModelListener(spyLoadListener);
	}

	@Override
	protected void testFailed(Throwable e) {
		recorder.record("Test - testFailed()");
		// let our event recorder get all the events that were pending in the client code
		waitForNotBusy();
		recorder.dumpEvents();
	}

	@Override
	protected TestDataKeyModel createTestModel() {
		final TestDataKeyModel[] box = new TestDataKeyModel[1];
		runSwing(() -> box[0] = new TestDataKeyModel(spyMonitor, false) {
			@Override
			void setDefaultTaskMonitor(TaskMonitor monitor) {
				// No! some of our tests use a spy monitor.  If you ever find that you
				// need the standard monitors to get wired, then wrap the monitor being
				// passed-in here by the spy and let it delegate whilst recording messages
			}

			@Override
			public void setIncrementalTaskMonitor(TaskMonitor monitor) {
				// no! some of our tests use a spy monitor
			}

			@Override
			public void setTableSortState(TableSortState newSortState) {
				record("model.setTableSortState() - " + newSortState);
				super.setTableSortState(newSortState);
			}
		});
		return box[0];
	}

	@Test
	public void testSortingWorksOnFilteredData() throws Exception {
		//
		// make sure the sort is on the filtered data and not *all* data
		//
		assertSortSize(12);

		filter_ten();

		sortByNormalClicking(TestDataKeyModel.STRING_COL);
		assertSortSize(3);// only 3 "ten" rows in the table
	}

	@Test
	public void testSortingAfterClearingFilter() throws Exception {
		//
		// Make sure that after we clear a filter the sorting of the data is updated to match the
		// current sort state.  We need to do this because the non-filtered data structure is
		// different than the filtered one *and* we have special code that tries not to sort data
		// when the sort state hasn't changed.
		//

		// start unfiltered, sorted on column c
		sortOnLongColumn();

		// filter
		filter_ten();// arbitrary filter

		// sort on column c'
		TableSortState stringSort = sortOnStringColumn();

		// remove the filter
		clearFilter();

		// verify the table is sorted on column c
		verifySort(stringSort);
	}

	@Test
	public void testSortingAfterFilteringGetsCorrectlyRestored() throws Exception {
		//
		// Test that as we back out a filter, that the data is correctly sorted.
		//
		// Filter -> sort -> filter -> sort
		//
		// then
		//
		// back out the last filter, check sort, all the way back to start
		//

		// start unfiltered, sorted on column c
		sortColumn(0);

		filter("t");
		sortColumn(1);

		filter("te");
		sortColumn(6);

		filter("t");
		checkSort(6);// no longer column 1

		clearFilter();
		checkSort(6);// no longer column 0
	}

	@Test
	public void testSortingDoesNotRefilter() throws Exception {
		//
		// We used to always filter when a re-sort was triggered.  Make sure this no longer happens.
		//
		sortColumn(0);

		filter("t");
		spyMonitor.clearMessages();

		sortColumn(1);

		assertDidNotFilter();
	}

	// Note: this is now handled the ThreadedTableFilterTest
	//
	//	public void testContinuedFilteringUsesPreviousFilteredData() throws Exception {
	//		//
	//		// Often we wish to filter data that is already filtered by added more text to the
	//		// current filter.  For the basic filters ('starts with', 'contains'), the results will
	//		// always be a subset of the current data.  In that case, the filter operation should
	//		// use the existing filtered data.
	//		//
	//	}

	@Test
	public void testRefilterHappensAfterAddRemove() throws Exception {

		filter("t");
		resetSpies();

		addItemToModel(model.getRowCount() + 1);

		assertDidFilter();
	}

	@Test
	public void testRefilterHappensAfterReload() throws Exception {
		filter("t");
		resetSpies();

		reloadModel();

		assertDidFilter();
	}

	@Test
	public void testRefilterWhenDataChangedInternally() throws Exception {
		//
		// Test that the table's filter() method will actually refilter when the only changes to
		// the data are changes to an item in the list of data, but with no actual changes to
		// the list of data itself.  In other words, we will pick an item that is in the list
		// and then change one of its attributes such that it no longer passes the filter.
		//

		filter("ten");
		assertRowCount(3);

		changeAnExistingStringValue("ten", "teen");

		triggerModelFilter();// this method needs to refilter, even when the data is ostensibly the same
		assertRowCount(2);
	}

	@Test
	public void testAddRemove_NoFilter() throws Exception {

		int newValue = model.getRowCount() + 1;
		addItemToModel(newValue);

		assertModelContains(newValue);

		removeItemFromModel(newValue);

		assertModelDoesNotContain(newValue);
	}

	@Test
	public void testAdd_WithFilter() throws Exception {
		//
		// Verify the add/remove works with a filter *and* that it applies to the unfiltered
		// data.
		//

		filter("1");// use filter that keeps the new value in the table

		int newValue = model.getRowCount() + 1;
		addItemToModel(newValue);
		assertModelContains(newValue);

		clearFilter();
		assertModelContains(newValue);
	}

	@Test
	public void testRemove_WithFilter() throws Exception {
		//
		// Verify the add/remove works with a filter *and* that it applies to the unfiltered
		// data.
		//

		int newValue = model.getRowCount() + 1;
		addItemToModel(newValue);

		filter("1");
		assertModelContains(newValue);

		removeItemFromModel(newValue);
		assertModelDoesNotContain(newValue);

		clearFilter();
		assertModelDoesNotContain(newValue);
	}

	@Test
	public void testAddSendsEvent() {
		waitForTableModel(model);
		AtomicReference<TableModelEvent> ref = new AtomicReference<>();
		runSwing(() -> model.addTableModelListener(e -> ref.set(e)));

		int newValue = model.getRowCount() + 1;
		addItemToModel(newValue);

		assertEvent_AllDataChanged(ref.get());
	}

	@Test
	public void testRemoveSendsEvent() {

		int newValue = model.getRowCount() + 1;
		addItemToModel(newValue);

		final AtomicReference<TableModelEvent> ref = new AtomicReference<>();
		model.addTableModelListener(e -> ref.set(e));

		removeItemFromModel(newValue);

		assertEvent_AllDataChanged(ref.get());
	}

	@Test
	public void testMultipleSorting() throws Exception {
		int columnIndex = TestDataKeyModel.STRING_COL;
		sortByNormalClicking(columnIndex);

		SortedTableModel sortedModel = (SortedTableModel) table.getModel();

		verifySortDirection(columnIndex, sortedModel);

		//
		// now add another sort column
		//
		int columnIndex2 = TestDataKeyModel.INT_COL;
		sortByClick(columnIndex2, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

		TableSortState tableSortState = sortedModel.getTableSortState();
		assertEquals(2, tableSortState.getSortedColumnCount());

		verifySortDirection(columnIndex, sortedModel);

		// hardcoded check: we expect the primary sort on String to have 3 equal rows and the
		// secondary sort to then be in order
		int[] equalsRows = { 7, 8, 9 };
		verifyColumnSort_Ascending(columnIndex2, equalsRows);

		//
		// ...and another
		//
		int columnIndex3 = TestDataKeyModel.BYTE_COL;
		sortByClick(columnIndex3, DockingUtils.CONTROL_KEY_MODIFIER_MASK);

		tableSortState = sortedModel.getTableSortState();
		assertEquals(3, tableSortState.getSortedColumnCount());

		verifySortDirection(columnIndex, sortedModel);

		// hardcoded check: we expect the primary sort on String to have 3 equal rows and the
		// secondary sort to then be in order
		verifyColumnSort_Ascending(columnIndex2, equalsRows);
		verifyColumnSort_Ascending(columnIndex3, equalsRows);

		// now try changing the sort direction on some of the already sorted columns...

		// ...number 2
		sortByNormalClicking(columnIndex2);

		tableSortState = sortedModel.getTableSortState();
		assertEquals(3, tableSortState.getSortedColumnCount());

		verifySortDirection(columnIndex, sortedModel);

		// hardcoded check: we expect the primary sort on String to have 3 equal rows and the
		// secondary sort to then be in order (which is now reversed)
		verifyColumnSort_Descending(columnIndex2, equalsRows);

		// ...number 1
		sortByNormalClicking(columnIndex);

		tableSortState = sortedModel.getTableSortState();
		assertEquals(3, tableSortState.getSortedColumnCount());

		verifySortDirection(columnIndex, sortedModel);

		// hardcoded check: we expect the primary sort on String to have 3 equal rows and the
		// secondary sort to then be in order (which is now reversed)
		equalsRows = new int[] { 2, 3, 4 };
		verifyColumnSort_Descending(columnIndex2, equalsRows);

		// now try to remove a sorted column to make sure that the remaining columns are still
		// sorted

		// ...number 1
		removeSortByClicking(columnIndex);

		tableSortState = sortedModel.getTableSortState();
		assertEquals(2, tableSortState.getSortedColumnCount());

		equalsRows = new int[] { 3, 4 };
		verifyColumnSort_Descending(columnIndex2, equalsRows);
		verifyColumnSort_Ascending(columnIndex3, equalsRows);

	}

	@Test
	public void testSortingBytes() throws Exception {
		doTestSorting(TestDataKeyModel.BYTE_COL);
	}

	@Test
	public void testSortingShorts() throws Exception {
		doTestSorting(TestDataKeyModel.SHORT_COL);
	}

	@Test
	public void testSortingInts() throws Exception {
		doTestSorting(TestDataKeyModel.INT_COL);
	}

	@Test
	public void testSortingLong() throws Exception {
		doTestSorting(TestDataKeyModel.LONG_COL);
	}

	@Test
	public void testSortingFloats() throws Exception {
		doTestSorting(TestDataKeyModel.FLOAT_COL);
	}

	@Test
	public void testSortingDoubles() throws Exception {
		doTestSorting(TestDataKeyModel.DOUBLE_COL);
	}

	@Test
	public void testSortingStrings() throws Exception {

		toggleStringColumnSort();

		verifySortDirectionAscending();

		for (int i = 0; i < table.getRowCount() - 1; ++i) {
			String comp1 = (String) table.getValueAt(i + 0, TestDataKeyModel.STRING_COL);
			String comp2 = (String) table.getValueAt(i + 1, TestDataKeyModel.STRING_COL);
			assertTrue(comp1.compareToIgnoreCase(comp2) <= 0);
		}
	}

	@Test
	public void testAutoLookupOnStringColumn() throws Exception {
		setAutoLookupColumn_String();

		toggleStringColumnSort();

		triggerText(table, "si");
		assertEquals(6, table.getSelectedRow());

		sleep(AutoLookup.KEY_TYPING_TIMEOUT);

		// try again with the sort in the other direction
		selectFirstRow();
		toggleStringColumnSort();

		triggerText(table, "si");

		int selectedRow = table.getSelectedRow();
		assertEquals("Expected 'si' to select 'sIx', but instead found: " +
			table.getValueAt(selectedRow, TestDataKeyModel.STRING_COL), 5, selectedRow);
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Test
	public void testDefaultSortColumn() throws Exception {
		dispose();
		runSwing(() -> {
			model = new TestDataKeyModel();
			model.addThreadedTableModelListener(testTableModelListener);
		});

		verifySortColumn(TestDataKeyModel.LONG_COL);

		GThreadedTablePanel<Long> panel = new GThreadedTablePanel<>(model, 1000);

		table = panel.getTable();

		buildFrame(panel);

		waitForTableModel(model);

		for (int i = 0; i < table.getRowCount() - 1; ++i) {
			Comparable comp1 = (Comparable) table.getValueAt(i, TestDataKeyModel.LONG_COL);
			Comparable comp2 = (Comparable) table.getValueAt(i + 1, TestDataKeyModel.LONG_COL);
			assertTrue(comp1.compareTo(comp2) <= 0);
		}
	}

	@Test
	public void testCSV() throws Exception {

		deleteMatchingTempFiles("~csv_table_test.+tmp");

		List<String> expectedList = loadTextResource(getClass(), "threaded.table.test.csv.txt");
		assertNotNull(expectedList);
		assertTrue(expectedList.size() > 0);

		String path = createTempFilePath("~csv_table_test");
		File outputFile = new File(path);

		GTableToCSV.writeCSV(outputFile, table);
		waitForTasks(); // 10 seconds timeout; should be enough

		verifyCSVContents(expectedList, outputFile);
	}

	@Test
	public void testShowPending() throws Exception {
		//
		// we need to use a model that loads slowly enough to trigger the pending panel to show
		//
		model.setDelayTimeBetweenAddingDataItemsWhileLoading(60000);
		model.setUpdateDelay(100000000, 100000001);// make sure we don't update after repeated requests arrive

		addLong(1);// add a few items to trigger pending notification
		addLong(2);
		addLong(3);
		addLong(4);

		// let Swing paint the new component--do NOT call waitForSwing() here, as that will
		// flush the model's update manager, which we need to be slow!
		yieldToSwing();

		assertPendingPanelShowing();
	}

//==================================================================================================
// Overridden
//==================================================================================================

	@Override
	protected void sortByClick(int columnToClick, int modifiers) throws Exception {
		recorder.record("Test." + testName.getMethodName() + " - clicking column=" + columnToClick +
			"; modifiers=" + 0);
		super.sortByClick(columnToClick, modifiers);
	}

	@Override
	protected void removeSortByClicking(int columnToClick) throws Exception {
		recorder.record("Test." + testName.getMethodName() +
			" - clicking column to remove sort - column=" + columnToClick);
		super.removeSortByClicking(columnToClick);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertPendingPanelShowing() {
		JComponent pendingPanel = (JComponent) getInstanceField("pendingPanel", threadedTablePanel);

		waitForCondition(() -> {

			boolean isShowing = isShowing(pendingPanel);

			if (!isShowing) {
				JComponent loadedComponent =
					(JComponent) getInstanceField("loadedComponent", threadedTablePanel);
				String name = (loadedComponent == null) ? "<no component showing>"
						: loadedComponent.getName();
				Msg.debug(this, "Pending is not yet showing--what is?: " + name);
			}

			return isShowing;
		});
	}

	private boolean isShowing(Component c) {
		AtomicBoolean isShowing = new AtomicBoolean();
		runSwing(() -> isShowing.set(c.isShowing()));
		return isShowing.get();
	}

	private void verifySortDirectionAscending() {
		SortedTableModel sortedModel = (SortedTableModel) table.getModel();
		TableSortState sortState = getSortState(sortedModel);
		ColumnSortState primarySortState = sortState.iterator().next();
		SortDirection sortDirection = primarySortState.getSortDirection();

		assertEquals(SortDirection.ASCENDING, sortDirection);
	}

	private void verifySortColumn(int column) {

		TableSortingContext<Long> sortingContext = model.getSortingContext();
		TableSortState sortState = sortingContext.getSortState();
		assertEquals(1, sortState.getSortedColumnCount());

		Iterator<ColumnSortState> iterator = sortState.iterator();
		ColumnSortState columnSortState = iterator.next();
		assertEquals(column, columnSortState.getColumnModelIndex());
	}

	private void setAutoLookupColumn_String() {
		runSwing(() -> table.setAutoLookupColumn(TestDataKeyModel.STRING_COL));
	}

	private void selectFirstRow() {
		runSwing(() -> table.setRowSelectionInterval(0, 0), true);
		waitForSwing();
		assertEquals(0, table.getSelectedRow());
	}

	private void toggleStringColumnSort() throws Exception {
		Rectangle rect = header.getHeaderRect(TestDataKeyModel.STRING_COL);
		resetBusyListener();
		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, 0);
		waitForNotBusy();
		waitForSwing();
	}

	private void verifyCSVContents(List<String> expectedList, File actualFile)
			throws FileNotFoundException, IOException {

		int expectedIndex = 0;
		BufferedReader actualReader = new BufferedReader(new FileReader(actualFile));
		try {
			while (true) {
				String line = actualReader.readLine();
				if (line == null) {
					break;
				}
				assertEquals(expectedList.get(expectedIndex++), line);
			}
		}
		finally {
			actualReader.close();
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void verifyColumnSort_Ascending(int column, int[] rows) {
		for (int i = 0; i < rows.length - 1; i++) {
			int row = rows[i];
			Comparable comp1 = (Comparable) table.getValueAt(row + 0, column);
			Comparable comp2 = (Comparable) table.getValueAt(row + 1, column);
			assertTrue(comp1.compareTo(comp2) <= 0);
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	private void verifyColumnSort_Descending(int column, int[] rows) {
		for (int i = 0; i < rows.length - 1; i++) {
			int row = rows[i];
			Comparable comp1 = (Comparable) table.getValueAt(row + 0, column);
			Comparable comp2 = (Comparable) table.getValueAt(row + 1, column);
			assertTrue(comp1.compareTo(comp2) >= 0);
		}
	}

	private void assertEvent_AllDataChanged(TableModelEvent e) {
		assertEquals("Table model did not send out a 'table data changed' event", Integer.MAX_VALUE,
			e.getLastRow());
	}

	private void assertModelDoesNotContain(int value) {
		TableData<Long> tableData = model.getCurrentTableData();
		List<Long> data = tableData.getData();
		for (Long row : data) {
			if (row == value) {
				Assert.fail("Model should NOT contain value: " + value);
			}
		}
	}

	private void assertModelContains(int value) {
		TableData<Long> tableData = model.getCurrentTableData();
		List<Long> data = tableData.getData();
		for (Long row : data) {
			if (row == value) {
				return;
			}
		}
		Assert.fail("Model does not contain value: " + value);
	}

	private void changeAnExistingStringValue(String from, String to) {
		String[] data = model.strings;
		for (int i = 0; i < data.length; i++) {
			if (data[i].equals(from)) {
				data[i] = to;
				return;
			}
		}
	}

	@Override
	protected void assertRowCount(int n) {
		if (n != model.getRowCount()) {
			spyFilter.dumpEvents();
		}
		assertEquals(n, model.getRowCount());
	}

	private void sortColumn(int column) {
		runSwing(() -> model.setTableSortState(TableSortState.createDefaultSortState(column)));
		waitForTableModel(model);
	}

	private void checkSort(int column) {
		TableSortState state = TableSortState.createDefaultSortState(column);
		verifySort(state);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private void verifySort(TableSortState expectedState) {
		TableSortingContext<Long> sortingContext = model.getSortingContext();
		TableSortState currentState = sortingContext.getSortState();
		assertEquals(expectedState, currentState);

		// make sure it actually did the sort
		ColumnSortState columnState = expectedState.getAllSortStates().get(0);
		int column = columnState.getColumnModelIndex();
		for (int i = 0; i < table.getRowCount() - 1; ++i) {
			Comparable comp1 = (Comparable) table.getValueAt(i, column);
			Comparable comp2 = (Comparable) table.getValueAt(i + 1, column);

			if (comp1 instanceof String) {
				comp1 = ((String) comp1).toLowerCase();// our model ignores case when comparing
				comp2 = ((String) comp2).toLowerCase();
			}

			boolean result = false;
			if (columnState.isAscending()) {
				result = comp1.compareTo(comp2) <= 0;
			}
			else {
				result = comp1.compareTo(comp2) >= 0;
			}
			assertTrue("Row " + i + " is not sorted correctly", result);
		}
	}

	private TableSortState sortOnStringColumn() throws Exception {
		sortByNormalClicking(TestDataKeyModel.STRING_COL);
		TableSortingContext<Long> sortingContext = model.getSortingContext();
		return sortingContext.getSortState();
	}

	private void sortOnLongColumn() throws Exception {
		TableSortingContext<Long> sortingContext = model.getSortingContext();
		TableSortState sortState = sortingContext.getSortState();
		ColumnSortState columnSortState = sortState.getColumnSortState(TestDataKeyModel.LONG_COL);
		if (columnSortState != null) {
			return;// already sorted on column
		}

		sortByNormalClicking(TestDataKeyModel.LONG_COL);
	}

	private void clearFilter() throws Exception {
		resetSpies();
		resetBusyListener();
		runSwing(() -> model.setTableFilter(null));

		waitForNotBusy();
		waitForTableModel(model);// TODO if this call is more reliable, then replace the above call to work like this one
		waitForSwing();
	}

	private void assertSortSize(int size) {

		String message = spyMonitor.getLastSortMessage();
		Matcher matcher = SORT_SIZE_PATTERN.matcher(message);
		assertTrue("Message for sorting has changed--update the test", matcher.matches());
		assertEquals(1, matcher.groupCount());
		String sizeString = matcher.group(1);
		int actualSize = Integer.parseInt(sizeString);
		assertEquals("Did not sort the correct number of rows", size, actualSize);
	}

	private void assertDidNotFilter() {
		assertFalse("The table filtered data when it should not have",
			spyMonitor.hasFilterMessage());
	}

	private void assertDidFilter() {
		assertTrue("The table did not filter data when it should have", spyFilter.hasFiltered());
	}

	@Override
	protected void doTestSorting(int columnIndex) throws Exception {

		sortByNormalClicking(columnIndex);

		SortedTableModel sortedModel = (SortedTableModel) table.getModel();
		verifySortDirection(columnIndex, sortedModel);

		sortByNormalClicking(columnIndex);
		verifySortDirection(columnIndex, sortedModel);
	}

	private void reloadModel() {
		model.reload();
		waitForTableModel(model);
	}

	private void filter_ten() throws Exception {
		String text = "ten";
		filter(text);

		List<Object> modelValues = getModelValues(model, TestDataKeyModel.STRING_COL);
		assertEquals("Filter did not match the expected row count", 3, modelValues.size());
		for (int i = 0; i < modelValues.size(); i++) {
			Object value = modelValues.get(i);
			assertEquals(text, value);
		}
	}

	private List<Object> getModelValues(TestDataKeyModel keyModel, int columnIndex) {
		List<Object> list = new ArrayList<>();
		runSwing(() -> {
			int rowCount = keyModel.getRowCount();
			for (int i = 0; i < rowCount; i++) {
				Object value = keyModel.getValueAt(i, columnIndex);
				list.add(value);
			}
		});
		return list;
	}

	private void filter(String text) throws Exception {

		DefaultRowFilterTransformer<Long> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		FilterOptions options = new FilterOptions();
		TextFilterFactory textFactory = options.getTextFilterFactory();
		TextFilter textFilter = textFactory.getTextFilter(text);

		resetBusyListener();

		spyFilter = new SpyTextFilter<>(textFilter, transformer, recorder);

		recorder.record("Test." + testName.getMethodName() + " - setting filter to '" + text + "'");
		runSwing(() -> model.setTableFilter(spyFilter));

		waitForNotBusy();
		waitForTableModel(model);
		waitForSwing();

		assertTrue("Table did not finish loading", testTableModelListener.doneWork());

		recorder.record(
			"Test." + testName.getMethodName() + " - done setting filter - should have reloaded");

		boolean hasFiltered = spyFilter.hasFiltered();
		if (!hasFiltered) {
			// debug - would we have eventually filtered if the assert didn't fail us right away
			sleep(1000);
			waitForNotBusy();
			waitForTableModel(model);
			waitForSwing();
			Msg.debug(this, "We are going to fail, but did the filter take place eventually?: " +
				spyFilter.hasFiltered());
		}

		assertTrue("Table did not filter; requested filter on '" + text + "'", hasFiltered);
	}

	@Override
	protected void record(String message) {
		recorder.record("Test - " + message);
	}

	private void resetSpies() {
		spyFilter.reset();
		spyMonitor.clearMessages();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class SpyTableModelLIstener implements ThreadedTableModelListener {

		@Override
		public void loadPending() {
			recorder.record("Swing - model load pending");
		}

		@Override
		public void loadingStarted() {
			recorder.record("Swing - model load started");
		}

		@Override
		public void loadingFinished(boolean wasCancelled) {
			if (wasCancelled) {
				recorder.record("Swing - model load cancelled");
			}
			else {
				recorder.record("Swing - model load finsished; size: " + model.getRowCount());
			}
		}

	}
}
