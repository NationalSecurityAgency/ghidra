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

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.*;

import java.awt.BorderLayout;
import java.util.Arrays;
import java.util.List;
import java.util.function.Predicate;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.table.JTableHeader;

import org.junit.*;

import docking.DockingFrame;
import docking.test.AbstractDockingTest;
import docking.widgets.filter.*;
import docking.widgets.table.*;
import ghidra.docking.spy.SpyEventRecorder;
import ghidra.util.task.TaskMonitor;

/**
 * Specifically tests the sub-filtering behavior of the {@link ThreadedTableModel}, as well
 * as some other more complicated filtering combinations
 */
public class DefaultThreadedTableFilterTest extends AbstractDockingTest {

	private SpyEventRecorder recorder = new SpyEventRecorder(getClass().getSimpleName());
	private SpyTaskMonitor monitor = new SpyTaskMonitor();
	private SpyTextFilter<TestRowObject> spyFilter;

	protected TestThreadedTableModel model;
	protected GTable table;
	protected JTableHeader header;
	protected JFrame frame;
	protected TestThreadedTableModelListener testTableModelListener;
	protected GThreadedTablePanel<TestRowObject> threadedTablePanel;
	protected volatile boolean isDisposing = false;

	private TestThreadedTableModel createTestModel() {

		// Note: from the test model, the data looks like this:
		//  "one", "two", "THREE", "Four", "FiVe", "sIx", "SeVEn", "EighT", "NINE", 
		//  "ten", "ten", "ten" 
		return runSwing(() -> new TestThreadedTableModel() {
			@Override
			void setDefaultTaskMonitor(TaskMonitor monitor) {
				// No! some of our tests use a spy monitor.  If you ever find that you
				// need the standard monitors to get wired, then wrap the monitor being
				// passed-in here by the spy and let it delegate whilst recording messages
			}
		});
	}

	@Before
	public void setUp() throws Exception {

		model = createTestModel();
		testTableModelListener = createListener();
		model.addThreadedTableModelListener(testTableModelListener);

		// do this in swing, as some of the table column setup can trigger concurrent modifications
		// due to the swing and the test working on the widgets at the same time
		runSwing(() -> {
			threadedTablePanel = new GThreadedTablePanel<>(model);
			table = threadedTablePanel.getTable();
			header = table.getTableHeader();

			buildFrame(threadedTablePanel);
		});

		// Restore this JVM property, as some tests change it
		System.setProperty(RowObjectFilterModel.SUB_FILTERING_DISABLED_PROPERTY,
			Boolean.FALSE.toString());

		waitForTableModel(model);
	}

	@After
	public void tearDown() throws Exception {
		isDisposing = true;
		dispose();
	}

	protected void buildFrame(GThreadedTablePanel<TestRowObject> tablePanel) {
		runSwing(() -> {
			frame = new DockingFrame("Threaded Table Test");
			frame.getContentPane().setLayout(new BorderLayout());
			frame.getContentPane().add(new JScrollPane(tablePanel));
			frame.pack();
			frame.setVisible(true);
		});
	}

	protected void dispose() {
		close(frame);
		runSwing(threadedTablePanel::dispose);
	}

	private TestThreadedTableModelListener createListener() {
		return new TestThreadedTableModelListener(model, recorder);
	}

	@Override
	protected void testFailed(Throwable e) {
		recorder.record("Test - testFailed()");
		// let our event recorder get all the events that were pending in the client code
		waitForNotBusy();
		recorder.dumpEvents();
	}

	@Test
	public void testRefilterHappensAfterAddItem_ItemAddedPassesFilter() throws Exception {

		int newRowIndex = getRowCount() + 1;

		filterOnRawColumnValue(newRowIndex);
		resetSpies();

		assertTableDoesNotContainValue(newRowIndex);

		addItemToModel(newRowIndex);

		assertDidFilter();
		assertTableContainsValue(newRowIndex);
	}

	@Test
	public void testRefilterHappensAfterRemoveAddItem_ItemAddedPassesFilter() throws Exception {

		int newRowIndex = getRowCount() + 1;

		filterOnRawColumnValue(newRowIndex);
		resetSpies();

		assertTableDoesNotContainValue(newRowIndex);

		TestRowObject newItem = addItemToModel(newRowIndex);
		assertDidFilter();
		assertTableContainsValue(newRowIndex);

		removeItemFromModel(newItem);
		assertDidFilter();
		assertTableDoesNotContainValue(newRowIndex);

		addItemToModel(newRowIndex);
		assertDidFilter();
		assertTableContainsValue(newRowIndex);
	}

	@Test
	public void testRefilterHappensAfterAdd_ItemAddedFailsFilter() throws Exception {

		int newRowIndex = getRowCount() + 1;

		long nonMatchingFilter = 1;
		filterOnRawColumnValue(nonMatchingFilter);
		resetSpies();

		assertTableDoesNotContainValue(newRowIndex);

		addItemToModel(newRowIndex);

		assertDidFilter();
		assertTableDoesNotContainValue(newRowIndex);
	}

	@Test
	public void testSubFilter() throws Exception {

		//
		// Our filters are smart enough to filter using the previous data when the new filter
		// is a subset of the previous filter.  Test that here.
		//

		startsWithFilter("t");
		assertFilteredEntireModel();
		assertRowCount(4); // matching values: two, ten, ten, ten

		// sub-filter
		startsWithFilter("te");
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(3); // matching values: ten, ten, ten

		// sub-filter again
		startsWithFilter("ten");
		assertNumberOfItemsPassedThroughFilter(3);
		assertRowCount(3); // matching values: ten, ten, ten

		// not a sub-filter
		startsWithFilter("F");
		assertFilteredEntireModel();
		assertRowCount(2); // matching values: Four, FiVe
	}

	@Test
	public void testSubFilter_RoundTrip_StartsWithFilter() throws Exception {

		//
		// Test that sub-filters are used for each successive addition.  Then test that the 
		// previous filtered data is used when deleting characters.
		//

		startsWithFilter("t");
		assertFilteredEntireModel();
		assertRowCount(4); // matching values: two, ten, ten, ten

		// sub-filter
		startsWithFilter("te");
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(3); // matching values: ten, ten, ten

		// sub-filter again
		startsWithFilter("ten");
		assertNumberOfItemsPassedThroughFilter(3);
		assertRowCount(3); // matching values: ten, ten, ten

		// go backwards
		startsWithFilter("te");
		assertNumberOfItemsPassedThroughFilter(3);
		assertRowCount(3); // matching values: two, ten, ten, ten

		startsWithFilter("t");

		// note: if the user is typing, no refilter will take place.  But, since we are setting a
		// new filter in this test, instead of typing, a refilter is forced.  This is why 4 items
		// pass through the filter instead of 0.
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(4); // matching values: two, ten, ten, ten
	}

	@Test
	public void testSubFilter_EscapeCharacters_StartsWithFilter() {

		//
		// Test that sub filters correctly handle escape characters.  Users may enter backslashes
		// when attempting to escape globbing characters (i.e., ? or *)
		//

		TestRowObject ro = new TestRowObject("t?n", System.currentTimeMillis());
		model.addObject(ro);
		waitForTableModel(model);

		startsWithFilter_AllowGlobbing("t");
		assertFilteredEntireModel();
		assertRowCount(5); // matching values: two, ten, ten, ten, t?n

		// sub-filter
		startsWithFilter_AllowGlobbing("t\\"); // t\
		assertNumberOfItemsPassedThroughFilter(5);
		assertRowCount(0); // nothing matching a literal backslash

		startsWithFilter_AllowGlobbing("t\\?");
		// sub-filter again
		// The previous filer was not used due to our the the code we have that checks for globbing
		// escape characters.  But, the filter before that using just 't' is a valid parent of the
		// current filter, so that get used.
		assertNumberOfItemsPassedThroughFilter(5);
		assertRowCount(1); // matching values: t?n

		// go backwards
		startsWithFilter_AllowGlobbing("t\\");
		assertNumberOfItemsPassedThroughFilter(5);
		assertRowCount(0); // nothing matching a literal backslash

		startsWithFilter_AllowGlobbing("t");

		// note: if the user is typing, no refilter will take place.  But, since we are setting a
		// new filter in this test, instead of typing, a refilter is forced.  This is why 5 items
		// pass through the filter instead of 0.
		assertNumberOfItemsPassedThroughFilter(5);
		assertRowCount(5); // matching values: two, ten, ten, ten, t?n
	}

	@Test
	public void testSubFilter_RoundTrip_RegexFilter() throws Exception {

		//
		// Test that sub-filters are used for each successive addition.  Then test that the 
		// previous filtered data is used when deleting characters.
		//

		regexFilter("^t");
		assertFilteredEntireModel();
		assertRowCount(4); // matching values: two, ten, ten, ten

		// sub-filter
		regexFilter("^te");
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(3); // matching values: ten, ten, ten

		// sub-filter again
		regexFilter("^ten");
		assertNumberOfItemsPassedThroughFilter(3);
		assertRowCount(3); // matching values: ten, ten, ten

		// go backwards
		regexFilter("^te");
		assertNumberOfItemsPassedThroughFilter(3);
		assertRowCount(3); // matching values: two, ten, ten, ten

		regexFilter("^t");

		// note: if the user is typing, no refilter will take place.  But, since we are setting a
		// new filter in this test, instead of typing, a refilter is forced.  This is why 4 items
		// pass through the filter instead of 0.
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(4); // matching values: two, ten, ten, ten
	}

	@Test
	public void testSubFilter_DeleteMultipleCharacters() throws Exception {

		startsWithFilter("t");
		assertFilteredEntireModel();
		assertRowCount(4); // matching values: two, ten, ten, ten

		// sub-filter
		startsWithFilter("te");
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(3); // matching values: ten, ten, ten

		// sub-filter again
		startsWithFilter("ten");
		assertNumberOfItemsPassedThroughFilter(3);
		assertRowCount(3); // matching values: ten, ten, ten

		// jump from 'ten' to 't'--should still used the filtered data for 't'
		startsWithFilter("t");

		// note: if the user is typing, no refilter will take place.  But, since we are setting a
		// new filter in this test, instead of typing, a refilter is forced.  This is why 4 items
		// pass through the filter instead of 0.
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(4); // matching values: two, ten, ten, ten
	}

	@Test
	public void testRefilterHappens_ChangeFilterTypeNotText() throws Exception {

		//  "one", "two", "THREE", "Four", "FiVe", "sIx", "SeVEn", "EighT", "NINE", 
		//  "ten", "ten", "ten"

		startsWithFilter("o");
		assertFilteredEntireModel();
		assertRowCount(1); // matching values: one

		containsFilter("o");
		assertFilteredEntireModel();
		assertRowCount(3); // matching values: one, two, Four
	}

	@Test
	public void testRefilterHappens_ChangeFilterOptionNotText() throws Exception {

		//  "one", "two", "THREE", "Four", "FiVe", "sIx", "SeVEn", "EighT", "NINE", 
		//  "ten", "ten", "ten"

		startsWithFilter("t");
		assertFilteredEntireModel();
		assertRowCount(4); // matching values: two, ten, ten, ten

		startsWithFilter_CaseInsensitive("t");
		assertFilteredEntireModel();
		assertRowCount(5); // matching values: two, THREE, ten, ten, ten
	}

	@Test
	public void testDisableSubFilter() throws Exception {

		// Make sure we can disable the sub-filtering mechanism
		System.setProperty(RowObjectFilterModel.SUB_FILTERING_DISABLED_PROPERTY,
			Boolean.TRUE.toString());

		startsWithFilter("t");
		assertFilteredEntireModel();

		// sub-filter
		startsWithFilter("te");
		assertFilteredEntireModel();

		// sub-filter again
		startsWithFilter("ten");
		assertFilteredEntireModel();

		startsWithFilter("t");
		assertFilteredEntireModel();
	}

	@Test
	public void testCombinedTableFilter_TwoFilters_FirstFilterStandard_SecondFilterEmpty() {

		//
		// Test that a combined filter will properly support sub-filtering.   In this case, 
		// combine a standard filter as the initial filter, with a custom filter as the second
		// filter.   This custom filter allows us to control when we return true for 
		// 'isSubFilterOf'
		//

		TableFilter<TestRowObject> customFilter = new EmptyCustomFilter();
		createCombinedStartsWithFilter("t", customFilter);
		assertFilteredEntireModel();
		assertRowCount(4); // matching values: two, ten, ten, ten

		// sub-filter; the custom filter is the empty filter, which reports it can be a 
		// child/sub-filter of any other filter.  This means it should allow the primary filter
		// to work as normal.
		createCombinedStartsWithFilter("te", customFilter);
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(3); // matching values: ten, ten, ten

		createCombinedStartsWithFilter("t", customFilter);
		assertNumberOfItemsPassedThroughFilter(4);
		assertRowCount(4); // matching values: two, ten, ten, ten
	}

	@Test
	public void testCombinedTableFilter_TwoFilters_FirstFilterStandard_SecondFilterNonEmpty() {

		//
		// Test that a combined filter will properly support sub-filtering.   In this case, 
		// combine a standard filter as the initial filter, with a custom filter as the second
		// filter.   This custom filter allows us to control when we return true for 
		// 'isSubFilterOf'
		//

		TableFilter<TestRowObject> customFilter = new StringColumnContainsCustomFilter("t");
		createCombinedStartsWithFilter("t", customFilter);
		assertFilteredEntireModel();
		assertRowCount(4); // matching values (for both filters): two, ten, ten, ten

		// sub-filter should not work, as the custom filter always reports false for 'isSubFilterOf'
		createCombinedStartsWithFilter("te", customFilter);
		assertFilteredEntireModel();
		assertRowCount(3); // matching values: ten, ten, ten

		createCombinedStartsWithFilter("t", customFilter);
		assertFilteredEntireModel();
		assertRowCount(4); // matching values (for both filters): two, ten, ten, ten
	}

	@Test
	public void testCombinedFilter_AddRemove_ItemPassesFilter_FilterJobStateDoesNotRun() {

		//
		// Tests that an item can be added/removed via addObject()/removeObject() *and* that,
		// with a *combined* filter installed, the *filter* phase of the TableLoadJob will *NOT*
		// get run.  (The add/remove operation should perform filtering and sorting outside of
		// the normal TableLoadJob's state machine.)
		//

		int fullCount = getRowCount();

		createCombinedFilterWithEmptyTextFilter(new AllPassesTableFilter());
		assertFilteredEntireModel();
		assertRowCount(fullCount); // our filter passes everything

		// call addObject()
		long newId = fullCount + 1;

		spyFilter.reset();
		addItemToModel(newId);
		assertNumberOfItemsPassedThroughFilter(1); // **this is the important check**

		assertRowCount(fullCount + 1); // our filter passes everything
	}

	@Test
	public void testCombinedFilter_AddRemove_ItemFailsFilter_FilterJobStateDoesNotRun() {

		//
		// Tests that an item can be added/removed via addObject()/removeObject() *and* that,
		// with a *combined* filter installed, the *filter* phase of the TableLoadJob will *NOT*
		// get run.  (The add/remove operation should perform filtering and sorting outside of
		// the normal TableLoadJob's state machine.)
		//

		int fullCount = getRowCount();

		Predicate<TestRowObject> predicate = ro -> {
			int index = model.getRowIndex(ro);
			return index >= 0; // < 0 means the row object is a new item not yet in the model
		};
		PredicateTableFilter noNewItemsPassFilter = new PredicateTableFilter(predicate);
		createCombinedFilterWithEmptyTextFilter(noNewItemsPassFilter);
		assertFilteredEntireModel();
		assertRowCount(fullCount); // our filter passes everything

		// call addObject()
		long newId = fullCount + 1;
		spyFilter.reset();
		addItemToModel(newId);
		assertNumberOfItemsPassedThroughFilter(1); // **this is the important check**

		assertRowCount(fullCount); // the new item should not be added
	}

	@Test
	public void testCombinedFilter_AddRemove_ItemPassesFilter_RefilterThenUndo() throws Exception {

		//
		// Bug Case: This was a case where a table (like the Symbol Table) that uses permanent
		//           combined filters would lose items inserted via the addObject() call.  The 
		//           issue is that the job was not properly updating the table's full source 
		//           data, only its filtered data.   Thus, when a job triggered a reload from 
		//           the original source data, the value would be lost.
		//

		int fullCount = getRowCount();

		createCombinedFilterWithEmptyTextFilter(new AllPassesTableFilter());
		assertFilteredEntireModel();
		assertRowCount(fullCount); // our filter passes everything

		// call addObject()
		long newId = fullCount + 1;
		addItemToModel(newId);
		assertRowCount(fullCount + 1); // our filter passes everything

		filterOnRawColumnValue(newId);
		assertRowCount(1);

		createCombinedFilterWithEmptyTextFilter(new AllPassesTableFilter());
		assertRowCount(fullCount + 1);
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	private void assertNumberOfItemsPassedThroughFilter(int expectedCount) {
		int numFiltered = spyFilter.getFilterCount();
		assertThat("Incorrect number of items filtered", numFiltered, is(expectedCount));
	}

	private void assertFilteredEntireModel() {
		int allCount = getUnfilteredRowCount();
		assertNumberOfItemsPassedThroughFilter(allCount);
	}

	private void assertTableContainsValue(long expected) {
		List<TestRowObject> modelValues = getModelData();
		for (TestRowObject ro : modelValues) {
			if (ro.getLongValue() == expected) {
				return;
			}
		}
		fail("Value not in the model--filtered out? - Expected " + expected + "; found " +
			modelValues);
	}

	private void assertTableDoesNotContainValue(long expected) {
		List<TestRowObject> modelValues = getModelData();
		for (TestRowObject ro : modelValues) {
			if (ro.getLongValue() == expected) {
				fail("Value in the model--should not be there - Value " + expected + "; found " +
					modelValues);
			}
		}
	}

	private int getUnfilteredRowCount() {
		return runSwing(() -> model.getUnfilteredRowCount());
	}

	private List<TestRowObject> getModelData() {
		return runSwing(() -> model.getModelData());
	}

	private void filterOnRawColumnValue(long filterValue) throws Exception {

		RowFilterTransformer<TestRowObject> transformer = value -> {
			List<String> result = Arrays.asList(Long.toString(value.getLongValue()));
			return result;
		};

		FilterOptions options =
			new FilterOptions(TextFilterStrategy.MATCHES_EXACTLY, false, true, false);
		TextFilterFactory textFactory = options.getTextFilterFactory();
		TextFilter textFilter = textFactory.getTextFilter(Long.toString(filterValue));

		spyFilter = new SpyTextFilter<>(textFilter, transformer, recorder);

		runSwing(() -> model.setTableFilter(spyFilter));

		waitForNotBusy();
		waitForTableModel(model);
		waitForSwing();
	}

	private void regexFilter(String filterValue) {
		filterOnStringsColumnValue(filterValue, TextFilterStrategy.REGULAR_EXPRESSION);
	}

	private void startsWithFilter(String filterValue) {
		filterOnStringsColumnValue(filterValue, TextFilterStrategy.STARTS_WITH);
	}

	private void startsWithFilter_AllowGlobbing(String filterValue) {
		filterOnStringsColumnValue(filterValue, TextFilterStrategy.STARTS_WITH, true);
	}

	private void containsFilter(String filterValue) {
		filterOnStringsColumnValue(filterValue, TextFilterStrategy.CONTAINS);
	}

	private void filterOnStringsColumnValue(String filterValue, TextFilterStrategy filterStrategy) {
		filterOnStringsColumnValue(filterValue, filterStrategy, false);
	}

	private void filterOnStringsColumnValue(String filterValue, TextFilterStrategy filterStrategy,
			boolean allowGlobbing) {

		DefaultRowFilterTransformer<TestRowObject> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		FilterOptions options = new FilterOptions(filterStrategy, allowGlobbing, true, false);
		TextFilterFactory textFactory = options.getTextFilterFactory();
		TextFilter textFilter = textFactory.getTextFilter(filterValue);

		spyFilter = new SpyTextFilter<>(textFilter, transformer, recorder);

		runSwing(() -> model.setTableFilter(spyFilter));

		waitForNotBusy();
		waitForTableModel(model);
		waitForSwing();
	}

	private void createCombinedFilterWithEmptyTextFilter(TableFilter<TestRowObject> nonTextFilter) {

		DefaultRowFilterTransformer<TestRowObject> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		TextFilter allPassesFilter = new EmptyTextFilter();
		spyFilter = new SpyTextFilter<>(allPassesFilter, transformer, recorder);

		CombinedTableFilter<TestRowObject> combinedFilter =
			new CombinedTableFilter<>(spyFilter, nonTextFilter, null);

		recorder.record("Before setting the new filter");
		runSwing(() -> model.setTableFilter(combinedFilter));
		recorder.record("\tafter setting filter");

		waitForNotBusy();
		waitForTableModel(model);
		waitForSwing();
	}

	private void createCombinedStartsWithFilter(String filterValue,
			TableFilter<TestRowObject> secondFilter) {

		DefaultRowFilterTransformer<TestRowObject> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		TextFilterStrategy filterStrategy = TextFilterStrategy.STARTS_WITH;
		FilterOptions options = new FilterOptions(filterStrategy, false, true, false);
		TextFilterFactory textFactory = options.getTextFilterFactory();
		TextFilter textFilter = textFactory.getTextFilter(filterValue);

		spyFilter = new SpyTextFilter<>(textFilter, transformer, recorder);

		CombinedTableFilter<TestRowObject> combinedFilter =
			new CombinedTableFilter<>(spyFilter, secondFilter, null);

		recorder.record("Before setting the new filter");
		runSwing(() -> model.setTableFilter(combinedFilter));
		recorder.record("\tafter setting filter");

		waitForNotBusy();
		waitForTableModel(model);
		waitForSwing();
	}

	private void startsWithFilter_CaseInsensitive(String filterValue) {

		DefaultRowFilterTransformer<TestRowObject> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());

		FilterOptions options =
			new FilterOptions(TextFilterStrategy.STARTS_WITH, false, false, false);
		TextFilterFactory textFactory = options.getTextFilterFactory();
		TextFilter textFilter = textFactory.getTextFilter(filterValue);

		spyFilter = new SpyTextFilter<>(textFilter, transformer, recorder);

		runSwing(() -> model.setTableFilter(spyFilter));

		waitForNotBusy();
		waitForTableModel(model);
		waitForSwing();
	}

	private void resetSpies() {
		spyFilter.reset();
		monitor.clearMessages();
	}

	private void assertDidFilter() {
		assertTrue("The table did not filter data when it should have", spyFilter.hasFiltered());
	}

	private void waitForNotBusy() {
		sleep(50);
		waitForCondition(() -> testTableModelListener.doneWork(),
			"Timed-out waiting for table model to update.");
		waitForSwing();
	}

	private int getRowCount() {
		return runSwing(() -> model.getRowCount());
	}

	private TestRowObject addItemToModel(long l) {
		TestRowObject ro = new TestRowObject(String.valueOf(l), l);
		model.addObject(ro);
		waitForTableModel(model);
		return ro;
	}

	private void removeItemFromModel(TestRowObject ro) {
		model.removeObject(ro);
		waitForTableModel(model);
	}

	private void assertRowCount(int expectedCount) {
		int rowCount = model.getRowCount();
		assertThat("Have different number of table rows than expected after filtering", rowCount,
			is(expectedCount));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================
	private class EmptyCustomFilter implements TableFilter<TestRowObject> {

		@Override
		public boolean acceptsRow(TestRowObject rowObject) {
			return true;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			// I pass everything, therefore anyone can be my parent
			return true;
		}
	}

	private class StringColumnContainsCustomFilter implements TableFilter<TestRowObject> {

		DefaultRowFilterTransformer<TestRowObject> transformer =
			new DefaultRowFilterTransformer<>(model, table.getColumnModel());
		private String filterText;

		StringColumnContainsCustomFilter(String filterText) {
			this.filterText = filterText;
		}

		@Override
		public boolean acceptsRow(TestRowObject rowObject) {

			List<String> strings = transformer.transform(rowObject);
			for (String s : strings) {
				if (s.contains(filterText)) {
					return true;
				}
			}
			return false;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			// for now we are too complicated to figure out if we are a sub-filter, so always 
			// return false
			return false;
		}

	}

	private class EmptyTextFilter implements TextFilter {

		@Override
		public boolean matches(String text) {
			return true;
		}

		@Override
		public String getFilterText() {
			return null;
		}

		@Override
		public boolean isSubFilterOf(TextFilter filter) {
			return true;
		}
	}

	private class AllPassesTableFilter implements TableFilter<TestRowObject> {

		@Override
		public boolean acceptsRow(TestRowObject rowObject) {
			return true;
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			return false;
		}
	}

	private class PredicateTableFilter implements TableFilter<TestRowObject> {

		private Predicate<TestRowObject> predicate;

		PredicateTableFilter(Predicate<TestRowObject> predicate) {
			this.predicate = predicate;
		}

		@Override
		public boolean acceptsRow(TestRowObject rowObject) {
			return predicate.test(rowObject);
		}

		@Override
		public boolean isSubFilterOf(TableFilter<?> tableFilter) {
			return false;
		}
	}
}
