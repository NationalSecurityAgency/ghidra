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
import java.awt.Rectangle;
import java.awt.event.MouseEvent;
import java.util.List;

import javax.swing.JFrame;
import javax.swing.JScrollPane;
import javax.swing.table.JTableHeader;

import org.junit.*;

import docking.DockingUtils;
import docking.test.AbstractDockingTest;
import docking.widgets.table.*;

public abstract class AbstractThreadedTableTest extends AbstractDockingTest {

	protected TestDataKeyModel model;
	protected GTable table;
	protected JTableHeader header;
	protected JFrame frame;
	protected TestThreadedTableModelListener testTableModelListener;
	protected GThreadedTablePanel<Long> threadedTablePanel;
	protected volatile boolean isDisposing = false;

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
	}

	protected abstract TestDataKeyModel createTestModel();

	protected TestThreadedTableModelListener createListener() {
		return new TestThreadedTableModelListener(model);
	}

	@After
	public void tearDown() throws Exception {
		isDisposing = true;
		dispose();
	}

	protected void buildFrame(GThreadedTablePanel<Long> tablePanel) {
		runSwing(() -> {
			frame = new JFrame("Threaded Table Test");
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

	protected void addItemToModel(long value) {
		model.addObject(Long.valueOf(value));
		waitForTableModel(model);
	}

	protected void removeItemFromModel(int value) {
		model.removeObject(Long.valueOf(value));
		waitForTableModel(model);
	}

	protected void triggerModelFilter() {
		model.reFilter();
		waitForTableModel(model);
	}

	protected void doTestSorting(int columnIndex) throws Exception {
		sortByNormalClicking(columnIndex);

		SortedTableModel sortedModel = (SortedTableModel) table.getModel();
		verifySortDirection(columnIndex, sortedModel);

		sortByNormalClicking(columnIndex);
		verifySortDirection(columnIndex, sortedModel);
	}

	@SuppressWarnings("rawtypes")
	protected void verifySortDirection(int columnIndex, SortedTableModel sortedModel) {
		TableSortState sortState = getSortState(sortedModel);
		ColumnSortState columnSortState = sortState.getColumnSortState(columnIndex);
		if (columnSortState == null) {
			System.err.println("Actual sorted column(s): " + sortState);
			Assert.fail("Expected column not sorted! - Expected: " + columnIndex);
		}

		for (int i = 0; i < table.getRowCount() - 1; ++i) {
			Comparable comp1 = (Comparable) table.getValueAt(i + 0, columnIndex);
			Comparable comp2 = (Comparable) table.getValueAt(i + 1, columnIndex);

			if (columnSortState.isAscending()) {
				int compareResult = compareValues(comp1, comp2);
				boolean lessThanOrEqual = compareResult <= 0;
				assertTrue("\"" + comp1 + "\"" + " is not <= " + "\"" + comp2 + "\"",
					lessThanOrEqual);
			}
			else {
				int compareResult = compareValues(comp1, comp2);
				boolean greaterThanOrEqual = compareResult >= 0;
				assertTrue("\"" + comp1 + "\"" + " is not >= " + "\"" + comp2 + "\"",
					greaterThanOrEqual);
			}
		}
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	protected int compareValues(Comparable comp1, Comparable comp2) {
		if ((comp1 instanceof String) && (comp2 instanceof String)) {
			String string1 = (String) comp1;
			String string2 = (String) comp2;
			return string1.compareToIgnoreCase(string2);
		}

		return comp1.compareTo(comp2);
	}

	protected void sortByNormalClicking(int columnToClick) throws Exception {
		sortByClick(columnToClick, 0);
	}

	protected void sortByClick(int columnToClick, int modifiers) throws Exception {

		SortedTableModel sortedModel = (SortedTableModel) table.getModel();
		TableSortState sortState = getSortState(sortedModel);
		record("sortByClick() - initial sort state: " + sortState);

		int currentSortColunn = -1;
		boolean isAscending = true;
		boolean checkSortDirection = false;
		if (!sortState.isUnsorted()) {

			// check to see if the tests is clicking the same column twice (to change the 
			// sort direction)
			ColumnSortState originalColumnSortState = sortState.iterator().next();
			currentSortColunn = originalColumnSortState.getColumnModelIndex();
			checkSortDirection = (columnToClick == currentSortColunn);
			isAscending = originalColumnSortState.isAscending();
		}

		testTableModelListener.reset(model);
		Rectangle rect = header.getHeaderRect(columnToClick);
		if (!header.isShowing()) {
			waitForPostedSwingRunnables();
		}

		record("Clicking table at column " + columnToClick);
		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1, modifiers);
		waitForNotBusy();
		record("\tafter click; table not busy");

		sortState = getSortState(sortedModel);
		record("Updated sort state: " + sortState);

		ColumnSortState columnSortState = sortState.iterator().next();
		int sortedIndex = columnSortState.getColumnModelIndex();
		verifyColumnSorted(sortedIndex, sortState);

		if (checkSortDirection) {
			boolean newDirection = columnSortState.isAscending();
			if (isAscending == newDirection) {
				fail("Not sorted in the expected direction");
			}
		}
	}

	protected TableSortState getSortState(SortedTableModel sortedModel) {
		return runSwing(() -> sortedModel.getTableSortState());
	}

	protected void removeSortByClicking(int columnToClick) throws Exception {
		SortedTableModel sortedModel = (SortedTableModel) table.getModel();

		testTableModelListener.reset(model);
		Rectangle rect = header.getHeaderRect(columnToClick);
		clickMouse(header, MouseEvent.BUTTON1, rect.x + 10, rect.y + 10, 1,
			DockingUtils.CONTROL_KEY_MODIFIER_MASK);
		waitForNotBusy();

		TableSortState sortState = getSortState(sortedModel);
		assertNull(sortState.getColumnSortState(columnToClick));
	}

	protected void verifyColumnSorted(int sortedIndex, TableSortState sortState) {
		ColumnSortState columnSortState = sortState.getColumnSortState(sortedIndex);
		assertNotNull(columnSortState);
	}

	protected void resetBusyListener() {
		testTableModelListener.reset(model);
	}

	protected void waitForNotBusy() {
		sleep(50);
		waitForCondition(() -> testTableModelListener.doneWork(),
			"Timed-out waiting for table model to update.");
		waitForSwing();
	}

	protected void addLong(final long value) {
		runSwing(() -> model.addObject(Long.valueOf(value)));
	}

	protected int getRowCount() {
		return runSwing(() -> model.getRowCount());
	}

	protected int getUnfilteredRowCount() {
		return runSwing(() -> model.getUnfilteredRowCount());
	}

	protected List<Long> getModelData() {
		return runSwing(() -> model.getModelData());
	}

	protected void record(String message) {
		// no-op for base class; subclasses know how to record debug
	}

	protected void assertRowCount(int expectedCount) {
		int rowCount = model.getRowCount();
		assertThat("Have different number of table rows than expected after filtering", rowCount,
			is(expectedCount));
	}

	protected void assertNoRowsFilteredOut() {
		List<Long> allData = model.getAllData();
		TableData<Long> currentData = model.getCurrentTableData();
		assertThat("Table has been filtered", currentData.size(), is(allData.size()));
	}
}
