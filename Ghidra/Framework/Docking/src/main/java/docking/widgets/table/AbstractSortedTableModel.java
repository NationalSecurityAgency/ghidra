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

import java.util.*;

import javax.swing.event.TableModelEvent;
import javax.swing.table.TableModel;

import docking.widgets.table.sort.DefaultColumnComparator;
import docking.widgets.table.sort.RowBasedColumnComparator;
import ghidra.util.Swing;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * Table models should extends this model when they want sorting, potentially across multiple
 * columns, but do not want Threading or do not work on Program-related data (Address,
 * ProgramLocations, etc...).
 * <p>
 * In order to define custom comparators for a column, simply override
 * {@link #createSortComparator(int)}.  Otherwise, a default comparator will be created for you.
 *
 * <p>Note on sorting: it is possible that the user can disable sorting by de-selecting all
 * sorted columns.   This can also be achieved programmatically by calling
 * {@link #setTableSortState(TableSortState)} with a value of
 * {@link TableSortState#createUnsortedSortState()}.
 *
 * @param <T> The row type upon which the table is based
 */
public abstract class AbstractSortedTableModel<T> extends AbstractGTableModel<T>
		implements SortedTableModel {

	private final Comparator<T> NO_SORT_COMPARATOR = (o1, o2) -> 0;

	private TableSortState pendingSortState;
	private TableSortState sortState = TableSortState.createUnsortedSortState();
	private boolean isSortPending;

	protected boolean hasEverSorted;

	// all callbacks to fire changes and add listeners are expected to be in the Swing thread
	private WeakSet<SortListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	public AbstractSortedTableModel() {
		this(0);
	}

	public AbstractSortedTableModel(int defaultSortColumn) {
		setDefaultTableSortState(TableSortState.createDefaultSortState(defaultSortColumn));
	}

	protected void setDefaultTableSortState(TableSortState defaultSortState) {
		sortState = defaultSortState;
		if (sortState == null) {
			sortState = TableSortState.createUnsortedSortState();
		}

	}

	@Override
	public void addSortListener(SortListener l) {
		listeners.add(l);
	}

	/**
	 * Returns the corresponding object for the given row.
	 * @param viewRow The row for which to get the row object.
	 * @return the row object.
	 */
	@Override
	public T getRowObject(int viewRow) {
		List<T> data = getModelData();
		if (viewRow < 0 || viewRow >= data.size()) {
			return null;
		}
		return data.get(viewRow);
	}

	/**
	 * Returns the index of the given row object in this model; a negative value if the model
	 * does not contain the given object.
	 *
	 * <p>Warning: if the this model has no sort applied, then performance will be O(n).  If
	 * sorted, then performance is O(log n).  You can call {@link #isSorted()} to know when
	 * this will happen.
	 */
	@Override
	public int getRowIndex(T rowObject) {
		if (rowObject == null) {
			return -1;
		}
		return getIndexForRowObject(rowObject);
	}

	@Override
	// overridden to sort the data on table changes
	public void fireTableChanged(TableModelEvent e) {
		super.fireTableChanged(e);

		reSort();
	}

	protected void reSort() {
		List<T> modelData = getModelData();
		if (modelData == null || modelData.isEmpty()) {
			return; // no data, no need to resort
		}

		pendingSortState = sortState;
		sort(modelData, new TableSortingContext<>(sortState, getComparatorChain(sortState)));
	}

	@Override
	public TableSortState getTableSortState() {
		return sortState;
	}

	@Override
	public int getPrimarySortColumnIndex() {
		if (sortState.isUnsorted()) {
			return -1;
		}
		return sortState.iterator().next().getColumnModelIndex();
	}

	@Override
	public void setTableSortState(TableSortState newSortState) {

		if (!isValidSortState(newSortState)) {
			// if the user calls this method with an invalid value, then let them know!
			throw new IllegalArgumentException(
				"Unable to sort the table by the given sort state!: " + newSortState);
		}

		doSetTableSortState(newSortState);
	}

	private boolean isValidSortState(TableSortState tableSortState) {
		int columnCount = getColumnCount();
		int sortedColumnCount = tableSortState.getSortedColumnCount();
		if (sortedColumnCount > columnCount) {
			return false; // more columns than we have
		}

		// verify the requested columns are sortable
		for (ColumnSortState state : tableSortState) {

			int index = state.getColumnModelIndex();
			if (!isSortable(index)) {
				return false; // the state wants to sort on an unsortable column
			}

			if (index >= columnCount) {
				return false; // requested a column that is larger than the number of columns
			}
		}

		return true;
	}

	/**
	 * A convenience method that will take a given sort state and remove from it any columns
	 * that cannot be sorted.  This is useful if the client is restoring a sort state that
	 * contains columns that have been removed or are no longer sortable (such as during major
	 * table model rewrites).
	 *
	 * @param state the state
	 * @return the updated state
	 */
	protected TableSortState cleanupTableSortState(TableSortState state) {

		int columnCount = getColumnCount();
		TableSortStateEditor editor = new TableSortStateEditor(state);
		int n = editor.getSortedColumnCount();
		for (int i = 0; i < n; i++) {
			ColumnSortState ss = editor.getColumnSortState(i);
			int columnIndex = ss.getColumnModelIndex();
			if (columnIndex >= columnCount) {
				editor.removeSortedColumn(columnIndex);
			}
			if (!isSortable(columnIndex)) {
				editor.removeSortedColumn(columnIndex);
			}
		}

		return editor.createTableSortState();
	}

	private void doSetTableSortState(final TableSortState newSortState) {
		if (newSortState.equals(pendingSortState)) {
			return; // there is an upcoming sort that matches the current request
		}

		// no pending event, is the current state different?
		if (newSortState.equals(sortState) && pendingSortState == null) {
			return; // the current state matches our request
		}

		isSortPending = true;
		pendingSortState = newSortState;
		Swing.runLater(() -> sort(getModelData(), createSortingContext(newSortState)));
	}

	public TableSortState getPendingSortState() {
		return pendingSortState;
	}

	/**
	 * Returns true if there is a pending change to the current sort state
	 * (this includes a sort state that signals no sort will be applied)
	 *
	 * @return true if there is a pending change to the current sort state
	 */
	public boolean isSortPending() {
		return isSortPending;
	}

	/**
	 * Returns true if this model has been sorted and does not have a new pending sort that will
	 * be applied
	 *
	 * @return true if sorted
	 * @see #isSortPending()
	 */
	public boolean isSorted() {
		return !isSortPending && !sortState.isUnsorted();
	}

	protected TableSortingContext<T> createSortingContext(TableSortState newSortState) {
		return new TableSortingContext<>(newSortState, getComparatorChain(newSortState));
	}

	/**
	 * The default implementation of {@link TableModel#getValueAt(int, int)} that calls the
	 * abstract {@link #getColumnValueForRow(Object, int)}.
	 */
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		initializeSorting();
		return super.getValueAt(rowIndex, columnIndex);
	}

	/**
	 * This method is an attempt to help models that forget to call fireTableDataChanged().  It
	 * is expected that tables will fire the notification when they are ready to display data,
	 * even if they have that data at construction time.  We put this call here so that the
	 * forgetful subclasses will have their data sorted for them the first time that this table
	 * tries to render itself.
	 */
	protected void initializeSorting() {
		if (hasEverSorted) {
			return;
		}

		hasEverSorted = true;
		isSortPending = true;
		pendingSortState = sortState;
		Swing.runLater(() -> sort(getModelData(), createSortingContext(sortState)));
	}

	/**
	 * A convenience method for subclasses to quickly/efficiently search for the index of a given
	 * row object <b>that is visible in the GUI</b>.  The <i>visible</i> limitation is due to the
	 * fact that the data searched is retrieved from {@link #getModelData()}, which may be
	 * filtered.
	 *
	 * @param rowObject The object for which to search.
	 * @return the index of the item in the data returned by
	 */
	@Override
	protected int getIndexForRowObject(T rowObject) {
		return getIndexForRowObject(rowObject, getModelData());
	}

	/**
	 * Returns the index for the given object in the given list
	 *
	 * @param rowObject the item
	 * @param data the data
	 * @return the index
	 */
	@Override
	protected int getIndexForRowObject(T rowObject, List<T> data) {
		if (isSorted()) {
			Comparator<T> comparator = getComparatorChain(sortState);
			return Collections.binarySearch(data, rowObject, comparator);
		}

		for (int i = 0; i < data.size(); i++) {
			T t = data.get(i);
			if (rowObject.equals(t)) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * A default sort method that uses the {@link Collections#sort(List, Comparator)} method for
	 * sorting.  Implementors with reasonably sized data sets can rely on this method.  For data
	 * sets that can become large, the <code>ThreadedTableModel</code> is the recommended base class,
	 * as it handles loading/sorting/filtering in a threaded way.
	 *
	 * @param data The data to be sorted
	 * @param sortingContext The context required to sort (it contains the sorting columns, a
	 *        comparator for sorting, etc...).
	 */
	protected void sort(List<T> data, TableSortingContext<T> sortingContext) {

		if (sortingContext.isUnsorted()) {
			// this is the 'no sort' state
			sortCompleted(sortingContext);
			notifyModelSorted(false);
			return;
		}

		hasEverSorted = true; // signal that we have sorted at least one time
		Collections.sort(data, sortingContext.getComparator());
		sortCompleted(sortingContext);
		notifyModelSorted(false);
	}

	protected void sortCompleted(TableSortingContext<T> sortingContext) {
		if (sortingContext != null) { // null implies that a sort didn't complete successfully
			sortState = sortingContext.getSortState();
		}

		isSortPending = false;
		pendingSortState = null;
	}

	/**
	 * Fires an event to let the listeners (like JTable) know that things have been changed.
	 * This method exists so that subclasses have a way to call the various <code>tableChanged()</code>
	 * methods without triggering this class's overridden version.
	 * @param dataChanged True signals that the actual data has changed; false signals that the
	 *        data is the same, with exception that attributes of that data may be different.
	 */
	protected void notifyModelSorted(boolean dataChanged) {
		if (dataChanged) {
			super.fireTableChanged(new TableModelEvent(this));
		}
		else {
			super.fireTableChanged(new TableModelEvent(this, 0, getRowCount() - 1,
				TableModelEvent.ALL_COLUMNS, TableModelEvent.UPDATE));
		}

		for (SortListener listener : listeners) {
			listener.modelSorted(sortState);
		}
	}

	/**
	 * An extension point for subclasses to insert their own comparator objects for their data.
	 * Subclasses can create comparators for a single or multiple columns, as desired.
	 *
	 * @param columnIndex the column index
	 * @return the comparator
	 */
	protected Comparator<T> createSortComparator(int columnIndex) {
		return new RowBasedColumnComparator<>(this, columnIndex, new DefaultColumnComparator(),
			new StringBasedBackupRowToColumnComparator());
	}

	private Comparator<T> createLastResortComparator(ComparatorLink parentChain) {
		Comparator<T> endOfChain = new EndOfChainComparator();

		//
		// 						Unusual Code Alert!
		// This is hard to explain, but here goes: there is a special case where we have only
		// one column sorted and that column is 'reversed', then to provide consistent sorting,
		// and later searching, we need to reverse the tie-breaker comparator.  Without this,
		// the tie-breaker always produces the same results, regardless of which direction the
		// search is going.  That will break any clients that call Collections.reverse() in
		// order to quickly invert an existing sort.
		//
		if (parentChain.primaryComparator instanceof AbstractSortedTableModel.ReverseComparator) {
			endOfChain = new ReverseComparator(endOfChain);
		}

		return endOfChain;
	}

	/**
	 * Creates a 'Chain of Responsibility' object that knows how to do comparisons in a
	 * waterfall fashion (this handles the case where there are multiple columns upon which the
	 * data is sorted).
	 */
	private Comparator<T> getComparatorChain(TableSortState newSortState) {

		if (newSortState.isUnsorted()) {
			return NO_SORT_COMPARATOR;
		}

		ComparatorLink comparatorLink = new ComparatorLink();
		for (ColumnSortState columnSortState : newSortState) {
			Comparator<T> nextComparator = getComparator(columnSortState);
			comparatorLink.add(nextComparator);
		}

		// Add a comparator to resolve the case where all other comparators return 0 values.
		// This provides some consistency between sorts.
		comparatorLink.add(createLastResortComparator(comparatorLink));
		return comparatorLink;
	}

	/**
	 * Builds a comparator for the given column sort state while allowing for subclasses to
	 * provider their own comparators.  This method also handles directionality of sorting, so
	 * that the comparators used can be simple and generic.
	 */
	private Comparator<T> getComparator(ColumnSortState columnSortState) {
		Comparator<T> comparator = createSortComparator(columnSortState.getColumnModelIndex());
		if (columnSortState.isAscending()) {
			return comparator;
		}
		return new ReverseComparator(comparator);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/** A comparator that can be linked to other comparators to form a chain of comparators */
	private class ComparatorLink implements Comparator<T> {

		private Comparator<T> primaryComparator;
		private Comparator<T> nextComparator;

		public ComparatorLink() {
			// default constructor that allows clients to build-up links manually
		}

		private ComparatorLink(Comparator<T> firstLink, Comparator<T> nextLink) {
			this.primaryComparator = firstLink;
			this.nextComparator = nextLink;
		}

		void add(Comparator<T> comparator) {
			if (primaryComparator == null) {
				primaryComparator = comparator;
			}
			else if (nextComparator == null) {
				nextComparator = comparator;
			}
			else {
				nextComparator = new ComparatorLink(nextComparator, comparator);
			}
		}

		@Override
		public int compare(T t1, T t2) {
			int result = primaryComparator.compare(t1, t2);
			if (result != 0 || nextComparator == null) {
				return result;
			}

			result = nextComparator.compare(t1, t2);
			return result;
		}
	}

	/**
	 * This class is designed to be used as the last link in a chain of comparators.  If we get
	 * to this comparator, then the two given objects are assumed to have compared as equal.  Thus,
	 * when we get to this comparator, then we have to make a decision about reasonable default
	 * comparisons in order to maintain sorting consistency across sorts.
	 */
	@SuppressWarnings("unchecked")	// Comparable cast 
	private class EndOfChainComparator implements Comparator<T> {
		@SuppressWarnings("rawtypes")
		@Override
		public int compare(T t1, T t2) {

			// at this point we compare the rows, since all of the sorting column values are equal
			// (Warning: due to comparable being specific to the class upon which it is defined,
			//           we have to make sure the class is the same to prevent class cast
			//           exceptions when the table has mixed implementations of 'T')
			if (t1 instanceof Comparable && t1.getClass().equals(t2.getClass())) {
				return ((Comparable) t1).compareTo(t2);
			}

			// use the identity hash to provide a consistent unique identifier within a JVM session
			return System.identityHashCode(t1) - System.identityHashCode(t2);
		}
	}

	private class ReverseComparator implements Comparator<T> {
		private final Comparator<T> comparator;

		public ReverseComparator(Comparator<T> comparator) {
			this.comparator = comparator;
		}

		@Override
		public int compare(T t1, T t2) {
			return -comparator.compare(t1, t2);
		}
	}

	private class StringBasedBackupRowToColumnComparator implements Comparator<Object> {

		@Override
		public int compare(Object c1, Object c2) {
			if (c1 == c2) {
				return 0;
			}

			String s1 = getColumStringValue(c1);
			String s2 = getColumStringValue(c2);

			if (s1 == null || s2 == null) {
				return TableComparators.compareWithNullValues(s1, s2);
			}

			return s1.compareToIgnoreCase(s2);
		}

		private String getColumStringValue(Object columnValue) {
			// just use the toString(), which may or may not produce a good value (this will
			// catch the cases where the column value is itself a string)
			return columnValue == null ? null : columnValue.toString();
		}
	}
}
