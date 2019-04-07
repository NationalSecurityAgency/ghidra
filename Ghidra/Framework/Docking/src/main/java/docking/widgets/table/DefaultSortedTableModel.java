/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.AssertException;

import java.util.*;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import docking.widgets.table.ColumnSortState.SortDirection;

/**
 * A sorter for TableModels. The sorter has a model (conforming to TableModel)
 * and itself implements TableModel. TableSorter does not store or copy
 * the data in the TableModel, instead it maintains an array of
 * integers which it keeps the same size as the number of rows in its
 * model. When the model changes it notifies the sorter that something
 * has changed (e.g., "rowsAdded") so that its internal array of integers
 * can be reallocated. As requests are made of the sorter (like
 * getValueAt(row, col) it redirects them to its model via the mapping
 * array. That way the TableSorter appears to hold another copy of the table
 * with the rows in a different order. The sorting algorithm used is stable
 * which means that it does not move around rows when its comparison
 * function returns 0 to denote that they are equivalent.
 * 
 * @deprecated You should instead be using {@link AbstractSortedTableModel}
 */
@Deprecated
public class DefaultSortedTableModel extends AbstractTableModel implements SortedTableModel,
		TableModelListener {

	// all callbacks to fire changes and add listeners are expected to be in the Swing thread
	private WeakSet<SortListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

//========================================================================    
// conversion to multi sorting tables     

	private TableSortState createSortState(int column, boolean ascending) {
		ColumnSortState sortState =
			new ColumnSortState(column, ascending ? SortDirection.ASCENDING
					: SortDirection.DESCENDING, 1);
		return new TableSortState(sortState);
	}

	public void setSort(int column, boolean ascending) {
		TableSortState sortState = createSortState(column, ascending);
		setTableSortState(sortState);
	}

	@Override
	public int getPrimarySortColumnIndex() {
		return tableSortState.iterator().next().getColumnModelIndex();
	}

	public boolean isAscending() {
		return true;
	}

// end conversion to multi sorting tables    

	private TableSortState tableSortState = new TableSortState();

	private int[] indexes;

	/**
	 * A poorly named variable that is intended to indicate that the client is making bulk updates
	 * and this table should not perform indexing while this bulk operation is happening.
	 */
	private boolean sortEnabled = true;

	private Map<Integer, Comparator<?>> registeredComparatorMap =
		new HashMap<Integer, Comparator<?>>();

	protected TableModel model;

	/**
	 * Construct a new TableSorter using the given model.
	 * 
	 * @deprecated You should instead be using {@link AbstractSortedTableModel}
	 */
	@Deprecated
	public DefaultSortedTableModel(TableModel model) {
		if (model == null) {
			throw new NullPointerException("Model cannot be null!");
		}

		if (model instanceof AbstractSortedTableModel<?>) {
			throw new AssertException("You cannot pass an AbstractSortedTableModel to " +
				getClass().getSimpleName() + "--it is already sorted!");
		}

		setModel(model);
		init();
	}

	private void init() {
		TableSortState defaultSortState = createSortState(0, true);
		this.tableSortState = defaultSortState;
	}

	public void setModel(TableModel model) {
		if (model == null) {
			throw new NullPointerException("Model cannot be null!");
		}
		this.model = model;
		model.addTableModelListener(this);
		reallocateIndexes();
	}

	public TableModel getModel() {
		return model;
	}

	/**
	 * Enable the sorter according to the enable parameter. This method
	 * should be called with enable set to <b>false</b> <i>before</i> the table
	 * model is populated or else a sort will be done after each row is
	 * inserted, and that would not be good.
	 * @param enable true means to enable the sorting.
	 */
	public void enableSorter(boolean enable) {
		sortEnabled = enable;
		if (!sortEnabled) {
			return;
		}

		reallocateIndexes();
		sort();

		SystemUtilities.runIfSwingOrPostSwingLater(new Runnable() {
			@Override
			public void run() {
				notifySorted();
			}
		});
	}

	private void notifySorted() {
		fireTableChangedEvent();

		for (SortListener listener : listeners) {
			listener.modelSorted(tableSortState);
		}
	}

	private void fireTableChangedEvent() {
		fireTableChanged(new TableModelEvent(this));
	}

	@Override
	public void addSortListener(SortListener l) {
		listeners.add(l);
	}

	public void registerComparator(Comparator<?> comparator, int column) {
		registeredComparatorMap.put(column, comparator);
	}

	public void deRegisterComparator(int column) {
		registeredComparatorMap.remove(column);
	}

	@SuppressWarnings("unchecked")
	// for the Comparator<?> usage
	private int compareRowsByColumn(int row1, int row2, int column) {
		TableModel data = model;
		Object o1 = data.getValueAt(row1, column);
		Object o2 = data.getValueAt(row2, column);

		// If both values are null return 0
		if (o1 == null && o2 == null) {
			return 0;
		}
		else if (o1 == null) { // Define null less than everything.
			return -1;
		}
		else if (o2 == null) {
			return 1;
		}

		// if the user has registered a comparator, prefer that
		Comparator comparator = getComparator(column);
		Object value1 = data.getValueAt(row1, column);
		Object value2 = data.getValueAt(row2, column);
		return comparator.compare(value1, value2);
	}

	private Comparator<?> getComparator(int column) {
		Comparator<?> comparator = registeredComparatorMap.get(column);
		if (comparator != null) {
			return comparator;
		}

		return DEFAULT_COMPARATOR;
	}

	private int compare(int row1, int row2) {

		for (ColumnSortState columnSortState : tableSortState) {
			int result = compareRowsByColumn(row1, row2, columnSortState.getColumnModelIndex());
			if (result != 0) {
				return columnSortState.isAscending() ? result : -result;
			}
		}
		return 0;
	}

	private void reallocateIndexes() {
		int rowCount = model.getRowCount();

		// Set up a new array of indexes with the right number of elements
		// for the new data model.
		indexes = new int[rowCount];

		// Initialize with the identity mapping.
		for (int row = 0; row < rowCount; row++) {
			indexes[row] = row;
		}
	}

	@Override
	public void tableChanged(TableModelEvent e) {
		if (sortEnabled) {
			reallocateIndexes();
			sort();
		}
		fireTableChanged(e);
	}

	private void checkModel() {
		if (indexes.length == model.getRowCount()) {
			return; // O.K.!
		}

		if (!sortEnabled) {
			return; // don't report an issue if we are called while in the middle of updating
		}

		Msg.error(this, "Sorter not informed of a change in model.");
	}

	private void sort() {
		checkModel();

		shuttlesort(indexes.clone(), indexes, 0, indexes.length);
	}

	// This is a home-grown implementation which we have not had time
	// to research - it may perform poorly in some circumstances. It
	// requires twice the space of an in-place algorithm and makes
	// NlogN assignments shuttling the values between the two
	// arrays. The number of compares appears to vary between N-1 and
	// NlogN depending on the initial order but the main reason for
	// using it here is that, unlike qsort, it is stable.
	private void shuttlesort(int[] from, int[] to, int low, int high) {
		if (high - low < 2) {
			return;
		}
		int middle = (low + high) / 2;
		shuttlesort(to, from, low, middle);
		shuttlesort(to, from, middle, high);

		int p = low;
		int q = middle;

		/* This is an optional short-cut; at each recursive call,
		check to see if the elements in this subset are already
		ordered.  If so, no further comparisons are needed; the
		sub-array can just be copied.  The array must be copied rather
		than assigned otherwise sister calls in the recursion might
		get out of sinc.  When the number of elements is three they
		are partitioned so that the first set, [low, mid), has one
		element and and the second, [mid, high), has two. We skip the
		optimization when the number of elements is three or less as
		the first compare in the normal merge will produce the same
		sequence of steps. This optimization seems to be worthwhile
		for partially ordered lists but some analysis is needed to
		find out how the performance drops to Nlog(N) as the initial
		order diminishes - it may drop very quickly.  */

		if (high - low >= 4 && compare(from[middle - 1], from[middle]) <= 0) {
			for (int i = low; i < high; i++) {
				to[i] = from[i];
			}
			return;
		}

		// A normal merge.

		for (int i = low; i < high; i++) {
			if (q >= high || (p < middle && compare(from[p], from[q]) <= 0)) {
				to[i] = from[p++];
			}
			else {
				to[i] = from[q++];
			}
		}
	}

	/**
	 * @see javax.swing.table.TableModel#getValueAt(int, int)
	 */
	@Override
	public Object getValueAt(int aRow, int aColumn) {
		checkModel();
		return model.getValueAt(indexes[aRow], aColumn);
	}

	/**
	 * Converts a sorted index into an unsorted index.
	 * This is good if you need to access the underlying table directly by
	 * the unsorted index.
	 */
	public int getSortedIndex(int aRow) {
		checkModel();
		return indexes[aRow];
	}

	/**
	 * @see javax.swing.table.TableModel#setValueAt(java.lang.Object, int, int)
	 */
	@Override
	public void setValueAt(Object aValue, int aRow, int aColumn) {
		checkModel();
		model.setValueAt(aValue, indexes[aRow], aColumn);
	}

	/**
	 * Sorts the model in ascending order by the specified columnIndex.
	 * @param column the index of the column to sort
	 */
	public void sortByColumn(int column) {
		ColumnSortState sortState = new ColumnSortState(column, SortDirection.ASCENDING, 1);
		TableSortState newCollection = new TableSortState(sortState);
		setTableSortState(newCollection);
	}

	@Override
	public boolean isSortable(int columnIndex) {
		return true;
	}

	public void resort() {
		tableChanged(new TableModelEvent(this));
	}

	@Override
	public TableSortState getTableSortState() {
		return tableSortState;
	}

	@Override
	public void setTableSortState(TableSortState sortStates) {
		this.tableSortState = sortStates;
		resort();
	}

//==================================================================================================
// Delegate Methods - We are a wrapper 
//==================================================================================================

	/**
	 * 
	 * @see javax.swing.table.TableModel#getRowCount()
	 */
	@Override
	public int getRowCount() {
		// Always rely on the indexed values as the count.  This prevents getValueAt() from
		// being called when the indexes are out-of-date, while the client is manipulating the table
		return indexes.length;
	}

	/**
	 * 
	 * @see javax.swing.table.TableModel#getColumnCount()
	 */
	@Override
	public int getColumnCount() {
		return model.getColumnCount();
	}

	/**
	 * 
	 * @see javax.swing.table.TableModel#getColumnName(int)
	 */
	@Override
	public String getColumnName(int aColumn) {
		return model.getColumnName(aColumn);
	}

	/**
	 * 
	 * @see javax.swing.table.TableModel#getColumnClass(int)
	 */
	@Override
	public Class<?> getColumnClass(int aColumn) {
		return model.getColumnClass(aColumn);
	}

	/**
	 * 
	 * @see javax.swing.table.TableModel#isCellEditable(int, int)
	 */
	@Override
	public boolean isCellEditable(int row, int column) {
		return model.isCellEditable(row, column);
	}

}
