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

import java.util.*;
import java.util.function.BiFunction;

import docking.widgets.table.TableFilter;
import docking.widgets.table.TableSortingContext;
import ghidra.util.SystemUtilities;

/**
 * A concept that represents the data used by the {@link ThreadedTableModel}.  This class 
 * encapsulates the actual data, along with any filter applied, any sort applied, along with 
 * some convenience methods for performing operations on this group of data.
 *
 * @param <ROW_OBJECT> the row type
 */
public class TableData<ROW_OBJECT> implements Iterable<ROW_OBJECT> {

	private static int nextID = 0;

	/** 
	 * This is null when 'data' is not derived from any other data set (like after a filter).
	 * When data is derived, this will be non-null.  Further, this 'source' data may itself 
	 * have a 'source' data, and so on.
	 */
	private TableData<ROW_OBJECT> source = null;

	/** This data may be a subset of 'source' */
	private List<ROW_OBJECT> data = Collections.emptyList();

	/**
	 * Note: There is an assumption that if this object is null, then the data is NOT sorted.  If
	 *       it is not null, then the data is sorted.
	 */
	private volatile TableSortingContext<ROW_OBJECT> sortContext;

	/** null if not filtered */
	private TableFilter<ROW_OBJECT> tableFilter;

	private int ID = ++nextID;

	static <ROW_OBJECT> TableData<ROW_OBJECT> createEmptyDataset() {
		return new TableData<>();
	}

	static <ROW_OBJECT> TableData<ROW_OBJECT> createFullDataset(List<ROW_OBJECT> data) {
		return new TableData<>(data, null /* not sorted yet */);
	}

	static <ROW_OBJECT> TableData<ROW_OBJECT> createSubDataset(TableData<ROW_OBJECT> source,
			List<ROW_OBJECT> derived, TableSortingContext<ROW_OBJECT> sortContext) {
		return new TableData<>(source, derived, sortContext);
	}

	private TableData() {
		// no source; no data; no sort
	}

	TableData(List<ROW_OBJECT> data, TableSortingContext<ROW_OBJECT> sortContext) {
		this.data = data;
		this.sortContext = sortContext;
	}

	private TableData(TableData<ROW_OBJECT> source, List<ROW_OBJECT> derived,
			TableSortingContext<ROW_OBJECT> sortContext) {
		this.source = source;
		this.data = derived;
		this.sortContext = sortContext;
	}

	TableData<ROW_OBJECT> copy() {
		return copy(source);
	}

	TableData<ROW_OBJECT> copy(TableData<ROW_OBJECT> newSource) {
		List<ROW_OBJECT> dataCopy = new ArrayList<>(data);
		TableData<ROW_OBJECT> newData = new TableData<>(dataCopy, sortContext);
		newData.source = newSource;
		newData.tableFilter = tableFilter;
		newData.ID = ID; // it is a copy, but represents the same data
		return newData;
	}

	TableFilter<ROW_OBJECT> getTableFilter() {
		return tableFilter;
	}

	void setTableFilter(TableFilter<ROW_OBJECT> tableFilter) {
		this.tableFilter = tableFilter;
	}

	TableSortingContext<ROW_OBJECT> getSortContext() {
		return sortContext;
	}

	boolean isSorted() {
		return sortContext != null && !sortContext.isUnsorted();
	}

	void setSortContext(TableSortingContext<ROW_OBJECT> sortContext) {
		this.sortContext = sortContext;
	}

	List<ROW_OBJECT> getData() {
		return data;
	}

	public int size() {
		return data.size();
	}

	void clear() {
		data.clear();
	}

	public ROW_OBJECT get(int modelRow) {
		return data.get(modelRow);
	}

	/**
	 * Uses the current sort to perform a fast lookup of the given item in the given list when 
	 * sorted; a brute-force lookup when not sorted
	 * @param t the item
	 * @return the index
	 */
	public int indexOf(ROW_OBJECT t) {
		if (!sortContext.isUnsorted()) {
			Comparator<ROW_OBJECT> comparator = sortContext.getComparator();
			return Collections.binarySearch(data, t, comparator);
		}

		// brute force
		for (int i = 0; i < data.size(); i++) {
			ROW_OBJECT item = data.get(i);
			if (t.equals(item)) {
				return i;
			}
		}
		return -1;
	}

	public boolean remove(ROW_OBJECT t) {
		if (source != null) {
			source.remove(t);
		}

		if (sortContext.isUnsorted()) {
			return data.remove(t); // no sort; cannot binary search
		}

		Comparator<ROW_OBJECT> comparator = sortContext.getComparator();
		int index = Collections.binarySearch(data, t, comparator);
		if (index >= 0) {
			data.remove(index);
			return true;
		}

		// We used to have code that pass proxy objects to this class to remove items.  That code
		// has been updated to no longer pass proxy objects.  Leaving this code here for a while
		// just in case we find another client doing the same thing.
		// return data.remove(t);
		return false;
	}

	/**
	 * A generic method that allows clients to process the contents of this table data.  This
	 * method is not synchronized and should only be called from a {@link TableUpdateJob} or
	 * one of its callbacks.
	 * 
	 * <P>Note: this method will do nothing if the data is not sorted.
	 * 
	 * @param function the consumer of the data and the current sort context
	 */
	public void process(
			BiFunction<List<ROW_OBJECT>, TableSortingContext<ROW_OBJECT>, List<ROW_OBJECT>> function) {

		if (source != null) {
			source.process(function);
		}

		data = function.apply(data, sortContext);
	}

	/**
	 * Adds the new <tt>value</tt> to the data at the appropriate location based on the sort
	 * 
	 * @param value the row Object to insert
	 */
	public void insert(ROW_OBJECT value) {

		if (source != null) {
			// always update the master data
			source.insert(value);
		}

		if (!passesFilter(value)) {
			return; // this item is filtered out of this data
		}

		if (!isSorted()) {
			// Not yet sorted or intentionally unsorted; just add the item, it will get sorted later
			data.add(value);
			return;
		}

		Comparator<ROW_OBJECT> comparator = sortContext.getComparator();
		int index = Collections.binarySearch(data, value, comparator);
		if (index < 0) {
			// not yet in the collection--add it
			index = -index - 1;
			data.add(index, value);
			return;
		}

		// The search thinks the item is in the list because a compareTo() result of 0 was 
		// found.  If the two objects are not equal(), then add the new value.
		ROW_OBJECT existingValue = data.get(index);
		if (!Objects.equals(value, existingValue)) {
			data.add(index, value);
		}
	}

	private boolean passesFilter(ROW_OBJECT value) {
		if (tableFilter == null) {
			return true; // no filter means it passes!
		}
		return tableFilter.acceptsRow(value);
	}

	/**
	 * Starts at this data object and looks for a suitable dataset for the given filter.  If
	 * this dataset is filtered and the filter is a more general case of the given filter, then
	 * this dataset can be used for the given filter as a source of data.  If this dataset
	 * is not suitable as a filter starting point, then this dataset's parent will be checked.
	 * This operation will walk up the parent chain this way until the root dataset is reached.
	 * 
	 * @param filter the filter to check for compatibility with this dataset's filter
	 * @return the correct dataset to use as a starting point for further filtering operations; 
	 *         null if this dataset is not compatible with the given filter.
	 */
	TableData<ROW_OBJECT> getLowestLevelSourceDataForFilter(TableFilter<ROW_OBJECT> filter) {

		if (hasParentFilterOf(filter)) {
			return this; // my data is the correct start point for the given filter
		}

		// check my ancestry
		if (source == null) {
			return null;
		}

		TableData<ROW_OBJECT> parent = source.getLowestLevelSourceDataForFilter(filter);
		return parent;
	}

	/**
	 * Returns true if the this data object has a filter that is a suitable starting point
	 * for the given filter.
	 * 
	 * @param filter the filter to check for compatibility with this dataset's filter
	 * @return the correct dataset to use as a starting point for further filtering operations; 
	 *         null if this dataset is not compatible with the given filter.
	 */
	private boolean hasParentFilterOf(TableFilter<ROW_OBJECT> filter) {

		if (tableFilter == null) {
			return false; // no filter--can't be a sub-filter
		}

		if (filter == null) {
			return false; // no previous filter--can't be a sub-filter
		}

		boolean isSubFilter = filter.isSubFilterOf(tableFilter);
		return isSubFilter;
	}

	/**
	 * True if the filter of this data matched the given filter <b>and</b> the given source 
	 * data is the same as the source data of this data.
	 *  
	 * @param filter the table's current filter
	 * @return true if the source data nor the filter are different that what is used by this object.
	 */
	boolean matchesFilter(TableFilter<ROW_OBJECT> filter) {
		// O.K., we are derived from the same source data, if the filter is the same, then there
		// is no need to refilter.  
		// 
		// Note: if a given filter does not override equals(), then this really means that they 
		//       must be the same filter for this method to return true
		return SystemUtilities.isEqual(tableFilter, filter);
	}

	/**
	 * Returns false if the given data is this object or if it an ancestor of this.  
	 * 
	 * @param other the other object to check
	 * @return false if the given data is this object or if it an ancestor of this.
	 */
	boolean isUnrelatedTo(TableData<ROW_OBJECT> other) {
		if (other == null) {
			return source != null;
		}

		if (other.ID == ID) {
			return false; // we are the same data; we are related
		}

		if (source == null) {
			return true;
		}

		// see if our parent is the different
		return source.isUnrelatedTo(other);
	}

	/**
	 * Returns the ID of this table data.   It is possible that two data instances of this class
	 * that have the same ID are considered to be the same data.
	 * 
	 * @return the ID
	 */
	int getId() {
		return ID;
	}

	/**
	 * Returns the root dataset for this data and all its ancestors.
	 * @return the root dataset for this data and all its ancestors.
	 */
	TableData<ROW_OBJECT> getRootData() {
		if (source == null) {
			return this;
		}
		return source.getRootData();
	}

	@Override
	public Iterator<ROW_OBJECT> iterator() {
		return data.iterator();
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" + 
			"\tderived? " + (source != null) + ",\n" +
			"\tdata:\t" + data + "\n," + 
			"\tsort:\t" + (sortContext == null ? "" : sortContext.toString()) + ",\n" + 
		"}";
		//@formatter:on
	}

	@Override
	final public boolean equals(Object obj) {
		// Made final to ensure that nobody attempts to subclass this to check the contents 
		// of 'data', as that could be expensive.
		return super.equals(obj);
	}

	@Override
	final public int hashCode() {
		// Made final to match equals()
		return super.hashCode();
	}
}
