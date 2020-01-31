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
package docking.widgets.table.constraint.dialog;

import java.util.*;

import javax.swing.event.*;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;

import docking.widgets.table.GDynamicColumnTableModel;
import docking.widgets.table.RowObjectFilterModel;
import docking.widgets.table.columnfilter.*;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * This class is for constructing and editing {@link ColumnBasedTableFilter}. It is used by the
 * {@link ColumnFilterDialog} and exists primarily to make testing easier.
 *
 * @param <R> the row type for the table
 */
public class ColumnFilterDialogModel<R> {

	private RowObjectFilterModel<R> tableModel;

	private List<ColumnFilterData<?>> allFilters = new ArrayList<>();
	private List<DialogFilterRow> filterRows = new ArrayList<>();

	private WeakSet<TableFilterDialogModelListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	private TableColumnModel columnModel;
	private TableColumnModelListener columnModelListener = new MyTableColumnModelListener();

	private ColumnBasedTableFilter<R> currentFilter;
	private ColumnBasedTableFilter<R> defaultFilter;

	/**
	 * Constructs a new ColumnFilterModel
	 *
	 * @param model the RowObjectFilterModel of the table being filtered.
	 * @param columnModel the TableColumnModel of the table being filtered.
	 * @param currentColumnTableFilter the currently applied TableColumnFilter or null if there is
	 * no current TableColumnFilter applied.
	 */
	public ColumnFilterDialogModel(RowObjectFilterModel<R> model, TableColumnModel columnModel,
			ColumnBasedTableFilter<R> currentColumnTableFilter) {
		this.tableModel = model;
		this.columnModel = columnModel;
		this.currentFilter = currentColumnTableFilter;
		columnModel.addColumnModelListener(columnModelListener);
		allFilters = getAllColumnFilterData(model, columnModel);

		addEntriesFromCurrentTableFilter(currentColumnTableFilter);

		// If there is no filter, populate with a default row to help the user get started
		if (filterRows.isEmpty()) {
			createFilterRow(LogicOperation.AND);
			// set the defaultFilter so that we can tell if the current filter is not really
			// something the user configured.
			defaultFilter = getTableColumnFilter();
		}
	}

	public static <R> List<ColumnFilterData<?>> getAllColumnFilterData(
			RowObjectFilterModel<R> model,
			TableColumnModel columnModel) {
		List<ColumnFilterData<?>> filters = new ArrayList<>();
		int columnCount = columnModel.getColumnCount();
		for (int viewIndex = 0; viewIndex < columnCount; viewIndex++) {
			int modelIndex = columnModel.getColumn(viewIndex).getModelIndex();
			Class<?> columnClass = model.getColumnClass(modelIndex);
			ColumnFilterData<?> columnData =
				createColumnFilterData(model, modelIndex, viewIndex, columnClass);
			if (columnData.isFilterable()) {
				filters.add(columnData);
			}
		}
		return filters;
	}

	/**
	 * clean up.
	 */
	public void dispose() {
		columnModel.removeColumnModelListener(columnModelListener);
	}

	/**
	 * Creates a new filter row (a new major row in the dialog filter panel)
	 * @param logicOperation the logical operation for how this row interacts with preceding rows 
	 * @return the new filter row that represents a major row in the dialog filter panel
	 */
	public DialogFilterRow createFilterRow(LogicOperation logicOperation) {

		DialogFilterRow filterRow = new DialogFilterRow(this, logicOperation);
		filterRows.add(filterRow);
		notifyFilterChanged();
		return filterRow;
	}

	/**
	 * Deletes a filter row (a major row in the dialog filter panel)
	 *
	 * @param filterRow the row to delete.
	 */
	public void deleteFilterRow(DialogFilterRow filterRow) {
		filterRows.remove(filterRow);
		notifyFilterChanged();
	}

	/**
	 * Returns a list of all filter rows in this model.
	 *
	 * @return  a list of all filter rows in this model.
	 */
	public List<DialogFilterRow> getFilterRows() {
		return filterRows;
	}

	/**
	 * Adds a listener to be notified for various changes that occur in this filter model.
	 *
	 * @param listener the listener to add.
	 */
	public void addListener(TableFilterDialogModelListener listener) {
		this.listeners.add(listener);
	}

	/**
	 * Removes the given listener.
	 *
	 * @param listener the listener to remove.
	 */
	public void removeListener(TableFilterDialogModelListener listener) {
		this.listeners.remove(listener);
	}

	/**
	 * Checks if this model represents a valid filter. While editing, some elements of the filter
	 * may be incomplete or invalid and if so, then this method will return false.
	 * @return true if the model represents a valid filter.
	 */
	public boolean isValid() {
		for (DialogFilterRow filterRow : filterRows) {
			if (!filterRow.hasValidFilterValue()) {
				return false;
			}
		}
		return true;
	}

	/**
	 * Callback from a DialogFilterRow to indicate that the structure of the filter row changed.  This includes
	 * changing the column, or adding, deleting, changing filter conditions.
	 *
	 * @param filterRow the DialogFilterRow that changed.
	 */
	void dialogFilterRowChanged(DialogFilterRow filterRow) {
		notifyFilterChanged();
	}

	/**
	 * Callback from a FilterRow to indicate that the user has change a value in one of the editors
	 * which may change the validity state of the model.
	 *
	 * @param editor the editor whose value has been changed.
	 */
	void editorValueChanged(ColumnConstraintEditor<?> editor) {
		for (TableFilterDialogModelListener listener : listeners) {
			listener.editorValueChanged(editor);
		}
	}

	/**
	 * Gets the table's DataSource (if it has one. Only table models that extends 
	 * {@link GDynamicColumnTableModel} can have a data source
	 * 
	 * @return the data source
	 */
	Object getDataSource() {
		if (tableModel instanceof GDynamicColumnTableModel) {
			return ((GDynamicColumnTableModel<?, ?>) tableModel).getDataSource();
		}
		return null;
	}

	/**
	 * Builds a ColumnTableFilter from this model if the model is valid.
	 *
	 * @return a new ColumnTableFilter based on the configuration of this model or null if the model
	 * is invalid.
	 */
	public ColumnBasedTableFilter<R> getTableColumnFilter() {
		if (!isValid()) {
			return null;
		}
		if (filterRows.isEmpty()) {
			return null;
		}
		ColumnBasedTableFilter<R> tableColumnFilter = new ColumnBasedTableFilter<>(tableModel);
		for (DialogFilterRow filterRow : filterRows) {
			filterRow.addToTableFilter(tableColumnFilter);
		}
		if (tableColumnFilter.isEquivalent(currentFilter)) {
			return currentFilter;
		}
		return tableColumnFilter;
	}

	/**
	 * Changes the configuration of this model to match the given ColumnTableFilter.  Any exiting
	 * filter configurations will be cleared.
	 *
	 * @param filter the ColumnTableFilter for which to model.
	 */
	void setFilter(ColumnBasedTableFilter<R> filter) {
		filterRows.clear();
		addEntriesFromCurrentTableFilter(filter);
		currentFilter = filter;
		notifyFilterChanged();
	}

	/**
	 * Clears the model of all filters.
	 */
	public void clear() {
		List<DialogFilterRow> temp = new ArrayList<>(filterRows);
		for (DialogFilterRow filterRow : temp) {
			deleteFilterRow(filterRow);
		}
	}

	/**
	 * Returns a list of the columnFilterData for all filterable columns in the table
	 * @return  a list of the columnFilterData for all filterable columns in the table
	 */
	public List<ColumnFilterData<?>> getAllColumnFilterData() {
		return allFilters;
	}

	/**
	 * Return true if there are no conditions (valid or invalid) defined for this filter model.
	 * @return  true if there are no conditions (valid or invalid) defined for this filter model.
	 */
	public boolean isEmpty() {
		return filterRows.isEmpty();
	}

	/**
	 * Returns true if this model has changes that make the filter different from the currently
	 * applied filter.
	 * @return if there are unapplied user changes to the filter.
	 */
	public boolean hasUnappliedChanges() {
		ColumnBasedTableFilter<R> tableColumnFilter = getTableColumnFilter();
		if (tableColumnFilter == null) {
			return currentFilter != null;
		}
		if (tableColumnFilter.isEquivalent(defaultFilter)) {
			return false;   // this prevents the default filter from prompting for unapplied changes
		}
		return !tableColumnFilter.isEquivalent(currentFilter);
	}

	RowObjectFilterModel<?> getTableModel() {
		return tableModel;
	}

	private static <R> ColumnFilterData<?> createColumnFilterData(
			RowObjectFilterModel<R> tableModel, int modelIndex, int viewIndex,
			Class<?> columnClass) {
		return new ColumnFilterData<>(tableModel, modelIndex, viewIndex, columnClass);
	}

	private void addEntriesFromCurrentTableFilter(ColumnBasedTableFilter<R> columnTableFilter) {
		if (columnTableFilter == null) {
			return;
		}

		List<ColumnConstraintSet<R, ?>> columnFilters = columnTableFilter.getConstraintSets();
		for (ColumnConstraintSet<R, ?> columnFilter : columnFilters) {
			if (hasColumnFilterData(columnFilter)) {
				DialogFilterRow filterRow = new DialogFilterRow(this, columnFilter);
				filterRows.add(filterRow);
			}
		}
	}

	private boolean hasColumnFilterData(ColumnConstraintSet<R, ?> columnFilter) {
		ColumnFilterData<?> data =
			getColumnFilterDataByModelIndex(columnFilter.getColumnModelIndex());
		return data != null;
	}

	private ColumnFilterData<?> getColumnFilterDataByModelIndex(int columnModelIndex) {
		for (ColumnFilterData<?> columnFilterData : allFilters) {
			if (columnFilterData.getColumnModelIndex() == columnModelIndex) {
				return columnFilterData;
			}
		}
		return null;
	}

	private ColumnFilterData<?> getColumnFilterDataByViewIndex(int viewIndex) {
		for (ColumnFilterData<?> columnFilterData : allFilters) {
			if (columnFilterData.getViewIndex() == viewIndex) {
				return columnFilterData;
			}
		}
		return null;
	}

	private DialogFilterRow getFilterRowForColumnData(ColumnFilterData<?> columnFilterData) {
		for (DialogFilterRow filterRow : filterRows) {
			if (filterRow.getColumnFilterData().equals(columnFilterData)) {
				return filterRow;
			}
		}
		return null;
	}

	private void notifyFilterChanged() {
		for (TableFilterDialogModelListener listener : listeners) {
			listener.structureChanged();
		}
	}

	private void updateColumnViewIndices() {
		for (int viewIndex = 0; viewIndex < columnModel.getColumnCount(); viewIndex++) {
			TableColumn column = columnModel.getColumn(viewIndex);
			int modelIndex = column.getModelIndex();
			ColumnFilterData<?> columnFilterData = getColumnFilterDataByModelIndex(modelIndex);
			if (columnFilterData != null) {
				columnFilterData.setViewIndex(viewIndex);
			}
		}
		Collections.sort(allFilters, (o1, o2) -> o1.getViewIndex() - o2.getViewIndex());
	}

	public void setCurrentlyAppliedFilter(ColumnBasedTableFilter<R> tableColumnFilter) {
		currentFilter = tableColumnFilter;
	}

	/**
	 * A listener for changes to the column structure of the table being filtered.  The ColumnFilterModel
	 * must adjust for these changes as follows:
	 * <ol>
	 * <li> Table column removed - any filters for that column must be deleted. </li>
	 * <li> Table column added - the list of columns that the user can filter must be updated. </li>
	 * <li> Table column moved - the model must update its mappings of view indexes to model indexes </li>
	 * </ol>
	 */
	private class MyTableColumnModelListener implements TableColumnModelListener {

		@Override
		public void columnAdded(TableColumnModelEvent e) {
			int viewIndex = e.getToIndex();
			TableColumn column = columnModel.getColumn(viewIndex);
			int modelIndex = column.getModelIndex();
			Class<?> columnClass = tableModel.getColumnClass(modelIndex);
			ColumnFilterData<?> columnFilterData =
				createColumnFilterData(tableModel, modelIndex, viewIndex, columnClass);
			if (columnFilterData.isFilterable()) {
				allFilters.add(columnFilterData);
			}
			updateColumnViewIndices();
			notifyFilterChanged();
		}

		@Override
		public void columnRemoved(TableColumnModelEvent e) {
			int viewIndex = e.getFromIndex();
			ColumnFilterData<?> columnFilterData = getColumnFilterDataByViewIndex(viewIndex);
			allFilters.remove(columnFilterData);
			DialogFilterRow filterRow = getFilterRowForColumnData(columnFilterData);
			if (filterRow != null) {
				deleteFilterRow(filterRow);
			}
			updateColumnViewIndices();
			notifyFilterChanged();
		}

		@Override
		public void columnMoved(TableColumnModelEvent e) {
			if (e.getFromIndex() == e.getToIndex()) {
				return;
			}
			updateColumnViewIndices();
			notifyFilterChanged();
		}

		@Override
		public void columnMarginChanged(ChangeEvent e) {
			// don't care
		}

		@Override
		public void columnSelectionChanged(ListSelectionEvent e) {
			// don't care
		}

	}

}
