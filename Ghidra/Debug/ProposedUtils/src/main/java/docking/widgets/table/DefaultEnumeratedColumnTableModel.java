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
import java.util.function.Predicate;

import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.DefaultEnumeratedColumnTableModel.EnumeratedTableColumn;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;

/**
 * A table model whose columns are described using an {@link Enum}.
 *
 * <p>
 * See the callers to this class' constructor to find example uses.
 *
 * @param <C> the type of the enum
 * @param <R> the type of rows
 */
public class DefaultEnumeratedColumnTableModel<C extends Enum<C> & EnumeratedTableColumn<C, R>, R>
		extends GDynamicColumnTableModel<R, Void> implements EnumeratedColumnTableModel<R> {
	// NOTE: If I need to track indices, addSortListener
	/**
	 * An interface on enums used to describe table columns
	 *
	 * @param <C> the type of the enum
	 * @param <R> the type of rows
	 */
	public static interface EnumeratedTableColumn<C extends Enum<C>, R> {
		/**
		 * Get the value class of cells in this column
		 * 
		 * @return the class
		 */
		public Class<?> getValueClass();

		/**
		 * Get the value of this column for the given row
		 * 
		 * @param row the row
		 * @return the value
		 */
		public Object getValueOf(R row);

		/**
		 * Get the name of this column
		 * 
		 * @return the name
		 */
		public String getHeader();

		/**
		 * Get the value of this column for the given row
		 * 
		 * @param row the row
		 * @param value the new value
		 */
		default public void setValueOf(R row, Object value) {
			throw new UnsupportedOperationException("Cell is not editable");
		}

		/**
		 * Check if this column can be modified for the given row
		 * 
		 * @param row the row
		 * @return true if editable
		 */
		default public boolean isEditable(R row) {
			return false;
		}

		/**
		 * Check if this column can be sorted
		 * 
		 * <p>
		 * TODO: Either this should be implemented as ported to {@link GDynamicColumnTableModel}, or
		 * removed.
		 * 
		 * @return true if sortable
		 */
		default public boolean isSortable() {
			return true;
		}

		/**
		 * Get the default sort direction for this column
		 * 
		 * @return the sort direction
		 */
		default public SortDirection defaultSortDirection() {
			return SortDirection.ASCENDING;
		}
	}

	private final List<R> modelData = new ArrayList<>();
	private final String name;
	private final C[] cols;

	public DefaultEnumeratedColumnTableModel(PluginTool tool, String name, Class<C> colType) {
		super(tool);
		this.name = name;
		this.cols = colType.getEnumConstants();

		reloadColumns(); // Smell
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public List<R> getModelData() {
		return modelData;
	}

	static class EnumeratedDynamicTableColumn<R>
			extends AbstractDynamicTableColumn<R, Object, Void>
			implements EditableDynamicTableColumn<R, Object, Void> {
		private final EnumeratedTableColumn<?, R> col;

		public EnumeratedDynamicTableColumn(EnumeratedTableColumn<?, R> col) {
			this.col = col;
		}

		@Override
		public String getColumnName() {
			return col.getHeader();
		}

		@Override
		public Object getValue(R rowObject, Settings settings, Void data,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return col.getValueOf(rowObject);
		}

		@Override
		@SuppressWarnings("unchecked")
		public Class<Object> getColumnClass() {
			return (Class<Object>) col.getValueClass();
		}

		@Override
		public boolean isEditable(R row, Settings settings, Void dataSource,
				ServiceProvider serviceProvider) {
			return col.isEditable(row);
		}

		@Override
		public void setValueOf(R row, Object value, Settings settings, Void dataSource,
				ServiceProvider serviceProvider) {
			col.setValueOf(row, value);
		}
	}

	@Override
	protected TableColumnDescriptor<R> createTableColumnDescriptor() {
		TableColumnDescriptor<R> descriptor = new TableColumnDescriptor<>();
		if (cols != null) { // Smells
			List<C> defaultOrder = defaultSortOrder();
			for (C col : cols) {
				descriptor.addVisibleColumn(
					new EnumeratedDynamicTableColumn<R>(col),
					defaultOrder.indexOf(col), // -1 means not found, not sorted
					col.defaultSortDirection().isAscending());
			}
		}
		return descriptor;
	}

	@Override
	public Void getDataSource() {
		return null;
	}

	/**
	 * Get the default sort order of the table
	 * 
	 * @return the list of columns in order of descending priority
	 */
	public List<C> defaultSortOrder() {
		return Collections.emptyList();
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		DynamicTableColumn<R, ?, ?> column = tableColumns.get(columnIndex);
		if (!(column instanceof EditableDynamicTableColumn)) {
			return; // TODO: throw?
		}
		@SuppressWarnings("unchecked") // tableColumns doesn't include DATA_SOURCE
		// May cause ClassCastException if given value can't be cast. Good.
		EditableDynamicTableColumn<R, Object, Void> editable =
			(EditableDynamicTableColumn<R, Object, Void>) column;
		synchronized (modelData) {
			if (rowIndex < 0 || rowIndex >= modelData.size()) {
				return; // TODO: throw?
			}
			R row = modelData.get(rowIndex);
			editable.setValueOf(row, aValue, columnSettings.get(column), getDataSource(),
				serviceProvider);
		}
		fireTableCellUpdated(rowIndex, columnIndex);
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		DynamicTableColumn<R, ?, ?> column = tableColumns.get(columnIndex);
		if (!(column instanceof EditableDynamicTableColumn)) {
			return false;
		}
		@SuppressWarnings("unchecked") // tableColumns doesn't include DATA_SOURCE
		EditableDynamicTableColumn<R, ?, Void> editable =
			(EditableDynamicTableColumn<R, ?, Void>) column;
		synchronized (modelData) {
			if (rowIndex < 0 || rowIndex >= modelData.size()) {
				return false;
			}
			R row = modelData.get(rowIndex);
			return editable.isEditable(row, columnSettings.get(column), getDataSource(),
				serviceProvider);
		}
	}

	@Override
	public void add(R row) {
		int rowIndex;
		synchronized (modelData) {
			rowIndex = modelData.size();
			modelData.add(row);
		}
		fireTableRowsInserted(rowIndex, rowIndex);
	}

	@Override
	public void addAll(Collection<R> c) {
		int startIndex;
		int endIndex;
		synchronized (modelData) {
			startIndex = modelData.size();
			modelData.addAll(c);
			endIndex = modelData.size() - 1;
		}
		fireTableRowsInserted(startIndex, endIndex);
	}

	@Override
	public void notifyUpdated(R row) {
		int rowIndex;
		synchronized (modelData) {
			rowIndex = modelData.indexOf(row);
		}
		fireTableRowsUpdated(rowIndex, rowIndex);
	}

	@Override
	public List<R> notifyUpdatedWith(Predicate<R> predicate) {
		int lastIndexUpdated = 0;
		List<R> updated = new ArrayList<>();
		ListIterator<R> rit = modelData.listIterator();
		synchronized (modelData) {
			while (rit.hasNext()) {
				R row = rit.next();
				if (predicate.test(row)) {
					lastIndexUpdated = rit.previousIndex();
					updated.add(row);
				}
			}
		}
		int size = updated.size();
		if (size == 0) {
		}
		else if (size == 1) {
			fireTableRowsUpdated(lastIndexUpdated, lastIndexUpdated);
		}
		else {
			fireTableDataChanged();
		}
		return updated;
	}

	@Override
	public void delete(R row) {
		int rowIndex;
		synchronized (modelData) {
			rowIndex = modelData.indexOf(row);
			if (rowIndex == -1) {
				return;
			}
			modelData.remove(rowIndex);
		}
		fireTableRowsDeleted(rowIndex, rowIndex);
	}

	@Override
	public List<R> deleteWith(Predicate<R> predicate) {
		int lastIndexRemoved = 0;
		List<R> removed = new ArrayList<>();
		synchronized (modelData) {
			ListIterator<R> rit = modelData.listIterator();
			while (rit.hasNext()) {
				R row = rit.next();
				if (predicate.test(row)) {
					lastIndexRemoved = rit.previousIndex();
					rit.remove();
					removed.add(row);
				}
			}
		}
		int size = removed.size();
		if (size == 0) {
		}
		else if (size == 1) {
			fireTableRowsDeleted(lastIndexRemoved, lastIndexRemoved);
		}
		else {
			fireTableDataChanged();
		}
		return removed;
	}

	@Override
	public R findFirst(Predicate<R> predicate) {
		synchronized (modelData) {
			for (R row : modelData) {
				if (predicate.test(row)) {
					return row;
				}
			}
			return null;
		}
	}

	@Override
	public void clear() {
		synchronized (modelData) {
			modelData.clear();
		}
		fireTableDataChanged();
	}

	@Override
	protected void sort(List<R> data, TableSortingContext<R> sortingContext) {
		synchronized (data) {
			super.sort(data, sortingContext);
		}
	}
}
