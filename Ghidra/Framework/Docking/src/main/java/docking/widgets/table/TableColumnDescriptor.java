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
import java.util.function.Function;

import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.util.Msg;

public class TableColumnDescriptor<ROW_TYPE> {
	private List<TableColumnInfo> columns = new ArrayList<>();

	public List<DynamicTableColumn<ROW_TYPE, ?, ?>> getAllColumns() {
		List<DynamicTableColumn<ROW_TYPE, ?, ?>> list = new ArrayList<>();
		for (TableColumnInfo info : columns) {
			list.add(info.column);
		}
		return list;
	}

	public List<DynamicTableColumn<ROW_TYPE, ?, ?>> getDefaultVisibleColumns() {
		List<DynamicTableColumn<ROW_TYPE, ?, ?>> list = new ArrayList<>();
		for (TableColumnInfo info : columns) {
			if (info.isVisible) {
				list.add(info.column);
			}
		}
		return list;
	}

	public TableSortState getDefaultTableSortState(DynamicColumnTableModel<ROW_TYPE> model) {
		TableSortStateEditor editor = new TableSortStateEditor();

		List<TableColumnInfo> sortedColumns = new ArrayList<>(columns);
		Collections.sort(sortedColumns);

		for (TableColumnInfo info : sortedColumns) {
			if (info.sortIndex == -1) {
				continue;
			}
			int columnIndex = model.getColumnIndex(info.column);
			editor.addSortedColumn(columnIndex);
			if (!info.ascending) {
				editor.flipColumnSortDirection(columnIndex);
			}
		}

		return editor.createTableSortState();
	}

	public void setVisible(String columnName, boolean visible) {
		TableColumnInfo info = getColumn(columnName);
		if (info == null) {
			Msg.debug(this,
				"Unable to change visibility state of column '%s'".formatted(columnName));
			return;
		}
		if (visible) {
			info.isVisible = true;
		}
		else {
			// remove and add a new info to clear any sort state info for a hidden column
			int index = columns.indexOf(info);
			columns.set(index, new TableColumnInfo(info.column));
		}
	}

	private TableColumnInfo getColumn(String name) {
		for (TableColumnInfo info : columns) {
			String columnName = info.column.getColumnName();
			if (columnName.equals(name)) {
				return info;
			}
		}
		return null;
	}

	public void addHiddenColumn(DynamicTableColumn<ROW_TYPE, ?, ?> column) {
		columns.add(new TableColumnInfo(column));
	}

	public void addVisibleColumn(DynamicTableColumn<ROW_TYPE, ?, ?> column) {
		addVisibleColumn(column, -1, true);
	}

	/**
	 * @param column the column to add
	 * @param sortOrdinal the <b>ordinal (i.e., 1, 2, 3...n)</b>, not the index (i.e, 0, 1, 2...n).
	 * @param ascending true to sort ascending
	 */
	public void addVisibleColumn(DynamicTableColumn<ROW_TYPE, ?, ?> column, int sortOrdinal,
			boolean ascending) {

		columns.add(new TableColumnInfo(column, true, sortOrdinal, ascending));
	}

	/**
	 * Adds a column to the descriptor via an anonymous accessor function instead.
	 * <P>
	 * If you would like to control the sorting behavior of your column, then use 
	 * {@link #addVisibleColumn(String, Class, Function, int, boolean)}.
	 * <P>
	 * Note: any columns created via this method will not be discoverable by other tables.  To use
	 * that feature, you must create a separate column class that extends 
	 * {@link DynamicTableColumnExtensionPoint}.
	 * 
	 * @param name the column name, visible in the UI
	 * @param columnTypeClass the column class type
	 * @param rowToColumnFunction a function to convert a row object to the column object
	 * @param <COLUMN_TYPE> the column type
	 */
	public <COLUMN_TYPE> void addVisibleColumn(String name, Class<COLUMN_TYPE> columnTypeClass,
			Function<ROW_TYPE, COLUMN_TYPE> rowToColumnFunction) {
		addVisibleColumn(name, columnTypeClass, rowToColumnFunction, -1, true);
	}

	/**
	 * Adds a column to the descriptor via an anonymous accessor function instead.
	 * <P>
	 * Note: any columns created via this method will not be discoverable by other tables.  To use
	 * that feature, you must create a separate column class that extends 
	 * {@link DynamicTableColumnExtensionPoint}.
	 *
	 * @param name the column name, visible in the UI
	 * @param columnTypeClass the column class type
	 * @param rowToColumnFunction a function to convert a row object to the column object
	 * @param sortOrdinal the <b>ordinal (i.e., 1, 2, 3...n)</b>, not the index (i.e, 0, 1, 2...n)
	 * @param ascending true for sort ascending; false for descending
	 * @param <COLUMN_TYPE> the column type
	 */
	public <COLUMN_TYPE> void addVisibleColumn(String name, Class<COLUMN_TYPE> columnTypeClass,
			Function<ROW_TYPE, COLUMN_TYPE> rowToColumnFunction, int sortOrdinal,
			boolean ascending) {

		AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Object> column =
			createColumnStub(name, columnTypeClass, rowToColumnFunction);
		addVisibleColumn(column, sortOrdinal, ascending);
	}

	/**
	 * Adds a column to the descriptor via an anonymous accessor function instead.  The column added
	 * will not be displayed until enabled by the user.
	 * <P>
	 * Note: any columns created via this method will not be discoverable by other tables.  To use
	 * that feature, you must create a separate column class that extends 
	 * {@link DynamicTableColumnExtensionPoint}.
	 * 
	 * @param name the column name, visible in the UI
	 * @param columnTypeClass the column class type
	 * @param rowToColumnFunction a function to convert a row object to the column object
	 * @param <COLUMN_TYPE> the column type
	 */
	public <COLUMN_TYPE> void addHiddenColumn(String name, Class<COLUMN_TYPE> columnTypeClass,
			Function<ROW_TYPE, COLUMN_TYPE> rowToColumnFunction) {

		AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Object> column =
			createColumnStub(name, columnTypeClass, rowToColumnFunction);
		addHiddenColumn(column);
	}

	private <COLUMN_TYPE> AbstractDynamicTableColumn<ROW_TYPE, COLUMN_TYPE, Object> createColumnStub(
			String name, Class<COLUMN_TYPE> columnTypeClass,
			Function<ROW_TYPE, COLUMN_TYPE> rowToColumnFunction) {

		return new AbstractDynamicTableColumn<>() {
			@Override
			public String getColumnName() {
				return name;
			}

			@Override
			public COLUMN_TYPE getValue(ROW_TYPE rowObject, Settings settings, Object data,
					ServiceProvider serviceProvider) throws IllegalArgumentException {
				return rowToColumnFunction.apply(rowObject);
			}

			@Override
			public Class<COLUMN_TYPE> getColumnClass() {
				return columnTypeClass;
			}

			@Override
			public Class<ROW_TYPE> getSupportedRowType() {
				// returning null means this column will not be available to use in other tables
				return null;
			}
		};
	}

	private class TableColumnInfo implements Comparable<TableColumnInfo> {
		private DynamicTableColumn<ROW_TYPE, ?, ?> column;
		private boolean isVisible = false;
		private int sortIndex = -1;
		private boolean ascending = true;

		TableColumnInfo(DynamicTableColumn<ROW_TYPE, ?, ?> column) {
			this.column = column;
		}

		TableColumnInfo(DynamicTableColumn<ROW_TYPE, ?, ?> column, boolean isVisible, int sortIndex,
				boolean ascending) {
			this.column = column;
			this.isVisible = isVisible;
			this.sortIndex = sortIndex;
			this.ascending = ascending;
		}

		@Override
		public int compareTo(TableColumnInfo o) {
			return sortIndex - o.sortIndex;
		}
	}
}
