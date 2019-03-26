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
package docking.widgets.table.columnfilter;

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;

import docking.widgets.table.RowObjectTableModel;

/**
 * Table model used by {@link ColumnTableFilterTest}
 */
class TestTableModel implements RowObjectTableModel<Integer> {

	private List<ColumnTestData<?>> columns = new ArrayList<>();
	private int rowCount = 0;

	private List<TableModelListener> listeners = new ArrayList<>();

	public <T> void addColumn(String name, T[] columnValues) {
		columns.add(new ColumnTestData<>(name, columnValues));
		rowCount = Math.max(rowCount, columnValues.length);
	}

	public void removeColumn(String name) {
		for (ColumnTestData<?> c : columns) {
			if (name.equals(c.getName())) {
				columns.remove(c);
				break;
			}
		}
		fireTableDataChanged();
	}

	@Override
	public int getRowCount() {
		return rowCount;
	}

	@Override
	public String getName() {
		return "Test Model";
	}

	@Override
	public int getColumnCount() {
		return columns.size();
	}

	@Override
	public String getColumnName(int columnIndex) {
		return columns.get(columnIndex).getName();
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return columns.get(columnIndex).getValue(0).getClass();
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		ColumnTestData<?> columnData = columns.get(columnIndex);
		return columnData.getValue(rowIndex);
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		// unsupported
	}

	@Override
	public void addTableModelListener(TableModelListener l) {
		listeners.add(l);
	}

	@Override
	public void removeTableModelListener(TableModelListener l) {
		listeners.remove(l);
	}

	@Override
	public Integer getRowObject(int viewRow) {
		return viewRow;
	}

	@Override
	public int getRowIndex(Integer t) {
		return t;
	}

	@Override
	public List<Integer> getModelData() {
		List<Integer> rowObjects = new ArrayList<>();
		for (int i = 0; i < getColumnCount(); i++) {
			rowObjects.add(i);
		}
		return rowObjects;
	}

	@Override
	public Object getColumnValueForRow(Integer t, int columnIndex) {
		return getValueAt(t, columnIndex);
	}

	@Override
	public void fireTableDataChanged() {
		TableModelEvent event = new TableModelEvent(this);
		for (TableModelListener listener : listeners) {
			listener.tableChanged(event);
		}
	}

	static class ColumnTestData<T> {
		private String name;
		private T[] values;

		public ColumnTestData(String name, T[] columnValues) {
			this.name = name;
			this.values = columnValues;
		}

		public String getName() {
			return name;
		}

		public T getValue(int index) {
			if (index < values.length) {
				return values[index];
			}
			return null;
		}
	}

}
