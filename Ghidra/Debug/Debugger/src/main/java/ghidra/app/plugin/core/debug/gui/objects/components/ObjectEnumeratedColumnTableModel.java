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
package ghidra.app.plugin.core.debug.gui.objects.components;

import java.util.*;
import java.util.function.Predicate;

import javax.swing.SwingUtilities;
import javax.swing.event.TableModelEvent;

import docking.widgets.table.AbstractSortedTableModel;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.EnumeratedColumnTableModel;
import ghidra.app.plugin.core.debug.gui.objects.components.ObjectEnumeratedColumnTableModel.ObjectsEnumeratedTableColumn;

public class ObjectEnumeratedColumnTableModel<C extends ObjectsEnumeratedTableColumn<C, ? super R>, R>
		extends AbstractSortedTableModel<R> implements EnumeratedColumnTableModel<R> {

	// NOTE: If I need to track indices, addSortListener
	public static interface ObjectsEnumeratedTableColumn<C, R> {
		public Object getValueOf(R row);

		public String getHeader();

		default public void setValueOf(R row, Object value) {
			throw new UnsupportedOperationException("Cell is not editable");
		}

		default public boolean isEditable(R row) {
			return false;
		}

		default public boolean isSortable() {
			return true;
		}

		default public SortDirection defaultSortDirection() {
			return SortDirection.ASCENDING;
		}
	}

	public class TableRowIterator implements RowIterator<R> {
		protected final ListIterator<R> it = modelData.listIterator();
		protected int index;

		@Override
		public boolean hasNext() {
			return it.hasNext();
		}

		@Override
		public R next() {
			index = it.nextIndex();
			return it.next();
		}

		@Override
		public boolean hasPrevious() {
			return it.hasPrevious();
		}

		@Override
		public R previous() {
			index = it.previousIndex();
			return it.previous();
		}

		@Override
		public int nextIndex() {
			return it.nextIndex();
		}

		@Override
		public int previousIndex() {
			return it.previousIndex();
		}

		@Override
		public void remove() {
			it.remove();
			fireTableRowsDeleted(index, index);
		}

		@Override
		public void set(R e) {
			it.set(e);
			fireTableRowsUpdated(index, index);
		}

		@Override
		public void notifyUpdated() {
			fireTableRowsUpdated(index, index);
		}

		@Override
		public void add(R e) {
			it.add(e);
			int nextIndex = it.nextIndex();
			fireTableRowsInserted(nextIndex, nextIndex);
		}
	}

	private final List<R> modelData = new ArrayList<>();
	private final String name;
	private C[] cols;

	public ObjectEnumeratedColumnTableModel(String name, C[] cols) {
		this.name = name;
		this.cols = cols;
	}

	public void setColumns(C[] cols) {
		this.cols = cols;
		fireTableStructureChanged();
	}

	@Override
	public String getName() {
		return name;
	}

	@Override
	public List<R> getModelData() {
		return modelData;
	}

	public List<C> defaultSortOrder() {
		return Collections.emptyList();
	}

	@Override
	public int getRowCount() {
		return modelData.size();
	}

	@Override
	public int getColumnCount() {
		return cols.length;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		if (rowIndex >= modelData.size()) {
			return "";
		}
		return getColumnValueForRow(modelData.get(rowIndex), columnIndex);
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		R row = modelData.get(rowIndex);
		C col = cols[columnIndex];
		Class<?> cls = String.class;
		col.setValueOf(row, cls.cast(aValue));
		fireTableCellUpdated(rowIndex, columnIndex);
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		R row = modelData.get(rowIndex);
		C col = cols[columnIndex];
		return col.isEditable(row);
	}

	@Override
	public boolean isSortable(int columnIndex) {
		C col = cols[columnIndex];
		return col.isSortable();
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return String.class;
	}

	@Override
	public String getColumnName(int column) {
		return cols[column].getHeader();
	}

	@Override
	public Object getColumnValueForRow(R t, int columnIndex) {
		if (columnIndex >= cols.length) {
			return "";
		}
		return cols[columnIndex].getValueOf(t);
	}

	@Override
	public void add(R row) {
		int rowIndex = modelData.size();
		modelData.add(row);
		fireTableRowsInserted(rowIndex, rowIndex);
	}

	@Override
	public void addAll(Collection<R> c) {
		int startIndex = modelData.size();
		modelData.addAll(c);
		int endIndex = modelData.size() - 1;
		fireTableRowsInserted(startIndex, endIndex);
	}

	@Override
	public void notifyUpdated(R row) {
		int rowIndex = modelData.indexOf(row);
		fireTableRowsUpdated(rowIndex, rowIndex);
	}

	@Override
	public List<R> notifyUpdatedWith(Predicate<R> predicate) {
		int lastIndexUpdated = 0;
		ListIterator<R> rit = modelData.listIterator();
		List<R> updated = new ArrayList<>();
		while (rit.hasNext()) {
			R row = rit.next();
			if (predicate.test(row)) {
				lastIndexUpdated = rit.previousIndex();
				updated.add(row);
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
		int rowIndex = modelData.indexOf(row);
		modelData.remove(rowIndex);
		fireTableRowsDeleted(rowIndex, rowIndex);
	}

	@Override
	public List<R> deleteWith(Predicate<R> predicate) {
		int lastIndexRemoved = 0;
		ListIterator<R> rit = modelData.listIterator();
		List<R> removed = new ArrayList<>();
		while (rit.hasNext()) {
			R row = rit.next();
			if (predicate.test(row)) {
				lastIndexRemoved = rit.previousIndex();
				rit.remove();
				removed.add(row);
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
		for (R row : modelData) {
			if (predicate.test(row)) {
				return row;
			}
		}
		return null;
	}

	@Override
	public void clear() {
		modelData.clear();
		fireTableDataChanged();
	}

	public R getRow(int index) {
		return modelData.get(index);
	}

	public void updateColumns(ObjectElementRow x) {
		List<String> keys = x.getKeys();
		cols = (C[]) ObjectElementColumn.generateColumns(keys);
	}

	@Override
	public void fireTableChanged(TableModelEvent e) {
		if (SwingUtilities.isEventDispatchThread()) {
			super.fireTableChanged(e);
			return;
		}
		final TableModelEvent e1 = e;
		SwingUtilities.invokeLater(() -> super.fireTableChanged(e1));
	}

}
