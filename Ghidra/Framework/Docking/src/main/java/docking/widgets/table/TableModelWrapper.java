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

import java.util.ArrayList;
import java.util.List;

import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

/**
 * A wrapper that will take a table model and decorate it with filtering capability.  This is
 * only needed when the given model does not have filtering.
 *
 * @param <ROW_OBJECT> the row object type
 */
public class TableModelWrapper<ROW_OBJECT>
		implements RowObjectFilterModel<ROW_OBJECT>, SelectionStorage<ROW_OBJECT>,
		WrappingTableModel {

	// The index in the list is the view index; the Integer value at that index is the model index
	protected List<Integer> filteredIndexList;
	private TableFilter<ROW_OBJECT> tableFilter;

	private RowObjectTableModel<ROW_OBJECT> wrappedModel;
	private List<ROW_OBJECT> lastSelectedObjects = new ArrayList<>();

	private WeakSet<TableModelListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	public TableModelWrapper(RowObjectTableModel<ROW_OBJECT> wrappedModel) {
		this.wrappedModel = wrappedModel;

		SystemUtilities.assertTrue(!(wrappedModel instanceof WrappingTableModel),
			"Attempted to wrap a table model that has already been wrapped");

		filteredIndexList = getMatchingFilteredIndices();
		copyListeners();
	}

	@Override
	public String getName() {
		return wrappedModel.getName();
	}

	@Override
	public List<ROW_OBJECT> getLastSelectedObjects() {
		return lastSelectedObjects;
	}

	@Override
	public void setLastSelectedObjects(List<ROW_OBJECT> lastSelectedObjects) {
		this.lastSelectedObjects = lastSelectedObjects;
	}

	@Override
	public void setTableFilter(TableFilter<ROW_OBJECT> tableFilter) {
		this.tableFilter = tableFilter;
		updateModel();
	}

	@Override
	public TableFilter<ROW_OBJECT> getTableFilter() {
		return tableFilter;
	}

	@Override
	public int getModelRow(int viewRow) {
		if (!isFiltered()) {
			return viewRow;
		}
		return filteredIndexList.get(viewRow);
	}

	@Override
	public int getViewRow(int modelRow) {
		if (!isFiltered()) {
			return modelRow;
		}
		for (int i = 0; i < filteredIndexList.size(); i++) {
			Integer nextModelRow = filteredIndexList.get(i);
			if (nextModelRow == modelRow) {
				return i;
			}
		}
		return -1; // asking for a row that has been filtered out
	}

	@Override
	public void wrappedModelChangedFromTableChangedEvent() {
		// note: don't call notifyTableModelChanged(), as we get this callback during a
		// tableChanged() event and we do not want to trigger another event.
		updateFilterIndices();
	}

	@Override
	public void fireTableChanged(TableModelEvent event) {
		for (TableModelListener listener : listeners) {
			listener.tableChanged(event);
		}
	}

	@Override
	public void fireTableDataChanged() {
		TableModelEvent event = new TableModelEvent(this);
		for (TableModelListener listener : listeners) {
			listener.tableChanged(event);
		}
	}

	private void updateModel() {
		updateFilterIndices();

		// kickoff an update
		fireTableDataChanged();
	}

	private void copyListeners() {
		if (!(wrappedModel instanceof AbstractTableModel)) {
			Msg.warn(this, "Wrapping a table model that does not give access to listeners.  You " +
				"should change your base table model implement a known class");
			return;
		}

		AbstractTableModel abstractModel = (AbstractTableModel) wrappedModel;
		TableModelListener[] wrappedListeners =
			abstractModel.getListeners(TableModelListener.class);
		for (TableModelListener listener : wrappedListeners) {
			addTableModelListener(listener);
		}
	}

	private void updateFilterIndices() {
		filteredIndexList = getMatchingFilteredIndices();
	}

	private List<Integer> getMatchingFilteredIndices() {
		List<Integer> rowIndexList = new ArrayList<>();
		int rowCount = wrappedModel.getRowCount();

		for (int modelRow = 0; modelRow < rowCount; modelRow++) {
			if (filterAcceptsRow(modelRow)) {
				rowIndexList.add(modelRow);
			}
		}
		return rowIndexList;
	}

	private boolean filterAcceptsRow(int modelRow) {
		if (tableFilter == null) {
			return true;
		}

		ROW_OBJECT rowObject = wrappedModel.getRowObject(modelRow);
		boolean accepts = tableFilter.acceptsRow(rowObject);
		return accepts;
	}

	@Override
	public boolean isFiltered() {
		return filteredIndexList.size() != wrappedModel.getRowCount();
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
	public Class<?> getColumnClass(int columnIndex) {
		return wrappedModel.getColumnClass(columnIndex);
	}

	@Override
	public int getColumnCount() {
		return wrappedModel.getColumnCount();
	}

	@Override
	public String getColumnName(int columnIndex) {
		return wrappedModel.getColumnName(columnIndex);
	}

	@Override
	public int getRowCount() {
		if (!isFiltered()) {
			return wrappedModel.getRowCount();
		}

		return filteredIndexList.size();
	}

	@Override
	public int getUnfilteredRowCount() {
		return wrappedModel.getRowCount();
	}

	@Override
	public List<ROW_OBJECT> getUnfilteredData() {
		return wrappedModel.getModelData();
	}

	@Override
	public List<ROW_OBJECT> getModelData() {
		if (!isFiltered()) {
			return getUnfilteredData();
		}

		List<ROW_OBJECT> list = new ArrayList<>();
		int size = filteredIndexList.size();
		for (int row = 0; row < size; row++) {
			Integer modelRowIndex = filteredIndexList.get(row);
			list.add(wrappedModel.getRowObject(modelRowIndex));
		}
		return list;
	}

	@Override
	public int getModelIndex(ROW_OBJECT t) {
		return wrappedModel.getRowIndex(t);
	}

	@Override
	public int getViewIndex(ROW_OBJECT t) {
		int modelRow = wrappedModel.getRowIndex(t);
		if (!isFiltered()) {
			return modelRow;
		}

		int viewRow = getViewRow(modelRow);
		return viewRow;
	}

	@Override
	public int getRowIndex(ROW_OBJECT t) {
		return getModelIndex(t);
	}

	@Override
	public ROW_OBJECT getRowObject(int viewRow) {
		if (isFiltered()) {
			viewRow = filteredIndexList.get(viewRow);
		}

		return wrappedModel.getRowObject(viewRow);
	}

	@Override
	public Object getColumnValueForRow(ROW_OBJECT t, int columnIndex) {
		return wrappedModel.getColumnValueForRow(t, columnIndex);
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		if (!isFiltered()) {
			return wrappedModel.getValueAt(rowIndex, columnIndex);
		}

		Integer modelRowIndex = filteredIndexList.get(rowIndex);
		return wrappedModel.getValueAt(modelRowIndex, columnIndex);
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (!isFiltered()) {
			return wrappedModel.isCellEditable(rowIndex, columnIndex);
		}

		Integer modelRowIndex = filteredIndexList.get(rowIndex);
		return wrappedModel.isCellEditable(modelRowIndex, columnIndex);
	}

	@Override
	public void setValueAt(Object value, int rowIndex, int columnIndex) {
		if (!isFiltered()) {
			wrappedModel.setValueAt(value, rowIndex, columnIndex);
			return;
		}

		Integer modelRowIndex = filteredIndexList.get(rowIndex);
		wrappedModel.setValueAt(value, modelRowIndex, columnIndex);
	}

	@Override
	public TableModel getWrappedModel() {
		return wrappedModel;
	}
}
