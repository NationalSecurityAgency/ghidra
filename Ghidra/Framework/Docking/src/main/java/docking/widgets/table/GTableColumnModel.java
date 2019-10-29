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

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.*;

import javax.swing.DefaultListSelectionModel;
import javax.swing.ListSelectionModel;
import javax.swing.event.*;
import javax.swing.table.*;

import org.jdom.Element;

import ghidra.docking.settings.Settings;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

public class GTableColumnModel
		implements TableColumnModel, PropertyChangeListener, ListSelectionListener {

	private VisibleColumns visibleColumns = new VisibleColumns();
	private List<TableColumn> completeList = new ArrayList<>();
	private int totalColumnWidth;
	private int columnMargin;
	private boolean columnSelectionAllowed;
	private ChangeEvent columnMarginChangeEvent = new ChangeEvent(this);

	private WeakSet<TableColumnModelListener> listeners =
		WeakDataStructureFactory.createSingleThreadAccessWeakSet();

	/** Model for keeping track of column selections */
	private GTable table;
	protected ListSelectionModel selectionModel;
	private TableColumnModelState columnModelState;

	GTableColumnModel(GTable table) {
		this.table = table;
		setSelectionModel(new DefaultListSelectionModel());
		setColumnMargin(1);
		invalidateWidthCache();
		setColumnSelectionAllowed(false);
		columnModelState = createTableColumnModelState();
	}

	protected TableColumnModelState createTableColumnModelState() {
		return new TableColumnModelState(table, this);
	}

	protected GTable getGTable() {
		return table;
	}

	void removeAllColumns() {

		fireColumnRemoved(new TableColumnModelEvent(this, 0, visibleColumns.size() - 1));
		visibleColumns.clear();

		// no need to fire the removed event for items in the complete list, as the clients
		// only know about the visible columns
		completeList.clear();

		invalidateWidthCache();
		columnModelState.saveState();
	}

	void dispose() {
		listeners.clear();
		visibleColumns.clear();
		completeList.clear();
		columnModelState.dispose();
	}

	/**
	 * Returns true if the given column is visible.
	 * @param column The column for which to check visibility.
	 * @return true if the given column is visible.
	 */
	public boolean isVisible(TableColumn column) {
		return visibleColumns.contains(column);
	}

	/**
	 * Returns true if the column at the given index is visible.  This call is handy when
	 * checking for visibility when dealing with model data that knows nothing about the
	 * hidden columns.
	 *
	 * @param modelIndex The column index for which to check visibility.  This is the model's
	 *                   index and <b>not the table's index</b>.
	 * @return true if the given column is visible.
	 */
	public boolean isVisible(int modelIndex) {
		TableColumn tableColumn = getColumnFromModelIndex(modelIndex);
		return isVisible(tableColumn);
	}

	public void setVisible(TableColumn column, boolean visible) {
		boolean isVisible = visibleColumns.contains(column);

		if (visible == isVisible) {
			return;
		}

		if (visible) {
			int insertIndex = findVisibleInsertionIndex(column);
			visibleColumns.add(insertIndex, column);
			fireColumnAdded(new TableColumnModelEvent(this, insertIndex, insertIndex));
		}
		else {
			int columnIndex = visibleColumns.indexOf(column);
			visibleColumns.remove(columnIndex);
			// Adjust for the selection
			if (selectionModel != null) {
				selectionModel.removeIndexInterval(columnIndex, columnIndex);
			}

			fireColumnRemoved(new TableColumnModelEvent(this, columnIndex, columnIndex));
		}
		invalidateWidthCache();

		columnModelState.saveState();
	}

	private int findVisibleInsertionIndex(TableColumn column) {
		int completeIndex = visibleColumns.indexOf(column);

		int size = visibleColumns.size();
		for (int i = completeIndex + 1; i < size; i++) {
			TableColumn nextColumn = completeList.get(i);
			int visibleIndex = visibleColumns.indexOf(nextColumn);
			if (visibleIndex != -1) {
				return visibleIndex;
			}
		}

		return size;
	}

	@Override
	public void addColumn(TableColumn aColumn) {
		if (aColumn == null) {
			throw new IllegalArgumentException("Object is null");
		}

		removeColumnWithModelIndex(aColumn.getModelIndex()); // dedup

		completeList.add(aColumn);
		visibleColumns.add(aColumn);

		aColumn.addPropertyChangeListener(this);

		invalidateWidthCache();

		// Post columnAdded event notification
		fireColumnAdded(new TableColumnModelEvent(this, 0, getColumnCount() - 1));
		columnModelState.restoreState();
	}

	/** Finds the table's column with the given model index */
	private TableColumn getColumnFromModelIndex(int modelIndex) {
		for (TableColumn tableColumn : completeList) {
			if (tableColumn.getModelIndex() == modelIndex) {
				return tableColumn;
			}
		}
		return null;
	}

	/**
	 * This method will make sure that there are no existing columns in this model's complete
	 * list of columns (visible and hidden) that have the same <b>table model</b> index as
	 * the given index.  This prevents duplicate columns from being added, since clients of this
	 * class do not know about hidden columns and may thus try to add a column that already
	 * exists, but is hidden.
	 * @param modelIndex The table model index of the column that should be removed
	 */
	private void removeColumnWithModelIndex(int modelIndex) {
		TableColumn tableColumn = getColumnFromModelIndex(modelIndex);
		if (tableColumn == null) {
			return;
		}

		completeList.remove(tableColumn);
		visibleColumns.remove(tableColumn);
		tableColumn.removePropertyChangeListener(this);
	}

	@Override
	public void addColumnModelListener(TableColumnModelListener listener) {
		listeners.add(listener);
	}

	@Override
	public TableColumn getColumn(int columnIndex) {
		if ((columnIndex < 0) || (columnIndex >= visibleColumns.size())) {
			return null;
		}
		return visibleColumns.get(columnIndex);
	}

	@Override
	public int getColumnCount() {
		return visibleColumns.size();
	}

	@Override
	public int getColumnIndex(Object columnIdentifier) {
		if (columnIdentifier == null) {
			throw new IllegalArgumentException("Identifier is null");
		}
		for (int i = 0; i < visibleColumns.size(); i++) {
			TableColumn tableColumn = visibleColumns.get(i);
			if (columnIdentifier.equals(tableColumn.getIdentifier())) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public int getColumnIndexAtX(int x) {
		if (x < 0) {
			return -1;
		}

		int cc = getColumnCount();
		int columnIndex = x;
		for (int i = 0; i < cc; i++) {
			TableColumn column = getColumn(i);
			columnIndex = columnIndex - column.getWidth();
			if (columnIndex < 0) {
				return i;
			}
		}
		return -1;
	}

	@Override
	public int getColumnMargin() {
		return columnMargin;
	}

	@Override
	public boolean getColumnSelectionAllowed() {
		return columnSelectionAllowed;
	}

	@Override
	public Enumeration<TableColumn> getColumns() {
		return visibleColumns.toEnumeration();
	}

	/**
	 * This returns all columns known by this model, both visible and not seen.
	 * @return all columns known by this model, both visible and not seen.
	 */
	public List<TableColumn> getAllColumns() {
		return new ArrayList<>(completeList);
	}

	@Override
	public int getSelectedColumnCount() {
		if (selectionModel != null) {
			int iMin = selectionModel.getMinSelectionIndex();
			int iMax = selectionModel.getMaxSelectionIndex();
			int count = 0;

			for (int i = iMin; i <= iMax; i++) {
				if (selectionModel.isSelectedIndex(i)) {
					count++;
				}
			}
			return count;
		}
		return 0;
	}

	@Override
	public int[] getSelectedColumns() {
		if (selectionModel != null) {
			int iMin = selectionModel.getMinSelectionIndex();
			int iMax = selectionModel.getMaxSelectionIndex();

			if ((iMin == -1) || (iMax == -1)) {
				return new int[0];
			}

			int[] tmp = new int[1 + (iMax - iMin)];
			int n = 0;
			for (int i = iMin; i <= iMax; i++) {
				if (selectionModel.isSelectedIndex(i)) {
					tmp[n++] = i;
				}
			}
			int[] selectedColumns = new int[n];
			System.arraycopy(tmp, 0, selectedColumns, 0, n);
			return selectedColumns;
		}
		return new int[0];
	}

	@Override
	public ListSelectionModel getSelectionModel() {
		return selectionModel;
	}

	@Override
	public int getTotalColumnWidth() {
		if (totalColumnWidth == -1) {
			recalcWidthCache();
		}
		return totalColumnWidth;
	}

	@Override
	public void moveColumn(int columnIndex, int newIndex) {
		if ((columnIndex < 0) || (columnIndex >= getColumnCount()) || (newIndex < 0) ||
			(newIndex >= getColumnCount())) {
			throw new IllegalArgumentException("moveColumn() - Index out of range");
		}

		// If the column has not yet moved far enough to change positions
		// post the event anyway, the "draggedDistance" property of the
		// tableHeader will say how far the column has been dragged.
		// Here we are really trying to get the best out of an
		// API that could do with some re-thinking. We preserve backward
		// compatibility by slightly bending the meaning of these methods.
		if (columnIndex == newIndex) {
			fireColumnMoved(new TableColumnModelEvent(this, columnIndex, newIndex));
			return;
		}

		// update the visible list
		TableColumn movedColumn = visibleColumns.remove(columnIndex);
		visibleColumns.add(newIndex, movedColumn);

		// update the complete list
		completeList.remove(movedColumn);
		if (columnIndex > newIndex) { // moving up in the list

			// get the item at the index after the new index (since we are moving up, we know
			// that there are columns below the new index)
			TableColumn column = visibleColumns.get(newIndex + 1);

			// find this column in the complete list and then place the moved column before that
			// position in the complete list
			int index = completeList.indexOf(column);
			completeList.add(index, movedColumn);
		}
		else { // moving down in the list

			// get the item at the index before the new index (since we are moving down, we know
			// that there are columns above the new index)
			TableColumn column = visibleColumns.get(newIndex - 1);

			// find this column in the complete list and then place the moved column after that
			// position in the complete list
			int index = completeList.indexOf(column);
			completeList.add(index + 1, movedColumn);
		}

		// update the selection model
		boolean selected = selectionModel.isSelectedIndex(columnIndex);
		selectionModel.removeIndexInterval(columnIndex, columnIndex);
		selectionModel.insertIndexInterval(newIndex, 1, true);
		if (selected) {
			selectionModel.addSelectionInterval(newIndex, newIndex);
		}
		else {
			selectionModel.removeSelectionInterval(newIndex, newIndex);
		}

		fireColumnMoved(new TableColumnModelEvent(this, columnIndex, newIndex));
		columnModelState.saveState();
	}

	@Override
	public void removeColumn(TableColumn column) {
		completeList.remove(column);

		int index = visibleColumns.indexOf(column);
		if (index >= 0) {
			visibleColumns.remove(index);
			// Adjust for the selection
			if (selectionModel != null) {
				selectionModel.removeIndexInterval(index, index);
			}

			fireColumnRemoved(new TableColumnModelEvent(this, index, index));
		}
		invalidateWidthCache();

		columnModelState.saveState();
	}

	@Override
	public void removeColumnModelListener(TableColumnModelListener listener) {
		listeners.remove(listener);
	}

	@Override
	public void setColumnMargin(int newMargin) {
		if (newMargin != columnMargin) {
			columnMargin = newMargin;
			// Post columnMarginChanged event notification.
			fireColumnMarginChanged();
		}
	}

	@Override
	public void setColumnSelectionAllowed(boolean flag) {
		columnSelectionAllowed = flag;
	}

	@Override
	public void setSelectionModel(ListSelectionModel newModel) {
		if (newModel == null) {
			throw new IllegalArgumentException("Cannot set a null SelectionModel");
		}

		ListSelectionModel oldModel = selectionModel;
		if (newModel != oldModel) {
			if (oldModel != null) {
				oldModel.removeListSelectionListener(this);
			}

			selectionModel = newModel;
			newModel.addListSelectionListener(this);
		}
	}

	/**
	 * Recalculates the total combined width of all columns.  Updates the
	 * <code>totalColumnWidth</code> property.
	 */
	private void recalcWidthCache() {
		totalColumnWidth = 0;
		for (TableColumn tableColumn : visibleColumns.getColumns()) {
			totalColumnWidth += tableColumn.getWidth();
		}
	}

	private void invalidateWidthCache() {
		totalColumnWidth = -1;
	}

	void restoreState(List<TableColumn> newCompleteList, List<Settings> newSettingsList,
			List<TableColumn> newVisibleList) {
		this.completeList = newCompleteList;
		this.visibleColumns = new VisibleColumns(newVisibleList);

		TableModel model = table.getModel();
		if (model instanceof ConfigurableColumnTableModel) {
			ConfigurableColumnTableModel configurableModel = (ConfigurableColumnTableModel) model;
			Settings[] columnIndexAndSettings = new Settings[newCompleteList.size()];
			for (int i = 0; i < columnIndexAndSettings.length; i++) {
				int modelIndex = newCompleteList.get(i).getModelIndex();
				columnIndexAndSettings[modelIndex] = newSettingsList.get(modelIndex);
			}
			configurableModel.setAllColumnSettings(columnIndexAndSettings);
		}

		// signal a change; we've added/removed columns, but we don't need to be specific
		TableColumnModelEvent e = new TableColumnModelEvent(this, 0, getColumnCount() - 1);
		fireColumnAdded(e);
	}

	void saveState() {
		columnModelState.saveState();
	}

	void restoreState() {
		columnModelState.restoreState();
	}

	boolean setEventsEnabled(boolean enabled) {
		boolean oldValue = columnModelState.isEnabled();
		if (oldValue == enabled) {
			return oldValue;
		}
		columnModelState.setEnabled(enabled);

		if (enabled) {
			columnModelState.restoreStateNow();
		}

		return oldValue;
	}

	/*
	 * A small class to provide a method to quickly see if a column is visible by calling contains
	 * on a hash set
	 */
	private class VisibleColumns {
		private Set<TableColumn> visibleSet = new HashSet<>();
		private List<TableColumn> visibleList = new ArrayList<>();

		public VisibleColumns() {
		}

		public VisibleColumns(List<TableColumn> newVisibleList) {
			this.visibleList = newVisibleList;
			visibleSet.addAll(visibleList);
		}

		List<TableColumn> getColumns() {
			return visibleList;
		}

		int size() {
			return visibleList.size();
		}

		public void remove(TableColumn column) {
			visibleList.remove(column);
			visibleSet.remove(column);
		}

		public void add(TableColumn column) {
			visibleList.add(column);
			visibleSet.add(column);
		}

		public Enumeration<TableColumn> toEnumeration() {
			return Collections.enumeration(visibleList);
		}

		public TableColumn get(int index) {
			return visibleList.get(index);
		}

		public int indexOf(TableColumn column) {
			return visibleList.indexOf(column);
		}

		public TableColumn remove(int index) {

			TableColumn column = visibleList.remove(index);
			visibleSet.remove(column);
			return column;
		}

		public void add(int insertIndex, TableColumn column) {
			visibleList.add(insertIndex, column);
			visibleSet.add(column);
		}

		void clear() {
			visibleList.clear();
			visibleSet.clear();
		}

		boolean contains(TableColumn c) {
			return visibleSet.contains(c);
		}
	}

//==================================================================================================
//  Listener and event methods
//==================================================================================================

	@Override
	public void propertyChange(PropertyChangeEvent evt) {
		String name = evt.getPropertyName();
		if ("width".equals(name) || "preferredWidth".equals(name)) {
			invalidateWidthCache();
			// This is a misnomer, we're using this method simply to cause a relayout
			fireColumnMarginChanged();
			columnModelState.saveState();
		}
	}

	@Override
	public void valueChanged(ListSelectionEvent e) {
		fireColumnSelectionChanged(e);
	}

	private void fireColumnAdded(TableColumnModelEvent e) {
		for (TableColumnModelListener listener : listeners) {
			listener.columnAdded(e);
		}
	}

	private void fireColumnRemoved(TableColumnModelEvent e) {
		for (TableColumnModelListener listener : listeners) {
			listener.columnRemoved(e);
		}
	}

	private void fireColumnSelectionChanged(ListSelectionEvent e) {
		for (TableColumnModelListener listener : listeners) {
			listener.columnSelectionChanged(e);
		}
	}

	private void fireColumnMoved(TableColumnModelEvent event) {
		for (TableColumnModelListener listener : listeners) {
			listener.columnMoved(event);
		}
	}

	private void fireColumnMarginChanged() {
		for (TableColumnModelListener listener : listeners) {
			listener.columnMarginChanged(columnMarginChangeEvent);
		}
	}

	public Element saveToXML() {
		return columnModelState.saveToXML();
	}

	public void restoreFromXML(Element element) {
		columnModelState.restoreFromXML(element);
	}

}
