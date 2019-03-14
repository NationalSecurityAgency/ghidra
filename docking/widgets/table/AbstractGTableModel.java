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

import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;

public abstract class AbstractGTableModel<T> extends AbstractTableModel
		implements RowObjectTableModel<T>, SelectionStorage<T> {

	public static final int WIDTH_UNDEFINED = -1;

	private List<T> lastSelectedObjects = new ArrayList<>();

	@Override
	public T getRowObject(int row) {
		List<T> data = getModelData();
		if (row < 0 || row >= data.size()) {
			return null;
		}
		return data.get(row);
	}

	@Override
	public int getRowIndex(T rowObject) {
		if (rowObject == null) {
			return -1;
		}

		return getIndexForRowObject(rowObject);
	}

	@Override
	public int getRowCount() {
		List<T> modelData = getModelData();
		if (modelData == null) {
			return 0;
		}
		return modelData.size();
	}

	/**
	 * Invoke this method when the underlying data has changed, but a reload is not required.
	 */
	public void refresh() {
		fireTableDataChanged();
	}

	@Override
	public List<T> getLastSelectedObjects() {
		return lastSelectedObjects;
	}

	@Override
	public void setLastSelectedObjects(List<T> lastSelectedObjects) {
		this.lastSelectedObjects = lastSelectedObjects;
	}

	public int getPreferredColumnWidth(int columnIndex) {
		return WIDTH_UNDEFINED;
	}

	/**
	 * The default implementation of {@link TableModel#getValueAt(int, int)} that calls the 
	 * abstract {@link #getColumnValueForRow(Object, int)}.
	 */
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		List<T> modelData = getModelData();

		if (rowIndex < 0 || rowIndex >= modelData.size()) {
			return null;
		}

		T t = modelData.get(rowIndex);
		return getColumnValueForRow(t, columnIndex);
	}

	/**
	 * A convenience method for subclasses to quickly/efficiently search for the index of a given
	 * row object <b>that is visible in the GUI</b>.  The <i>visible</i> limitation is due to the
	 * fact that the data searched is retrieved from {@link #getModelData()}, which may be 
	 * filtered.  
	 * <p>
	 * If a need for access to all of the data is required in the future, then an overloaded 
	 * version of this method should be created that takes the data to be searched.
	 * 
	 * @param rowObject The object for which to search.
	 * @return the index of the item in the data returned by 
	 */
	protected int getIndexForRowObject(T rowObject) {
		return getIndexForRowObject(rowObject, getModelData());
	}

	protected int getIndexForRowObject(T rowObject, List<T> data) {
		return data.indexOf(rowObject);
	}

	/**
	 * Call this when the model will no longer be used
	 */
	public void dispose() {
		// subclass to override and call super
		lastSelectedObjects.clear();
		getModelData().clear();
	}
}
