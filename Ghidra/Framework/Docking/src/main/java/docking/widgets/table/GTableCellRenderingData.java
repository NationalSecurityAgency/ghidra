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

import java.lang.ref.WeakReference;

import javax.swing.JTable;

import ghidra.docking.settings.Settings;
import ghidra.docking.settings.SettingsImpl;

/**
 * A state object to provide a table cell renderer with data beyond the standard Java 
 * {@link javax.swing.table.TableCellRenderer} interface.
 * <p>
 * Additional data about the context of a rendering operation -- like the columns' Settings 
 * or the row-object -- are easily passed to the renderer without refactor of each client.
 *
 */
public class GTableCellRenderingData {

	/* 
	 *  Fields inherited from the TableCellRenderer.getTableCellRendererComponent() method
	 */
	private final WeakReference<JTable> jTableRef;
	private int columnViewIndex;

	private int rowViewIndex;
	private Object value;

	private boolean isSelected;
	private boolean hasFocus;

	/*
	 * Fields are extensions, provided for convenience
	 */
	private final WeakReference<Settings> columnSettingsRef;
	private WeakReference<Object> rowObjectRef;

	/**
	 * Create a data object for a specific column in a table
	 * @param jTable Reference to the associated JTable
	 * @param column View index of this column
	 * @param columnSettings Settings state provided and used by this column
	 */
	public GTableCellRenderingData(JTable jTable, int column, Settings columnSettings) {
		this.jTableRef = new WeakReference<>(jTable);
		this.columnViewIndex = column;

		this.columnSettingsRef = new WeakReference<>(columnSettings);

		resetRowData();
	}

	/**
	 * Create a new data object from this data, changing only the cells' value object.
	 * 
	 * <p>This method is a convenience for use by renderers that wish to change the value 
	 * passed to them.
	 * 
	 * @param newValue New cell value object
	 * @return A new data object with the same state as this object
	 */
	public GTableCellRenderingData copyWithNewValue(Object newValue) {

		GTableCellRenderingData newData =
			new GTableCellRenderingData(getTable(), getColumnViewIndex(), getColumnSettings());

		newData.setRowData(getRowViewIndex(), getRowObject());
		newData.setCellData(newValue, columnViewIndex, isSelected(), hasFocus());

		return newData;
	}

	/**
	 * Set data specific to a row, as used during the rendering phase
	 * @param row View row index
	 * @param rowObject Object for which this table row is generated
	 */
	public void setRowData(int row, Object rowObject) {
		this.rowViewIndex = row;
		this.rowObjectRef = new WeakReference<>(rowObject);
	}

	/**
	 * Set data specific to a cell, as used during the rendering phase
	 * @param value The models' value at row-column
	 * @param column the view column index
	 * @param isSelected True if the cell is to be rendered with the 
	 * selection highlighted; otherwise false
	 * @param hasFocus This cell has the users' focus
	 */
	public void setCellData(Object value, int column, boolean isSelected, boolean hasFocus) {
		this.value = value;
		this.columnViewIndex = column;
		this.isSelected = isSelected;
		this.hasFocus = hasFocus;
	}

	/**
	 * Clear the row state
	 * @see #setRowData(int, Object)
	 */
	void resetRowData() {
		setRowData(this.rowViewIndex, null);
		setCellData(null, columnViewIndex, isSelected, hasFocus);
	}

	public JTable getTable() {
		return jTableRef.get();
	}

	public int getColumnViewIndex() {
		return columnViewIndex;
	}

	public int getColumnModelIndex() {
		return getTable().convertColumnIndexToModel(columnViewIndex);
	}

	public Settings getColumnSettings() {
		Settings s = columnSettingsRef.get();
		if (s == null) {
			s = SettingsImpl.NO_SETTINGS;
		}
		return s;
	}

	public int getRowViewIndex() {
		return rowViewIndex;
	}

	public int getRowModelIndex() {
		return getTable().convertRowIndexToModel(rowViewIndex);
	}

	public Object getValue() {
		return value;
	}

	public Object getRowObject() {
		return rowObjectRef.get();
	}

	public boolean isSelected() {
		return isSelected;
	}

	public boolean hasFocus() {
		return hasFocus;
	}

	@Override
	public String toString() {

		return "[" + this.getClass().getSimpleName() + ":" +
			getTable().getModel().getClass().getSimpleName() + ":" + getColumnViewIndex() + ":" +
			getColumnSettings() + "]";
	}

}
