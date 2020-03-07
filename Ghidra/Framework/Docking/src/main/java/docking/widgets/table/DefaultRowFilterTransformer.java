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

import javax.swing.JLabel;
import javax.swing.table.TableColumnModel;

import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.column.GColumnRenderer.ColumnConstraintFilterMode;

public class DefaultRowFilterTransformer<ROW_OBJECT> implements RowFilterTransformer<ROW_OBJECT> {

	private List<String> columnData = new ArrayList<>();
	private TableColumnModel columnModel;
	private final RowObjectTableModel<ROW_OBJECT> model;

	public DefaultRowFilterTransformer(RowObjectTableModel<ROW_OBJECT> tableModel,
			TableColumnModel columnModel) {
		this.model = tableModel;
		this.columnModel = columnModel;
	}

	@Override
	public List<String> transform(ROW_OBJECT rowObject) {
		columnData.clear();
		int columnCount = model.getColumnCount();
		for (int col = 0; col < columnCount; col++) {
			String value = getStringValue(rowObject, col);
			if (value != null) {
				columnData.add(value);
			}
		}
		return columnData;
	}

	protected String getStringValue(ROW_OBJECT rowObject, int column) {
		// we have to account for 'magic' hidden columns
		if (columnModel instanceof GTableColumnModel) {
			if (!((GTableColumnModel) columnModel).isVisible(column)) {
				return null;
			}
		}

		if (columnUsesConstraintFilteringOnly(column)) {
			// This allows columns to be ignored for default text filtering while still being
			// filterable through the column constraints API
			return null;
		}

		// note: this call can be slow when columns dynamically calculate values from the database
		Object value = model.getColumnValueForRow(rowObject, column);
		if (value == null) {
			return null;
		}

		/*
		 	Methods for turning the cell value into a string to be filtered (in preference order):
		 		1) Use the dynamic column's renderer (if applicable), as this is the most
		 		   direct way for clients to specify the filter value
		 		2) See if the value is an instance of DisplayStringProvider, which describes how
		 		   it should be rendered
		 		3) See if it is a label (this is uncommon)
		 		4) Rely on the toString(); this works as intended for Strings.  This is the 
		 		   default way that built-in table cell renderers will generate display text
		 */

		// 1)
		String renderedString = getRenderedColumnValue(value, column);
		if (renderedString != null) {
			return renderedString;
		}

		// 2) special plug-in point where clients can specify a value object that can return 
		// its display string
		if (value instanceof DisplayStringProvider) {
			return ((DisplayStringProvider) value).toString();
		}

		// 3
		if (value instanceof JLabel) { // some models do this odd thing
			JLabel label = (JLabel) value;
			String valueString = label.getText();
			return valueString == null ? "" : valueString;
		}

		// 4)
		return value.toString();
	}

	private boolean columnUsesConstraintFilteringOnly(int column) {
		if (!(model instanceof DynamicColumnTableModel)) {
			return false;
		}

		DynamicColumnTableModel<ROW_OBJECT> columnBasedModel =
			(DynamicColumnTableModel<ROW_OBJECT>) model;
		GColumnRenderer<Object> renderer = getColumnRenderer(columnBasedModel, column);
		if (renderer == null) {
			return false;
		}

		ColumnConstraintFilterMode mode = renderer.getColumnConstraintFilterMode();
		return mode == ColumnConstraintFilterMode.ALLOW_CONSTRAINTS_FILTER_ONLY;
	}

	private String getRenderedColumnValue(Object columnValue, int columnIndex) {

		if (!(model instanceof DynamicColumnTableModel)) {
			return null;
		}

		DynamicColumnTableModel<ROW_OBJECT> columnBasedModel =
			(DynamicColumnTableModel<ROW_OBJECT>) model;
		GColumnRenderer<Object> renderer = getColumnRenderer(columnBasedModel, columnIndex);
		if (renderer == null) {
			return null;
		}

		Settings settings = columnBasedModel.getColumnSettings(columnIndex);
		String s = renderer.getFilterString(columnValue, settings);
		return s;
	}

	private GColumnRenderer<Object> getColumnRenderer(
			DynamicColumnTableModel<ROW_OBJECT> columnBasedModel, int columnIndex) {
		DynamicTableColumn<ROW_OBJECT, ?, ?> column = columnBasedModel.getColumn(columnIndex);
		@SuppressWarnings("unchecked")
		GColumnRenderer<Object> columnRenderer =
			(GColumnRenderer<Object>) column.getColumnRenderer();
		return columnRenderer;
	}

	@Override
	public int hashCode() {
		// not meant to put in hashing structures; the data for equals may change over time
		throw new UnsupportedOperationException();
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}

		DefaultRowFilterTransformer<?> other = (DefaultRowFilterTransformer<?>) obj;
		if (!Objects.equals(columnData, other.columnData)) {
			return false;
		}

		if (!Objects.equals(columnModel, other.columnModel)) {
			return false;
		}

		// use '==' so that we don't end up comparing all table data
		if (model != other.model) {
			return false;
		}
		return true;
	}
}
