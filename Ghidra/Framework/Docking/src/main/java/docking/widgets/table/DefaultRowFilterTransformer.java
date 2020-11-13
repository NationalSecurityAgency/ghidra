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

import javax.swing.table.TableColumnModel;

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

		return TableUtils.getTableCellStringValue(model, rowObject, column);
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
