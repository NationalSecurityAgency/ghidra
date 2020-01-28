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

import java.awt.Rectangle;

import javax.swing.JLabel;
import javax.swing.table.TableCellRenderer;

import docking.widgets.AutoLookup;

/**
 * {@link AutoLookup} implementation for {@link GTable}s
 */
public class GTableAutoLookup extends AutoLookup {

	private GTable table;

	public GTableAutoLookup(GTable table) {
		this.table = table;
	}

	@Override
	public int getCurrentRow() {
		return table.getSelectedRow();
	}

	@Override
	public int getRowCount() {
		return table.getRowCount();
	}

	@Override
	public String getValueString(int row, int col) {
		TableCellRenderer renderer = table.getCellRenderer(row, col);
		if (renderer instanceof JLabel) {
			table.prepareRenderer(renderer, row, col);
			return ((JLabel) renderer).getText();
		}

		Object obj = table.getValueAt(row, col);
		return obj == null ? null : obj.toString();
	}

	private boolean isSortableTableModel() {
		return table.getModel() instanceof SortedTableModel;
	}

	@Override
	public boolean isSorted(int column) {
		if (!isSortableTableModel()) {
			return false;
		}

		SortedTableModel sortedModel = (SortedTableModel) table.getModel();
		return column == sortedModel.getPrimarySortColumnIndex();
	}

	@Override
	public boolean isSortedAscending() {
		if (!isSortableTableModel()) {
			return false;
		}

		SortedTableModel model = (SortedTableModel) table.getModel();
		int primarySortColumnIndex = model.getPrimarySortColumnIndex();
		TableSortState columnSortState = model.getTableSortState();
		ColumnSortState sortState = columnSortState.getColumnSortState(primarySortColumnIndex);
		return sortState.isAscending();
	}

	@Override
	public void matchFound(int row) {
		table.setRowSelectionInterval(row, row);
		Rectangle rect = table.getCellRect(row, 0, false);
		table.scrollRectToVisible(rect);
	}
}
