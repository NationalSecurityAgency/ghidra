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
package ghidra.util.table;

import java.util.List;

import javax.swing.JTable;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

import docking.widgets.table.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;

/**
 * This is a "program aware" version of GTableFilterPanel
 * @param <ROW_OBJECT> the row type
 */
public class GhidraTableFilterPanel<ROW_OBJECT> extends GTableFilterPanel<ROW_OBJECT> {

	/**
	 * Creates a table filter panel that filters the contents of the given table.
	 *
	 * @param table The table whose contents will be filtered.
	 * @param tableModel The table model used by the table--passed in by the type that we require
	 */
	public GhidraTableFilterPanel(JTable table, RowObjectTableModel<ROW_OBJECT> tableModel) {
		super(table, tableModel);
	}

	public GhidraTableFilterPanel(JTable table, RowObjectTableModel<ROW_OBJECT> tableModel,
			String filterLabel) {
		super(table, tableModel, filterLabel);
	}

	@Override // overridden because of our knowledge of program table models
	protected RowObjectFilterModel<ROW_OBJECT> createTextFilterModel(
			RowObjectTableModel<ROW_OBJECT> clientModel) {

		RowObjectFilterModel<ROW_OBJECT> filterModel = super.createTextFilterModel(clientModel);
		if (!(clientModel instanceof ProgramTableModel)) {
			return filterModel; // nothing to do
		}

		if (filterModel instanceof ProgramTableModel) {
			// the model is already filterable and a ProgramTableModel (e.g., a ThreadedTableModel)
			return filterModel;
		}

		return new FilterModelToProgramModelAdapter(filterModel, (ProgramTableModel) clientModel);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	/**
	 * A class to adapt a table model that can filter into a {@link ProgramTableModel}.
	 */
	private class FilterModelToProgramModelAdapter
			implements RowObjectFilterModel<ROW_OBJECT>, ProgramTableModel, WrappingTableModel {

		private final RowObjectFilterModel<ROW_OBJECT> filterModel;
		private final ProgramTableModel programModel;

		private FilterModelToProgramModelAdapter(RowObjectFilterModel<ROW_OBJECT> tableModel,
				ProgramTableModel programModel) {
			this.filterModel = tableModel;
			this.programModel = programModel;
		}

		@Override
		public String getName() {
			return filterModel.getName();
		}

		@Override
		public void fireTableChanged(TableModelEvent event) {
			if (filterModel instanceof WrappingTableModel) {
				((WrappingTableModel) filterModel).fireTableChanged(event);
			}
		}

		@Override
		public void wrappedModelChangedFromTableChangedEvent() {
			if (filterModel instanceof WrappingTableModel) {
				((WrappingTableModel) filterModel).wrappedModelChangedFromTableChangedEvent();
			}
		}

		@Override
		public ROW_OBJECT getRowObject(int row) {
			return filterModel.getRowObject(row);
		}

		@Override
		public List<ROW_OBJECT> getModelData() {
			return filterModel.getModelData();
		}

		@Override
		public int getModelRow(int viewRow) {
			return filterModel.getModelRow(viewRow);
		}

		@Override
		public int getRowIndex(ROW_OBJECT t) {
			return filterModel.getRowIndex(t);
		}

		@Override
		public int getViewIndex(ROW_OBJECT t) {
			return filterModel.getViewIndex(t);
		}

		@Override
		public int getModelIndex(ROW_OBJECT t) {
			return filterModel.getModelIndex(t);
		}

		@Override
		public int getUnfilteredRowCount() {
			return filterModel.getUnfilteredRowCount();
		}

		@Override
		public int getViewRow(int modelRow) {
			return filterModel.getViewRow(modelRow);
		}

		@Override
		public boolean isFiltered() {
			return filterModel.isFiltered();
		}

		@Override
		public void setTableFilter(TableFilter<ROW_OBJECT> tableFilter) {
			filterModel.setTableFilter(tableFilter);
		}

		@Override
		public TableFilter<ROW_OBJECT> getTableFilter() {
			return filterModel.getTableFilter();
		}

		@Override
		public void fireTableDataChanged() {
			filterModel.fireTableDataChanged();
		}

		@Override
		public void addTableModelListener(TableModelListener l) {
			filterModel.addTableModelListener(l);
		}

		@Override
		public void removeTableModelListener(TableModelListener l) {
			filterModel.removeTableModelListener(l);
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return filterModel.getColumnClass(columnIndex);
		}

		@Override
		public int getColumnCount() {
			return filterModel.getColumnCount();
		}

		@Override
		public String getColumnName(int columnIndex) {
			return filterModel.getColumnName(columnIndex);
		}

		@Override
		public int getRowCount() {
			return filterModel.getRowCount();
		}

		@Override
		public List<ROW_OBJECT> getUnfilteredData() {
			return filterModel.getUnfilteredData();
		}

		@Override
		public Object getColumnValueForRow(ROW_OBJECT t, int columnIndex) {
			return filterModel.getColumnValueForRow(t, columnIndex);
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			return filterModel.getValueAt(rowIndex, columnIndex);
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return filterModel.isCellEditable(rowIndex, columnIndex);
		}

		@Override
		public void setValueAt(Object value, int rowIndex, int columnIndex) {
			filterModel.setValueAt(value, rowIndex, columnIndex);
		}

		@Override
		public TableModel getWrappedModel() {
			return filterModel;
		}

		@Override
		public Program getProgram() {
			return programModel.getProgram();
		}

		@Override
		public ProgramLocation getProgramLocation(int row, int column) {
			// Note: the given row is the filtered row index
			int unfilteredRow = getModelRow(row);
			return programModel.getProgramLocation(unfilteredRow, column);
		}

		@Override
		public ProgramSelection getProgramSelection(int[] rows) {
			// Note: the given rows are the filtered row indexes
			int[] unfilteredRows = new int[rows.length];
			for (int i = 0; i < rows.length; i++) {
				unfilteredRows[i] = getModelRow(rows[i]);
			}
			return programModel.getProgramSelection(unfilteredRows);
		}
	}

}
