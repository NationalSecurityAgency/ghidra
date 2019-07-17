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

import java.util.ArrayList;
import java.util.List;

import javax.swing.JTable;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
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

	@Override
	// overridden because of our knowledge of threaded models and program table models
	protected RowObjectFilterModel<ROW_OBJECT> createTextFilterModel(
			RowObjectTableModel<ROW_OBJECT> model) {

		// NOTE: order is important here, since ThreadedTableModels can also be sorted table
		// models.  We want to handle those first!
		RowObjectFilterModel<ROW_OBJECT> newModel = super.createTextFilterModel(model);
		if (newModel instanceof ThreadedTableModel<?, ?>) {
			// we don't wrap Threaded models, as they can do their own filtering
			return newModel;
		}

		// Next, see if we need to create a wrapper to handle ProgramTableModel implementations
		if (!(model instanceof ProgramTableModel)) {
			return newModel; // nope, the given model is not a ProgramTableModel; no new 
		}

		return new ProgramTableModelWrapperWrapper(newModel, newModel);
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class ProgramTableModelWrapperWrapper
			implements RowObjectFilterModel<ROW_OBJECT>, ProgramTableModel {

		private final RowObjectFilterModel<ROW_OBJECT> wrappedFilterModel;
		private final RowObjectFilterModel<ROW_OBJECT> wrappedTableModel;

		private ProgramTableModelWrapperWrapper(RowObjectFilterModel<ROW_OBJECT> tableModel,
				RowObjectFilterModel<ROW_OBJECT> filterModel) {
			this.wrappedTableModel = tableModel;
			this.wrappedFilterModel = filterModel;
		}

		@Override
		public String getName() {
			return wrappedTableModel.getName();
		}

		@Override
		public ROW_OBJECT getRowObject(int row) {
			return wrappedTableModel.getRowObject(row);
		}

		@Override
		public List<ROW_OBJECT> getModelData() {
			return wrappedTableModel.getModelData();
		}

		@Override
		public int getModelRow(int viewRow) {
			return wrappedFilterModel.getModelRow(viewRow);
		}

		@Override
		public int getRowIndex(ROW_OBJECT t) {
			return wrappedFilterModel.getRowIndex(t);
		}

		@Override
		public int getViewIndex(ROW_OBJECT t) {
			return wrappedFilterModel.getViewIndex(t);
		}

		@Override
		public int getModelIndex(ROW_OBJECT t) {
			return wrappedFilterModel.getModelIndex(t);
		}

		@Override
		public int getUnfilteredRowCount() {
			return wrappedFilterModel.getUnfilteredRowCount();
		}

		@Override
		public int getViewRow(int modelRow) {
			return wrappedFilterModel.getViewRow(modelRow);
		}

		@Override
		public boolean isFiltered() {
			return wrappedFilterModel.isFiltered();
		}

		@Override
		public void setTableFilter(TableFilter<ROW_OBJECT> tableFilter) {
			wrappedFilterModel.setTableFilter(tableFilter);
		}

		@Override
		public TableFilter<ROW_OBJECT> getTableFilter() {
			return wrappedFilterModel.getTableFilter();
		}

		@Override
		public void fireTableDataChanged() {
			wrappedTableModel.fireTableDataChanged();
		}

		@Override
		public void addTableModelListener(TableModelListener l) {
			wrappedTableModel.addTableModelListener(l);
		}

		@Override
		public void removeTableModelListener(TableModelListener l) {
			wrappedTableModel.removeTableModelListener(l);
		}

		@Override
		public Class<?> getColumnClass(int columnIndex) {
			return wrappedTableModel.getColumnClass(columnIndex);
		}

		@Override
		public int getColumnCount() {
			return wrappedTableModel.getColumnCount();
		}

		@Override
		public String getColumnName(int columnIndex) {
			return wrappedTableModel.getColumnName(columnIndex);
		}

		@Override
		public int getRowCount() {
			return wrappedTableModel.getRowCount();
		}

		@Override
		public List<ROW_OBJECT> getUnfilteredData() {
			List<ROW_OBJECT> list = new ArrayList<>();
			int rowCount = getUnfilteredRowCount();
			for (int i = 0; i < rowCount; i++) {
				list.add(wrappedTableModel.getRowObject(i));
			}
			return list;
		}

		@Override
		public Object getColumnValueForRow(ROW_OBJECT t, int columnIndex) {
			return wrappedTableModel.getColumnValueForRow(t, columnIndex);
		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex) {
			return wrappedTableModel.getValueAt(rowIndex, columnIndex);
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex) {
			return wrappedTableModel.isCellEditable(rowIndex, columnIndex);
		}

		@Override
		public void setValueAt(Object value, int rowIndex, int columnIndex) {
			wrappedTableModel.setValueAt(value, rowIndex, columnIndex);
		}

		private TableModel getBaseTableModel() {
			if (wrappedTableModel instanceof TableModelWrapper<?>) {
				TableModelWrapper<ROW_OBJECT> tableModelWrapper =
					(TableModelWrapper<ROW_OBJECT>) wrappedTableModel;
				return tableModelWrapper.getWrappedModel();
			}
			return wrappedTableModel;
		}

		private ProgramTableModel getProgramTableModel() {
			TableModel baseTableModel = getBaseTableModel();
			if (baseTableModel instanceof ProgramTableModel) {
				return (ProgramTableModel) baseTableModel;
			}
			return null;
		}

		@Override
		public Program getProgram() {
			ProgramTableModel programTableModel = getProgramTableModel();
			if (programTableModel != null) {
				return programTableModel.getProgram();
			}
			return null;
		}

		@Override
		public ProgramLocation getProgramLocation(int row, int column) {
			ProgramTableModel programTableModel = getProgramTableModel();
			if (programTableModel != null) {
				return programTableModel.getProgramLocation(row, column);
			}
			return null;
		}

		@Override
		public ProgramSelection getProgramSelection(int[] rows) {
			ProgramTableModel programTableModel = getProgramTableModel();
			if (programTableModel != null) {
				return programTableModel.getProgramSelection(rows);
			}
			return null;
		}
	}

}
