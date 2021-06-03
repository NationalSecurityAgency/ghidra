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

import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.table.*;

import ghidra.docking.settings.Settings;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.column.GColumnRenderer.ColumnConstraintFilterMode;

/**
 * A utility class for JTables used in Ghidra.
 */
public class TableUtils {

	/**
	 * Uses the given row-based table model, row object and column index to determine what the
	 * String value should be for that cell.
	 * 
	 * <P>This is used to provide a means for filtering on the text that is displayed to the user.
	 * 
	 * @param <ROW_OBJECT> The model's row object type
	 * @param model the model
	 * @param rowObject the row object for the row being queried
	 * @param column the column index <b>in the table model</b> 
	 * @return the string value; null if no value can be fabricated
	 */
	public static <ROW_OBJECT> String getTableCellStringValue(RowObjectTableModel<ROW_OBJECT> model,
			ROW_OBJECT rowObject,
			int column) {

		// note: this call can be slow when columns dynamically calculate values from the database
		Object value = model.getColumnValueForRow(rowObject, column);
		if (value == null) {
			return null;
		}

		/*
		 	Methods for turning the cell value into the display value (in preference order):
		 		1) Use the dynamic column's renderer (if applicable), as this is the most
		 		   direct way for clients to specify the display value
		 		2) See if the value is an instance of DisplayStringProvider, which describes how
		 		   it should be rendered
		 		3) See if it is a label (this is uncommon)
		 		4) Rely on the toString(); this works as intended for Strings.  This is the 
		 		   default way that built-in table cell renderers will generate display text
		 */

		// 1)
		String renderedString = getRenderedColumnValue(model, value, column);
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

	private static <ROW_OBJECT> String getRenderedColumnValue(RowObjectTableModel<ROW_OBJECT> model,
			Object columnValue, int columnIndex) {

		if (!(model instanceof DynamicColumnTableModel)) {
			return null;
		}

		DynamicColumnTableModel<ROW_OBJECT> columnBasedModel =
			(DynamicColumnTableModel<ROW_OBJECT>) model;
		GColumnRenderer<Object> renderer = getColumnRenderer(columnBasedModel, columnIndex);
		if (renderer == null) {
			return null;
		}

		ColumnConstraintFilterMode mode = renderer.getColumnConstraintFilterMode();
		if (mode == ColumnConstraintFilterMode.ALLOW_CONSTRAINTS_FILTER_ONLY) {
			// this is a renderer that does not know how to create its own display string
			return null;
		}

		Settings settings = columnBasedModel.getColumnSettings(columnIndex);
		String s = renderer.getFilterString(columnValue, settings);
		return s;
	}

	private static <ROW_OBJECT> GColumnRenderer<Object> getColumnRenderer(
			DynamicColumnTableModel<ROW_OBJECT> columnBasedModel, int columnIndex) {
		DynamicTableColumn<ROW_OBJECT, ?, ?> column = columnBasedModel.getColumn(columnIndex);
		@SuppressWarnings("unchecked")
		GColumnRenderer<Object> columnRenderer =
			(GColumnRenderer<Object>) column.getColumnRenderer();
		return columnRenderer;
	}

	/**
	 * Attempts to sort the given table based upon the given column index.  If the {@link TableModel}
	 * of the given table is not a {@link SortedTableModel}, then this method will do nothing.
	 * <p>
	 * If the given column index is not sortable, then this method will not change the state of
	 * the model.  Otherwise, the sorted model will be sorted on the given column index.  The 
	 * results of calling this method depend upon the current sorted state of the given column:
	 * <ol>
	 * <li>if the column is not yet the sorted column, then the column is made the sorted 
	 * column, if sortable, <b>and any other sorted columns will be made unsorted</b>, or</li>
	 * <li>if the column is the sorted column and the direction will simply be toggled.</li>
	 * </ol> 
	 * 
	 * @param table The table whose model shall be sorted.
	 * @param columnIndex The column index upon which to sort.
	 */
	public static void columnSelected(JTable table, int columnIndex) {
		SortedTableModel sortedModel = getSortedTableModel(table);
		if (sortedModel == null) {
			return;
		}

		int modelColumnIndex = getColumnModelIndex(table, columnIndex);
		if (modelColumnIndex < 0) {
			return;
		}

		if (!sortedModel.isSortable(modelColumnIndex)) {
			return;
		}

		TableSortState columnSortStates = sortedModel.getTableSortState();

		TableSortStateEditor editor = new TableSortStateEditor(columnSortStates);
		if (editor.isColumnSorted(modelColumnIndex)) {
			editor.flipColumnSortDirection(modelColumnIndex);
		}
		else {
			editor.clear();
			editor.addSortedColumn(modelColumnIndex);
		}

		sortedModel.setTableSortState(editor.createTableSortState());
		repaintTableHeader(table);
	}

	/**
	 * Attempts to sort the given table based upon the given column index.  If the {@link TableModel}
	 * of the given table is not a {@link SortedTableModel}, then this method will do nothing.
	 * <p>
	 * If the given column index is not sortable, then this method will not change the state of
	 * the model. The results of calling this method depend upon the current sorted state 
	 * of the given column:
	 * <ol>
	 *   <li>if the column is not yet sorted, then the column is made sorted, if sortable, 
	 *   <b>and any other sorted columns will not be changed</b>, or</li>
	 *   <li>if the column is sorted, then:
	 *     <ol>
	 *      <li>if there are other sorted columns, this column will no longer be sorted</li>
	 *      <li>if there are no other sorted columns, then no action will be taken</li>
	 *     </ol>
	 *   </li>
	 * </ol> 
	 * 
	 * @param table The table whose model shall be sorted.
	 * @param columnIndex The column index upon which to sort.
	 */
	public static void columnAlternativelySelected(JTable table, int columnIndex) {
		SortedTableModel sortedModel = getSortedTableModel(table);
		if (sortedModel == null) {
			return;
		}

		int modelColumnIndex = getColumnModelIndex(table, columnIndex);
		if (modelColumnIndex < 0) {
			return;
		}

		if (!sortedModel.isSortable(modelColumnIndex)) {
			return;
		}

		TableSortState columnSortStates = sortedModel.getTableSortState();
		TableSortStateEditor editor = new TableSortStateEditor(columnSortStates);

		if (editor.isColumnSorted(modelColumnIndex)) {

			/*			 
			 	Note: this code allows us to disable the 'unsorting' of a table via the UI
			 
				// remove it.  If there is only one, don't remove the last one
				if (editor.getSortedColumnCount() == 1) {
					Toolkit.getDefaultToolkit().beep();
					return;
				}
			*/

			editor.removeSortedColumn(modelColumnIndex);
		}
		else {
			editor.addSortedColumn(modelColumnIndex);
		}

		sortedModel.setTableSortState(editor.createTableSortState());
		repaintTableHeader(table);
	}

	private static SortedTableModel getSortedTableModel(JTable table) {
		TableModel model = table.getModel();
		if (!(model instanceof SortedTableModel)) {
			return null;
		}
		return (SortedTableModel) model;
	}

	private static int getColumnModelIndex(JTable table, int columnIndex) {
		TableColumnModel columnModel = table.getColumnModel();
		return columnModel.getColumn(columnIndex).getModelIndex();
	}

	private static void repaintTableHeader(JTable table) {
		// force an update on the headers so they display the new sorting order
		JTableHeader tableHeader = table.getTableHeader();
		if (tableHeader != null) {
			tableHeader.paintImmediately(tableHeader.getBounds());
		}
	}
}
