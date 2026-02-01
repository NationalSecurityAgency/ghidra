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

import java.awt.Graphics;
import java.math.BigDecimal;
import java.time.Duration;
import java.util.*;

import javax.swing.*;
import javax.swing.table.*;

import org.apache.commons.collections4.CollectionUtils;
import org.jdesktop.animation.timing.Animator;

import docking.util.AnimationPainter;
import docking.util.AnimationRunner;
import ghidra.docking.settings.Settings;
import ghidra.util.bean.GGlassPane;
import ghidra.util.table.column.GColumnRenderer;
import ghidra.util.table.column.GColumnRenderer.ColumnConstraintFilterMode;

/**
 * A utility class for JTables used in Ghidra.
 */
public class TableUtils {

	/**
	 * An animation runner that emphasizes the sorted columns using the table's header.
	 */
	private static AnimationRunner sortEmphasizingAnimationRunner;

	/**
	 * Select the given row objects.  No selection will be made if the objects are filtered out of
	 * view.  Passing a {@code null} list or an empty list will clear the selection.
	 * 
	 * @param table the table in which to select the items
	 * @param items the row objects to select
	 */
	public static <ROW_OBJECT> void setSelectedItems(JTable table, List<ROW_OBJECT> items) {

		if (CollectionUtils.isEmpty(items)) {
			table.clearSelection();
			return;
		}

		TableModel model = table.getModel();
		if (!(model instanceof RowObjectTableModel gModel)) {
			return;
		}

		ListSelectionModel selectionModel = table.getSelectionModel();
		int mode = selectionModel.getSelectionMode();
		if (mode == ListSelectionModel.SINGLE_SELECTION) {
			// take the last item to mimic what the selection model does internally
			ROW_OBJECT item = items.get(items.size() - 1);
			@SuppressWarnings({ "unchecked" })
			int viewRow = gModel.getRowIndex(item);
			table.setRowSelectionInterval(viewRow, viewRow);
			return;
		}

		//
		// For ListSelectionModel SINGLE_INTERVAL_SELECTION and MULTIPLE_INTERVAL_SELECTION, the
		// model will update any selection given to it to match the current mode.
		//
		List<Integer> rows = new ArrayList<>();
		for (ROW_OBJECT item : items) {
			@SuppressWarnings({ "unchecked" })
			int viewRow = gModel.getRowIndex(item);
			if (viewRow >= 0) {
				rows.add(viewRow);
			}
		}
		if (rows.isEmpty()) {
			return; // items may be filtered out of view
		}

		selectionModel.setValueIsAdjusting(true);
		selectionModel.clearSelection();
		for (int row : rows) {
			selectionModel.addSelectionInterval(row, row);
		}
		selectionModel.setValueIsAdjusting(false);
	}

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
			ROW_OBJECT rowObject, int column) {

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

		TableModel unwrappedModel = RowObjectTableModel.unwrap(model);
		if (!(unwrappedModel instanceof DynamicColumnTableModel)) {
			return null;
		}

		@SuppressWarnings("unchecked")
		DynamicColumnTableModel<ROW_OBJECT> columnBasedModel =
			(DynamicColumnTableModel<ROW_OBJECT>) unwrappedModel;
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

		TableSortState newSortState = editor.createTableSortState();
		sortedModel.setTableSortState(newSortState);

		if (sortEmphasizingAnimationRunner != null) {
			sortEmphasizingAnimationRunner.stop();
		}

		int n = newSortState.getSortedColumnCount();
		if (n >= 2) { // don't emphasize a single column
			sortEmphasizingAnimationRunner =
				new SortEmphasisAnimationRunner(table, newSortState, columnIndex);
			sortEmphasizingAnimationRunner.start();
		}

		repaintTableHeaderForSortChange(table);
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

		TableSortState newSortState = editor.createTableSortState();
		sortedModel.setTableSortState(newSortState);

		if (sortEmphasizingAnimationRunner != null) {
			sortEmphasizingAnimationRunner.stop();
		}

		int n = newSortState.getSortedColumnCount();
		if (n >= 2) { // don't emphasize a single column
			sortEmphasizingAnimationRunner =
				new SortEmphasisAnimationRunner(table, newSortState, columnIndex);
			sortEmphasizingAnimationRunner.start();
		}

		repaintTableHeaderForSortChange(table);
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

	private static void repaintTableHeaderForSortChange(JTable table) {
		// force an update on the headers so they display the new sorting order
		JTableHeader tableHeader = table.getTableHeader();
		if (tableHeader != null) {
			tableHeader.paintImmediately(tableHeader.getBounds());
		}
	}

	private static void resetEmphasis(JTable table) {
		// clear all emphasis state
		TableColumnModel columnModel = table.getColumnModel();
		int n = columnModel.getColumnCount();
		for (int i = 0; i < n; i++) {
			TableColumn column = columnModel.getColumn(i);
			TableCellRenderer renderer = column.getHeaderRenderer();
			if (renderer instanceof GTableHeaderRenderer gRenderer) {
				gRenderer.setSortEmphasis(-1);
			}
		}
	}

	/**
	 * An animation runner that creates the painter and the values that will be interpolated by
	 * the animator.  Each column that is sorted will be emphasized, except for the column that was
	 * clicked, as not to be annoying to the user.   The intent of emphasizing the columns is to 
	 * signal to the user that other columns are part of the sort, not just the column that was 
	 * clicked.   We hope that this will remind the user of the overall sort so they are not 
	 * confused when the column that was clicked produces unexpected sort results. 
	 */
	private static class SortEmphasisAnimationRunner extends AnimationRunner {

		private JTable table;

		public SortEmphasisAnimationRunner(JTable table, TableSortState tableSortState,
				int clickedColumn) {
			super(table);
			this.table = table;

			// Create an array of sort ordinals to use as the values. We need 1 extra value to 
			// create a range between ordinals (e.g., 1-2, 2-3 for 2 ordinals)
			int n = tableSortState.getSortedColumnCount();
			int[] ordinals = new int[n];
			for (int i = 1; i < n + 1; i++) {
				ordinals[i - 1] = i;
			}

			// create double values to get a range for the client as the timer calls back
			Double[] values = new Double[n];
			for (int i = 0; i < n; i++) {
				values[i] = Double.valueOf(ordinals[i]);
			}

			EmphasizingSortPainter painter =
				new EmphasizingSortPainter(table, tableSortState, clickedColumn, ordinals);
			setPainter(painter);
			setValues(values);
			setDuration(Duration.ofSeconds(1));
			setDoneCallback(this::done);
		}

		@Override
		public void start() {
			Animator animator = createAnimator();

			// acceleration / deceleration make some of the column numbers jiggle, so turn it off
			animator.setAcceleration(0);
			animator.setDeceleration(0);
			super.start();
		}

		private void done() {
			resetEmphasis(table);
		}
	}

	/**
	 * A painter that will emphasize each sorted column, except for the clicked column, over the 
	 * course of an animation.  The painter is called with the current emphasis that is passed to
	 * the column along with a repaint request.
	 */
	private static class EmphasizingSortPainter implements AnimationPainter {

		private TableSortState tableSortState;
		private JTable table;
		private Map<Integer, Integer> columnsByOrdinal = new HashMap<>();
		private int clickedColumnIndex;

		public EmphasizingSortPainter(JTable table, TableSortState tableSortState,
				int clickedColumnIndex, int[] ordinals) {
			this.table = table;
			this.tableSortState = tableSortState;
			this.clickedColumnIndex = clickedColumnIndex;

			mapOrdinalsToColumns(ordinals);
		}

		private void mapOrdinalsToColumns(int[] ordinals) {
			for (int i = 0; i < ordinals.length; i++) {
				List<ColumnSortState> sortStates = tableSortState.getAllSortStates();
				for (ColumnSortState ss : sortStates) {
					int columnOrdinal = ss.getSortOrder();
					if (columnOrdinal == ordinals[i]) {
						int sortColumnIndex = ss.getColumnModelIndex();
						columnsByOrdinal.put(ordinals[i], sortColumnIndex);
						break;
					}
				}
			}
		}

		@Override
		public void paint(GGlassPane glassPane, Graphics graphics, double value) {

			JTableHeader tableHeader = table.getTableHeader();
			if (tableHeader == null) {
				return; // not sure if this can happen
			}

			resetEmphasis(table);

			ColumnAndRange columnAndRange = getColumnAndRange(value);
			if (columnAndRange == null) {
				return;
			}

			TableColumnModel columnModel = table.getColumnModel();
			int columnViewIndex = table.convertColumnIndexToView(columnAndRange.column());
			TableColumn column = columnModel.getColumn(columnViewIndex);
			TableCellRenderer renderer = column.getHeaderRenderer();
			if (!(renderer instanceof GTableHeaderRenderer gRenderer)) {
				return;
			}

			// 
			// Have the emphasis transition from normal -> large -> normal over the range 0.0 to 
			// 1.1, with an emphasis of 1.x.
			// 
			double range = columnAndRange.range();
			double emphasis;
			if (range < .5) {
				emphasis = 1 + range;
			}
			else {
				emphasis = 2 - range;
			}

			gRenderer.setSortEmphasis(emphasis);
			tableHeader.repaint();
		}

		private ColumnAndRange getColumnAndRange(double value) {
			//
			// The values are the sort ordinals: 1, 2, 3, etc, in double form: 1.1, 1.5... Each
			// value has the ordinal and a range from 0 - .99
			//
			BigDecimal bigDecimal = new BigDecimal(String.valueOf(value));
			int ordinal = bigDecimal.intValue();
			Integer columnModelIndex = columnsByOrdinal.get(ordinal);
			if (columnModelIndex >= clickedColumnIndex) {
				// Ignore the clicked column when emphasizing the header, as to not be distracting 
				// for the column that they are looking at already.  Once we have gotten to or past
				// the clicked column, then choose the next ordinal to emphasize.
				int nextOrdinal = ordinal + 1;
				columnModelIndex = columnsByOrdinal.get(nextOrdinal);
			}

			BigDecimal bigOrdinal = new BigDecimal(ordinal);
			BigDecimal decimalValue = bigDecimal.subtract(bigOrdinal);
			return new ColumnAndRange(columnModelIndex, decimalValue.doubleValue());
		}

		/**
		 * Simple container for a column index and it's range (from 0 to .99)
		 */
		private record ColumnAndRange(int column, double range) {}

	}
}
