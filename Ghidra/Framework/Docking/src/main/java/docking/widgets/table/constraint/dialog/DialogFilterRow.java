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
package docking.widgets.table.constraint.dialog;

import java.util.ArrayList;
import java.util.List;

import docking.widgets.table.RowObjectFilterModel;
import docking.widgets.table.columnfilter.*;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;

/**
 * This class represents a major "and-able" row in the dialog's filter panel.  It is associated with
 * a single column at any given time.  It has a single {@link DialogFilterConditionSet}  which is
 * typed on the ColumnType. If the column changes, it will create a new condition set for the new
 * Column.
 *
 * <P> The {@link DialogFilterRow} and the {@link DialogFilterConditionSet} classes work together to
 * represent a row in the dialog's filter panel.  The row is untyped since the associated column can
 * change.  The {@link DialogFilterConditionSet} is typed on the column's value type which allows
 * it to take advantage of Java's templating for type safety.
 */
public class DialogFilterRow {
	private ColumnFilterDialogModel<?> dialogModel;
	private DialogFilterConditionSet<?> columnConditionSet;
	private LogicOperation logicOperation;

	/**
	 * Constructor with the first column selected
	 *
	 * @param dialogModel the model that created this filter row.
	 * @param logicOperation the logic operation for how this filter row is combined with previous
	 * rows.
	 */
	public DialogFilterRow(ColumnFilterDialogModel<?> dialogModel, LogicOperation logicOperation) {
		this.dialogModel = dialogModel;
		this.logicOperation = logicOperation;
		doSetColumnData(getAllColumnData().get(0));
	}

	/**
	 * Constructor when constructing the model from an exiting filter.
	 *
	 * @param dialogModel the model that created this class.
	 * @param columnFilter A column filter from the existing filter.
	 */
	public <T> DialogFilterRow(ColumnFilterDialogModel<?> dialogModel,
			ColumnConstraintSet<?, T> columnFilter) {
		this.dialogModel = dialogModel;
		this.columnConditionSet = new DialogFilterConditionSet<>(this, columnFilter);
		this.logicOperation = columnFilter.getLogicOperation();
	}

	/**
	 * Sets the column for this filter row.
	 *
	 * @param columnData the data for the column.
	 */
	public void setColumnData(ColumnFilterData<?> columnData) {
		doSetColumnData(columnData);
		dialogModel.dialogFilterRowChanged(this);
	}

	/**
	 * Returns the {@link LogicOperation} that specifies how this DialogFilterRow relates to
	 * previous rows.
	 * @return the LogicOperation for this row.
	 */
	public LogicOperation getLogicOperation() {
		return logicOperation;
	}

	private <T> void doSetColumnData(ColumnFilterData<T> columnData) {
		columnConditionSet = new DialogFilterConditionSet<>(this, columnData);
	}

	/**
	 * Method for the dialog to use to get the columns for the comboBox
	 *
	 * @return all the columns available to be filtered in the table.
	 */
	public List<ColumnFilterData<?>> getAllColumnData() {
		return dialogModel.getAllColumnFilterData();
	}

	/**
	 * Gets the current ColumnData for this filter row.
	 *
	 * @return the current ColumnData for this filter row.
	 */
	public ColumnFilterData<?> getColumnFilterData() {
		return columnConditionSet.getColumnFilterData();
	}

	/**
	 * Pass through for checking filter condition validity.
	 * @return true if valid, false otherwise.
	 */
	public boolean hasValidFilterValue() {
		return columnConditionSet.hasValidFilterValue();
	}

	/**
	 * Returns a list of the "or-able" constraints configured for this column.
	 * @return a list of the "or-able" constraints configured for this column.
	 */
	public List<DialogFilterCondition<?>> getFilterConditions() {
		return new ArrayList<>(columnConditionSet.getFilterConditions());
	}

	/**
	 * Adds a new DialogFilterCondition to this filter row.
	 * @return the newly created condition.
	 */
	public DialogFilterCondition<?> addFilterCondition() {
		return columnConditionSet.addFilterCondition();
	}

	/**
	 * Adds this columns filter configuration to the TableColumnFilter under construction.
	 *
	 * @param tableColumnFilter the filter to add.
	 */
	void addToTableFilter(ColumnBasedTableFilter<?> tableColumnFilter) {
		columnConditionSet.addToTableFilter(tableColumnFilter, logicOperation);
	}

	Object getDataSource() {
		return dialogModel.getDataSource();
	}

	void editorValueChanged(ColumnConstraintEditor<?> editor) {
		dialogModel.editorValueChanged(editor);
	}

	void conditionSetChanged(DialogFilterConditionSet<?> conditionSet) {
		dialogModel.dialogFilterRowChanged(this);
	}

	RowObjectFilterModel<?> getTableModel() {
		return dialogModel.getTableModel();
	}

	void delete() {
		dialogModel.deleteFilterRow(this);
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\toperation: " + logicOperation + ",\n" +
			"\tconditions: " + columnConditionSet +"\n" +
		"}";
		//@formatter:on
	}
}
