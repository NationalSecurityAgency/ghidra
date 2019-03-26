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
import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.ColumnData;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;

/**
 * This class represents the set of "or-able" filter conditions for a single column.
 *
 * @param <T> the column type.
 */
public class DialogFilterConditionSet<T> {
	private final DialogFilterRow filterRow;
	private final ColumnFilterData<T> columnFilterData;
	private final List<DialogFilterCondition<T>> conditionSet = new ArrayList<>();

	/**
	 * Constructs a new DialogFilterCondtionSet for a specific Column.
	 *
	 * @param filterRow the DialogFilterRow that created this DialogFilterConditionSet.
	 * @param columnFilterData the data for the column this condition set is tied to.
	 */
	DialogFilterConditionSet(DialogFilterRow filterRow, ColumnFilterData<T> columnFilterData) {
		this.filterRow = filterRow;
		this.columnFilterData = columnFilterData;
		conditionSet.add(new DialogFilterCondition<>(this));
	}

	/**
	 * Constructor used when building from an existing table model
	 *
	 * @param filterRow the FilterRow that created this DialogFilterConditionSet.
	 * @param columnFilter the ColumnFilter from the existing TableFilter to build from.
	 */
	DialogFilterConditionSet(DialogFilterRow filterRow, ColumnConstraintSet<?, T> columnFilter) {
		this.filterRow = filterRow;
		columnFilterData = getColumnFilterData(columnFilter.getColumnModelIndex());
		List<ColumnConstraint<T>> constraints = new ArrayList<>(columnFilter.getConstraints());
		for (ColumnConstraint<T> constraint : constraints) {
			conditionSet.add(new DialogFilterCondition<>(this, constraint));
		}
	}

	DialogFilterCondition<T> addFilterCondition() {
		DialogFilterCondition<T> condition = new DialogFilterCondition<>(this);
		conditionSet.add(condition);
		filterRow.conditionSetChanged(this);
		return condition;
	}

	ColumnFilterData<T> getColumnFilterData() {
		return columnFilterData;
	}

	boolean hasValidFilterValue() {
		for (DialogFilterCondition<T> condition : conditionSet) {
			if (!condition.hasValidFilterValue()) {
				return false;
			}
		}
		return true;
	}

	void conditionChanged(DialogFilterCondition<T> condition) {
		filterRow.conditionSetChanged(this);
	}

	void editorValueChanged(ColumnConstraintEditor<T> editor) {
		filterRow.editorValueChanged(editor);
	}

	/**
	 * Adds a column filter to the TableColumnFilter that matches this configuration.
	 *
	 * @param tableColumnFilter the TableColumnFilter under construction.
	 * @param logicOperation the logic operation for how this set of filter conditions will
	 * be combined with previous sets of conditions.
	 */
	void addToTableFilter(ColumnBasedTableFilter<?> tableColumnFilter,
			LogicOperation logicOperation) {
		List<ColumnConstraint<T>> orConditions = new ArrayList<>();
		for (DialogFilterCondition<T> condition : conditionSet) {
			orConditions.add(condition.getConstraint());
		}
		tableColumnFilter.addConstraintSet(logicOperation, columnFilterData.getColumnModelIndex(),
			orConditions);
	}

	List<DialogFilterCondition<T>> getFilterConditions() {
		return conditionSet;
	}

	/**
	 * Returns a ColumnDataSource that provide access to the columns values for each row.
	 *
	 * @return a ColumnDataSource for the column.
	 */
	@SuppressWarnings("unchecked")
	<R> ColumnData<T> getColumnData() {
		RowObjectFilterModel<R> tableModel = (RowObjectFilterModel<R>) filterRow.getTableModel();
		int columnModelIndex = columnFilterData.getColumnModelIndex();
		return new ColumnData<T>() {

			@Override
			public String getColumnName() {
				return tableModel.getColumnName(columnModelIndex);
			}

			@Override
			public int getCount() {
				return tableModel.getUnfilteredRowCount();
			}

			@Override
			public T getColumnValue(int row) {
				R rowObject = tableModel.getUnfilteredData().get(row);
				return (T) tableModel.getColumnValueForRow(rowObject, columnModelIndex);
			}

			@Override
			public Object getTableDataSource() {
				return filterRow.getDataSource();
			}

		};
	}

	void delete(DialogFilterCondition<T> condition) {
		conditionSet.remove(condition);
		if (conditionSet.isEmpty()) {
			filterRow.delete();
		}
		else {
			filterRow.conditionSetChanged(this);
		}
	}

	@SuppressWarnings("unchecked")
	private ColumnFilterData<T> getColumnFilterData(int columnModelIndex) {
		List<ColumnFilterData<?>> columnDataList = filterRow.getAllColumnData();
		for (ColumnFilterData<?> data : columnDataList) {
			if (data.getColumnModelIndex() == columnModelIndex) {
				return (ColumnFilterData<T>) data;
			}
		}
		return null;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tfilterRow: " + filterRow + ",\n" +
			"\tdata: " + columnFilterData + ",\n" +
			"\tconditions: " + conditionSet +"\n" +
		"}";
		//@formatter:on
	}

}
