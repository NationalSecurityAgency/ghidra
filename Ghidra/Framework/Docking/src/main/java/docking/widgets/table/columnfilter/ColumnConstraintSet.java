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
package docking.widgets.table.columnfilter;

import java.util.*;

import org.apache.commons.collections4.CollectionUtils;

import docking.widgets.table.DiscoverableTableUtils;
import docking.widgets.table.RowObjectTableModel;
import docking.widgets.table.constraint.*;
import ghidra.framework.options.SaveState;

/**
 * This class maintains a collection of {@link ColumnConstraint} that are applied to a specific table column
 * for filtering purposes. In order for this ColumnConstraintSet to "pass", (i.e. accept the table
 * row) the column value for that row must pass at least one of the constraints in this set, thus
 * effectively OR'ing the constraints.
 *
 * <P> Instances of this class are used by the {@link ColumnBasedTableFilter} to filter rows of table.
 *
 * @param <R> the row type of the table being filtered.
 * @param <T> the column type of column whose values are being tested by this filter.
 */
public class ColumnConstraintSet<R, T> {
	private final List<ColumnConstraint<T>> constraints = new ArrayList<>();
	private final int columnIndex;
	private final RowObjectTableModel<R> model;
	private final LogicOperation logicOperation;

	/**
	 * Constructor
	 *
	 * @param model the table model being filtered.
	 * @param columnIndex the index of the column whose values are tested by this filter.
	 * @param constraints the list of ColumnConstraints whose results are or'ed together.
	 * @param logicOperation the logical operation for how this constraintSet relates to other contraint sets.
	 */
	public ColumnConstraintSet(RowObjectTableModel<R> model, int columnIndex,
			List<ColumnConstraint<T>> constraints, LogicOperation logicOperation) {
		this.model = model;
		this.columnIndex = columnIndex;
		this.logicOperation = logicOperation;
		this.constraints.addAll(constraints);
	}

	/**
	 * Constructor when deserializing from a SaveState
	 *
	 * @param model the table model being filtered
	 * @param saveState the SaveState which contains the configuration for this filter.
	 * @param dataSource the table's DataSource.
	 */
	public ColumnConstraintSet(RowObjectTableModel<R> model, SaveState saveState,
			Object dataSource) {
		String columnName = saveState.getString("COLUMN_NAME", null);
		int constraintCount = saveState.getInt("CONSTRAINT_COUNT", 0);
		this.columnIndex = saveState.getInt("COLUMN_MODEL_INDEX", -1);
		this.logicOperation = LogicOperation.valueOf(saveState.getString("LOGICAL_OP", "AND"));
		if (!model.getColumnName(columnIndex).equals(columnName)) {
			throw new IllegalArgumentException("ColumnFilter does not match table model");
		}
		this.model = model;
		for (int i = 0; i < constraintCount; i++) {
			String constraintName = saveState.getString("CONSTRAINT_NAME_" + i, null);
			String valueString = saveState.getString("CONSTRAINT_VALUE_" + i, null);
			constraints.add(findColumnConstraint(constraintName, valueString, dataSource));

		}

	}

	@SuppressWarnings("unchecked")
	private ColumnConstraint<T> findColumnConstraint(String constraintName, String value,
			Object dataSource) {
		Class<T> columnClass = (Class<T>) model.getColumnClass(columnIndex);
		Collection<ColumnConstraint<T>> columnConstraints =
			DiscoverableTableUtils.getColumnConstraints(columnClass);

		for (ColumnConstraint<?> constraint : columnConstraints) {
			if (constraint.getName().equals(constraintName)) {
				return (ColumnConstraint<T>) constraint.parseConstraintValue(value, dataSource);
			}
		}
		throw new IllegalArgumentException(
			"Can't find constraint for " + constraintName + " for value: " + value);
	}

	/**
	 * Return the name of the column whose values will be tested by this filter.
	 *
	 * @return  the name of the column whose values will be tested by this filter.
	 */
	public String getColumnName() {
		return model.getColumnName(getColumnModelIndex());
	}

	/**
	 * Returns the model index of the column whose values will be tested by this filter.
	 *
	 * @return  the model index of the column whose values will be tested by this filter.
	 */
	public int getColumnModelIndex() {
		return columnIndex;
	}

	/**
	 * Return true if the given table row object passes this filter.
	 *
	 * @param rowObject the table row object.
	 * @param context the {@link TableFilterContext} for this table's filter.
	 * @return  true if the given table row object passes this filter.
	 */
	public boolean accepts(R rowObject, TableFilterContext context) {
		// the constraint filters are ORed together

		@SuppressWarnings("unchecked")
		// This is fine unless some table returns values for a column that are a different
		// type than it reported in its getColumnClass().  If so, this will stack trace and the
		// offending table will need to be fixed.
		T value = (T) model.getColumnValueForRow(rowObject, columnIndex);

		// the constraints are or'ed together
		for (ColumnConstraint<T> constraint : constraints) {
			if (constraint.accepts(value, context)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns a list of ColumnConstraints in this ColumnFilter
	 *
	 * @return a list of ColumnConstraints in this ColumnFilter
	 */
	public List<ColumnConstraint<T>> getConstraints() {
		return constraints;
	}

	/**
	 * Returns the logical operation (AND or OR) for how to combine this object's {@link #accepts(Object, TableFilterContext)}
	 * results with the results of previous constraintSet results in the overall filter.
	 * @return the logical operation (AND or OR)
	 */
	public LogicOperation getLogicOperation() {
		return logicOperation;
	}

	SaveState save() {
		SaveState saveState = new SaveState("CONSTRAINT_TABLE_FILTER");
		saveState.putString("COLUMN_NAME", model.getColumnName(columnIndex));
		saveState.putInt("COLUMN_MODEL_INDEX", columnIndex);
		saveState.putInt("CONSTRAINT_COUNT", constraints.size());
		saveState.putString("LOGICAL_OP", logicOperation.name());
		for (int i = 0; i < constraints.size(); i++) {
			ColumnConstraint<T> constraint = constraints.get(i);
			saveState.putString("CONSTRAINT_NAME_" + i, constraint.getName());
			saveState.putString("CONSTRAINT_VALUE_" + i, constraint.getConstraintValueString());
		}
		return saveState;
	}

	/**
	 * Returns an HTML representation of this constraint set in a tabular form. It will be used
	 * inside the HTML representation of the entire filter. See {@link ColumnBasedTableFilter#getHtmlRepresentation()}
	 * for a description of the table format.
	 */
	String getHtmlRepresentation() {
		StringBuilder builder = new StringBuilder();
		builder.append("<table valign=top cellpadding=0 cellspacing=0>");
		builder.append("<tr><td style=\"color:#990099\">");
		builder.append(model.getColumnName(columnIndex));
		builder.append("&nbsp;");
		builder.append("</td>");
		builder.append("<td>");
		builder.append(getHtmlRepresentation(constraints.get(0)));
		builder.append("<td></tr>");
		for (int i = 1; i < constraints.size(); i++) {
			builder.append("<tr><td style=\"color:gray;text-align:center\">or</td>");
			builder.append("<td >");
			builder.append(getHtmlRepresentation(constraints.get(i)));
			builder.append("</td></tr>");
		}
		builder.append("</table>");
		return builder.toString();
	}

	private String getHtmlRepresentation(ColumnConstraint<?> columnConstraint) {
		StringBuilder buf = new StringBuilder();
		buf.append(columnConstraint.getName());

		boolean quoteValue = isStringBasedConstraint(columnConstraint);

		buf.append(" ");
		if (quoteValue) {
			buf.append("\"");
		}
		buf.append("<span style=\"color: blue\">");
		buf.append(columnConstraint.getConstraintValueString());
		buf.append("</span>");
		if (quoteValue) {
			buf.append("\"");
		}
		buf.append(" ");
		return buf.toString();
	}

	/**
	 * Returns true if this is a String constraint or a type converting constraint where the type
	 * is converted to a string constraint. (i.e. uses a String editor)
	 * @param constraint the constraint to check.
	 * @return true if this is a String constraint or something that is converted to a string constraint.
	 */
	private static boolean isStringBasedConstraint(ColumnConstraint<?> constraint) {

		if (constraint instanceof MappedColumnConstraint) {

			constraint = ((MappedColumnConstraint<?, ?>) constraint).getDelegate();

			return isStringBasedConstraint(constraint);
		}

		return constraint.getColumnType().equals(String.class);
	}

	@Override
	public int hashCode() {
		return Objects.hash(model.getClass(), columnIndex, constraints);
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
		ColumnConstraintSet<?, ?> other = (ColumnConstraintSet<?, ?>) obj;
		if (this.logicOperation != other.logicOperation) {
			return false;
		}
		if (columnIndex != other.columnIndex) {
			return false;
		}
		if (model != other.model) {
			return false;
		}
		return Objects.equals(constraints, other.constraints);
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tcolumn: " + columnIndex +",\n" +
			"\toperation: " + logicOperation + ",\n" +
			"\tconstraints: " + CollectionUtils.collect(constraints, c -> c.asString())  +"\n" +
		"}";
		//@formatter:on
	}

}
