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
package docking.widgets.table.constraint;

import docking.widgets.table.constrainteditor.ColumnConstraintEditor;

/**
 * ColumnConstraints are objects used to filter table rows based on values from a particular column.
 *
 * @param <T> The column type
 */
public interface ColumnConstraint<T> extends Comparable<ColumnConstraint<T>> {

	/**
	 * Compares value against the current constraint value to determine
	 * acceptance; true if value satisfies the constraints' value, false
	 * otherwise
	 *
	 * @param value the column value to be tested.
	 * @param context provides additional information about the the table and its data. This
	 * allows the filter to base its decision on information other than just the column value.
	 * @return true if the column value passes the constraint, false otherwise
	 */
	public boolean accepts(T value, TableFilterContext context);

	/**
	 * Returns a reasonable String version of this constraint useful for debugging.
	 * @return the String representation of this constraint
	 */
	public default String asString() {
		return getName() + " " + getConstraintValueTooltip();
	}

	/**
	 * Returns the name of the constraint
	 *
	 * @return the name of the constraint.
	 */
	public String getName();

	/**
	 * Returns the column type that this constraint can be used to filter.
	 * @return the column type
	 */
	public Class<T> getColumnType();

	/**
	 * Returns a ColumnConstraintEditor which will provide gui components for users to edit the
	 * constraint values.
	 *
	 * @param columnDataSource This provides the constraint with access to the column data in the
	 * table model as well as the DataProvider of the table (if it has one)
	 * @return A columnConstraintEditor for editing the constraints value.
	 */
	public ColumnConstraintEditor<T> getEditor(ColumnData<T> columnDataSource);

	/**
	 * Returns a "group" string that is used to logically group column constraints for
	 * presentation to the user
	 * @return the group this constraint belongs to.
	 */
	public String getGroup();

	/**
	 * returns a description of the constraint suitable for displaying in a tooltip
	 * @return a description of the constraint.
	 */
	public default String getConstraintValueTooltip() {
		return getConstraintValueString();
	}

	/**
	 * Returns the "value" of the constraint in string form
	 *
	 * <P>This is used for serializing the constraint.
	 * @return the "value" of the constraint in string form.
	 */
	public String getConstraintValueString();

	/**
	 * Parses the constraint value string for deserialization purposes.
	 * @param constraintValueString the value of the constraint in string form.
	 * @param dataSource the DataSource from the Table.
	 * @return a new ColumnConstraint
	 */
	public ColumnConstraint<T> parseConstraintValue(String constraintValueString,
			Object dataSource);

	/**
	 * ColumnConstraints are displayed by group and then by name
	 */
	@Override
	public default int compareTo(ColumnConstraint<T> other) {
		int result = getGroup().compareTo(other.getGroup());
		if (result == 0) {
			result = getName().compareTo(other.getName());
		}
		return result;
	}
}
