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

import java.util.*;
import java.util.stream.Collectors;

import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import docking.widgets.table.constrainteditor.EnumConstraintEditor;

/**
 * Column Constraint where acceptable column values are Enum values that match one of a set of
 * selected values from the Enum.
 *
 * @param <T> the Enum column type.
 */
public class EnumColumnConstraint<T extends Enum<T>> implements ColumnConstraint<T> {

	private Set<T> acceptableValues;
	private Class<T> enumClass;

	/**
	 * Construct an EnumColumnConstraint with a set of acceptable Enum values.
	 *
	 * @param enumClass the Enum class.
	 * @param acceptableValues the set of acceptable Enum values.
	 */
	public EnumColumnConstraint(Class<T> enumClass, Set<T> acceptableValues) {
		this.enumClass = enumClass;
		this.acceptableValues = acceptableValues;
	}

	@Override
	public String getGroup() {
		return "enumeration";
	}

	@Override
	public String getName() {
		return "Is One Of";
	}

	@Override
	public boolean accepts(T value, TableFilterContext context) {
		return acceptableValues.contains(value);
	}

	@Override
	public ColumnConstraintEditor<T> getEditor(ColumnData<T> columnDataSource) {
		return new EnumConstraintEditor<>(this);
	}

	@Override
	public Class<T> getColumnType() {
		return enumClass;
	}

	/**
	 * Return the class of the column's Enum type.
	 * @return  the class of the column's Enum type.
	 */
	public Class<T> getEnumClass() {
		return enumClass;
	}

	/**
	 * Returns the set of acceptable (matching) Enum values that are acceptable to this constraint.
	 *
	 * @return the set of acceptable (matching) Enum values that are acceptable to this constraint.
	 */
	public Set<T> getSelectedValues() {
		return acceptableValues;
	}

	@Override
	public String getConstraintValueTooltip() {
		EnumConstraintEditor<T> editor = (EnumConstraintEditor<T>) getEditor(null);

		StringBuffer buf = new StringBuffer();

		buf.append("{");
		// @formatter:off
		buf.append(acceptableValues.stream()
			.map(editor::getElementDisplayName)
			.collect(Collectors.joining(", ")));
		// @formatter:on

		buf.append("}");
		return buf.toString();
	}

	@Override
	public String getConstraintValueString() {

		StringBuffer buf = new StringBuffer();

		buf.append("{");
		// @formatter:off
		buf.append(acceptableValues.stream()
			.map(e ->  e.toString())
			.collect(Collectors.joining(",")));
		// @formatter:on

		buf.append("}");
		return buf.toString();
	}

	@Override
	public ColumnConstraint<T> parseConstraintValue(String newValue, Object dataSource) {
		// Expecting a string in the form:  {value1, value2, value3, etc. }

		Set<T> values = new HashSet<>();

		newValue = newValue.trim();
		if (newValue.charAt(0) == '{' && newValue.charAt(newValue.length() - 1) == '}') {

			// First remove the surrounding braces...
			String substring = newValue.substring(1, newValue.length() - 1);
			String[] split = substring.split("\\s*,\\s*");

			for (String string : split) {
				try {
					T value = Enum.valueOf(enumClass, string.trim());
					values.add(value);
				}
				catch (IllegalArgumentException iae) {
					// The value of 'string' can't be resolved into a
					// value of T; ignore it and move on
				}

			}
		}

		return new EnumColumnConstraint<>(enumClass, values);
	}

	@Override
	public int hashCode() {
		return Objects.hash(getEnumClass(), getSelectedValues());
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
		EnumColumnConstraint<?> other = (EnumColumnConstraint<?>) obj;
		if (enumClass != other.enumClass) {
			return false;
		}
		return Objects.equals(acceptableValues, other.acceptableValues);
	}
}
