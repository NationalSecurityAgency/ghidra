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

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import docking.widgets.table.constraint.provider.EditorProvider;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;

/**
 * Abstract base class for range constraints.
 *
 * @param <T> the column type
 */
public abstract class RangeColumnConstraint<T> implements ColumnConstraint<T> {

	/**
	 * This pattern is used to extract the minimum and maximum values from a range specification.
	 *
	 * <P> A range specification adheres to this format:
	 * <code>'[' (whitespace)? (minimum value) (whitespace)? ',' (whitespace)? (maximum value) (whitespace)? ']'</code>
	 *
	 * <P> For example, matching values would be [ 10 , 20 ],  [10,20]
	 * <p>
	 * <ul>
	 * <li>The minimum and maximum value-strings must not contain commas or closing square brackets.</li>
	 * <li>Leading and trailing whitespace is removed from the value-string.</li>
	 * </ul>
	 */
	private final static Pattern RANGE_SPEC_PATTERN =
		Pattern.compile("\\[\\s*([^,\\]]+)\\s*,\\s*([^,\\]]+)\\s*\\]");

	/**
	 * This constraints' name
	 * <p>
	 * It sometimes makes grammatical sense to set a more useful name than the default;
	 * while 'at least' makes sense for a number-based constraint, 'after' reads better for
	 * date-based constraints.
	 */
	protected final String name;
	private T minValue;
	private T maxValue;
	protected EditorProvider<T> editorProvider;
	private String group;

	/**
	 * Constructor
	 *
	 * @param name the name of the constraint.
	 * @param minValue the min value of the range.
	 * @param maxValue the max value of the range.
	 * @param editorProvider the editor provider that generates the appropriate editors for
	 * constraints of this type.
	 * @param group the group of the constraint for visual grouping when presenting to the user.
	 */
	protected RangeColumnConstraint(String name, T minValue, T maxValue,
			EditorProvider<T> editorProvider, String group) {
		this.name = name;
		this.minValue = minValue;
		this.maxValue = maxValue;
		this.editorProvider = editorProvider;
		this.group = group;
	}

	@Override
	public String getGroup() {
		return group;
	}

	@Override
	public String getName() {
		return name;
	}

	/**
	 * Returns the min value of the range used by this constraint.
	 *
	 * @return  the min value of the range used by this constraint.
	 */
	public T getMinValue() {
		return minValue;
	}

	/**
	 * Returns the max value of the range used by this constraint.
	 *
	 * @return  the max value of the range used by this constraint.
	 */
	public T getMaxValue() {
		return maxValue;
	}

	@SuppressWarnings("unchecked")
	@Override
	public Class<T> getColumnType() {
		return (Class<T>) getMinValue().getClass();
	}

	@Override
	public final ColumnConstraintEditor<T> getEditor(ColumnData<T> columnDataSource) {
		return editorProvider.getEditor(this, columnDataSource);
	}

	@Override
	public String getConstraintValueString() {
		StringBuilder buf = new StringBuilder();
		buf.append("[");
		buf.append(editorProvider.toString(minValue));
		buf.append(",");
		buf.append(editorProvider.toString(maxValue));
		buf.append("]");
		return buf.toString();
	}

	@Override
	public ColumnConstraint<T> parseConstraintValue(String newValue, Object dataSource) {
		// Expecting a string in the form:  [min,max]

		Matcher m = RANGE_SPEC_PATTERN.matcher(newValue);
		if (m.matches()) {
			String minStr = m.group(1);
			String maxStr = m.group(2);

			T newMinValue = editorProvider.parseValue(minStr.trim(), dataSource);
			T newMaxValue = editorProvider.parseValue(maxStr.trim(), dataSource);

			return copy(newMinValue, newMaxValue);
		}
		throw new IllegalArgumentException("Don't know how to parse '" + newValue + "'");
	}

	/**
	 * subclasses must override to generate new versions of themselves but with new range values.
	 *
	 * @param min the min value of the range.
	 * @param max the max value of the range.
	 * @return a new ColumnConstraint that is the same type as this constraint but with a new range defined.
	 */
	public abstract RangeColumnConstraint<T> copy(T min, T max);

	@Override
	public int hashCode() {
		return Objects.hash(this.getClass(), getMinValue(), getMaxValue());
	}

	@Override
	public boolean equals(Object o) {
		if (o == this) {
			return true;
		}
		if (o == null) {
			return false;
		}

		if (!(getClass().equals(o.getClass()))) {
			return false;
		}

		RangeColumnConstraint<?> otherRangeConstraint = (RangeColumnConstraint<?>) o;

		return getMinValue().equals(otherRangeConstraint.getMinValue()) &&
			getMaxValue().equals(otherRangeConstraint.getMaxValue());

	}

}
