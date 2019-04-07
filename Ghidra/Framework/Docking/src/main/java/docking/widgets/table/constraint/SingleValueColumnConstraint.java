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

import docking.widgets.table.constraint.provider.EditorProvider;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;

/**
 * Abstract base class for single value constraints such as "At Most" or "At Least"
 *
 * @param <T> the column type
 */
public abstract class SingleValueColumnConstraint<T> implements ColumnConstraint<T> {

	/**
	 * This constraints' name
	 * <p>
	 * It sometimes makes grammatical sense to set a more useful name than the default;
	 * while 'at least' makes sense for a number-based constraint, 'after' reads better for
	 * date-based constraints.
	 */
	protected final String name;
	private T constraintValue = null;
	protected EditorProvider<T> editorProvider;
	private String group;

	/**
	 * Constructor
	 *
	 * @param name the name of the constraint.
	 * @param constraintValue the value of this constraint to be compared with column values.
	 * @param editorProvider the editor provider that generates the appropriate editors for
	 * constraints of this type.
	 * @param group the group of the constraint for visual grouping when presenting to the user.
	 */
	protected SingleValueColumnConstraint(String name, T constraintValue,
			EditorProvider<T> editorProvider, String group) {
		this.name = name;
		this.constraintValue = constraintValue;
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
	 * Returns the constraint value
	 * @return the constraint value
	 */
	public final T getConstraintValue() {
		return constraintValue;
	}

	/**
	 * subclasses must override to generate new versions of themselves but with new comparison value.
	 *
	 * @param newValue the new value to compare column values against.
	 * @return a new ColumnConstraint that is the same type as this constraint but with a new comparison value.
	 */
	public abstract SingleValueColumnConstraint<T> copy(T newValue);

	@Override
	public ColumnConstraintEditor<T> getEditor(ColumnData<T> columnDataSource) {
		return editorProvider.getEditor(this, columnDataSource);
	}

	@Override
	public String getConstraintValueString() {
		return editorProvider.toString(constraintValue);
	}

	@Override
	public ColumnConstraint<T> parseConstraintValue(String newValue, Object dataSource) {
		return copy(editorProvider.parseValue(newValue, dataSource));
	}

	@SuppressWarnings("unchecked")
	@Override
	public Class<T> getColumnType() {
		T t = getConstraintValue();
		return (Class<T>) t.getClass();
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.getClass(), getConstraintValue());
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

		SingleValueColumnConstraint<?> otherConstraint = (SingleValueColumnConstraint<?>) o;

		return getConstraintValue().equals(otherConstraint.getConstraintValue());

	}

}
