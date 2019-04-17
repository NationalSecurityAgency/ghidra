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

import docking.widgets.table.constraint.provider.EditorProvider;

/**
 * Column Constraint where acceptable column values are greater than or equal to some specified
 * value of the column type.
 *
 * @param <T> the column type.
 */
public class AtLeastColumnConstraint<T extends Comparable<T>>
		extends SingleValueColumnConstraint<T> {

	/**
	 * Constructs a new AtLeastColumnConstraint with a default name, default group and a minimum value.
	 *
	 * @param minValue the value for which all acceptable column values must be greater than or equal.
	 * @param editorProvider an object that can provide a ConstraintEditor for this constraint type.
	 */
	public AtLeastColumnConstraint(T minValue, EditorProvider<T> editorProvider) {
		this("At Least", minValue, editorProvider, "number");
	}

	/**
	 * Constructs a new AtLeastColumnConstraint with a minimum value, constraint name, and group
	 *
	 * @param name the name of the constraint.  For some types T, the default "At Least" may not be best.
	 * @param minValue the value for which all acceptable column values must be greater than or equal.
	 * @param editorProvider an object that can provide a ConstraintEditor for this constraint type.
	 * @param group the name of the group used to organize the list of constraints for a column.
	 */
	public AtLeastColumnConstraint(String name, T minValue, EditorProvider<T> editorProvider,
			String group) {
		super(name, minValue, editorProvider, group);
	}

	@Override
	public boolean accepts(T value, TableFilterContext context) {
		if (value == null) {
			return false;
		}
		return value.compareTo(getConstraintValue()) >= 0;
	}

	@Override
	public SingleValueColumnConstraint<T> copy(T newValue) {
		return new AtLeastColumnConstraint<>(getName(), newValue, editorProvider, getGroup());
	}

}
