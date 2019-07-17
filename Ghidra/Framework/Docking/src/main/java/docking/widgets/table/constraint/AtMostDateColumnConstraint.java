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

import java.time.LocalDate;

import docking.widgets.table.constraint.provider.EditorProvider;

/**
 * Column Constraint where acceptable column values are greater than or equal to some specified
 * value of the column type
 */
public class AtMostDateColumnConstraint extends SingleValueColumnConstraint<LocalDate> {

	/**
	 * Constructs a new AtLeastDateColumnConstraint with a default name, default group and a minimum value
	 *
	 * @param minValue the value for which all acceptable column values must be greater than or equal.
	 * @param editorProvider an object that can provide a ConstraintEditor for this constraint type.
	 */
	public AtMostDateColumnConstraint(LocalDate minValue,
			EditorProvider<LocalDate> editorProvider) {
		super("On or Before Date", minValue, editorProvider, "date");
	}

	@Override
	public boolean accepts(LocalDate value, TableFilterContext context) {
		if (value == null) {
			return false;
		}
		return value.compareTo(getConstraintValue()) <= 0;
	}

	@Override
	public SingleValueColumnConstraint<LocalDate> copy(LocalDate newValue) {
		return new AtMostDateColumnConstraint(newValue, editorProvider);
	}

}
