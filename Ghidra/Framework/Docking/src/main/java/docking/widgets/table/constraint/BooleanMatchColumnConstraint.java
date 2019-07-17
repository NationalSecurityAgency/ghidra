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

import docking.widgets.table.constrainteditor.BooleanConstraintEditor;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;

/**
 * Column Constraint for boolean values where the column values must match the constraint value
 * of either true of false.
 */
public class BooleanMatchColumnConstraint implements ColumnConstraint<Boolean> {

	private Boolean matchValue;

	/**
	 * Construct a new BooleanMatchColumnConstraint that matches the given boolean value.
	 * @param matchValue the value (true or false) that acceptable column values have.
	 */
	public BooleanMatchColumnConstraint(Boolean matchValue) {
		this.matchValue = matchValue;
	}

	@Override
	public String getGroup() {
		return "boolean";
	}

	@Override
	public String getName() {
		return "Is";
	}

	@Override
	public boolean accepts(Boolean value, TableFilterContext context) {
		if (value == null) {
			return false;
		}
		return value.equals(matchValue);
	}

	@Override
	public ColumnConstraintEditor<Boolean> getEditor(ColumnData<Boolean> columnDataSource) {
		return new BooleanConstraintEditor(this);
	}

	@Override
	public Class<Boolean> getColumnType() {
		return Boolean.class;
	}

	/**
	 * Returns the constraints boolean value for matching.
	 * @return  the constraints boolean value for matching.
	 */
	public Boolean getValue() {
		return matchValue;
	}

	@Override
	public String getConstraintValueString() {
		return matchValue.toString();
	}

	@Override
	public ColumnConstraint<Boolean> parseConstraintValue(String newValue, Object dataSource) {
		boolean b = Boolean.parseBoolean(newValue);
		return new BooleanMatchColumnConstraint(b);
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
		BooleanMatchColumnConstraint other = (BooleanMatchColumnConstraint) obj;
		return Objects.equals(matchValue, other.matchValue);
	}

}
