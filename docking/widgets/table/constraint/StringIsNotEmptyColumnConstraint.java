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

import org.apache.commons.lang3.StringUtils;

import docking.widgets.table.constrainteditor.ColumnConstraintEditor;
import docking.widgets.table.constrainteditor.DoNothingColumnConstraintEditor;

/**
 * String column constraint for matching when the value is not null and not the empty string.
 */
public class StringIsNotEmptyColumnConstraint implements ColumnConstraint<String> {

	@Override
	public String getName() {
		return "Is Not Empty";
	}

	@Override
	public boolean accepts(String value, TableFilterContext context) {
		return !StringUtils.isBlank(value);
	}

	@Override
	public Class<String> getColumnType() {
		return String.class;
	}

	@Override
	public ColumnConstraintEditor<String> getEditor(ColumnData<String> columnDataSource) {
		return new DoNothingColumnConstraintEditor<>(this);
	}

	@Override
	public String getGroup() {
		return "z string";
	}

	@Override
	public String getConstraintValueString() {
		return "";
	}

	@Override
	public ColumnConstraint<String> parseConstraintValue(String constraintValueString,
			Object dataSource) {
		return this;
	}

}
