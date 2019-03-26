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
package docking.widgets.table.constraint.provider;

import docking.widgets.table.constraint.ColumnConstraint;
import docking.widgets.table.constraint.ColumnData;
import docking.widgets.table.constrainteditor.ColumnConstraintEditor;

/**
 * Class used by some generic constraints to fulfill their requirement to provide and editor. These types
 * of constraints are passed in an EditorProvider in their constructor.  This allows these constraint
 * types to be created using generics without subclassing.
 *
 * @param <T> the constraint type.
 */
public interface EditorProvider<T> {

	/**
	 * Returns an editor initialized to the given columnConstraint.
	 *
	 * @param columnConstraint the constraint whose value is to be edited.
	 * @param columnData the context of the data in the table.
	 * @return an editor initialized to the given columnConstraint.
	 */
	public ColumnConstraintEditor<T> getEditor(ColumnConstraint<T> columnConstraint,
			ColumnData<T> columnData);

	/**
	 * Parses the given string into a T object.
	 *
	 * @param value the value to parse.
	 * @param dataSource the table's context object.
	 * @return a new T object created by parsing the given string.
	 */
	public T parseValue(String value, Object dataSource);

	/**
	 * Converts the T value into a string that can be parsed back by the {@link #parseValue(String, Object)} method.
	 *
	 * @param value the value to convert to a parsable string.
	 * @return The parsable string fromthe T value.
	 */
	public String toString(T value);

}
