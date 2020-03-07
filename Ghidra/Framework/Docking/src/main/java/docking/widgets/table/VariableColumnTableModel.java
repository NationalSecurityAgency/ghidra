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
package docking.widgets.table;

import javax.swing.table.TableModel;

/**
 * An interface for marking table models whose supported columns are discovered at runtime
 */
public interface VariableColumnTableModel extends TableModel {

	/**
	 * Returns a {@link VariableColumnTableModel} if the given model is an instance of this
	 * type or is wraps another table model that is an instance of this type.  If the given 
	 * model is not such an instance, then null is returned.
	 * 
	 * @return the variable column model
	 */
	public static VariableColumnTableModel from(TableModel m) {
		TableModel unwrapped = RowObjectTableModel.unwrap(m);
		if (unwrapped instanceof VariableColumnTableModel) {
			return (VariableColumnTableModel) unwrapped;
		}
		return null;
	}

	public String getColumnDisplayName(int column);

	public String getColumnDescription(int column);

	/**
	 * Returns a value that is unique for a given table column.  This is different than getting
	 * the display name, which may be shared by different columns.
	 * @param column the index (in the model space) of the column for which to get the identifier
	 */
	public String getUniqueIdentifier(int column);

	/**
	 * Gets the count of the default columns for this model.  This model may have non-default
	 * columns added.  This method will return the count of columns that have been setup 
	 * specifically by the table model.  This method can be used to iterate of the first 
	 * <code>n</code> columns of this model in order to get information for the default columns by
	 * calling methods like {@link #getColumnName(int)}. 
	 *  
	 * @return Gets the count of the default columns for this model.
	 */
	public int getDefaultColumnCount();

	/**
	 * Returns true if the column denoted by the given model index is default (specified 
	 * initially by the table model).
	 * @param modelIndex The index in the column in the column model.
	 * @return true if the column denoted by the given model index is default.
	 */
	public boolean isDefaultColumn(int modelIndex);

	/**
	 * Returns true if the column denoted by the given model index is specified by the table 
	 * model as being visible when the table is loaded for the first time. 
	 * @param modelIndex The index in the column in the column model.
	 * @return true if the column denoted by the given model index is visible default.
	 */
	public boolean isVisibleByDefault(int modelIndex);
}
