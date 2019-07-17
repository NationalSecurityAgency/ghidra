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

/**
 * Marks this model as one that is column-based, using {@link DynamicTableColumn}s.
 *
 * @param <ROW_TYPE> the row type of the underlying table model
 */
public interface DynamicColumnTableModel<ROW_TYPE>
		extends ConfigurableColumnTableModel, RowObjectTableModel<ROW_TYPE> {

	/**
	 * Returns the column for the given model index
	 * 
	 * @param index the model index of the column (this can differ from the view index)
	 * @return the column
	 */
	public DynamicTableColumn<ROW_TYPE, ?, ?> getColumn(int index);

	/**
	 * Returns the model index for the given column
	 * 
	 * @param column the column
	 * @return the model index
	 */
	public int getColumnIndex(DynamicTableColumn<ROW_TYPE, ?, ?> column);
}
