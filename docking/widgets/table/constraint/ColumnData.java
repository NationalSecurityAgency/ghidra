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

/**
 * Interface for providing column data and a table's DataSource to a constraint editor.  Some editors
 * require access to the table column data.  One example is a String "Starts With" column might
 * pre-process the data to provide an autocompletion feature in the editor.
 *
 * @param <T> the column data type.
 */
public interface ColumnData<T> {

	/**
	 * Returns the name of the column being filtered.
	 *
	 * @return  the name of the column being filtered.
	 */
	public String getColumnName();

	/**
	 * Returns the number of column values (unfiltered table row count)
	 *
	 * @return the number of column values (unfiltered table row count)
	 */
	public int getCount();

	/**
	 * Returns the column value for the given row.
	 * @param row the row for which to get the column value.
	 * @return the column value for the given row.
	 */
	public T getColumnValue(int row);

	/**
	 * Returns the table's DataSource.
	 * @return  the table's DataSource.
	 */
	public Object getTableDataSource();

}
