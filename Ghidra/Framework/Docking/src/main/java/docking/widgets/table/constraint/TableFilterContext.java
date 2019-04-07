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

import docking.widgets.table.GDynamicColumnTableModel;

/**T
 * Provides additional information (context) to column filter constraint objects.  This  allows
 * the possibility for {@link ColumnConstraint} objects to make filtering decisions based on
 * information other than just the column value.  For example, the column value might be a key
 * into some other data mapping.
 */
public interface TableFilterContext {
	/**
	 * Returns the table's data source object if it has one; otherwise it returns null.
	 * @return  the table's data source object if it has one; otherwise it returns null.
	 * @see GDynamicColumnTableModel#getDataSource()
	 */
	Object getDataSource();
}
