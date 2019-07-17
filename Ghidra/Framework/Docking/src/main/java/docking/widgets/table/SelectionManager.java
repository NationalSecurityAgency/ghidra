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

import javax.swing.ListSelectionModel;
import javax.swing.event.TableModelListener;

/**
 * A class to track and restore selections made in a table.  We use this in the docking 
 * environment primarily due to the heavy usage of filtering for most tables.  As tables are
 * filtered, the contents change (and then change back when the filter is removed).  It is nice
 * to be able to filter a table, select an item of interest, and then unfilter the table to see
 * that item in more context.
 */
public interface SelectionManager extends ListSelectionModel, TableModelListener {

	public void addSelectionManagerListener(SelectionManagerListener listener);

	public void removeSelectionManagerListener(SelectionManagerListener listener);

	public void clearSavedSelection();

	public void dispose();
}
