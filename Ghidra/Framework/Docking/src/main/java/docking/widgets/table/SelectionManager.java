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
import javax.swing.table.TableModel;

import org.apache.logging.log4j.Logger;

/**
 * A class to track and restore selections made in a table.  We use this in the docking 
 * environment primarily due to the heavy usage of filtering for most tables.  As tables are
 * filtered, the contents change (and then change back when the filter is removed).  It is nice
 * to be able to filter a table, select an item of interest, and then unfilter the table to see
 * that item in more context.
 * <p>
 * Notes on usage:
 * <ul>
 * 		<li>Some table models are sensitive to the order in which {@link TableModel#tableChanged()}
 * 		 is called.  These models should either not use this SelectionManger, or need to 
 * 		 change their code to be more robust.  As an example, the {@link DefaultSortedTableModel}
 * 	     updates its indexes in odd ways.   Further, there is a chance that the state of its
 *       indexing is incorrect when <tt>tableChanged</tt> is called.  So, that model has to 
 *       account for the fact that it may get called by this class when it is in a bad state.
 *       </li>
 * </ul>
 */
public interface SelectionManager extends ListSelectionModel, TableModelListener {

	public void addSelectionManagerListener(SelectionManagerListener listener);

	public void removeSelectionManagerListener(SelectionManagerListener listener);

	public void clearSavedSelection();

	/**
	 * Allows clients to enable tracing by providing a logger with tracing enabled.
	 * @param logger The logger to be used by this manager, which has tracing embedded in its
	 *               code.
	 */
	public void setLogger(Logger logger);

	public void dispose();
}
