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
package ghidra.util.table;

import javax.swing.JTable;

import docking.widgets.table.GTableFilterPanel;
import docking.widgets.table.RowObjectTableModel;

/**
 * This is a "program aware" version of GTableFilterPanel
 * @param <ROW_OBJECT> the row type
 */
public class GhidraTableFilterPanel<ROW_OBJECT> extends GTableFilterPanel<ROW_OBJECT> {

	/**
	 * Creates a table filter panel that filters the contents of the given table.
	 *
	 * @param table The table whose contents will be filtered.
	 * @param tableModel The table model used by the table--passed in by the type that we require
	 */
	public GhidraTableFilterPanel(JTable table, RowObjectTableModel<ROW_OBJECT> tableModel) {
		super(table, tableModel);
	}

	public GhidraTableFilterPanel(JTable table, RowObjectTableModel<ROW_OBJECT> tableModel,
			String filterLabel) {
		super(table, tableModel, filterLabel);
	}

}
