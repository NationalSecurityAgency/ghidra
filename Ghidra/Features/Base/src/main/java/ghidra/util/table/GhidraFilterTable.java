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

import docking.widgets.table.*;
import docking.widgets.table.threaded.GThreadedTablePanel;
import docking.widgets.table.threaded.ThreadedTableModel;

public class GhidraFilterTable<ROW_OBJECT> extends GFilterTable<ROW_OBJECT> {

	public GhidraFilterTable(RowObjectTableModel<ROW_OBJECT> model) {
		super(model);

	}

	@Override
	protected GTable createTable(RowObjectTableModel<ROW_OBJECT> tableModel) {
		return new GhidraTable(tableModel);
	}

	@Override
	protected GTableFilterPanel<ROW_OBJECT> createTableFilterPanel(GTable gTable,
			RowObjectTableModel<ROW_OBJECT> tableModel) {
		return new GhidraTableFilterPanel<ROW_OBJECT>(gTable, tableModel);
	}

	@Override
	protected GThreadedTablePanel<ROW_OBJECT> createThreadedTablePanel(
			ThreadedTableModel<ROW_OBJECT, ?> threadedModel) {

		return new GhidraThreadedTablePanel<ROW_OBJECT>(threadedModel);
	}

}
