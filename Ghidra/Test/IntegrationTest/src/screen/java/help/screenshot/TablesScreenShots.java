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
package help.screenshot;

import javax.swing.table.TableColumnModel;

import org.junit.Test;

import docking.ComponentProvider;
import docking.widgets.table.*;
import docking.widgets.table.ColumnSortState.SortDirection;
import docking.widgets.table.threaded.GThreadedTablePanel;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.functionwindow.FunctionWindowProvider;
import ghidra.app.plugin.core.table.TableComponentProvider;
import ghidra.program.model.address.Address;

public class TablesScreenShots extends GhidraScreenShotGenerator {

	public TablesScreenShots() {
		super();
	}

@Test
	public void testBytesSettingsDialog() throws Exception {
		performMemorySearch("55");
		waitForTasks();
		@SuppressWarnings("unchecked")
		TableComponentProvider<Address> provider = getProvider(TableComponentProvider.class);
		GThreadedTablePanel<Address> threadedTablePanel = provider.getThreadedTablePanel();
		GTable table = threadedTablePanel.getTable();
		showTableColumn(table, "Bytes");
		showColumnSettings(table, "Bytes");
		captureDialog();

	}

@Test
    public void testMultipleColumnSortDialog() {
		showProvider(FunctionWindowProvider.class);
		ComponentProvider provider = getProvider(FunctionWindowProvider.class);
		ThreadedTableModel<?, ?> model =
			(ThreadedTableModel<?, ?>) getInstanceField("functionModel", provider);
		TableSortStateEditor editor = new TableSortStateEditor();
		editor.addSortedColumn(0, SortDirection.ASCENDING);
		editor.addSortedColumn(1, SortDirection.ASCENDING);
		editor.addSortedColumn(2, SortDirection.ASCENDING);
		setSort(model, editor.createTableSortState());
		captureIsolatedProvider(FunctionWindowProvider.class, 600, 300);
	}

@Test
    public void testSelectColumnsDialog() {
		showProvider(FunctionWindowProvider.class);
		ComponentProvider provider = getProvider(FunctionWindowProvider.class);
		GTable table = (GTable) getInstanceField("functionTable", provider);
		showColumnAddRemove(table);

		captureDialog();
	}

	private void setSort(final ThreadedTableModel<?, ?> model, final TableSortState sortState) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				model.setTableSortState(sortState);
			}
		});
	}

	private void showColumnAddRemove(final GTable table) {
		runSwing(new Runnable() {
			@Override
			public void run() {
				TableColumnModel model = table.getColumnModel();
				SelectColumnsDialog dialog =
					new SelectColumnsDialog((GTableColumnModel) model, table.getModel());
				tool.showDialog(dialog);
			}
		}, false);
		waitForSwing();
	}
}
