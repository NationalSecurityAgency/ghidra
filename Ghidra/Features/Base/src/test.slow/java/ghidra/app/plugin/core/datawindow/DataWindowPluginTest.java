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
package ghidra.app.plugin.core.datawindow;

import static org.junit.Assert.*;

import java.awt.Dimension;

import org.junit.*;

import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.*;
import ghidra.util.task.TaskMonitor;

public class DataWindowPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private FilterAction filterAction;
	private Program program;
	private DataWindowPlugin plugin;
	private CodeBrowserPlugin browser;
	private GTable dataTable;
	private DataWindowProvider provider;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();

		loadProgram("notepad");

		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(DataWindowPlugin.class);
		browser = env.getPlugin(CodeBrowserPlugin.class);
		filterAction = (FilterAction) getAction(plugin, "Filter Data Types");

		tool.getToolFrame().setSize(new Dimension(1024, 768));
		waitForSwing();
		provider = plugin.getProvider();

		runSwing(() -> tool.showComponentProvider(provider, true));

		DataWindowProvider dataWindowProvider =
			(DataWindowProvider) tool.getComponentProvider("Data Window");

		dataTable = dataWindowProvider.getTable();
		assertNotNull(dataTable);
		waitForNotBusy(dataTable);
	}

	private void waitForNotBusy(GTable table) {
		waitForTableModel((ThreadedTableModel<?, ?>) table.getModel());
	}

	@After
	public void tearDown() {
		env.dispose();
	}

	private void loadProgram(String programName) throws Exception {
		ClassicSampleX86ProgramBuilder builder = new ClassicSampleX86ProgramBuilder();
		program = builder.getProgram();
	}

	private void closeProgram() {
		ProgramManager pm = tool.getService(ProgramManager.class);
		pm.closeProgram(program, true);
	}

	@Test
	public void testNavigation() throws Exception {
		int rows = 10; // no need to test them all; a sample will do
		for (int i = 0; i < rows; i++) {
			clickTableCell(dataTable, i, DataTableModel.LOCATION_COL, 2);
			waitForSwing();
			Address addr = browser.getCurrentAddress();
			int row = i;
			Object value = runSwing(() -> dataTable.getValueAt(row, DataTableModel.LOCATION_COL));
			Object tableAddr = addr.getAddress(value.toString());
			assertEquals(addr, tableAddr);
		}
	}

	@Test
	public void testDeleteAndRestore() throws Exception {

		int numData = dataTable.getRowCount();

		tx(program, () -> {
			program.getListing().clearAll(false, TaskMonitor.DUMMY);
		});

		waitForNotBusy(dataTable);
		assertEquals(0, dataTable.getRowCount());

		undo(program);
		waitForNotBusy(dataTable);

		assertEquals(numData, dataTable.getRowCount());
	}

	@Test
	public void testFilter() throws Exception {
		int totalRows = dataTable.getRowCount();
		String type = dataTable.getValueAt(0, DataTableModel.TYPE_COL).toString();

		filterType(type);

		int filteredRows = dataTable.getRowCount();
		assertEquals(totalRows > filteredRows, true);

		for (int i = 0; i < filteredRows; i++) {
			int row = i;
			Object value = runSwing(() -> dataTable.getValueAt(row, DataTableModel.TYPE_COL));
			assertNotEquals(value.toString(), type);
		}

		disableFilter();
		assertEquals(dataTable.getRowCount(), totalRows);
	}

	@Test
	public void testProgramClose() throws Exception {

		closeProgram();
		waitForNotBusy(dataTable);

		assertEquals(dataTable.getRowCount(), 0);
		loadProgram("notepad");
	}

	private void disableFilter() {
		performAction(filterAction, false);
		DataWindowFilterDialog filterDialog = waitForDialogComponent(DataWindowFilterDialog.class);

		runSwing(() -> {
			filterDialog.setFilterEnabled(false);
		});

		pressButtonByText(filterDialog, "OK");
		waitForNotBusy(dataTable);
	}

	private void filterType(String type) {

		performAction(filterAction, false);
		DataWindowFilterDialog filterDialog = waitForDialogComponent(DataWindowFilterDialog.class);

		runSwing(() -> {
			filterDialog.setTypeEnabled(type, false);
			filterDialog.setFilterEnabled(true);
		});

		pressButtonByText(filterDialog, "OK");
		waitForNotBusy(dataTable);
	}

}
