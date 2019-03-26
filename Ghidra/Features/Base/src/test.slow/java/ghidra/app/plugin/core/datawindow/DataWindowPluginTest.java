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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

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
import ghidra.util.task.TaskMonitorAdapter;

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
		int numRows = dataTable.getRowCount();
		for (int i = 0; i < numRows; i++) {
			clickTableCell(dataTable, i, DataTableModel.LOCATION_COL, 2);
			waitForSwing();
			Address addr = browser.getCurrentAddress();
			Object tableAddr =
				addr.getAddress(dataTable.getValueAt(i, DataTableModel.LOCATION_COL).toString());
			assertEquals(addr, tableAddr);
		}
	}

	@Test
	public void testDeleteAndRestore() throws Exception {

		int numData = dataTable.getRowCount();

		int id = program.startTransaction(testName.getMethodName());
		try {
			program.getListing().clearAll(false, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		finally {
			program.endTransaction(id, true);
		}
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
		filterAction.setTypeEnabled(type, false);
		filterAction.setFilterEnabled(true);
		plugin.reload();
		waitForNotBusy(dataTable);

		int filteredRows = dataTable.getRowCount();
		for (int i = 0; i < filteredRows; i++) {
			assertEquals(dataTable.getValueAt(i, DataTableModel.TYPE_COL).toString().equals(type),
				false);
		}

		assertEquals(totalRows > filteredRows, true);

		filterAction.setFilterEnabled(false);
		plugin.reload();
		waitForNotBusy(dataTable);

		assertEquals(dataTable.getRowCount(), totalRows);
	}

	@Test
	public void testProgramClose() throws Exception {

		closeProgram();
		waitForNotBusy(dataTable);

		assertEquals(dataTable.getRowCount(), 0);
		loadProgram("notepad");
	}
}
