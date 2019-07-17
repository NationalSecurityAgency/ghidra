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
package ghidra.app.plugin.core.functionwindow;

import static org.junit.Assert.assertEquals;

import org.junit.*;

import docking.ComponentProvider;
import docking.widgets.table.GTable;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.plugin.core.clear.ClearCmd;
import ghidra.app.plugin.core.clear.ClearOptions;
import ghidra.app.services.ProgramManager;
import ghidra.framework.cmd.CompoundCmd;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.*;
import ghidra.test.*;

public class FunctionWindowPluginTest extends AbstractGhidraHeadedIntegrationTest {
	private TestEnv env;
	private PluginTool tool;
	private Program program;
	private FunctionWindowPlugin plugin;
	private GTable functionTable;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		loadProgram("notepad");
		tool = env.launchDefaultTool(program);

		plugin = env.getPlugin(FunctionWindowPlugin.class);

		plugin.showFunctions();
		waitForSwing();
		ComponentProvider provider = tool.getComponentProvider("Functions Window");
		functionTable = (GTable) findComponentByName(provider.getComponent(), "FunctionTable");
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
	public void testDeleteAndRestore() throws Exception {

		int numData = functionTable.getRowCount();

		CompoundCmd cmd = new CompoundCmd("Clear");
		FunctionIterator itr = program.getListing().getFunctions(true);
		while (itr.hasNext()) {
			Function f = itr.next();
			cmd.add(new ClearCmd(f.getBody(), new ClearOptions()));
		}
		applyCmd(program, cmd);
		waitForNotBusy(functionTable);

		assertEquals(0, functionTable.getRowCount());

		undo(program);
		waitForNotBusy(functionTable);

		assertEquals(numData, functionTable.getRowCount());

	}

	@Test
	public void testProgramClose() throws Exception {
		closeProgram();
		waitForNotBusy(functionTable);

		assertEquals(functionTable.getRowCount(), 0);
		loadProgram("notepad");
	}

	private void waitForNotBusy(GTable table) {
		waitForTableModel((ThreadedTableModel<?, ?>) table.getModel());
	}

}
