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
package ghidra.app.cmd.function;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class CreateFunctionThunkTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;

	private Program program;

	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
	}

	@After
	public void tearDown() {
		if (program != null) {
			env.release(program);
		}
		program = null;
		env.dispose();
	}

	private void analyze() {
		// turn off some analyzers
		setAnalysisOptions("Stack");
		setAnalysisOptions("Embedded Media");
		setAnalysisOptions("DWARF");
		setAnalysisOptions("Create Address Tables");
		setAnalysisOptions("MIPS Constant Reference Analyzer");

		AutoAnalysisManager analysisMgr = AutoAnalysisManager.getAnalysisManager(program);
		analysisMgr.reAnalyzeAll(null);

		Command cmd = new AnalysisBackgroundCommand(analysisMgr, false);
		tool.execute(cmd, program);
		waitForBusyTool(tool);
	}

	protected void setAnalysisOptions(String optionName) {
		int txId = program.startTransaction("Analyze");
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		analysisOptions.setBoolean(optionName, false);
		program.endTransaction(txId, true);
	}

	@Test
	public void testDelaySlotThunk() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._MIPS);

		builder.setBytes("0x1000", "08 22 96 44 24 04 00 02  08 11 96 44 00 00 00 00");
		builder.disassemble("0x1000", 27, false);
		builder.disassemble("0x1008", 27, false);
		builder.createFunction("0x1000");
		builder.createFunction("0x1008");

		builder.analyze();

		program = builder.getProgram();

		Function noThunk = program.getFunctionManager().getFunctionAt(builder.addr(0x1000));
		assertEquals(false, noThunk.isThunk());

		Function isThunk = program.getFunctionManager().getFunctionAt(builder.addr(0x1008));
		assertEquals(true, isThunk.isThunk());
	}

	/**
	 * This tests the forcing of a function to be a thunk with CreateThunkFunctionCmd
	 * Tests that the Function start analyzer will create a thunk given the thunk tag on a matching function
	 * That the MIPS BE language has a thunking pattern.
	 * That the MIPS 64/32 hybrid with sign extension of registers still gets found as a thunk.
	 * That the thunking function can be found with out the constant reference analyzer
	 * 
	 */
	@Test
	public void testDelayMips6432SlotThunk() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._MIPS_6432);

		builder.setBytes("0x466050", "3c 0f 00 47  8d f9 72 24  03 20 00 08  25 f8 72 24");
		builder.setBytes("0x477224", "00 47 99 c0");
		builder.createEmptyFunction("chdir", "0x4799c0", 1, DataType.VOID);
		builder.disassemble("0x466050", 27, true);

		builder.createFunction("0x466050");

		program = builder.getProgram();

		analyze();

		Function isThunk = program.getFunctionManager().getFunctionAt(builder.addr(0x466050));
		assertEquals(true, isThunk.isThunk());
		assertEquals("chdir", isThunk.getName());
	}
}
