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
package ghidra.app.plugin.core.analysis;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

public class ArmBranchReturnDetectionTest extends AbstractGhidraHeadedIntegrationTest {

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
	
	/**
	 * This tests that a pop to the pc with the lr register is changed to a return
	 * 
	 * That the thunking function can be found with the constant reference analyzer
	 * 
	 */
	@Test
	public void testDelayArmPopReturn1() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._ARM);

		builder.setBytes("0x00015d9c", "10 b5 03 48 10 bc 01 bc 00 47");
		builder.setRegisterValue("TMode", "0x00015d9c", "0x00015d9c", 1);
		builder.disassemble("0x00015d9c", 27, true);
		
		builder.createFunction("0x00015d9c");
		builder.createLabel("0x00015d9c", "func1");;

		program = builder.getProgram();

		analyze();
		
		Instruction instruction = program.getListing().getInstructionAt(builder.addr(0x00015da4));
		assertNotNull(instruction);
		
		assertTrue("pop turned into return", instruction.getFlowType().isTerminal());
	}
}
