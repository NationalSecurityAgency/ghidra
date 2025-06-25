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
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
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

		Command<Program> cmd = new AnalysisBackgroundCommand(analysisMgr, false);
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
	
	/**
	 * This tests the forcing of a function to be a thunk with CreateThunkFunctionCmd
	 * Tests that the Function start analyzer will create a thunk given the thunk tag on a matching function
	 * That the ARM Thumb language has a thunking pattern.
	 * 
	 * That the thunking function can be found with the constant reference analyzer
	 * 
	 */
	@Test
	public void testArmThumbThunk() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._ARM);

		builder.setBytes("0x00015d9c", "00 00 00 00 03 b4 01 48 01 90 01 bd ad 5d 01 00 10 bd");
		builder.setRegisterValue("TMode", "0x00015da0", "0x00015da0", 1);
		builder.disassemble("0x00015da0", 27, true);

		
		builder.createFunction("0x00015da0");
		builder.createLabel("0x15dac", "chdir");
		builder.createFunction("0x15dac");

		program = builder.getProgram();
		
		builder.applyDataType("0x00015d9c", DWordDataType.dataType);

		analyze();
		
		
		Instruction instruction = program.getListing().getInstructionAt(builder.addr(0x15dac));
		assertNotNull(instruction);
		

		Function isThunk = program.getFunctionManager().getFunctionAt(builder.addr(0x00015da0));
		assertEquals(true, isThunk.isThunk());
		assertEquals("chdir", isThunk.getName());
	}
	
	/**
	 * This tests the forcing of a function to be a thunk with CreateThunkFunctionCmd
	 * Tests that the Function start analyzer will create a thunk given the thunk tag on a matching function
	 * That the ARM Thumb language has a thunking pattern.
	 * 
	 * That the thunking function can be found with the constant reference analyzer
	 * 
	 */
	@Test
	public void testArmThumbThunk2() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._ARM);

		builder.setBytes("0x10000", "10 b5 02 4c 24 68 01 94 10 bd 00 00 14 00 01 00 01 20 70 47 11 00 01 00");
		builder.setRegisterValue("TMode", "0x10000", "0x10000", 1);
		builder.disassemble("0x10000", 27, true);

		
		builder.createLabel("00010000", "thunker");
		builder.createFunction("0x10000");
		builder.createLabel("00010010", "thunkee");
		builder.createFunction("00010010");

		program = builder.getProgram();
		
		//builder.applyDataType("0x00015d9c", DWordDataType.dataType);

		analyze();
		
		
		Instruction instruction = program.getListing().getInstructionAt(builder.addr(0x10000));
		assertNotNull(instruction);
		

		Function isThunk = program.getFunctionManager().getFunctionAt(builder.addr(0x10000));
		assertEquals(true, isThunk.isThunk());
		assertEquals("thunker", isThunk.getName());
	}
	
	/**
	 * Tests that the Function start analyzer will create a thunk given the thunk tag on a matching function
	 * Tests that constant propagation creates a reference using the callfixup value in LR
	 * 
	 */
	@Test
	public void testPPCblrlThunk() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._PPC_32);

		/**
         *  bl         __get_pc_thunk_lr
         *  mfspr      r30,LR
         *  lbz        r3,0x0(r30)
         *  blr
		 */
		builder.setBytes("0x00002000", "42 80 00 31 7f c8 02 a6 88 1e 00 00 4e 80 00 20");
		builder.disassemble("0x00002000", 27, true);

		/**
         *  blrl
         *  lbz        r12,0x0(r10)
         *  blr
		 */
		builder.setBytes("0x0002030", "4e 80 00 21 89 8a 00 00 4e 80 00 20");
		builder.disassemble("0x0002030", 27, true);

		builder.createFunction("0x0002000");
		
		builder.createFunction("0x0002030");

		program = builder.getProgram();

		analyze();
		
		
		Instruction instruction = program.getListing().getInstructionAt(builder.addr(0x2008));
		assertNotNull(instruction);
		Reference[] referencesFrom = instruction.getReferencesFrom();
		
		// Thunk will set a value in LR that is not normal from the assumed return of a function
		// used to calculate a constant reference
		// TODO: There is a left-over BAD reference.  Need to clean references on re-analysis
		assertEquals(0x2034L, referencesFrom[1].getToAddress().getOffset());
		

		Function thunker = program.getFunctionManager().getFunctionAt(builder.addr(0x0002030));
		assertEquals("__get_pc_thunk_lr", thunker.getName());
		assertEquals("get_pc_thunk_lr", thunker.getCallFixup());
	}
}
