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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.analysis.AnalysisBackgroundCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.framework.cmd.Command;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Test for the {@link CreateFunctionCmdWithFlowTest}.
 */
public class CreateFunctionCmdWithFlowTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private PluginTool tool;
	
	private Program program;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();

		builder = new ProgramBuilder("notepad.exe", ProgramBuilder._PPC_32);
		builder.createMemory("test", "0x07000000", 1024);

		program = builder.getProgram();

		//
		// Create some functions (byte patterns, not Ghidra objects) with varying separation
		//
		// single function
		builder.setBytes("0x07000008", "3d 60 07 00 61 6b 00 20 7d 69 03 a6 4e 80 04 20");
		builder.disassemble("0x07000008", 16);
		builder.createMemoryJumpReference("0x070000014", "0x07000020");

		// Thunk to above single function
		builder.setBytes("0x07000020", "7c 69 1b 78 88 04 00 00 38 84 00 01 7c 00 07 74 2f 80 00 00 98 09 00 00 39 29 00 01 40 9e ff e8 4e 80 00 20");
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
	public void testCreateFunction() {

		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x07000008));
		createCmd.applyTo(program);

		program.endTransaction(transactionID, true);

		Function func8 = func(addr(0x07000008));
		assertNotNull("Created normal function", func8);

		assertEquals("Normal function body size", 16, func8.getBody().getNumAddresses());
	}
	
	@Test
	public void testCreateFunctionOneByte() throws OverlappingFunctionException {

		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x07000008));
		createCmd.applyTo(program);
		
		// doctor body
		AddressSet body = new AddressSet(addr(0x07000008),addr(0x07000017));
		body.add(addr(0x07000020));
		
		Function func8 = func(addr(0x07000008));
		
		func8.setBody(body);

		assertEquals("Normal function body size", 17, func8.getBody().getNumAddresses());

		builder.disassemble("0x07000020", 36);
		
		createCmd = new CreateFunctionCmd(addr(0x07000020));
		createCmd.applyTo(program);

		program.endTransaction(transactionID, true);

		assertNotNull("Created normal function", func8);

		assertEquals("Normal function body size", 16, func8.getBody().getNumAddresses());
		
		Function func20 = func(addr(0x07000020));
		
		assertNotNull("Created normal function", func20);

		assertEquals("Normal function body size", 36, func20.getBody().getNumAddresses());
	}
	
	@Test
	public void testPPCDisassemblyRef() throws OverlappingFunctionException {

		int transactionID = program.startTransaction("Perform the TEST");

		CreateFunctionCmd createCmd = new CreateFunctionCmd(addr(0x07000008));
		createCmd.applyTo(program);
		
		Function func8 = func(addr(0x07000008));
		
		program.getMemory().getBlock(addr(0x07000000)).setExecute(true);
		
		assertFalse("is not Thunk yet", func8.isThunk());
		
		Instruction instructionAt = program.getListing().getInstructionAt(addr(0x07000020));
		
		assertNull("Not disassembled yet", instructionAt);
		
		builder.analyze();
		
		assertNotNull("Created normal function", func8);

		assertEquals("Normal function body size", 16, func8.getBody().getNumAddresses());
		
		instructionAt = program.getListing().getInstructionAt(addr(0x07000020));
		
		assertNotNull("Disassembled from computed branch", instructionAt);
		
		createCmd = new CreateFunctionCmd(addr(0x07000020));
		createCmd.applyTo(program);
		
		Function func20 = func(addr(0x07000020));
		
		builder.analyze();

		program.endTransaction(transactionID, true);
		
		assertTrue("is Thunk ", func8.isThunk());
		
		assertEquals("Normal function body size", 36, func20.getBody().getNumAddresses());
	}

	private Address addr(long l) {
		AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
		return addressSpace.getAddress(l);
	}

	private Function func(Address a) {
		FunctionManager fm = program.getFunctionManager();
		return fm.getFunctionAt(a);
	}

}
