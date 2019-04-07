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

import static org.junit.Assert.assertEquals;

import org.junit.*;

import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Test the changing of the ARM/Thumb bit for code flow
 * 
 *  ARM code:
 *   ADR r12=addr
 *   bx  r12
 * addr:
 *   Thumb code...
 *   
 *   Also tests that analysis puts on the correct reference on the r12, and not on the BX
 */
public class ArmThumbChangeDisassemblyTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;

	private Program program;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
	}

	@After
	public void tearDown() {
		if (program != null)
			env.release(program);
		program = null;
		env.dispose();
	}

	protected void setAnalysisOptions(String optionName) {
		int txId = program.startTransaction("Analyze");
		Options analysisOptions = program.getOptions(Program.ANALYSIS_PROPERTIES);
		analysisOptions.setBoolean(optionName, false);
		program.endTransaction(txId, true);
	}

	
	@Test
	public void testCorrectDisassembly() throws Exception {
		ProgramBuilder programBuilder = new ProgramBuilder("Test", ProgramBuilder._ARM);
		program = programBuilder.getProgram();
		int txId = program.startTransaction("Add Memory");// leave open until tearDown
		programBuilder.createMemory(".text", "1000", 64).setExecute(true);// initialized
		programBuilder.setBytes("1000", "ff ff ff ea 01 c0 8f e2 1c ff 2f e1 82 08 30 b5 70 47");
		
		programBuilder.disassemble("1000", 11, true);
		programBuilder.analyze();
		
		// should disassemble as ARM, then transition to Thumb
		Address instrAddr = programBuilder.addr("100c");
		Instruction instructionAt = program.getListing().getInstructionAt(instrAddr);
		Assert.assertNotEquals(null,instructionAt);
		
		assertEquals(6, program.getListing().getNumInstructions());
		
		RegisterValue registerValue = program.getProgramContext().getRegisterValue(program.getRegister("TMode"), instrAddr);

		assertEquals(1,registerValue.getUnsignedValue().intValue());
		
		// make sure reference put on operand 0, not mnemonic
		instrAddr = programBuilder.addr("1008");
		instructionAt = program.getListing().getInstructionAt(instrAddr);
		Reference[] operandReferences = instructionAt.getOperandReferences(0);
		assertEquals(1,operandReferences.length);
		assertEquals(0x100cL, operandReferences[0].getToAddress().getOffset());
	}
}
