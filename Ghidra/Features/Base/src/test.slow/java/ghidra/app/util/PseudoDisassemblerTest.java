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
package ghidra.app.util;

import static org.junit.Assert.assertEquals;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class PseudoDisassemblerTest extends AbstractGhidraHeadlessIntegrationTest {

	private ProgramBuilder programBuilder;// Instructions are 2-byte aligned 
	private Program program;
	private PseudoDisassembler disassembler;

	private int txId;

	@Before
	public void setUp() throws Exception {
		programBuilder = new ProgramBuilder("Test", ProgramBuilder._ARM);
		program = programBuilder.getProgram();
		txId = program.startTransaction("Add Memory");// leave open until tearDown
		programBuilder.createMemory(".text", "0", 64).setExecute(true);// initialized
		programBuilder.createUninitializedMemory(".unint", "0x40", 64).setExecute(true);// uninitialized
		programBuilder.createUninitializedMemory(".dat", "0x80", 64);// no-execute
		programBuilder.createMemory(".text2", "0x3e0", 0x800).setExecute(true);// initialized

		disassembler = new PseudoDisassembler(program);
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(txId, true);
		}
		if (programBuilder != null) {
			programBuilder.dispose();
		}
	}

	@Test
	public void testToStringArmSeparator() throws Exception {
		programBuilder.setBytes("0", "08 f8 00 00 40 00");// strb.w r0,[r8,r0,0x0]
		programBuilder.setRegisterValue("TMode", "0", "1", 1);
		PseudoInstruction instr =
			disassembler.disassemble(program.getAddressFactory().getAddress("0"));

		String str = instr.toString();
		assertEquals("strb.w r0,[r8,r0,lsl #0x0]", str);// wan't to make sure all markup is printed

		programBuilder.setBytes("0", "00 f0 20 03");// nopeq
		programBuilder.setRegisterValue("TMode", "0", "1", 0);
		instr = disassembler.disassemble(program.getAddressFactory().getAddress("0"));

		str = instr.toString();
		assertEquals("nopeq", str);
	}
}
