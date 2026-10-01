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
package ghidra.program.util;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.task.TaskMonitor;

/**
 * Constant folding of INT_RIGHT, INT_DIV and INT_REM, which are unsigned, and INT_SRIGHT,
 * which is signed. Each program below is loaded at 0x1000 and the register values are read
 * at the trailing return instruction.
 */
public class SymbolicPropogatorTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;
	private SymbolicPropogator symEval;

	@After
	public void tearDown() {
		if (builder != null) {
			builder.dispose();
		}
	}

	@Test
	public void testUnsignedShiftFold() throws Exception {
		// MOV RBX,-0x8000000000000000
		// SHR RBX,0x4
		// MOV RCX,-0x8000000000000000
		// SAR RCX,0x4
		// MOV R8,-0x8000000000000000
		// SHR R8,0x3c
		// MOV ESI,0xfffffff0
		// SAR ESI,0x4
		// MOV EDI,0xfffffff0
		// SHR EDI,0x4
		// RET
		Address ret = flowConstants(ProgramBuilder._X64,
			"48 bb 00 00 00 00 00 00 00 80 48 c1 eb 04 48 b9 00 00 00 00 00 00 00 80 " +
				"48 c1 f9 04 49 b8 00 00 00 00 00 00 00 80 49 c1 e8 3c be f0 ff ff ff " +
				"c1 fe 04 bf f0 ff ff ff c1 ef 04 c3");

		assertRegister(ret, "RBX", 0x0800000000000000L);
		assertRegister(ret, "RCX", 0xf800000000000000L);
		assertRegister(ret, "R8", 0x8L);
		assertRegister(ret, "RSI", 0xffffffffL);
		assertRegister(ret, "RDI", 0x0fffffffL);
	}

	@Test
	public void testUnsignedDivideAndRemainderFold() throws Exception {
		// MOV RDX,0x0
		// MOV RAX,-0x7fffffffffffffff
		// MOV RCX,0x3
		// DIV RCX
		// RET
		Address ret = flowConstants(ProgramBuilder._X64,
			"48 c7 c2 00 00 00 00 48 b8 01 00 00 00 00 00 00 80 48 c7 c1 03 00 00 00 " +
				"48 f7 f1 c3");

		assertRegister(ret, "RAX", 0x2aaaaaaaaaaaaaabL);
		assertRegister(ret, "RDX", 0x0L);
	}

	@Test
	public void testBitfieldInsertMaskFold() throws Exception {
		// mov x14,#0x0
		// mov x13,#-0x1
		// bfxil x14,x13,#0x0,#0x3e
		// ret
		//
		// AARCH64 builds the field mask as 0xffffffffffffffff >> (64 - width)
		Address ret = flowConstants(ProgramBuilder._AARCH64,
			"0e 00 80 d2 0d 00 80 92 ae f5 40 b3 c0 03 5f d6");

		assertRegister(ret, "x14", 0x3fffffffffffffffL);
	}

	private Address flowConstants(String languageName, String byteString) throws Exception {
		builder = new ProgramBuilder("propogate", languageName);
		builder.setBytes("0x1000", byteString);

		program = builder.getProgram();
		AddressSetView body = new AddressSet(program.getMemory());
		builder.disassemble(body, false);

		int id = program.startTransaction("Test");
		try {
			symEval = new SymbolicPropogator(program, false);
			symEval.flowConstants(builder.addr("0x1000"), body, new ContextEvaluatorAdapter(), true,
				TaskMonitor.DUMMY);
		}
		finally {
			program.endTransaction(id, true);
		}

		return program.getListing().getInstructionContaining(body.getMaxAddress()).getAddress();
	}

	private void assertRegister(Address address, String registerName, long expected) {
		Register register = program.getRegister(registerName);
		assertNotNull("No such register " + registerName, register);

		Value value = symEval.getRegisterValue(address, register);
		assertNotNull(registerName + " has no value at " + address, value);
		assertFalse(registerName + " is register relative", value.isRegisterRelativeValue());
		assertEquals(registerName, Long.toHexString(expected), Long.toHexString(value.getValue()));
	}
}
