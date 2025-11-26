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

import java.math.BigInteger;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.app.plugin.core.function.StackVariableAnalyzer;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.SymbolicPropogator.Value;
import ghidra.util.task.TaskMonitor;

/**
 * quick and dirty test of the ProgramContextImpl just to see
 * if the values are being set for specified address range.
 * The ProgramContextPlugin will be a more complete test
 * program, with a gui interface to specify the values and
 * select/highlight an address range.
 */
public class FunctionStackAnalysisCmdTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;

	private StackVariableAnalyzer analyzer;

	public FunctionStackAnalysisCmdTest() {
		super();
	}
	
	public void do16bitTest(String processor) throws Exception {
		
		builder = new ProgramBuilder("ProtectedMode", processor);

		/**
		 *  undefined __cdecl16near FUN_1000_00cc()
             1000:00cc 45             0              INC        BP
             1000:00cd 55             0              PUSH       BP
             1000:00ce 8b ec        002              MOV        BP,SP
             1000:00d0 56           002              PUSH       SI
             1000:00d1 57           004              PUSH       DI
             1000:00d2 8a 46 f0     006              MOV        AL,byte ptr [BP + local_12]
             1000:00d5 b4 4c        006              MOV        AH,0x4c
             1000:00d7 8b 56 08     006              MOV        DX,word ptr [BP + Stack[0x6]]
             1000:00da 8b 46 06     006              MOV        AX,word ptr [BP + Stack[0x4]]
             1000:00dd ff 76 08     006              PUSH       word ptr [BP + Stack[0x6]]
             1000:00e0 ff 76 ee     008              PUSH       word ptr [BP + local_14]
             1000:00e3 83 7e 06 00  00a              CMP        word ptr [BP + Stack[0x4]],0x0
             1000:00e7 dd 46 04     00a              FLD        double ptr [BP + Stack[0x2]]
             1000:00ea 07           00a              POP        ES
             1000:00eb c3           008              RET

		 */
		builder.setBytes("0x1000:00cc",
			"45 55 8b ec 56 57 8a 46 f0 b4 4c 8b 56 08 8b 46 06 ff 76 08 ff 76 ee 83 7e 06 00 dd 46 04 07 c3");

		builder.disassemble("0x1000:0x00CC", 48);

		analyzer = new StackVariableAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr("0x1000:0x00CC");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));
		
		builder.createFunction("0x1000:0x00cc");

		Instruction instr = listing.getInstructionAt(addr("0x1000:0x00d2"));
		assertNoOperandReference(0, instr);
		assertNoOperandReference(1, instr);

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(48));
		analyze(addressSet);

		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x0").subtract(0x12));
		
		instr = listing.getInstructionAt(addr("0x1000:0x00d7"));
		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x6"));
		
		instr = listing.getInstructionAt(addr("0x1000:0x00da"));
		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x4"));
		
		instr = listing.getInstructionAt(addr("0x1000:0x00dd"));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr("stack:0x6"));
		
		instr = listing.getInstructionAt(addr("0x1000:0x00e0"));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr("stack:0x0").subtract(0x14));
		
		instr = listing.getInstructionAt(addr("0x1000:0x00e3"));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr("stack:0x4"));
		
		instr = listing.getInstructionAt(addr("0x1000:0x00e7"));
		assertOperandReferenceTo(0, instr, addr("stack:0x2"));
	}

	@Test
	public void testOperandRef_x86ProtectedMode() throws Exception {
		do16bitTest("x86:LE:16:Protected Mode");
	}
	
	@Test
	public void testOperandRef_x86RealMode() throws Exception {
		do16bitTest("x86:LE:16:Real Mode");
	}
	
	@Test
	public void testMIPS64() throws Exception {
		builder = new ProgramBuilder("MIPS", "MIPS:LE:32:default");

		/**
		 *                                undefined FUN_9d010b2c()
              9d010b2c c0 ff bd 27    0              addiu      sp,sp,-0x40
              9d010b30 24 00 b0 af  040              sw         s0,local_1c(sp)
              9d010b34 01 a0 10 3c  040              lui        s0,0xa001
              9d010b38 40 5c 02 26  040              addiu      v0,s0,0x5c40
              9d010b3c 14 00 42 8c  040              lw         v0,0x14(v0)=>DAT_a0015c54
              9d010b40 3c 00 bf af  040              sw         ra,local_4(sp)
              9d010b44 31 00 43 2c  040              sltiu      v1,v0,0x31
              9d010b48 38 00 b5 af  040              sw         s5,local_8(sp)
              9d010b4c 34 00 b4 af  040              sw         s4,local_c(sp)
              9d010b50 30 00 b3 af  040              sw         s3,local_10(sp)
              9d010b54 2c 00 b2 af  040              sw         s2,local_14(sp)
              9d010b58 b7 05 60 10  040              beq        v1,zero,switchD_9d010b74
              9d010b5c 28 00 b1 af                   _sw        s1,local_18(sp)
              9d010b60 01 9d 03 3c  040              lui        v1,0x9d01
              9d010b64 80 10 02 00  040              sll        v0,v0,0x2
              9d010b68 7c 0b 63 24  040              addiu      v1,v1,0xb7c
              9d010b6c 21 10 62 00  040              addu       v0,v1,v0
              9d010b70 00 00 42 8c  040              lw         v0,0x0(v0)
              9d010b74 08 00 40 00  040              jr         v0

		 */
		String funcStartAddrString = "0x9d010b2c";
		builder.setBytes(funcStartAddrString,
			"c0 ff bd 27 24 00 b0 af 01 a0 10 3c 40 5c 02 26 14 00 42 8c 3c 00 bf af 31 00 43 2c 38 00 b5 af 34 "
			+ "00 b4 af 30 00 b3 af 2c 00 b2 af b7 05 60 10 28 00 b1 af 01 9d 03 3c 80 10 02 00 7c 0b 63 24 21 "
			+ "10 62 00 00 00 42 8c 08 00 40 00");

		builder.disassemble(funcStartAddrString, 72);

		analyzer = new StackVariableAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr(funcStartAddrString);
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));
		
		builder.createFunction(funcStartAddrString);

		Instruction instr = listing.getInstructionAt(addr("0x9d010b30"));
		assertNoOperandReference(0, instr);
		assertNoOperandReference(1, instr);

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(72));
		analyze(addressSet);

		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x0").subtract(0x1c));
		
		// should not create any memory refs, is stack analyzer
		instr = listing.getInstructionAt(addr("0x9d010b3c"));
		assertNoOperandReference(0, instr);
		assertNoOperandReference(1, instr);
		
		instr = listing.getInstructionAt(addr("0x9d010b40"));
		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x0").subtract(4));
		
		instr = listing.getInstructionAt(addr("0x9d010b48"));
		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x0").subtract(8));
		
		instr = listing.getInstructionAt(addr("0x9d010b4c"));
		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x0").subtract(12));
		
		// delay slot stack reference case
		instr = listing.getInstructionAt(addr("0x9d010b5c"));
		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("stack:0x0").subtract(0x18));
	}

	private void assertNoOperandReference(int opIndex, Instruction instr) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		assertEquals("No reference on operand " + opIndex, 0, refs.length);
	}

	private void assertOperandReferenceTo(int opIndex, Instruction instr, Address to) {
		Reference[] refs = instr.getOperandReferences(opIndex);
		assertEquals("Operand " + opIndex + " num refs", 1, refs.length);
		assertEquals("Operand " + opIndex + " Ref Check", to, refs[0].getToAddress());
	}

	private void analyze(AddressSet addrs) throws Exception {
		analyzer.added(program, addrs, TaskMonitor.DUMMY, null);
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
