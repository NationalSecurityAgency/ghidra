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

import java.math.BigInteger;

import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.app.plugin.core.analysis.ConstantPropagationAnalyzer;
import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
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
import ghidra.util.exception.NotFoundException;
import ghidra.util.task.TaskMonitor;

/**
 * quick and dirty test of the ProgramContextImpl just to see
 * if the values are being set for specified address range.
 * The ProgramContextPlugin will be a more complete test
 * program, with a gui interface to specify the values and
 * select/highlight an address range.
 */
public class ConstantPropogationReferenceTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private Program program;

	private ConstantPropagationAnalyzer analyzer;

	public ConstantPropogationReferenceTest() {
		super();
	}

	@Test
	public void testOperandRef_MIPS6432() throws Exception {

		builder = new ProgramBuilder("MIPS_6432", "MIPS:BE:64:64-32addr");

		// lui v0, 0x80a8
		// addiu v0, v0, -0xdf0
		// sw    v0, -0x46e8(gp)
		builder.setBytes("0x80a7f210",
			"00,00,00,00,3c,02,80,a8,24,42,f2,10,af,82,b9,18,01,01,01,01");

		builder.disassemble("0x80a7f214", 12);

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr("0x80a7f214");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(12));
		analyze(addressSet);

		Instruction instr = listing.getInstructionAt(addr("0x80a7f21c"));
		assertOperandReferenceTo(0, instr, addr("0x80a7f210"));
		assertNoOperandReference(1, instr);

		setRegister(codeStart, "gp", 0x90000000L);

		analyze(addressSet);

		assertOperandReferenceTo(1, instr, addr("0x8fffb918"));
	}

	@Test
	public void testBadAddressOffsetTracking() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._MIPS);

		builder.setBytes("0x1000",
			"3c 1c 00 14 27 9c b3 34 03 99 e0 21 27 bd ff e0" +
				"af bc 00 10 3c 07 12 34 24 e7 45 67 ac a7 00 10" +
				"3c 06 0a 0b 24 c6 0c 0d ae 06 00 10 8e 11 00 10" +
				"8c b1 00 10 8f b1 00 10 8e 51 00 10 ae 53 00 10" +
				"8e 51 00 10 36 92 00 00 8e 51 00 10 8e 92 00 10" +
				"3c 11 00 53 8e 51 00 10 03 e0 00 08 27 bd 00 20");

		//00001000        lui      gp,0x14
		//00001004        addiu    gp,gp,-0x4ccc
		//00001008        addu     gp,gp,t9
		//0000100c        addiu    sp,sp,-0x20
		//00001010        sw       gp,0x10(sp)
		//00001014        lui      a3,0x1234
		//00001018        addiu    a3,a3,0x4567
		//0000101c        sw       a3,0x10(a1)
		//00001020        lui      a2,0xa0b
		//00001024        addiu    a2,a2,0xc0d
		//00001028        sw       a2=>DAT_0a0b0c0d,0x10(s0)
		//0000102c        lw       s1,0x10(s0)
		//00001030        lw       s1,0x10(a1)
		//00001034        lw       s1,0x10(sp)
		//00001038        lw       s1,0x10(s2)
		//0000103c        sw       s3,0x10(s2)
		//00001040        lw       s1,0x10(s2)
		//00001044         ori      s2,s4,0x0
		//00001048         lw       s1,0x10(s2)
		//0000104c         lw       s2,0x10(s4)
		//00001050         lui      s1=>DAT_00530000,0x53
		//00001054         lw       s1,0x10(s2)
		//00001058         jr       ra
		//0000105c         _addiu   sp,sp,0x20

		builder.disassemble("0x1000", 88, false);

		builder.createFunction("0x1000");

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr("0x1000");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		setRegister(addr("0x1000"), "gp", 0x11200000);

		// follow all flows building up context
		// use context to fill out addresses on certain instructions 
		ContextEvaluator eval = new ConstantPropagationContextEvaluator(TaskMonitor.DUMMY, true) {
			@Override
			public boolean evaluateContextBefore(VarnodeContext context, Instruction instr) {

				// TODO Auto-generated method stub
				return super.evaluateContextBefore(context, instr);
			}

			private Varnode regValue(VarnodeContext context, String regName) {
				return context.getRegisterVarnodeValue(context.getRegister(regName));
			}

			@Override
			public boolean evaluateContext(VarnodeContext context, Instruction instr) {
				String loc = instr.getMinAddress().toString();
				Varnode registerVarnode;

				switch (loc) {
					case "00001010":
						// gp should be 0x14 + t9 offset space
						registerVarnode = regValue(context, "gp");
						assertTrue("symbolic value", context.isSymbol(registerVarnode));
						assertEquals("(t9, 0x13b334, 4)", registerVarnode.toString());
						// S3 should be S3 at entry
						registerVarnode = regValue(context, "s3");
						assertTrue("register s3", context.isRegister(registerVarnode));
						assertEquals("s3", context.getRegister(registerVarnode).getName());
						break;
					case "0000102c":
						// s1 restored from space 0x10(s0) space
						registerVarnode = regValue(context, "s1");
						assertTrue("constant value", registerVarnode.isConstant());
						assertEquals("(const, 0xa0b0c0d, 4)", registerVarnode.toString());
						break;
					case "00001030":
						// s1 restored from space 0x10(a1) space
						registerVarnode = regValue(context, "s1");
						assertTrue("symbolic value", registerVarnode.isConstant());
						assertEquals("(const, 0x12344567, 4)", registerVarnode.toString());
						break;
					case "00001034":
						// s1 restored from space 0x10(sp) space
						registerVarnode = regValue(context, "s1");
						assertTrue("symbolic value", context.isSymbol(registerVarnode));
						assertEquals("(t9, 0x13b334, 4)", registerVarnode.toString());
						break;
					case "00001038":
						// s1 restored from space 0x10(s2) space
						registerVarnode = regValue(context, "s1");
						//assertTrue("Still s1", registerVarnode.isRegister());
						boolean isBad = false;
						try {
							context.getConstant(registerVarnode, null);
						}
						catch (NotFoundException e) {
							isBad = true;
						}
						assertTrue("Can get constant value", isBad);
						break;
					case "00001040":
						// s1 restored from space 0x10(s2) space - stored a3
						registerVarnode = regValue(context, "s1");
						assertTrue("register s3", registerVarnode.isRegister());
						assertEquals("s3", context.getRegister(registerVarnode).getName());

						Address lastSetLocation = context.getLastSetLocation(
							context.getRegisterVarnode(context.getRegister("s2")), null);
						assertEquals("s2 last set", null, lastSetLocation);
						break;
					case "00001048":
						// s1 restored from space 0x10(s2) after s2 has been set again
						// it should no longer be s3 that was stored in another s2 relative space
						registerVarnode = regValue(context, "s1");
						//assertTrue("Still s1", registerVarnode.isRegister());
						isBad = false;
						try {
							context.getConstant(registerVarnode, null);
						}
						catch (NotFoundException e) {
							isBad = true;
						}
						assertTrue("Can get constant value", isBad);
						break;
					case "0000104c":
						// s1 restored from space 0x10(s2) after s2 has been set again
						// it should no longer be s3 that was stored in another s2 relative space
						registerVarnode = regValue(context, "s2");
						//assertTrue("Still s2", registerVarnode.isRegister());
						isBad = false;
						try {
							context.getConstant(registerVarnode, null);
						}
						catch (NotFoundException e) {
							isBad = true;
						}
						assertTrue("Can get constant value", isBad);
						lastSetLocation = context.getLastSetLocation(
							context.getRegisterVarnode(context.getRegister("s2")), null);
						assertEquals("s2 last set", 0x104fL, lastSetLocation.getOffset());
						break;
					case "00001054":
						// s1 restored from space 0x10(s2) after s2 has been set again
						// it should no longer be s3 that was stored in another s2 relative space
						registerVarnode = regValue(context, "s1");
						//assertTrue("Still s1", registerVarnode.isRegister());
						//assertEquals(context.getRegister(registerVarnode).getName(),"s1");
						isBad = false;
						try {
							context.getConstant(registerVarnode, null);
						}
						catch (NotFoundException e) {
							isBad = true;
						}
						assertTrue("Can get constant value", isBad);
						break;
				}
				return super.evaluateContext(context, instr);
			}
		};

		setRegister(addr("0x1000"), "s1", 0);
		SymbolicPropogator symEval = new SymbolicPropogator(program);

		Function func = program.getFunctionManager().getFunctionAt(builder.addr(0x1000));

		symEval.flowConstants(codeStart, func.getBody(), eval, true, TaskMonitor.DUMMY);

		Value registerValue = symEval.getRegisterValue(addr("0x1010"), null);
	}

	@Test
	public void testCorrectOperandConstantParam_X86_64() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._X64, "gcc", this);

		// PUSH     RBP
		// MOV      RBP,RSP
		// MOV      EDI,s_STRING_%s_%s_00040100
		// MOV      EAX,0x0
		// CALL     FUN_0004003d
		// LEAVE
		// RET

		builder.setBytes("0x00040000",
			"55 48 89 e5 bf 00 01 04 00 b8 00 00 00 00 66 67 e8 2a 00 c9 c3");

		builder.setBytes("0x00040100", "53 54 52 49 4e 47 20 25 73 20 25 73 0a 00 00");

		builder.disassemble("0x00040000", 21);

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr("0x00040000");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(21));
		analyze(addressSet);

		Instruction instr = listing.getInstructionAt(addr("0x00040004"));
		assertNoOperandReference(0, instr);
		assertOperandReferenceTo(1, instr, addr("0x00040100"));
	}

	@Test
	public void testOverlayReferences_AARCH64() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._AARCH64);

		//  Copy and use PasteCopiedListingsBytesScript
		//	00400000 fd 7b bf a9    stp        x29,x30,[sp, #local_10]!
		//	00400004 fd 03 00 91    mov        x29,sp
		//	00400008 60 00 00 d0    adrp       x0,0x40e000
		//	0040000c 01 00 24 91    add        x1,x0,#0x900
		//	00400010 60 00 00 d0    adrp       x0,0x40e000
		//	00400014 00 40 24 91    add        x0=>data:DWORD_0040e910,x0,#0x910
		//	00400018 e2 03 01 aa    mov        x2=>data:DWORD_0040e900,x1
		//	0040001c e1 15 80 52    mov        w1,#0xaf
		//	00400020 05 00 00 94    bl         FUN_00400034
		//	00400024 21 00 80 d2    mov        x1,#0x1
		//	00400028 40 00 80 d2    mov        x0,#0x2
		//	0040002c 02 00 00 94    bl         FUN_00400034
		//	00400030 c0 03 5f d6    ret
		//	
		//	00400034 c0 03 5f d6    ret
		//	00400038 00 00 00 00    ddw        0h
		//	0040003c 00 00 00 00    ddw        0h
		//	
		//	0040e900 53 74 72 69    ddw        53747269h
		//	0040e904 6e 67 50 61    ddw        6E675061h
		//	0040e908 72 61 6d 31    ddw        72616D31h
		//	0040e90c 00 00 00 00    ddw        0h
		//	
		//	0040e910 53 74 72 69    ddw        53747269h
		//	0040e914 6e 67 50 61    ddw        6E675061h
		//	0040e918 72 61 6d 32    ddw        72616D32h
		//	0040e91c 00 00 00 00    ddw        0h

		String ovBlockName = "textov";

		MemoryBlock textBlock = builder.createOverlayMemory(ovBlockName, "0x400000", 0x10000);

		builder.setBytes(textBlock.getStart().toString(),
			"fd 7b bf a9 fd 03 00 91 60 00 00 d0 01 00 24 91 60 00 00 d0 00 40 24 91 e2 03 01 aa e1 15 80 52 05 00 00 94 21 00 80 d2 40 00 80 d2 02 00 00 94 c0 03 5f d6 c0 03 5f d6");

		builder.setBytes(ovBlockName + ":" + "0x0040e900",
			"53 74 72 69 6e 67 50 61 72 61 6d 31 00 00 00 00 53 74 72 69 6e 67 50 61 72 61 6d 32 00 00 00 00");

		builder.disassemble(textBlock.getStart().toString(), 16 * 4);

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");
		Address codeStart = addr(ovBlockName + ":" + "0x00400000");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(16 * 4));
		analyze(addressSet);

		Instruction instr;
		instr = listing.getInstructionAt(addr(ovBlockName + ":" + "0x00400000").add(20));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr(ovBlockName + ":" + "0x0040e910"));

		instr = listing.getInstructionAt(addr(ovBlockName + ":" + "0x00400000").add(24));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr(ovBlockName + ":" + "0x0040e900"));
	}

	@Test
	public void testOverlayReferencesToBase_AARCH64() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._AARCH64);

		String ovBlockName = "textov";

		// Same as above test

		MemoryBlock textBlock = builder.createOverlayMemory(ovBlockName, "0x400000", 0x1000);

		builder.setBytes(textBlock.getStart().toString(),
			"fd 7b bf a9 fd 03 00 91 60 00 00 d0 01 00 24 91 60 00 00 d0 00 40 24 91 e2 03 01 aa e1 15 80 52 05 00 00 94 21 00 80 d2 40 00 80 d2 02 00 00 94 c0 03 5f d6 c0 03 5f d6");

		builder.setBytes("0x0040e900",
			"53 74 72 69 6e 67 50 61 72 61 6d 31 00 00 00 00 53 74 72 69 6e 67 50 61 72 61 6d 32 00 00 00 00");

		builder.disassemble(textBlock.getStart().toString(), 16 * 4);

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");
		Address codeStart = addr(ovBlockName + ":" + "0x00400000");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(16 * 4));
		analyze(addressSet);

		Instruction instr;
		instr = listing.getInstructionAt(addr(ovBlockName + ":" + "0x00400000").add(20));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr("0x0040e910"));

		instr = listing.getInstructionAt(addr(ovBlockName + ":" + "0x00400000").add(24));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr("0x0040e900"));
	}

	@Test
	public void testOverlayReferencesToSplit_AARCH64() throws Exception {

		builder = new ProgramBuilder("thunk", ProgramBuilder._AARCH64);

		String ovBlockName = "textov";

		// Same as above test

		MemoryBlock textBlock = builder.createOverlayMemory(ovBlockName, "0x400000", 0x1000);

		builder.setBytes(textBlock.getStart().toString(),
			"fd 7b bf a9 fd 03 00 91 60 00 00 d0 01 00 24 91 60 00 00 d0 00 40 24 91 e2 03 01 aa e1 15 80 52 05 00 00 94 21 00 80 d2 40 00 80 d2 02 00 00 94 c0 03 5f d6 c0 03 5f d6");

		builder.withTransaction(() -> {
			try {
				MemoryBlock dataBlock = builder.getProgram()
						.getMemory()
						.createInitializedBlock(ovBlockName,
							textBlock.getStart()
									.getAddressSpace()
									.getAddressInThisSpaceOnly(0x0040e900),
							0x100L, (byte) 0, TaskMonitor.DUMMY, false);

				builder.setBytes(dataBlock.getStart().toString(),
					"53 74 72 69 6e 67 50 61 72 61 6d 31 00 00 00 00 53 74 72 69 6e 67 50 61 72 61 6d 32 00 00 00 00");
			}
			catch (Exception e) {
				e.printStackTrace();
			}
		});

		builder.disassemble(textBlock.getStart().toString(), 16 * 4);

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");
		Address codeStart = addr(ovBlockName + ":" + "0x00400000");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(16 * 4));
		analyze(addressSet);

		Instruction instr;
		instr = listing.getInstructionAt(addr(ovBlockName + ":" + "0x00400000").add(20));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr(ovBlockName + ":" + "0x0040e910"));

		instr = listing.getInstructionAt(addr(ovBlockName + ":" + "0x00400000").add(24));
		assertNoOperandReference(1, instr);
		assertOperandReferenceTo(0, instr, addr(ovBlockName + ":" + "0x0040e900"));
	}

	@Test
	public void testPIC_Call_X86_64() throws Exception {

		builder = new ProgramBuilder("PICCode", ProgramBuilder._X64, "gcc", this);

		// entry
		// 48 83 ec 28                   SUB      RSP,0x28
		// e8 00 00 00 00                CALL     LAB_140020119
		// LAB_140020119
		// 8f c3                         POP      RBX
		// 48 8d 43 e0                   LEA      RAX,[RBX + -0x20]
		// ff d0                         CALL     RAX
		// 48 83 c4 28                   ADD      RSP,0x28
		// c3                            RET

		builder.setBytes("0x140020110",
			"48 83 ec 28 e8 00 00 00 00 8f c3 48 8d 43 e0 ff d0 48 83 c4 28 c3");

		builder.setBytes("0x1400200f9", "15 02 2f 00 00 89 05 e8 b9 00 00 48 83 c4 38");

		builder.disassemble("0x140020110", 21);

		analyzer = new ConstantPropagationAnalyzer();

		program = builder.getProgram();
		program.startTransaction("Test");

		Address codeStart = addr("140020110");
		Listing listing = program.getListing();
		assertNotNull("Bad instruction disassembly", listing.getInstructionAt(codeStart));

		AddressSet addressSet = new AddressSet(codeStart, codeStart.add(21));
		analyze(addressSet);

		Instruction instr = listing.getInstructionAt(addr("0x140020114"));
		assertOperandReferenceTo(0, instr, addr("0x140020119"));
		instr = listing.getInstructionAt(addr("0x140020119"));
		ReferenceIterator referenceIteratorTo = instr.getReferenceIteratorTo();
		Reference ref = referenceIteratorTo.next();
		assertTrue(ref.getReferenceType().isJump());
		instr = listing.getInstructionAt(addr("0x14002011f"));
		Reference[] referencesFrom = instr.getReferencesFrom();
		assertTrue(referencesFrom[0].getReferenceType().isFlow());
		assertEquals("1400200f9", referencesFrom[0].getToAddress().toString());
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

	private void setRegister(Address a, String regname, long value) throws Exception {
		ProgramContext context = program.getProgramContext();
		Register gp = context.getRegister(regname);
		context.setRegisterValue(a, a.add(12), new RegisterValue(gp, BigInteger.valueOf(value)));
	}

	private Address addr(String address) {
		return builder.addr(address);
	}
}
