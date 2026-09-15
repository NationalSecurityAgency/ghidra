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
package ghidra.program.model.pcode;

import static org.junit.Assert.*;

import org.apache.commons.lang3.StringUtils;
import org.junit.*;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.ParallelInstructionLanguageHelper;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractProgramBasedTest;

public class PcodeEmitContextCrossBuildTest extends AbstractProgramBasedTest {
	private ProgramBuilder builder;
	private Address baseAddr;
	private AddressSpace defaultSpace;
	private Listing listing;
	private SleighLanguage language;
	private Address testUniqueInCrossbuildAddr;
	private Address testCallotherOverrideSingletonPacketAddr;
	private ParallelInstructionLanguageHelper parallelHelper;
	private ReferenceManager refManager;
	private Address func1Addr;
	private Address testCallotherOverrideCrossbuildAddr;
	private Address func2Addr;
	private Address testFallthroughOverrideTerminalAddr;
	private Address testFallthroughOverrideMidPacketAddr;
	private Address testFlowOverrideSingletonCallAddr;
	private Address testFlowOverrideCallInPacketAddr;
	private Address testUniqueSubpieceAddr;
	private Address testRegisterSubpieceAddr;

	private static final int ASL_PLUS_INSTANCES = 16;

	//singleton instruction packet whose pcode has exactly one varnode in the unique space
	private static final String ASL_PLUS_TERMINAL_BYTES = "c0 c0 01 8e ";

	// example of lower SUBPIECE use on unique
	private static final String VASRW_BYTES = "44 c2 00 c5";

	// example of lower SUBPIECE use on register
	private static final String BOUNDSCHECK_BYTES = "a1 e2 02 d2";

	private static final String ADDSAT_NON_TERMINAL_BYTES = "80 40 00 d5 ";

	private static final String MEMW_LOCKED_NON_TERMINAL_BYTES = "00 42 b0 a0 ";

	private static final String MEMW_LOCKED_TERMINAL_BYTES = "00 c2 b0 a0 ";

	private static final String CALL_TERMINAL_BYTES = "c6 c7 00 5a ";

	private static final String CALL_NON_TERMINAL_BYTES = "c4 47 00 5a ";

	private static final String BASE_ADDRESS = "0x100000";

	private static final String DEST_FUNC1_ADDR = "0x101000";

	private static final String DEST_FUNC2_ADDR = "0x102000";

	@Before
	public void setup() throws Exception {
		buildProgram();
		initialize();
	}

	@Override
	@After
	public void tearDown() throws Exception {
		env.dispose();
		builder.dispose();
	}

	@Override
	public Program getProgram() {
		return program;
	}

	private void buildProgram() throws Exception {
		builder = new ProgramBuilder("crossbuildEmitTest", "Hexagon:LE:32:default");
		builder.createMemory(".text", BASE_ADDRESS, 0x10000);
		builder.createEmptyFunction("func1", DEST_FUNC1_ADDR, 4, null);
		builder.createEmptyFunction("func2", DEST_FUNC2_ADDR, 4, null);

		//testUniqueAddresses
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < ASL_PLUS_INSTANCES; i++) {
			sb.append(ASL_PLUS_TERMINAL_BYTES);
		}

		//testUniqueInCrossbuild
		sb.append(ASL_PLUS_TERMINAL_BYTES);
		sb.append(ADDSAT_NON_TERMINAL_BYTES);
		sb.append(ASL_PLUS_TERMINAL_BYTES);

		//testCallotherOverrideSingletonPacket
		sb.append(MEMW_LOCKED_TERMINAL_BYTES);

		//testCallotherOverrideCrossbuild
		sb.append(MEMW_LOCKED_NON_TERMINAL_BYTES);
		sb.append(ASL_PLUS_TERMINAL_BYTES);

		//testFallthroughOverrideTerminal
		sb.append(ASL_PLUS_TERMINAL_BYTES);
		sb.append(ASL_PLUS_TERMINAL_BYTES);
		sb.append(ASL_PLUS_TERMINAL_BYTES);

		//testFallthroughOverrideMidPacket
		sb.append(MEMW_LOCKED_NON_TERMINAL_BYTES);
		sb.append(ADDSAT_NON_TERMINAL_BYTES);
		sb.append(ASL_PLUS_TERMINAL_BYTES);
		sb.append(ASL_PLUS_TERMINAL_BYTES);

		//testFlowOverrideSingleCall
		sb.append(CALL_TERMINAL_BYTES);

		//testFlowOverrideCallInPacket
		//testSimpleCallReferenceOverride
		sb.append(CALL_NON_TERMINAL_BYTES);
		sb.append(ASL_PLUS_TERMINAL_BYTES);

		// testUniqueSubpiece (access directly at sub-offset of unique varnode)
		sb.append(VASRW_BYTES);

		// testRegisterSubpiece
		sb.append(BOUNDSCHECK_BYTES);

		String byteString = sb.toString().trim();
		builder.setBytes(BASE_ADDRESS, byteString);
		int byteLength = (byteString.length() - StringUtils.countMatches(byteString, ' ')) / 2;

		builder.disassemble(BASE_ADDRESS, byteLength, false);
		program = builder.getProgram();
		defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		baseAddr = defaultSpace.getAddress(BASE_ADDRESS);
		testUniqueInCrossbuildAddr = baseAddr.add(ASL_PLUS_INSTANCES * 4);
		testCallotherOverrideSingletonPacketAddr = testUniqueInCrossbuildAddr.add(12);
		listing = program.getListing();
		language = (SleighLanguage) program.getLanguage();
		parallelHelper = language.getParallelInstructionHelper();
		refManager = program.getReferenceManager();
		func1Addr = defaultSpace.getAddress(DEST_FUNC1_ADDR);
		testCallotherOverrideCrossbuildAddr = testCallotherOverrideSingletonPacketAddr.add(4);
		func2Addr = defaultSpace.getAddress(DEST_FUNC2_ADDR);
		testFallthroughOverrideTerminalAddr = testCallotherOverrideCrossbuildAddr.add(8);
		testFallthroughOverrideMidPacketAddr = testFallthroughOverrideTerminalAddr.add(12);
		testFlowOverrideSingletonCallAddr = testFallthroughOverrideMidPacketAddr.add(16);
		testFlowOverrideCallInPacketAddr = testFlowOverrideSingletonCallAddr.add(4);
		testUniqueSubpieceAddr = testFlowOverrideCallInPacketAddr.add(8);
		testRegisterSubpieceAddr = testUniqueSubpieceAddr.add(4);
	}

	/**
	 * Test that offsets of varnodes in the unique space are adjusted based on
	 * the unique allocation mask of the language and the address of an 
	 * instruction.
	 * 
	    00100000 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100004 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100008 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    0010000c c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100010 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100014 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100018 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    0010001c c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100020 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100024 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100028 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    0010002c c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100030 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100034 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100038 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    0010003c c0 c0 01 8e            asl+=      R0,R1,#0x0 
	 */
	@Test
	public void testUniqueAddresses() {
		int uniqueMask = language.getUniqueAllocationMask();
		assertEquals(0xff, uniqueMask);
		for (int i = 0; i < ASL_PLUS_INSTANCES; ++i) {
			//verify the test instruction
			Instruction inst = listing.getInstructionAt(baseAddr.add(4 * i));
			assertNotNull(inst);
			assertEquals("asl+= R0,R1,#0x0", inst.toString().trim());
			assertFalse(parallelHelper.isParallelInstruction(inst));
			assertTrue(parallelHelper.isEndOfParallelInstructionGroup(inst));
			PcodeOp[] ops = inst.getPcode();
			assertEquals(8, ops.length);

			//verify the op with output in the unique space
			PcodeOp shift = ops[4];
			assertEquals(PcodeOp.INT_LEFT, shift.getOpcode());
			Varnode shiftOut = shift.getOutput();
			assertNotNull(shiftOut);
			assertTrue(shiftOut.isUnique());

			//verify that the address in the unique space has the adjustment
			//or'd in 
			long actualOffset = shiftOut.getOffset();
			long adjustment = (inst.getAddress().getOffset() & uniqueMask) << 8;
			if (i == 0) {
				assertTrue(adjustment == 0);
			}
			else {
				assertTrue(adjustment != 0);
			}
			assertEquals(actualOffset, actualOffset | adjustment);
		}
	}

	/**
	 * Tests that a unique defined in the main section of an instruction and used in a named 
	 * section is correctly referenced in the pcode of a separate instruction that crossbuilds the 
	 * named section.
	 * 
	    00100040 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	    00100044 80 40 00 d5            add:sat    R0,R0.L,R0.L 
	    00100048 c0 c0 01 8e  ||        asl+=      R0,R1,#0x0 
	 */
	@Test
	public void testUniqueInCrossbuild() {
		//verify the instructions used in the test
		Instruction aslSingleton = listing.getInstructionAt(testUniqueInCrossbuildAddr);
		Instruction addSat = listing.getInstructionAt(testUniqueInCrossbuildAddr.add(4));
		Instruction aslPacket = listing.getInstructionAt(testUniqueInCrossbuildAddr.add(8));
		assertNotNull(aslSingleton);
		assertEquals("asl+= R0,R1,#0x0", aslSingleton.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(aslSingleton));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(aslSingleton));
		assertNotNull(addSat);
		assertEquals("add:sat R0,R0.L,R0.L", addSat.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(addSat));
		assertFalse(parallelHelper.isEndOfParallelInstructionGroup(addSat));
		assertNotNull(aslPacket);
		assertEquals("asl+= R0,R1,#0x0", aslPacket.toString().trim());
		assertTrue(parallelHelper.isParallelInstruction(aslPacket));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(aslPacket));

		//grab the unique varnode which is the output of the SCARRY op in addSat
		long uniqueOffset = -1;
		long uniqueSize = 0;
		for (PcodeOp op : addSat.getPcode()) {
			if (op.getOpcode() == PcodeOp.INT_SCARRY) {
				Varnode uniqueOut = op.getOutput();
				assertTrue(uniqueOut.isUnique());
				uniqueOffset = uniqueOut.getOffset();
				uniqueSize = uniqueOut.getSize();
				break;
			}
		}
		//verify that we found the INT_SCARRY op
		assertFalse(uniqueOffset == -1);

		//verify that this varnode is an input to an op in the pcode for aslPacket
		boolean foundIt = false;
		for (PcodeOp op : aslPacket.getPcode()) {
			if (op.getOpcode() == PcodeOp.INT_OR) {
				Varnode uniqueIn = op.getInput(1);
				assertTrue(uniqueIn.isUnique());
				assertEquals(uniqueOffset, uniqueIn.getOffset());
				assertEquals(uniqueSize, uniqueIn.getSize());
				foundIt = true;
				break;
			}
		}
		assertTrue(foundIt);

		//verify that the singleton asl instruction does not have an INT_OR op
		//(so the INT_OR op must have come from a crossbuild from the add:sat instruction)
		foundIt = false;
		for (PcodeOp op : aslSingleton.getPcode()) {
			if (op.getOpcode() == PcodeOp.INT_OR) {
				foundIt = true;
			}
		}
		assertFalse(foundIt);
	}

	/**
	 * Tests that a unique lower-subpiece (LE) on a COPY directly access the smaller portion
	 * of the unique varnode.
	 * 
	    00100080 44 c2 00 c5            vasrw R4,R1R0,R2 
	 */
	@Test
	public void testUniqueSubpiece() {

		// NOTE: Really need big-endian language to fully test

		//verify the instructions used in the test
		Instruction vasrwSingleton = listing.getInstructionAt(testUniqueSubpieceAddr);
		assertNotNull(vasrwSingleton);
		assertEquals("vasrw R4,R1R0,R2", vasrwSingleton.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(vasrwSingleton));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(vasrwSingleton));

		//grab the unique varnode which is the input of the SCARRY op in addSat
		long uniqueOffset = -1;
		long uniqueSize = 0;
		boolean foundIt = false;
		for (PcodeOp op : vasrwSingleton.getPcode()) {
			if (op.getOpcode() == PcodeOp.INT_ADD) {
				Varnode uniqueOut = op.getOutput();
				assertTrue(uniqueOut.isUnique());
				uniqueOffset = uniqueOut.getOffset();
				assertEquals(0, uniqueOffset & 0x7f);
				uniqueSize = uniqueOut.getSize();
				assertEquals(4, uniqueSize);
			}
			else if (uniqueOffset != -1 && op.getOpcode() == PcodeOp.COPY) {
				Varnode uniqueIn = op.getInputs()[0];
				assertTrue(uniqueIn.isUnique());
				assertEquals(uniqueOffset, uniqueIn.getOffset());
				assertEquals(2, uniqueIn.getSize());
				foundIt = true;
				break;
			}
		}
		//verify that we found the INT_ADD and COPY ops
		assertFalse(uniqueOffset == -1);
		assertTrue(foundIt);
	}

	/**
	 * Tests that a register lower-subpiece (LE) on uses the SUBPIECE op properly
	 * 
	    00100084 a1 e2 02 d2            boundscheck:raw:hi P1,R3R2,R3R2
	 */
	@Test
	public void testRegisterSubpiece() {

		// NOTE: Really need big-endian language to fully test

		//verify the instructions used in the test
		Instruction boundscheckSingleton = listing.getInstructionAt(testRegisterSubpieceAddr);
		assertNotNull(boundscheckSingleton);
		assertEquals("boundscheck:raw:hi P1,R3R2,R3R2", boundscheckSingleton.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(boundscheckSingleton));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(boundscheckSingleton));

		//grab the unique varnode which is the input of the SCARRY op in addSat
		long uniqueOffset = -1;
		long uniqueSize = 0;
		boolean foundIt = false;
		for (PcodeOp op : boundscheckSingleton.getPcode()) {
			if (op.getOpcode() == PcodeOp.SUBPIECE) {

				// Check output
				Varnode uniqueOut = op.getOutput();
				assertTrue(uniqueOut.isUnique());
				uniqueOffset = uniqueOut.getOffset();
				assertEquals(0, uniqueOffset & 0x7f);
				uniqueSize = uniqueOut.getSize();
				assertEquals(4, uniqueSize);

				// Check inputs
				Varnode[] inputs = op.getInputs();
				assertTrue(inputs[0].isRegister());
				assertEquals(8, inputs[0].getOffset());
				assertEquals(8, inputs[0].getSize());
				assertTrue(inputs[1].isConstant());
				assertEquals(4, inputs[1].getOffset());
				assertEquals(4, inputs[1].getSize());
				foundIt = true;
				break;
			}
		}
		//verify that we found the SUBPIECE op
		assertFalse(uniqueOffset == -1);
		assertTrue(foundIt);
	}

	/**
	 * Verify that a CALLOTHER_OVERRIDE_CALL reference modifies the
	 * first CALLOTHER op in a singleton instruction packet
	 * 
	     0010004c 00 c2 b0 a0            memw_loc   (R16,P0),R2 
	 */
	@Test
	public void testCallotherOverrideSingletonPacket() {
		//verify the instruction used in the test
		Instruction memw_locked_last =
			listing.getInstructionAt(testCallotherOverrideSingletonPacketAddr);
		assertNotNull(memw_locked_last);
		assertEquals("memw_locked (R16,P0),R2", memw_locked_last.toString().trim());
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(memw_locked_last));

		//verify that the pcode from the instruction doesn't change if you 
		//request overrides
		PcodeOp[] memw_locked_last_original = memw_locked_last.getPcode();
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_locked_last_original,
			memw_locked_last.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_locked_last_original,
			memw_locked_last.getPcode(true)));

		//apply a CALLOTHER_OVERRIDE_CALL reference	
		int id = program.startTransaction("test");
		Reference overrideRef =
			refManager.addMemoryReference(testCallotherOverrideSingletonPacketAddr, func1Addr,
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRef, true);
		program.endTransaction(id, true);

		//verify that the pcode doesn't change if you request no overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_locked_last_original,
			memw_locked_last.getPcode()));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_locked_last_original,
			memw_locked_last.getPcode(false)));

		//verify that the first CALLOTHER op is changed to a CALL if you request overrides
		PcodeOp[] memw_locked_last_overridden = memw_locked_last.getPcode(true);
		assertEquals(memw_locked_last_original.length, memw_locked_last_overridden.length);
		assertEquals(14, memw_locked_last_overridden.length);
		for (int i = 0; i < 14; ++i) {
			PcodeOp orig = memw_locked_last_original[i];
			PcodeOp overridden = memw_locked_last_overridden[i];
			if (i == 4) {
				assertEquals(PcodeOp.CALLOTHER, orig.getOpcode());
				assertEquals(PcodeOp.CALL, overridden.getOpcode());
			}
			else {
				if (i == 12) {
					//just to document that a second CALLOTHER op exists (and is unchanged)
					assertEquals(PcodeOp.CALLOTHER, overridden.getOpcode());
				}
				assertTrue(PcodeEmitContextTest.equalPcodeOps(orig, overridden));
			}
		}
	}

	/**
	 * Tests applying CALLOTHER_OVERRIDE_CALL references to an instruction with two CALLOTHER
	 * ops, one in the main section and another in a named section.  When this instruction is
	 * part of a packet, placing an overriding reference on the address corresponding to the
	 * main section will override the first (main) CALLOTHER, and placing a reference on the
	 * (separate) address corresponding to the named section will override the second CALLOTHER.
	 *
	     00100050 00 42 b0 a0            memw_loc   (R16,P0),R2 
	     00100054 c0 c0 01 8e  ||        asl+=      R0,R1,#0x0 
	 *
	 */
	@Test
	public void testCallotherOverrideCrossbuild() {
		//verify the instructions used for the test
		Instruction memw_locked_nonterminal =
			listing.getInstructionAt(testCallotherOverrideCrossbuildAddr);
		Instruction asl_plus_last =
			listing.getInstructionAfter(testCallotherOverrideCrossbuildAddr);
		assertNotNull(memw_locked_nonterminal);
		assertEquals("memw_locked (R16,P0),R2", memw_locked_nonterminal.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(memw_locked_nonterminal));
		assertFalse(parallelHelper.isEndOfParallelInstructionGroup(memw_locked_nonterminal));
		assertNotNull(asl_plus_last);
		assertEquals("asl+= R0,R1,#0x0", asl_plus_last.toString().trim());
		assertTrue(parallelHelper.isParallelInstruction(asl_plus_last));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(asl_plus_last));

		//verify that the pcode is the same whether or not you ask for overrides
		PcodeOp[] memw_unmod = memw_locked_nonterminal.getPcode();
		assertEquals(7, memw_unmod.length);
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode(true)));
		PcodeOp[] asl_plus_unmod = asl_plus_last.getPcode();
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus_last.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus_last.getPcode(true)));

		//apply override at the address of the main section
		int id = program.startTransaction("test");
		Reference overrideRefMain =
			refManager.addMemoryReference(memw_locked_nonterminal.getAddress(), func1Addr,
				RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRefMain, true);
		program.endTransaction(id, true);

		//verify that the pcode does not change if you ask for no overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode()));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode(false)));

		//verify that the callother op in the main section is changed but in named section 
		//it is not
		PcodeOp[] memw_mod = memw_locked_nonterminal.getPcode(true);
		assertEquals(memw_unmod.length, memw_mod.length);
		for (int i = 0; i < memw_unmod.length; ++i) {
			if (i == 4) {
				assertEquals(PcodeOp.CALL, memw_mod[i].getOpcode());
				assertEquals(func1Addr.getOffset(), memw_mod[i].getInput(0).getOffset());
				assertTrue(memw_mod[i].getInput(0).isAddress());
				assertEquals(PcodeOp.CALLOTHER, memw_unmod[i].getOpcode());
			}
			else {
				assertTrue(PcodeEmitContextTest.equalPcodeOps(memw_unmod[i], memw_mod[i]));
			}
		}
		assertEquals(10, asl_plus_unmod.length);
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus_last.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus_last.getPcode(true)));

		//apply a second override at the address of the named section
		id = program.startTransaction("test");
		Reference overrideRefNamed = refManager.addMemoryReference(asl_plus_last.getAddress(),
			func2Addr, RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRefNamed, true);
		program.endTransaction(id, true);

		//verify no changes if you request no overrides
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus_last.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode(false)));

		//verify that both CALLOTHER ops are changed if you do request overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_mod,
			memw_locked_nonterminal.getPcode(true)));
		PcodeOp[] asl_plus_mod = asl_plus_last.getPcode(true);
		assertEquals(asl_plus_unmod.length, asl_plus_mod.length);
		for (int i = 0; i < asl_plus_unmod.length; ++i) {
			if (i == 8) {
				assertEquals(PcodeOp.CALLOTHER, asl_plus_unmod[i].getOpcode());
				assertEquals(PcodeOp.CALL, asl_plus_mod[i].getOpcode());
				assertEquals(func2Addr.getOffset(), asl_plus_mod[i].getInput(0).getOffset());
				assertTrue(asl_plus_mod[i].getInput(0).isAddress());
			}
			else {
				assertTrue(PcodeEmitContextTest.equalPcodeOps(asl_plus_unmod[i], asl_plus_mod[i]));
			}
		}

		//set the override at the address of the main section to non-primary
		id = program.startTransaction("test");
		refManager.setPrimary(overrideRefMain, false);
		program.endTransaction(id, true);

		//verify that the CALLOTHER in the main section is unchanged 
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode()));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_unmod,
			memw_locked_nonterminal.getPcode(true)));

		//verify that the CALLOTHER op in the names section is unchanged if you
		//request no overrides
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus_last.getPcode()));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus_last.getPcode(false)));

		//verify the CALLOTHER op in the named section is changed if you request overrides
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_mod, asl_plus_last.getPcode(true)));
	}

	/**
	 * Tests that a fallthrough override applied to a singleton packet simply appends a
	 * BRANCH op.
	 * 
	     00100058 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	     0010005c c0 c0 01 8e            asl+=      R0,R1,#0x0 
	     00100060 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	 */
	@Test
	public void testFallthroughOverrideTerminal() {
		//verify the instruction used in the test
		Instruction aslTerminal = listing.getInstructionAt(testFallthroughOverrideTerminalAddr);
		assertNotNull(aslTerminal);
		assertEquals("asl+= R0,R1,#0x0", aslTerminal.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(aslTerminal));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(aslTerminal));

		//verify that asking for overrides has no effect on the pcode
		PcodeOp[] asl_unmod = aslTerminal.getPcode();
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(asl_unmod, aslTerminal.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(asl_unmod, aslTerminal.getPcode(true)));

		//apply a fallthrough override
		int id = program.startTransaction("test");
		aslTerminal.setFallThrough(aslTerminal.getAddress().add(8));
		program.endTransaction(id, true);

		//verify that pcode is unchanged if you request no overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(asl_unmod, aslTerminal.getPcode()));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(asl_unmod, aslTerminal.getPcode(false)));

		//verify that if you request override a BRANCH op is appended to the pcode for the
		//instruction and that there are no other changes
		PcodeOp[] asl_mod = aslTerminal.getPcode(true);
		assertEquals(asl_unmod.length + 1, asl_mod.length);
		for (int i = 0; i < asl_unmod.length; ++i) {
			assertTrue(PcodeEmitContextTest.equalPcodeOps(asl_unmod[i], asl_mod[i]));
		}
		PcodeOp appended = asl_mod[asl_mod.length - 1];
		assertEquals(PcodeOp.BRANCH, appended.getOpcode());
		assertTrue(appended.getInput(0).isAddress());
		assertEquals(aslTerminal.getAddress().add(8).getOffset(), appended.getInput(0).getOffset());
	}

	/**
	 * Tests that a fallthrough override applied to an instruction in a packet appends
	 * a branch to the main section and does not change the pcode in a named section.
	 * 
	     00100064 00 42 b0 a0            memw_loc   (R16,P0),R2 
	     00100068 80 40 00 d5  ||        add:sat    R0,R0.L,R0.L 
	     0010006c c0 c0 01 8e  ||        asl+=      R0,R1,#0x0 
	     00100070 c0 c0 01 8e            asl+=      R0,R1,#0x0 
	 */
	@Test
	public void testFallthroughOverrideMidPacket() {
		//verify the instructions used in the test
		Instruction memw_locked = listing.getInstructionAt(testFallthroughOverrideMidPacketAddr);
		assertNotNull(memw_locked);
		assertEquals("memw_locked (R16,P0),R2", memw_locked.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(memw_locked));
		assertFalse(parallelHelper.isEndOfParallelInstructionGroup(memw_locked));
		Instruction addSat = listing.getInstructionAfter(memw_locked.getAddress());
		assertNotNull(addSat);
		assertEquals("add:sat R0,R0.L,R0.L", addSat.toString().trim());
		assertTrue(parallelHelper.isParallelInstruction(addSat));
		assertFalse(parallelHelper.isEndOfParallelInstructionGroup(addSat));
		Instruction aslTerminal = listing.getInstructionAfter(addSat.getAddress());
		assertNotNull(aslTerminal);
		assertEquals("asl+= R0,R1,#0x0", aslTerminal.toString().trim());
		assertTrue(parallelHelper.isParallelInstruction(aslTerminal));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(aslTerminal));

		//verify that pcode unchanged when asking for overrides to be applied
		PcodeOp[] memw_locked_unmod = memw_locked.getPcode();
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_locked_unmod,
			memw_locked.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(memw_locked_unmod, memw_locked.getPcode(true)));
		PcodeOp[] addSat_unmod = addSat.getPcode();
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(addSat_unmod, addSat.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(addSat_unmod, addSat.getPcode(true)));
		PcodeOp[] aslTerminal_unmod = aslTerminal.getPcode();
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(aslTerminal_unmod,
			aslTerminal.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(aslTerminal_unmod, aslTerminal.getPcode(true)));

		//verify that the pcode for aslTerminal contains an "unlock" pcodeop (crossbuilt from memw_locked)
		PcodeOp callother = aslTerminal_unmod[15];
		assertEquals(PcodeOp.CALLOTHER, callother.getOpcode());
		assertEquals("unlock",
			language.getUserDefinedOpName((int) callother.getInput(0).getOffset()));

		//apply the fallthrough override
		int id = program.startTransaction("test");
		memw_locked.setFallThrough(memw_locked.getAddress().add(12));
		program.endTransaction(id, true);

		//verify that pcode at address of main section is unchanged when overrides are not applied
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(memw_locked_unmod,
			memw_locked.getPcode(false)));

		//verify that the pcode at the address for the main section has a BRANCH appended when
		//overrides are applied and is otherwise unchanged
		PcodeOp[] memw_locked_mod = memw_locked.getPcode(true);
		assertEquals(memw_locked_unmod.length + 1, memw_locked_mod.length);
		for (int i = 0; i < memw_locked_unmod.length; ++i) {
			assertTrue(
				PcodeEmitContextTest.equalPcodeOps(memw_locked_unmod[i], memw_locked_mod[i]));
		}
		PcodeOp appended = memw_locked_mod[memw_locked_mod.length - 1];
		assertEquals(PcodeOp.BRANCH, appended.getOpcode());
		assertEquals(memw_locked.getAddress().add(12).getOffset(),
			appended.getInput(0).getOffset());
		assertTrue(appended.getInput(0).isAddress());

		//verify that pcode at address where the named section is crossbuilt is unchanged
		//whether or not overides are requested
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(aslTerminal_unmod, aslTerminal.getPcode()));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(aslTerminal_unmod,
			aslTerminal.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(aslTerminal_unmod, aslTerminal.getPcode(true)));

	}

	/**
	 * Tests that a BRANCH override applied to a CALL instruction in a singleton
	 * packet replaes the CALL op with a BRANCH
	 * 
	      00100074 c6 c7 00 5a            call       func1                                                                                               undefined func1(void)
	 */
	@Test
	public void testFlowOverrideSingletonCall() {
		//verify the instructions used in the test
		Instruction call = listing.getInstructionAt(testFlowOverrideSingletonCallAddr);
		assertNotNull(call);
		assertEquals("call 0x00101000", call.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(call));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(call));

		//verify that the pcode is the same whether or not you request overrides
		PcodeOp[] call_unmod = call.getPcode();
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(true)));
		assertEquals(7, call_unmod.length);

		//verify the CALL op exists
		assertEquals(PcodeOp.CALL, call_unmod[6].getOpcode());
		assertEquals(func1Addr, call_unmod[6].getInput(0).getAddress());

		//apply the fallthrough override
		int id = program.startTransaction("test");
		call.setFlowOverride(FlowOverride.BRANCH);
		program.endTransaction(id, true);

		//verify that nothing changes if you ask for no overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(false)));

		//verify that the CALL is changed to a BRANCH if you request overrides
		//and there are no other changes
		PcodeOp[] call_mod = call.getPcode(true);
		assertEquals(call_unmod.length, call_mod.length);
		for (int i = 0; i < call_mod.length - 1; i++) {
			assertTrue(PcodeEmitContextTest.equalPcodeOps(call_unmod[i], call_mod[i]));
		}
		PcodeOp overridden = call_mod[6];
		assertTrue(PcodeEmitContextTest.equalInputsAndOutput(overridden, call_unmod[6]));
		assertEquals(PcodeOp.BRANCH, overridden.getOpcode());
	}

	/**
	 * Tests that to override the flow of a CALL instruction in a packet the flow override
	 * must be placed on the instruction where the CALL op is crossbuilt (which is not the "call" 
	 * instruction in this example).
	 * 
	     00100078 c4 47 00 5a            call       func1 
	     0010007c c0 c0 01 8e  ||        asl+=      R0,R1,#0x0                                                                                          undefined func1(void)
	 */
	@Test
	public void testFlowOverrideCallInPacket() {
		//verify the instructions used in the test
		Instruction call = listing.getInstructionAt(testFlowOverrideCallInPacketAddr);
		assertNotNull(call);
		assertEquals("call 0x00101000", call.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(call));
		assertFalse(parallelHelper.isEndOfParallelInstructionGroup(call));
		Instruction asl_plus = listing.getInstructionAfter(call.getAddress());
		assertNotNull(asl_plus);
		assertEquals("asl+= R0,R1,#0x0", asl_plus.toString().trim());
		assertTrue(parallelHelper.isParallelInstruction(asl_plus));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(asl_plus));

		PcodeOp[] call_unmod = call.getPcode();
		PcodeOp[] asl_plus_unmod = asl_plus.getPcode();

		//verify that there are no changes if you ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(true)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(true)));

		//apply a BRANCH override at the address of the call instruction.  This should have
		//no effect on the pcode, since the CALL op is in a named section and will be crossbuilt
		//into the pcode of the next instruction 
		//(note that the associated action would be disabled in the gui for the call instruction)
		int id = program.startTransaction("test");
		call.setFlowOverride(FlowOverride.BRANCH);
		program.endTransaction(id, true);

		// verify no changes whether or not you ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(true)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(true)));

		//apply a BRANCH override at the address of the asl instruction.
		id = program.startTransaction("test");
		asl_plus.setFlowOverride(FlowOverride.BRANCH);
		program.endTransaction(id, true);

		// verify no changes if you don't ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(false)));

		//pcode for call instruction should not change if you ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(true)));

		//verify that the CALL instruction becomes a BRANCH when overrides are requested
		//and that there are no other changes
		PcodeOp[] asl_plus_mod = asl_plus.getPcode(true);
		assertEquals(asl_plus_unmod.length, asl_plus_mod.length);
		for (int i = 0; i < asl_plus_unmod.length; ++i) {
			PcodeOp mod = asl_plus_mod[i];
			PcodeOp unmod = asl_plus_unmod[i];
			if (i < (asl_plus_unmod.length - 1)) {
				assertTrue(PcodeEmitContextTest.equalPcodeOps(unmod, mod));
			}
			else {
				assertTrue(PcodeEmitContextTest.equalInputsAndOutput(unmod, mod));
				assertEquals(PcodeOp.CALL, unmod.getOpcode());
				assertEquals(PcodeOp.BRANCH, mod.getOpcode());
			}
		}
	}

	/**
	 * Tests that to override the destination of a CALL instruction in a packet a simple reference
	 * must be placed on the instruction where the CALL op is crossbuilt (which is not the "call" 
	 * instruction in this example).
	     00100078 c4 47 00 5a            call       func1 
	     0010007c c0 c0 01 8e  ||        asl+=      R0,R1,#0x0                                                                                          undefined func1(void)
	 */
	@Test
	public void testSimpleCallReferenceOverride() {
		//verify the instructions used in the test
		Instruction call = listing.getInstructionAt(testFlowOverrideCallInPacketAddr);
		assertNotNull(call);
		assertEquals("call 0x00101000", call.toString().trim());
		assertFalse(parallelHelper.isParallelInstruction(call));
		assertFalse(parallelHelper.isEndOfParallelInstructionGroup(call));
		Instruction asl_plus = listing.getInstructionAfter(call.getAddress());
		assertNotNull(asl_plus);
		assertEquals("asl+= R0,R1,#0x0", asl_plus.toString().trim());
		assertTrue(parallelHelper.isParallelInstruction(asl_plus));
		assertTrue(parallelHelper.isEndOfParallelInstructionGroup(asl_plus));

		PcodeOp[] call_unmod = call.getPcode();
		PcodeOp[] asl_plus_unmod = asl_plus.getPcode();

		//verify that there are no changes if you ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(true)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(true)));

		//apply a simple overriding reference at the address of the call instruction
		//verify that it has no effect on the Pcode, since the CALL op is crossbuilt to
		//a different address
		int id = program.startTransaction("test");
		Reference simpleCallRef = refManager.addMemoryReference(call.getAddress(), func2Addr,
			RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, -1);
		//any default reference is primary, so need to set simpleCallRef to primary to unseat it
		refManager.setPrimary(simpleCallRef, true);
		program.endTransaction(id, true);

		// verify no changes whether or not you ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(false)));
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(true)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(true)));

		id = program.startTransaction("test");
		simpleCallRef = refManager.addMemoryReference(asl_plus.getAddress(), func2Addr,
			RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, -1);
		//any default reference is primary, so need to set simpleCallRef to primary to unseat it
		refManager.setPrimary(simpleCallRef, true);
		program.endTransaction(id, true);

		// verify no changes if you don't ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(false)));
		assertTrue(
			PcodeEmitContextTest.equalPcodeOpArrays(asl_plus_unmod, asl_plus.getPcode(false)));

		//pcode for call instruction should not change if you ask for overrides
		assertTrue(PcodeEmitContextTest.equalPcodeOpArrays(call_unmod, call.getPcode(true)));

		//verify that the CALL target changes if overrides are requested
		//and that there are no other changes
		PcodeOp[] asl_plus_mod = asl_plus.getPcode(true);
		assertEquals(asl_plus_unmod.length, asl_plus_mod.length);
		for (int i = 0; i < asl_plus_unmod.length; ++i) {
			PcodeOp mod = asl_plus_mod[i];
			PcodeOp unmod = asl_plus_unmod[i];
			if (i < (asl_plus_unmod.length - 1)) {
				assertTrue(PcodeEmitContextTest.equalPcodeOps(unmod, mod));
			}
			else {
				assertEquals(PcodeOp.CALL, unmod.getOpcode());
				assertEquals(PcodeOp.CALL, mod.getOpcode());
				assertEquals(func1Addr, unmod.getInput(0).getAddress());
				assertEquals(func2Addr, mod.getInput(0).getAddress());
			}
		}
	}
}
