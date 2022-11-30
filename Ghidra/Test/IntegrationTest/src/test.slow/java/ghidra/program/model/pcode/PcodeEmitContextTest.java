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

import java.util.Objects;

import org.junit.*;

import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.*;

/**
 * 
 * This class tests the various "instruction-level" methods for modifying the pcode emitted for
 * an instruction.  These include flow overrides, fallthrough overrides, and various overriding
 * references.
 *
 * In practice, it should be exceedingly rare to have multiple modifiers defined on the same 
 * instruction.  Nonetheless, it is possible.  Note that the operations introduced by flow 
 * overrides and fallthrough overrides are subject to further modification.  Modifications
 * by any overriding reference are final and cannot themselves be modified.
 * 
 * Several tests involve delay slots. Delay slots present some complications since they 
 * essentially combine two instructions but the various overrides are associated with a single 
 * address (either via a Reference or by being a property of an Instruction). 
 * Note that fallthrough overrides are disabled for instructions in delay slots, and that
 * flow overrides are disabled when emitting pcode for a delayslot directive.
 * 
 * Some tests capture behavior on situations that probably don't occur in practice
 * (such as a call instruction in a delay slot).  Breaking such tests isn't necessarily indicative
 * of an error, but should at least be investigated.
 * 
 * Potential additional tests:
 *   multiple instructions in delay slots?
 *   crossbuilds? 
 *     adjustment of uniques
 *     interpretation of inst_next
 *     interaction with delay slots
 *     analog of corner case described in testFlowOverridesAndDelaySlots
 *   tests with overlays?
 *   skeq in delay slot
 *   test location generation
 */
public class PcodeEmitContextTest extends AbstractGhidraHeadlessIntegrationTest {
	private TestEnv env;
	private Program program;
	private static final String DEST_FUNC1_ADDR = "0x100100";
	private static final String DEST_FUNC2_ADDR = "0x100200";
	private static final String DEST_FUNC3_ADDR = "0x1000a0";
	private static final String FIXME_ADDR = "0x00100300";
	private static final String INDIRECT_CALL_100000 = "0x100000";
	private static final String INDIRECT_JUMP_100002 = "0x100002";
	private static final String ADD_R0_R0_100004 = "0x100004";
	private static final String SUB_R0_R0_100006 = "0x100006";
	private static final String SK_EQ_100008 = "0x100008";
	private static final String ADD_R0_R0_10000a = "0x10000a";
	private static final String SUB_R0_R0_10000c = "0x10000c";
	private static final String SUB_R0_R0_10000e = "0x10000e";
	private static final String CALL_PLUS_TWO_100010 = "0x100010";
	private static final String ADD_R0_R0_100012 = "0x100012";
	private static final String SUB_R0_R0_100014 = "0x100014";
	private static final String CONDITIONAL_JUMP_100016 = "0x100016";
	private static final String ADD_R0_R0_100018 = "0x100018";
	private static final String SUB_R0_R0_10001a = "0x10001a";
	private static final String CALL_FIXME_10001c = "0x10001c";
	private static final String CALL_FUNC1_10001e = "0x10001e";
	private static final String USER_TWO_R0_100020 = "0x100020";
	private static final String CALLDS_FUNC3_100022 = "0x100022";
	private static final String USER_THREE_100024 = "0x100024";
	private static final String SUB_R0_R0_100026 = "0x100026";
	private static final String ADD_R0_R0_100028 = "0x100028";
	private static final String CALLDS_FUNC3_10002a = "0x10002a";
	private static final String CALL_FUNC1_10002c = "0x10002c";
	private static final String SK_EQ_10002e = "0x10002e";
	private static final String USER_ONE_100030 = "0x100030";
	private static final String UNCONDITIONAL_JUMP_100032 = "0x100032";
	private static final String CONDITIONAL_JUMP_100034 = "0x100034";
	private static final String INDIRECT_JUMP_100036 = "0x100036";
	private static final String CALL_FUNC1_100038 = "0x100038";
	private static final String INDIRECT_CALL_10003a = "0x10003a";
	private static final String RETURN_10003c = "0x10003c";

	//methods testing the flow overrides all use the same instructions
	//easiest to make them fields of this class
	private Instruction skeq_10002e;
	private Instruction user_one_100030;
	private Instruction br_100032;
	private Instruction breq_100034;
	private Instruction br_r0_100036;
	private Instruction call_100038;
	private Instruction call_r0_10003a;
	private Instruction ret_10003c;

	private AddressSpace defaultSpace;
	private Address func1Addr;
	private Address func2Addr;
	private Address fixMeAddr;
	private Address func3Addr;
	private ReferenceManager refManager;

	@Before
	public void setUp() throws Exception {
		program = buildProgram();
		defaultSpace = program.getAddressFactory().getDefaultAddressSpace();
		func1Addr = defaultSpace.getAddress(DEST_FUNC1_ADDR);
		func2Addr = defaultSpace.getAddress(DEST_FUNC2_ADDR);
		fixMeAddr = defaultSpace.getAddress(FIXME_ADDR);
		func3Addr = defaultSpace.getAddress(DEST_FUNC3_ADDR);
		refManager = program.getReferenceManager();
		env = new TestEnv();
	}

	private ProgramDB buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("notepad", true);

		builder.createMemory(".text", "0x100000", 0x10000);
		builder.createEmptyFunction(null, DEST_FUNC1_ADDR, 2, null);
		builder.createReturnInstruction(DEST_FUNC1_ADDR);
		builder.createEmptyFunction(null, DEST_FUNC2_ADDR, 2, null);
		builder.createReturnInstruction(DEST_FUNC2_ADDR);
		builder.createEmptyFunction("fixme", FIXME_ADDR, 2, null);
		builder.createReturnInstruction(FIXME_ADDR);
		builder.createEmptyFunction(null, DEST_FUNC3_ADDR, 2, null);
		builder.createReturnInstruction(DEST_FUNC3_ADDR);

		//testIndirectCallOverride
		builder.createEmptyFunction("main", INDIRECT_CALL_100000, 0x30, null);
		builder.setBytes(INDIRECT_CALL_100000, "f6 00");

		//testFallthroughOverrideBranchToInstNext
		builder.setBytes(INDIRECT_JUMP_100002, "f0 00");
		builder.setBytes(ADD_R0_R0_100004, "c0 00");
		builder.setBytes(SUB_R0_R0_100006, "c1 00");

		//testFallthoughOverrideBranchToInstNext2
		builder.setBytes(SK_EQ_100008, "80 00");
		builder.setBytes(ADD_R0_R0_10000a, "c0 00");
		builder.setBytes(SUB_R0_R0_10000c, "c1 00");
		builder.setBytes(SUB_R0_R0_10000e, "c1 00");

		//testFlowOverridePrimacy
		builder.setBytes(CALL_PLUS_TWO_100010, "f8 02");
		builder.setBytes(ADD_R0_R0_100012, "c0 00");
		builder.setBytes(SUB_R0_R0_100014, "c1 00");

		//testConditionalJumpOverride
		builder.setBytes(CONDITIONAL_JUMP_100016, "e0 40");
		builder.setBytes(ADD_R0_R0_100018, "c0 00");
		builder.setBytes(SUB_R0_R0_10001a, "c1 00");

		//testSimpleRefOverride
		builder.setBytes(CALL_FIXME_10001c, "fa e4");
		builder.setBytes(CALL_FUNC1_10001e, "f8 e2");

		//testCallotherCallOverride
		//testCallotherJumpOverride
		builder.setBytes(USER_TWO_R0_100020, "a2 00");

		//testFallthroughOverridesAndDelaySlots
		//testOverridingRefAndDelaySlots
		builder.setBytes(CALLDS_FUNC3_100022, "f5 7e");
		builder.setBytes(USER_THREE_100024, "a3 00");
		builder.setBytes(SUB_R0_R0_100026, "c1 00");
		builder.setBytes(ADD_R0_R0_100028, "c0 00");

		//testFlowOverridesAndDelaySlots
		//testSimpleRefsAndDelaySlots
		builder.setBytes(CALLDS_FUNC3_10002a, "f5 76");
		builder.setBytes(CALL_FUNC1_10002c, "f8 d4");

		//testBranchOverride
		builder.setBytes(SK_EQ_10002e, "80 00");
		builder.setBytes(USER_ONE_100030, "a1 00");
		builder.setBytes(UNCONDITIONAL_JUMP_100032, "e0 47");
		builder.setBytes(CONDITIONAL_JUMP_100034, "e0 40");
		builder.setBytes(INDIRECT_JUMP_100036, "f0 07");
		builder.setBytes(CALL_FUNC1_100038, "f8 c8");
		builder.setBytes(INDIRECT_CALL_10003a, "f6 00");
		builder.setBytes(RETURN_10003c, "f4 00");

		builder.disassemble(INDIRECT_CALL_100000, 0x3e, false);
		return builder.getProgram();
	}

	@After
	public void tearDown() throws Exception {
		env.dispose();
	}

	/**
	 * Tests that a CALL_OVERRIDE_UNCONDITIONAL reference:
	 *   1) converts a CALLIND op to a CALL op
	 *   2) changes the call target
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testIndirectCallOverride() throws AddressFormatException {
		//verify the instructions needed for the test
		Address indirectCallAddr = defaultSpace.getAddress(INDIRECT_CALL_100000);
		Instruction indirectCall = program.getListing().getInstructionAt(indirectCallAddr);
		assertNotNull(indirectCall);
		assertEquals("call r0", indirectCall.toString());

		PcodeOp[] unmodified = indirectCall.getPcode(false);
		assertTrue(unmodified[0].getOpcode() == PcodeOp.COPY); //save return address to lr
		assertTrue(unmodified[1].getOpcode() == PcodeOp.CALLIND); //indirect call

		//no overrides applied, pcode should be the same whether or not overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode(true)));
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode()));

		//add a non-primary CALL_OVERRIDE_UNCONDITIONAL reference 
		int id = program.startTransaction("test");
		Reference overrideRef = refManager.addMemoryReference(indirectCallAddr, func1Addr,
			RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRef, false);
		program.endTransaction(id, true);

		//no modifications to pcode since the reference is not primary
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode(true)));

		//make reference primary
		id = program.startTransaction("test");
		refManager.setPrimary(overrideRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode()));

		//verify that the CALLIND op has been changed to a CALL op
		//with call target func1Addr
		PcodeOp[] overridden = indirectCall.getPcode(true);
		assertFalse(equalPcodeOpArrays(unmodified, overridden));
		assertEquals(unmodified.length, overridden.length);
		assertEquals(unmodified.length, 2);
		assertTrue(equalPcodeOps(unmodified[0], overridden[0]));
		PcodeOp callind = unmodified[1];
		PcodeOp call = overridden[1];
		assertNull(callind.getOutput());
		assertNull(call.getOutput());
		assertTrue(callind.getOpcode() == PcodeOp.CALLIND);
		assertTrue(call.getOpcode() == PcodeOp.CALL);
		assertTrue(callind.getNumInputs() == 1);
		assertTrue(call.getNumInputs() == 1);
		assertTrue(callind.getInput(0).getAddress().isRegisterAddress());
		assertTrue(call.getInput(0).getAddress().isMemoryAddress());
		assertTrue(call.getInput(0).getOffset() == func1Addr.getOffset());

		//add another primary CALL_OVERRIDE_UNCONDITIONAL reference
		//pcode should be unmodified: override only active if exactly one primary reference
		id = program.startTransaction("test");
		overrideRef = refManager.addMemoryReference(indirectCallAddr, func2Addr,
			RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(overrideRef, true);
		program.endTransaction(id, true);
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode(true)));

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, indirectCall.getPcode()));
	}

	/**
	 * Tests that a fallthrough override modifies branches to the next instruction
	 * (e.g., from a {@code goto inst_next;}
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testFallthroughOverrideBranchToInstNext() throws AddressFormatException {
		//verify the instructions needed for the test
		Address indirectCallAddr = defaultSpace.getAddress(INDIRECT_JUMP_100002);
		Instruction indirectJump = program.getListing().getInstructionAt(indirectCallAddr);
		assertNotNull(indirectJump);
		assertEquals("breq r0", indirectJump.toString());

		Address addAddr = defaultSpace.getAddress(ADD_R0_R0_100004);
		Instruction add = program.getListing().getInstructionAt(addAddr);
		assertNotNull(add);
		assertEquals("add r0,r0", add.toString());
		Address subAddr = defaultSpace.getAddress(SUB_R0_R0_100006);
		Instruction sub = program.getListing().getInstructionAt(subAddr);
		assertNotNull(sub);
		assertEquals("sub r0,r0", sub.toString());

		//verify that requesting overrides when there are none is the same as not 
		//requesting overrides
		assertTrue(equalPcodeOpArrays(indirectJump.getPcode(true), indirectJump.getPcode(false)));

		/*
		 * verify that the fallthrough override: 
		 * 1) changes the destination of the CBRANCH op (which is from a goto inst_next) 
		 * 2) appends a BRANCH op with destination subAddr to the pcode for breq r0
		 * 3) makes no other changes
		*/
		PcodeOp[] unmodified = indirectJump.getPcode(false);
		assertTrue(unmodified.length == 3);
		assertTrue(unmodified[0].getOpcode() == PcodeOp.BOOL_NEGATE);  //negate condition
		assertTrue(unmodified[1].getOpcode() == PcodeOp.CBRANCH);      //CBRANCH to inst_next  
		assertTrue(unmodified[2].getOpcode() == PcodeOp.BRANCHIND);    //BRANCHIND r0

		//apply a fallthrough override
		int tid = program.startTransaction("test");
		indirectJump.setFallThrough(subAddr);
		program.endTransaction(tid, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, indirectJump.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, indirectJump.getPcode()));

		PcodeOp[] overridden = indirectJump.getPcode(true);
		assertTrue(overridden.length == unmodified.length + 1);

		//shouldn't change first op 
		assertTrue(equalPcodeOps(overridden[0], unmodified[0]));

		//second op (CBRANCH to inst_next) needs destination updated
		PcodeOp unmodifiedCbranch = unmodified[1];
		PcodeOp modifiedCbranch = overridden[1];
		assertNull(unmodifiedCbranch.getOutput());
		assertNull(modifiedCbranch.getOutput());
		assertTrue(unmodifiedCbranch.getOpcode() == modifiedCbranch.getOpcode());
		assertTrue(unmodifiedCbranch.getNumInputs() == 2);
		assertTrue(modifiedCbranch.getNumInputs() == 2);
		assertTrue(unmodifiedCbranch.getInput(0).isAddress());
		assertTrue(unmodifiedCbranch.getInput(0).getOffset() == addAddr.getOffset());
		assertTrue(modifiedCbranch.getInput(0).isAddress());
		assertTrue(modifiedCbranch.getInput(0).getOffset() == subAddr.getOffset()); //updated dest
		assertEquals(unmodifiedCbranch.getInput(1), modifiedCbranch.getInput(1));

		//shouldn't change third op
		assertTrue(equalPcodeOps(overridden[2], unmodified[2]));

		//verify appended branch
		PcodeOp appendedBranch = overridden[3];
		assertNull(appendedBranch.getOutput());
		assertTrue(appendedBranch.getOpcode() == PcodeOp.BRANCH);
		assertTrue(appendedBranch.getNumInputs() == 1);
		assertTrue(appendedBranch.getInput(0).isAddress());
		assertTrue(appendedBranch.getInput(0).getOffset() == subAddr.getOffset());
	}

	/**
	 * Test that a fallthrough override does *not* modify branches to inst_next2
	 * Test that the BRANCH op appended by a fallthrough override *is* subject to 
	 * further modification by a JUMP_OVERRIDE_UNCONDITIONAL reference
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testFallthoughOverrideBranchToInstNext2() throws AddressFormatException {
		//verify the instructions needed for the test
		Address skip2Addr = defaultSpace.getAddress(SK_EQ_100008);
		Instruction skip2 = program.getListing().getInstructionAt(skip2Addr);
		assertNotNull(skip2);
		assertEquals("skeq", skip2.toString());
		Address addAddr = defaultSpace.getAddress(ADD_R0_R0_10000a);
		Instruction add = program.getListing().getInstructionAt(addAddr);
		assertNotNull(add);
		assertEquals("add r0,r0", add.toString());
		Address subAddr2 = defaultSpace.getAddress(SUB_R0_R0_10000c);
		Instruction sub2 = program.getListing().getInstructionAt(subAddr2);
		assertNotNull(sub2);
		assertEquals("sub r0,r0", sub2.toString());
		Address subAddr3 = defaultSpace.getAddress(SUB_R0_R0_10000e);
		Instruction sub3 = program.getListing().getInstructionAt(subAddr3);
		assertNotNull(sub3);
		assertEquals("sub r0,r0", sub3.toString());

		//get the pcode before the fallthrough override
		PcodeOp[] beforeFallthroughOverride = skip2.getPcode(false);
		assertTrue(beforeFallthroughOverride.length == 1);
		assertTrue(beforeFallthroughOverride[0].getOpcode() == PcodeOp.CBRANCH); //CBRANCH to inst_next2

		//verify that requesting overrides when there are none is the same as not requesting overrides
		assertTrue(equalPcodeOpArrays(skip2.getPcode(true), skip2.getPcode(false)));

		//apply the fallthrough override
		int tid = program.startTransaction("test");
		skip2.setFallThrough(subAddr3);
		program.endTransaction(tid, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(beforeFallthroughOverride, skip2.getPcode(false)));
		assertTrue(equalPcodeOpArrays(beforeFallthroughOverride, skip2.getPcode()));

		//get the overridden pcode
		PcodeOp[] afterFallthroughOverride = skip2.getPcode(true);
		assertTrue(afterFallthroughOverride.length == beforeFallthroughOverride.length + 1);

		//verify that the CBRANCH to inst_next2 is *not* modified
		assertTrue(beforeFallthroughOverride[0].getOpcode() == PcodeOp.CBRANCH);
		assertTrue(equalPcodeOps(beforeFallthroughOverride[0], afterFallthroughOverride[0]));

		//verify the appended branch
		PcodeOp appendedBranch = afterFallthroughOverride[1];
		assertNull(appendedBranch.getOutput());
		assertTrue(appendedBranch.getOpcode() == PcodeOp.BRANCH);
		assertTrue(appendedBranch.getNumInputs() == 1);
		assertTrue(appendedBranch.getInput(0).isAddress());
		assertTrue(appendedBranch.getInput(0).getOffset() == subAddr3.getOffset());

		//create primary overriding reference and fallthrough override on add
		int id = program.startTransaction("test");
		Reference overrideRef = refManager.addMemoryReference(addAddr, func2Addr,
			RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRef, true);
		add.setFallThrough(subAddr3);
		program.endTransaction(id, true);

		//verify that overrideRef changes the target of the appended branch
		//and makes no other changes
		PcodeOp[] unmodifiedAdd = add.getPcode(false);
		PcodeOp[] overriddenAdd = add.getPcode(true);
		assertTrue(overriddenAdd.length == unmodifiedAdd.length + 1);
		for (int i = 0; i < unmodifiedAdd.length; ++i) {
			assertTrue(equalPcodeOps(unmodifiedAdd[i], overriddenAdd[i]));
		}
		PcodeOp overriddenBranch = overriddenAdd[overriddenAdd.length - 1];
		assertTrue(overriddenBranch.getOpcode() == PcodeOp.BRANCH);
		assertTrue(overriddenBranch.getInput(0).getOffset() == func2Addr.getOffset());
	}

	/**
	 * Tests that pcode ops introduced by a flow override can be affected by fallthrough overrides 
	 * and overriding references.
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testFlowOverridePrimacy() throws AddressFormatException {
		//verify the instructions needed for the test
		Address callAddr = defaultSpace.getAddress(CALL_PLUS_TWO_100010);
		Instruction call = program.getListing().getInstructionAt(callAddr);
		assertNotNull(call);
		assertEquals("call 0x00100012", call.toString());
		Address addAddr = defaultSpace.getAddress(ADD_R0_R0_100012);
		Instruction add = program.getListing().getInstructionAt(addAddr);
		assertNotNull(add);
		assertEquals("add r0,r0", add.toString());
		Address subAddr = defaultSpace.getAddress(SUB_R0_R0_100014);
		Instruction sub = program.getListing().getInstructionAt(subAddr);
		assertNotNull(sub);
		assertEquals("sub r0,r0", sub.toString());

		//get unmodified Pcode
		PcodeOp[] unmodified = call.getPcode(false);
		assertTrue(unmodified.length == 2);
		assertTrue(unmodified[0].getOpcode() == PcodeOp.COPY); //save return address to lr
		assertTrue(unmodified[1].getOpcode() == PcodeOp.CALL); //perform call

		//verify that requesting overrides has no effect on the pcode before any overrides
		//are applied
		assertTrue(equalPcodeOpArrays(call.getPcode(true), call.getPcode(false)));

		//apply a CALL_OVERRIDE_UNCONDITIONAL reference and verify that it changes the 
		//call target
		//place it on operand 0 so that the default reference to the call target
		//is made not primary
		int id = program.startTransaction("test");
		Reference callOverrideRef = refManager.addMemoryReference(callAddr, func2Addr,
			RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(callOverrideRef, true);
		program.endTransaction(id, true);

		PcodeOp[] callOverride = call.getPcode(true);
		assertTrue(callOverride[1].getOpcode() == PcodeOp.CALL);
		assertTrue(callOverride[1].getInput(0).getOffset() == func2Addr.getOffset());

		//deactivate the call override by setting the reference to non-primary
		id = program.startTransaction("test");
		refManager.setPrimary(callOverrideRef, false);
		program.endTransaction(id, true);

		//verify that the pcode is not changed
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode(true)));

		//apply flow override
		int tid = program.startTransaction("test");
		call.setFlowOverride(FlowOverride.BRANCH);
		program.endTransaction(tid, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode()));

		//verify the flow override occurred
		PcodeOp[] flow = call.getPcode(true);
		assertTrue(flow.length == unmodified.length);
		//first op saves the return address to lr; shouldn't change
		assertTrue(equalPcodeOps(unmodified[0], flow[0]));

		//verify that the flow override changed the CALL to a BRANCH
		//and made no other changes
		PcodeOp callOp = unmodified[1];
		PcodeOp branchOp = flow[1];
		assertTrue(branchOp.getOpcode() == PcodeOp.BRANCH);
		assertTrue(equalInputsAndOutput(branchOp, callOp));

		//set the CALL_OVERRIDE_CALL reference to primary
		id = program.startTransaction("test");
		refManager.setPrimary(callOverrideRef, true);
		program.endTransaction(id, true);

		//verify that a primary CALL_OVERRIDE_CALL reference has no effect since
		//the flow override has precedence
		assertTrue(equalPcodeOpArrays(flow, call.getPcode(true)));

		//delete callOverrideRef - no longer needed
		//note: simply setting it to non-primary can cause complications later in
		//this test since removing a flow override updates existing references
		id = program.startTransaction("test");
		refManager.delete(callOverrideRef);
		program.endTransaction(id, true);

		//apply fallthrough override
		tid = program.startTransaction("test");
		call.setFallThrough(subAddr);
		program.endTransaction(tid, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode()));

		PcodeOp[] flowFallthrough = call.getPcode(true);

		//verify that the first op hasn't changed
		assertTrue(equalPcodeOps(unmodified[0], flowFallthrough[0]));

		//verify that the target of the branch that was a call has changed
		PcodeOp adjustedBranch = flowFallthrough[1];
		assertTrue(Objects.equals(branchOp.getOutput(), adjustedBranch.getOutput()));
		assertTrue(adjustedBranch.getOpcode() == PcodeOp.BRANCH);
		assertTrue(adjustedBranch.getNumInputs() == 1);
		assertTrue(adjustedBranch.getInput(0).isAddress());
		assertTrue(adjustedBranch.getInput(0).getOffset() == subAddr.getOffset());
		assertTrue(branchOp.getInput(0).isAddress());
		assertTrue(branchOp.getInput(0).getOffset() == addAddr.getOffset());

		//verify that exactly one op has been appended
		assertTrue(flowFallthrough.length == unmodified.length + 1);

		//verify the appended branch
		PcodeOp appendedBranch = flowFallthrough[2];
		assertNull(appendedBranch.getOutput());
		assertTrue(appendedBranch.getOpcode() == PcodeOp.BRANCH);
		assertTrue(appendedBranch.getNumInputs() == 1);
		assertTrue(appendedBranch.getInput(0).isAddress());
		assertTrue(appendedBranch.getInput(0).getOffset() == subAddr.getOffset());

		//apply an overriding jump reference
		tid = program.startTransaction("test");
		Reference jumpOverrideRef = refManager.addMemoryReference(callAddr, func1Addr,
			RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(jumpOverrideRef, true);
		program.endTransaction(tid, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode()));

		//ref should change the appended BRANCH since the fallthrough override has precedence
		//on the adjusted branch
		PcodeOp[] flowFallthroughRef = call.getPcode(true);
		assertEquals(flowFallthroughRef.length, unmodified.length + 1);
		assertTrue(equalPcodeOps(flowFallthrough[0], flowFallthroughRef[0])); //save return address
		assertTrue(equalPcodeOps(flowFallthrough[1], flowFallthroughRef[1])); //adjusted branch
		PcodeOp appended = flowFallthroughRef[2]; //appended branch
		assertNull(appended.getOutput());
		assertTrue(appended.getOpcode() == PcodeOp.BRANCH);
		assertTrue(appended.getNumInputs() == 1);
		assertTrue(appended.getInput(0).isAddress());
		assertTrue(appended.getInput(0).getOffset() == func1Addr.getOffset());

		//remove fallthrough override
		tid = program.startTransaction("test");
		call.clearFallThroughOverride();
		program.endTransaction(tid, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, call.getPcode()));

		PcodeOp[] flowRef = call.getPcode(true);
		assertTrue(flowRef.length == unmodified.length);
		//first op shouldn't change
		assertTrue(equalPcodeOps(flowRef[0], unmodified[0]));

		//overriding jump reference should now change BRANCH from flow override
		PcodeOp refBranch = flowRef[1];
		assertNull(refBranch.getOutput());
		assertTrue(refBranch.getOpcode() == PcodeOp.BRANCH);
		assertTrue(refBranch.getNumInputs() == 1);
		assertTrue(refBranch.getInput(0).isAddress());
		assertTrue(refBranch.getInput(0).getOffset() == func1Addr.getOffset());

		//remove flow override
		tid = program.startTransaction("test");
		call.setFlowOverride(FlowOverride.NONE);
		program.endTransaction(tid, true);

		//overriding jump ref should do nothing since it doesn't apply to CALL ops
		PcodeOp[] ref = call.getPcode(true);
		assertTrue(equalPcodeOpArrays(ref, unmodified));
	}

	/**
	 * Tests that a single primary JUMP_OVERRIDE_UNCONDITIONAL reference:
	 *  1) changes a CBRANCH op to a BRANCH op 
	 *  2) changes the jump target
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it 
	 */
	@Test
	public void testConditionalJumpOverride() throws AddressFormatException {
		//verify the instructions needed for the test
		Address condJumpAddr = defaultSpace.getAddress(CONDITIONAL_JUMP_100016);
		Instruction condJump = program.getListing().getInstructionAt(condJumpAddr);
		assertNotNull(condJump);
		assertEquals("breq 0x0010001a", condJump.toString());
		Address addAddr = defaultSpace.getAddress(ADD_R0_R0_100018);
		Instruction add = program.getListing().getInstructionAt(addAddr);
		assertNotNull(add);
		assertEquals("add r0,r0", add.toString());
		Address subAddr = defaultSpace.getAddress(SUB_R0_R0_10001a);
		Instruction sub = program.getListing().getInstructionAt(subAddr);
		assertNotNull(sub);
		assertEquals("sub r0,r0", sub.toString());

		//verify unmodified pcode
		PcodeOp[] noRef = condJump.getPcode(false);
		assertTrue(noRef.length == 3);
		assertTrue(noRef[0].getOpcode() == PcodeOp.BOOL_NEGATE); //negate condition
		assertTrue(noRef[1].getOpcode() == PcodeOp.CBRANCH);     //CBRANCH to inst_next
		assertTrue(noRef[2].getOpcode() == PcodeOp.BRANCH);      //BRANCH to 0x10001a

		//verify that requesting overrides when there are none is the same as not 
		//requesting overriders
		assertTrue(equalPcodeOpArrays(condJump.getPcode(true), condJump.getPcode(false)));

		//create non-primary overriding reference
		int id = program.startTransaction("test");
		Reference overrideRef = refManager.addMemoryReference(condJumpAddr, func2Addr,
			RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRef, false);
		program.endTransaction(id, true);

		//verify that pcode is unchanged
		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode()));
		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode(false)));
		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode(true)));

		//set the reference to primary
		id = program.startTransaction("test");
		refManager.setPrimary(overrideRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode(false)));
		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode()));

		PcodeOp[] overridden = condJump.getPcode(true);
		//verify that the CBRANCH op has been changed and that no other ops have changed
		assertTrue(overridden.length == noRef.length);
		assertTrue(equalPcodeOps(noRef[0], overridden[0]));
		assertNull(overridden[1].getOutput());
		assertTrue(overridden[1].getOpcode() == PcodeOp.BRANCH);
		assertTrue(overridden[1].getInput(0).isAddress());
		assertTrue(overridden[1].getInput(0).getOffset() == func2Addr.getOffset());

		//note: the 2nd input is left over from the CBRANCH op and should probably be destroyed
		assertTrue(overridden[1].getNumInputs() == 2);
		assertTrue(equalPcodeOps(noRef[2], overridden[2]));

		//apply another primary reference, no overrides should occur
		id = program.startTransaction("test");
		overrideRef = refManager.addMemoryReference(condJumpAddr, func1Addr,
			RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(overrideRef, true);
		program.endTransaction(id, true);

		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode(true)));
		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode(false)));
		assertTrue(equalPcodeOpArrays(noRef, condJump.getPcode()));
	}

	/**
	 * Test that simple call reference overrides (retained for backward compatibility) have
	 * precedence over CALL_OVERRIDE_UNCONDITIONAL reference overrides, and that neither
	 * override applies if the call target has a call fixup.
	 * 
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testSimpleRefOverride() throws AddressFormatException {
		//verify the instructions needed for the test
		Address callFunc1Addr = defaultSpace.getAddress(CALL_FUNC1_10001e);
		Instruction callFunc1 = program.getListing().getInstructionAt(callFunc1Addr);
		assertNotNull(callFunc1);
		assertEquals("call 0x" + func1Addr.toString(), callFunc1.toString());

		PcodeOp[] unmodified = callFunc1.getPcode(false);
		assertEquals(unmodified.length, 2);
		assertTrue(unmodified[0].getOpcode() == PcodeOp.COPY); //save return address in lr
		assertTrue(unmodified[1].getOpcode() == PcodeOp.CALL); //call op

		//verify that requesting overrides when there aren't any is the same as
		//not requesting overrides
		assertTrue(equalPcodeOpArrays(callFunc1.getPcode(true), callFunc1.getPcode(false)));

		int id = program.startTransaction("test");
		Reference simpleCallRef = refManager.addMemoryReference(callFunc1Addr, func2Addr,
			RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
		//default reference is primary, so need to set simpleCallRef to primary to unseat it
		refManager.setPrimary(simpleCallRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes with no overrides requested
		assertTrue(equalPcodeOpArrays(unmodified, callFunc1.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, callFunc1.getPcode()));

		//simple call ref override
		PcodeOp[] simpleRefOverride = callFunc1.getPcode(true);

		//verify same number of ops		
		assertEquals(simpleRefOverride.length, unmodified.length);

		//verify COPY op not changed
		assertTrue(equalPcodeOps(unmodified[0], simpleRefOverride[0]));

		//verify the call target changed
		assertNull(unmodified[1].getOutput());
		assertNull(simpleRefOverride[1].getOutput());
		assertTrue(unmodified[1].getOpcode() == simpleRefOverride[1].getOpcode());
		assertTrue(unmodified[1].getNumInputs() == simpleRefOverride[1].getNumInputs());
		assertTrue(unmodified[1].getInput(0).getOffset() == func1Addr.getOffset());
		assertTrue(simpleRefOverride[1].getInput(0).getOffset() == func2Addr.getOffset());

		//verify that a simple reference override has precedence over a CALL_OVERRIDE_UNCONDITIONAL
		Address main = defaultSpace.getAddress(INDIRECT_CALL_100000);
		assertTrue(main.getOffset() == 0x100000);
		id = program.startTransaction("test");
		//use a different opIndex than simpleCallRef so we can verify what happens
		//when both refs are primary
		Reference overrideRef = refManager.addMemoryReference(callFunc1Addr, main,
			RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRef, true);
		program.endTransaction(id, true);

		//verify nothing changes with no overrides requested
		assertTrue(equalPcodeOpArrays(unmodified, callFunc1.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, callFunc1.getPcode()));

		//verify that with overrides what you get is simpleRef
		PcodeOp[] bothOverrides = callFunc1.getPcode(true);
		assertTrue(equalPcodeOpArrays(simpleRefOverride, bothOverrides));

		//set simpleRef to non-primary
		id = program.startTransaction("test");
		refManager.setPrimary(simpleCallRef, false);
		program.endTransaction(id, true);

		//verify that overrideRef then applies
		PcodeOp[] callOverrideOps = callFunc1.getPcode(true);
		assertTrue(equalPcodeOps(unmodified[0], callOverrideOps[0]));
		assertTrue(callOverrideOps[1].getInput(0).getOffset() == main.getOffset());

		Address callFixmeAddr = defaultSpace.getAddress(CALL_FIXME_10001c);
		Instruction callFixme = program.getListing().getInstructionAt(callFixmeAddr);
		assertNotNull(callFixme);
		assertEquals("call 0x" + fixMeAddr.toString(), callFixme.toString());

		unmodified = callFixme.getPcode(false);

		//add a simple ref override on a call to a function with a call fixup
		id = program.startTransaction("test");
		simpleCallRef = refManager.addMemoryReference(callFixmeAddr, func2Addr,
			RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
		//default reference is primary; set simpleCallRef to primary to unseat it
		refManager.setPrimary(simpleCallRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes with no overrides requested
		assertTrue(equalPcodeOpArrays(unmodified, callFixme.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, callFixme.getPcode()));

		//verify that nothing changes WITH overrides requested since "fixme" has a 
		//call fixup
		assertTrue(equalPcodeOpArrays(unmodified, callFixme.getPcode(true)));

		//add a CALL_OVERRIDE_UNCONDITIONAL reference on a call to a function with
		//a call fixup
		id = program.startTransaction("test");
		overrideRef = refManager.addMemoryReference(callFixmeAddr, main,
			RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(overrideRef, false);
		program.endTransaction(id, true);

		//verify that nothing changes with no overrides requested
		assertTrue(equalPcodeOpArrays(unmodified, callFixme.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, callFixme.getPcode()));

		//verify that nothing changes WITH overrides requested since "fixme" has a 
		//call fixup
		assertTrue(equalPcodeOpArrays(unmodified, callFixme.getPcode(true)));
	}

	/**
	 * Tests that a single primary CALLOTHER_OVERRIDE_CALL reference:
	 *   1) Changes the first CALLOTHER op encountered as follows:
	 *     a) CALLOTHER op -> CALL op
	 *     b) this new CALL op is not affected by simple reference overrides
	 *        or CALL_OVERRIDE_UNCONDITIONAL references
	 *     c) input 0 becomes the CALL target
	 *     d) other inputs destroyed
	 *   2) Does not change subsequent CALLOTHER ops associated with the same instruction
	 * @throws AddressFormatException if {@code AddressSpace.getAddress()} throws it
	 */
	@Test
	public void testCallotherCallOverride() throws AddressFormatException {
		//verify the instructions need for the test
		Address userTwoAddr = defaultSpace.getAddress(USER_TWO_R0_100020);
		Instruction userTwo = program.getListing().getInstructionAt(userTwoAddr);
		assertNotNull(userTwo);
		assertEquals("user_two r0", userTwo.toString());

		PcodeOp[] unmodified = userTwo.getPcode(false);
		assertNull(unmodified[0].getOutput());
		assertTrue(unmodified[0].getOpcode() == PcodeOp.CALLOTHER); //pcodeop_two(rs)
		assertTrue(unmodified[0].getNumInputs() == 2);              //callother op index, rs
		assertNull(unmodified[1].getOutput());
		assertTrue(unmodified[1].getOpcode() == PcodeOp.CALLOTHER); //pcodeop_three()
		assertTrue(unmodified[1].getNumInputs() == 1);              //callother op index

		//lay down CALLOTHER_OVERRIDE_CALL ref as non-primary
		int id = program.startTransaction("test");
		Reference callotherOverrideRef1 = refManager.addMemoryReference(userTwoAddr, func1Addr,
			RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(callotherOverrideRef1, false);
		program.endTransaction(id, true);

		//nothing should change regardless of whether overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(true)));

		//make the reference primary
		id = program.startTransaction("test");
		refManager.setPrimary(callotherOverrideRef1, true);
		program.endTransaction(id, true);

		//nothing should change without requesting overrides overrides
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));

		PcodeOp[] modified = userTwo.getPcode(true);
		//first CALLOTHER op should be changed to a CALL call target as the only input
		assertNull(modified[0].getOutput());
		assertTrue(modified[0].getOpcode() == PcodeOp.CALL);
		assertTrue(modified[0].getNumInputs() == 1);
		assertTrue(modified[0].getInput(0).isAddress());
		assertTrue(modified[0].getInput(0).getOffset() == func1Addr.getOffset());
		//second CALLOTHER op should be unchanged
		assertTrue(equalPcodeOps(modified[1], unmodified[1]));

		//add a primary simple call ref
		id = program.startTransaction("test");
		Reference simpleCallRef = refManager.addMemoryReference(userTwoAddr, func2Addr,
			RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(simpleCallRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes when overrides are not requested
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));

		//verify that this reference does not change the call target
		assertTrue(equalPcodeOpArrays(modified, userTwo.getPcode(true)));

		//remove simpleCallRef and add a CALL_OVERRIDE_UNCONDITIONAL reference
		id = program.startTransaction("test");
		Reference overrideCallRef = refManager.addMemoryReference(userTwoAddr, func2Addr,
			RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
		refManager.delete(simpleCallRef);
		refManager.setPrimary(overrideCallRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes when overrides are not requested
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));

		//verify that this reference does not change the call target
		assertTrue(equalPcodeOpArrays(modified, userTwo.getPcode(true)));

		//remove overrideCallRef and add another primary CALLOTHER_OVERRIDE_CALL reference
		id = program.startTransaction("test");
		Reference callotherOverrideRef2 = refManager.addMemoryReference(userTwoAddr, func1Addr,
			RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, 0);
		refManager.delete(overrideCallRef);
		refManager.setPrimary(callotherOverrideRef2, true);
		program.endTransaction(id, true);

		//two primary references CALLOTHER_OVERRIDE_CALL references: overrides should not happen
		assertTrue(equalPcodeOpArrays(userTwo.getPcode(true), unmodified));

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));
	}

	/**
	 * Tests that a single primary CALLOTHER_OVERRIDE_JUMP reference:
	 *   1) Changes the first CALLOTHER op encountered as follows:
	 *     a) CALLOTHER op -> BRANCH op
	 *     b) new BRANCH op not affected by JUMP_OVERRIDE_UNCONDITIONAL references
	 *     c) input 0 becomes the branch target
	 *     d) other inputs untouched
	 *   2) Does not change subsequent CALLOTHER ops corresponding to the same instruction
	 *   3) Is pre-empted by a single primary CALLOTHER_OVERRIDE_CALL reference
	 * @throws AddressFormatException if {@code AddressSpace.getAddress()} throws it
	 */
	@Test
	public void testCallotherJumpOverride() throws AddressFormatException {
		//verify the instructions needed for the test
		Address userTwoAddr = defaultSpace.getAddress(USER_TWO_R0_100020);
		Instruction userTwo = program.getListing().getInstructionAt(userTwoAddr);
		assertNotNull(userTwo);
		assertEquals("user_two r0", userTwo.toString());

		PcodeOp[] unmodified = userTwo.getPcode(false);
		assertNull(unmodified[0].getOutput());
		assertTrue(unmodified[0].getOpcode() == PcodeOp.CALLOTHER); //pcodeop_two(rs)
		assertTrue(unmodified[0].getNumInputs() == 2);              //callother op index, rs
		assertNull(unmodified[1].getOutput());
		assertTrue(unmodified[1].getOpcode() == PcodeOp.CALLOTHER); //pcodeop_three()
		assertTrue(unmodified[1].getNumInputs() == 1);              //callother op index

		//lay down CALLOTHER_OVERRIDE_JUMP ref as non-primary
		int id = program.startTransaction("test");
		Reference callotherOverrideJump1 = refManager.addMemoryReference(userTwoAddr, func1Addr,
			RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.USER_DEFINED, -1);
		refManager.setPrimary(callotherOverrideJump1, false);
		program.endTransaction(id, true);

		//nothing should change regardless of whether overrides are requested
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(true)));

		//make the reference primary
		id = program.startTransaction("test");
		refManager.setPrimary(callotherOverrideJump1, true);
		program.endTransaction(id, true);

		//nothing should change without overrides
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));

		PcodeOp[] modified = userTwo.getPcode(true);
		//verify first CALLOTHER changed to a BRANCH
		assertNull(modified[0].getOutput());
		assertTrue(modified[0].getOpcode() == PcodeOp.BRANCH);
		assertTrue(modified[0].getNumInputs() == 2); //should probably destroy second input...
		assertTrue(modified[0].getInput(0).isAddress());
		assertTrue(modified[0].getInput(0).getOffset() == func1Addr.getOffset());
		//verify that second CALLOTHER not changed
		assertTrue(equalPcodeOps(unmodified[1], modified[1]));

		//add a primary JUMP_OVERRIDE_UNCONDITIONAL reference
		id = program.startTransaction("test");
		Reference jumpOverrideRef = refManager.addMemoryReference(userTwoAddr, func2Addr,
			RefType.JUMP_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(jumpOverrideRef, true);
		program.endTransaction(id, true);

		//nothing should change without overrides
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));

		//with overrides, jumpOverrideRef should not do anything
		assertTrue(equalPcodeOpArrays(modified, userTwo.getPcode(true)));

		//set a primary CALLOTHER_OVERRIDE_CALL reference at the same address
		//delete jumpOverrideRef
		id = program.startTransaction("test");
		Reference callotherOverrideCall2 = refManager.addMemoryReference(userTwoAddr, func1Addr,
			RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, 0);
		refManager.delete(jumpOverrideRef);
		refManager.setPrimary(callotherOverrideCall2, true);
		program.endTransaction(id, true);

		//verify that the CALLOTHER_OVERRIDE_CALL reference has precedence
		PcodeOp[] precedence = userTwo.getPcode(true);
		assertNull(precedence[0].getOutput());
		assertTrue(precedence[0].getOpcode() == PcodeOp.CALL);
		assertTrue(precedence[0].getNumInputs() == 1);
		assertTrue(precedence[0].getInput(0).isAddress());
		assertTrue(precedence[0].getInput(0).getOffset() == func1Addr.getOffset());
		assertTrue(equalPcodeOps(precedence[1], unmodified[1]));

		//nothing should change without overrides
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));

		//add another primary CALL_OVERRIDE_JUMP reference and set the
		//CALLOTHER_OVERRIDE_CALL ref to non-primary
		id = program.startTransaction("test");
		Reference callotherOverrideJump3 = refManager.addMemoryReference(userTwoAddr, func1Addr,
			RefType.CALLOTHER_OVERRIDE_JUMP, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(callotherOverrideCall2, false);
		refManager.setPrimary(callotherOverrideJump3, true);
		program.endTransaction(id, true);

		//verify that nothing changes, with or without requesting overrides
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode()));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(false)));
		assertTrue(equalPcodeOpArrays(unmodified, userTwo.getPcode(true)));
	}

	// callds Rel8  { delayslot(1); lr = inst_next; call Rel8; }

	/**
	 * Tests that fallthrough overrides:
	 *   1) work as expected when applied to instructions with delay slots
	 *   2) have no effect when applied to instructions in delay slots
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testFallthroughOverridesAndDelaySlots() throws AddressFormatException {
		//verify that the test program contains the instructions for the test
		Address calldsFunc3Addr = defaultSpace.getAddress(CALLDS_FUNC3_100022);
		Instruction calldsFunc3 = program.getListing().getInstructionAt(calldsFunc3Addr);
		assertNotNull(calldsFunc3);
		assertEquals("callds 0x" + func3Addr.toString(), calldsFunc3.toString());

		Address user3Addr = defaultSpace.getAddress(USER_THREE_100024);
		Instruction user3 = program.getListing().getInstructionAt(user3Addr);
		assertNotNull(user3);
		assertEquals("_user_three", user3.toString());

		Address subAddr = defaultSpace.getAddress(SUB_R0_R0_100026);
		Instruction sub = program.getListing().getInstructionAt(subAddr);
		assertNotNull(sub);
		assertEquals("sub r0,r0", sub.toString());

		Address addAddr = defaultSpace.getAddress(ADD_R0_R0_100028);
		Instruction add = program.getListing().getInstructionAt(addAddr);
		assertNotNull(add);
		assertEquals("add r0,r0", add.toString());

		//get the pcode for the callds instruction before any overrides applied
		PcodeOp[] calldsUnmodified = calldsFunc3.getPcode(false);
		assertTrue(calldsUnmodified.length == 3);
		assertTrue(calldsUnmodified[0].getOpcode() == PcodeOp.CALLOTHER);  //from delay slot
		assertTrue(calldsUnmodified[1].getOpcode() == PcodeOp.COPY);       //save return address to lr
		assertTrue(calldsUnmodified[1].getNumInputs() == 1);
		//return address should be address of instruction after instruction in delay slot
		assertTrue(calldsUnmodified[1].getInput(0).getOffset() == subAddr.getOffset());
		assertTrue(calldsUnmodified[2].getOpcode() == PcodeOp.CALL);

		//get the pcode for the instruction in the delay slot before any overrides applied
		PcodeOp[] user3Unmodified = user3.getPcode(false);
		assertTrue(user3Unmodified.length == 1);
		assertTrue(user3Unmodified[0].getOpcode() == PcodeOp.CALLOTHER);

		//test that requesting overrides when there aren't any is the same as not requesting
		//overrides
		assertTrue(equalPcodeOpArrays(calldsFunc3.getPcode(false), calldsFunc3.getPcode(true)));
		assertTrue(equalPcodeOpArrays(user3.getPcode(false), user3.getPcode(true)));

		//apply fallthrough override on instruction in delay slot
		int tid = program.startTransaction("test");
		user3.setFallThrough(addAddr);
		program.endTransaction(tid, true);

		//verify that there are no changes if you request no overrides
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode()));
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode()));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode(false)));

		//verify that the fallthrough override does nothing to the instruction in the delay slot
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode(true)));

		//clear the fallthrough override on the instruction in the delay slot
		tid = program.startTransaction("test");
		user3.clearFallThroughOverride();
		program.endTransaction(tid, true);

		//apply fallthrough override on instruction with a delay slot
		tid = program.startTransaction("test");
		calldsFunc3.setFallThrough(addAddr);
		program.endTransaction(tid, true);

		//verify that there are no changes if you request no overrides
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode()));
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode()));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode(false)));

		PcodeOp[] calldsModified = calldsFunc3.getPcode(true);

		//verify that a BRANCH op is appended to the pcode for callds
		assertTrue(calldsModified.length == calldsUnmodified.length + 1);
		for (int i = 0; i < calldsUnmodified.length; ++i) {
			assertTrue(equalPcodeOps(calldsModified[i], calldsUnmodified[i]));
		}
		assertTrue(calldsModified[3].getOpcode() == PcodeOp.BRANCH);
		assertTrue(calldsModified[3].getInput(0).isAddress());
		assertTrue(calldsModified[3].getInput(0).getOffset() == addAddr.getOffset());
	}

	/**
	 * Test that CALLOTHER_CALL_OVERRIDE references:
	 *   1) When placed on an instruction *with* a delay slot:
	 *       a) changes a CALLOTHER op in the pcode for the instruction with the delay slot 
	 *       b) do not change a CALLOTHER op in the pcode for the instruction in the delay slot
	 *          when generated directly
	 *      Note: the callds instruction in this test has the delayslot directive before
	 *            any other pcode and does not itself contain a CALLOTHER op
	 *   2) When placed on an instruction *in* a delay slot
	 *      a) do not change the pcode for the instruction with the delay slot
	 *      b) changes a CALLOTHER op in the pcode for the instruction in the delay slot when
	 *         generated directly
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testOverridingRefAndDelaySlots() throws AddressFormatException {
		//verify that the test program contains the instructions for the test
		Address calldsFunc3Addr = defaultSpace.getAddress(CALLDS_FUNC3_100022);
		Instruction calldsFunc3 = program.getListing().getInstructionAt(calldsFunc3Addr);
		assertNotNull(calldsFunc3);
		assertEquals("callds 0x" + func3Addr.toString(), calldsFunc3.toString());

		Address user3Addr = defaultSpace.getAddress(USER_THREE_100024);
		Instruction user3 = program.getListing().getInstructionAt(user3Addr);
		assertNotNull(user3);
		assertEquals("_user_three", user3.toString());

		//grab pcode for both instructions before any overrides applied
		PcodeOp[] calldsUnmodified = calldsFunc3.getPcode(false);
		PcodeOp[] user3Unmodified = user3.getPcode(false);

		//verify that requesting overrides when there aren't any is the same as 
		//not requesting overrides
		assertTrue(equalPcodeOpArrays(calldsFunc3.getPcode(false), calldsFunc3.getPcode(true)));
		assertTrue(equalPcodeOpArrays(user3.getPcode(false), user3.getPcode(true)));

		//lay down a primary CALLOTHER_OVERRIDE_CALL reference on the instruction in the delay slot
		int id = program.startTransaction("test");
		Reference user3OverrideRef = refManager.addMemoryReference(user3Addr, func1Addr,
			RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(user3OverrideRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode()));
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode()));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode(false)));

		//verify that the override doesn't change the pcode for the instruction with the delay slot
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode(true)));

		//verify that the override does change the pcode for the instruction in the delay slot
		PcodeOp[] user3Modified = user3.getPcode(true);
		assertTrue(user3Modified.length == 1);
		assertNull(user3Modified[0].getOutput());
		assertTrue(user3Modified[0].getOpcode() == PcodeOp.CALL);
		assertTrue(user3Modified[0].getNumInputs() == 1);
		assertTrue(user3Modified[0].getInput(0).isAddress());
		assertTrue(user3Modified[0].getInput(0).getOffset() == func1Addr.getOffset());

		//set user3OverrideRef to non-primary and create a primary CALLOTHER_OVERRIDE_CALL
		//reference on callds
		id = program.startTransaction("test");
		refManager.setPrimary(user3OverrideRef, false);
		Reference calldsOverrideRef = refManager.addMemoryReference(calldsFunc3Addr, func1Addr,
			RefType.CALLOTHER_OVERRIDE_CALL, SourceType.USER_DEFINED, 0);
		refManager.setPrimary(calldsOverrideRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode()));
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode()));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode(false)));

		//verify that nothing changes for the instruction in the delay slot if overrides are requested
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode(true)));

		//verify that the CALLOTHER_OVERRIDE_CALL reference on callds DOES change the
		//CALLOTHER op from the delay slot to a CALL in the pcode for callds
		PcodeOp[] calldsModified = calldsFunc3.getPcode(true);
		assertTrue(calldsModified.length == calldsUnmodified.length);
		assertNull(calldsModified[0].getOutput());
		assertTrue(calldsModified[0].getOpcode() == PcodeOp.CALL);
		assertTrue(calldsModified[0].getNumInputs() == 1);
		assertTrue(calldsModified[0].getInput(0).isAddress());
		assertTrue(calldsModified[0].getInput(0).getOffset() == func1Addr.getOffset());

		//verify that the rest of the pcode ops for callds are unchanged
		for (int i = 1; i < calldsModified.length; ++i) {
			assertTrue(equalPcodeOps(calldsModified[i], calldsUnmodified[i]));
		}

		//set the CALLOTHER_OVERRIDE_CALL reference on user3 to primary, so that
		//both user3 and callds have primary CALLOTHER_OVERRIDE_CALL refs
		id = program.startTransaction("test");
		refManager.setPrimary(user3OverrideRef, true);
		program.endTransaction(id, true);

		//verify that nothing changes if no overrides are requested
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode()));
		assertTrue(equalPcodeOpArrays(calldsUnmodified, calldsFunc3.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode()));
		assertTrue(equalPcodeOpArrays(user3Unmodified, user3.getPcode(false)));

		//verify that the CALLOTHER is changed to a CALL in the pcode for callds 
		assertTrue(equalPcodeOpArrays(calldsModified, calldsFunc3.getPcode(true)));
		//verify that the CALLOTHER is changed to a CALL in the pcode for callds 
		assertTrue(equalPcodeOpArrays(user3Modified, user3.getPcode(true)));
	}

	/**
	 * Tests that flow overrides: 
	 *   1) do not apply to pcode generated by a delayslot directive
	 *   2) do apply to instructions in a delay slot when their pcode is generated
	 *      directly
	 *   3) do apply to pcode not generated by a delayslot directive in instructions
	 *      with a delay slot 
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testFlowOverridesAndDelaySlots() throws AddressFormatException {
		//verify that the test program contains the instructions for the test
		Address calldsAddr = defaultSpace.getAddress(CALLDS_FUNC3_10002a);
		Instruction callds = program.getListing().getInstructionAt(calldsAddr);
		assertNotNull(callds);
		assertEquals("callds 0x" + func3Addr.toString(), callds.toString());

		Address callAddr = defaultSpace.getAddress(CALL_FUNC1_10002c);
		Instruction call = program.getListing().getInstructionAt(callAddr);
		assertNotNull(call);
		assertEquals("_call 0x" + func1Addr.toString(), call.toString());

		//grab pcode for both instructions before any overrides applied
		PcodeOp[] calldsUnmodified = callds.getPcode(false);
		assertTrue(calldsUnmodified.length == 4);
		assertTrue(calldsUnmodified[0].getOpcode() == PcodeOp.COPY);  //from inst in delay slot
		assertTrue(calldsUnmodified[1].getOpcode() == PcodeOp.CALL);  //from inst in delay slot
		assertTrue(calldsUnmodified[1].getInput(0).getOffset() == func1Addr.getOffset());
		assertTrue(calldsUnmodified[2].getOpcode() == PcodeOp.COPY);  //save ret address to lr
		assertTrue(calldsUnmodified[3].getInput(0).getOffset() == func3Addr.getOffset());
		assertTrue(calldsUnmodified[3].getOpcode() == PcodeOp.CALL);  //call to func3
		PcodeOp[] callUnmodified = call.getPcode(false);
		assertTrue(callUnmodified.length == 2);
		assertTrue(equalPcodeOps(callUnmodified[0], calldsUnmodified[0]));  //save ret address to lr
		assertTrue(equalPcodeOps(callUnmodified[1], calldsUnmodified[1]));  //call to func1

		//verify that pcode is the same whether or not you request overrides for the instruction
		//in the delay slot
		assertTrue(equalPcodeOpArrays(call.getPcode(false), call.getPcode(true)));

		//this is a corner case that would probably never occur in practice
		//callds has a CALL op, so a call reference, R, is created by default
		//the instruction in the delay slot also has a CALL op, so when its pcode gets
		//inserted into the pcode for callds the pcode emitter sees R and thinks that
		//the CALL op in the delay slot should be overridden
		//end result is that whether or not you request overrides matters because of a
		//reference laid down automatically 
		PcodeOp[] cornerCase = callds.getPcode(true);
		assertFalse(equalPcodeOpArrays(callds.getPcode(false), cornerCase));
		assertTrue(cornerCase[0].getOpcode() == PcodeOp.COPY);  //from inst in delay slot
		assertTrue(cornerCase[1].getOpcode() == PcodeOp.CALL);  //from inst in delay slot, overridden
		assertTrue(cornerCase[1].getInput(0).getOffset() == func3Addr.getOffset());
		assertTrue(cornerCase[2].getOpcode() == PcodeOp.COPY);  //save ret address to lr
		assertTrue(cornerCase[3].getOpcode() == PcodeOp.CALL);  //call to func3
		assertTrue(cornerCase[3].getInput(0).getOffset() == func3Addr.getOffset());

		//flow override on instruction in delay slot
		int tid = program.startTransaction("test");
		call.setFlowOverride(FlowOverride.BRANCH);
		program.endTransaction(tid, true);

		//verify that nothing happens if no overrides are requested
		assertTrue(equalPcodeOpArrays(calldsUnmodified, callds.getPcode()));
		assertTrue(equalPcodeOpArrays(calldsUnmodified, callds.getPcode(false)));
		assertTrue(equalPcodeOpArrays(callUnmodified, call.getPcode()));
		assertTrue(equalPcodeOpArrays(callUnmodified, call.getPcode(false)));

		//verify that requesting overrides on the instruction produces the same pcode 
		//that was produced before the override was applied
		assertTrue(equalPcodeOpArrays(cornerCase, callds.getPcode(true)));

		//verify that the override does apply to the instruction in the delay slot
		//when its pcode is generated directly
		PcodeOp[] overriddenCall = call.getPcode(true);
		assertTrue(equalPcodeOps(overriddenCall[0], callUnmodified[0]));
		assertTrue(overriddenCall[1].getOpcode() == PcodeOp.BRANCH);
		assertTrue(equalInputsAndOutput(overriddenCall[1], callUnmodified[1]));

		//remove existing flow override on call instruction
		//set flow override on callds instruction
		tid = program.startTransaction("test");
		call.setFlowOverride(FlowOverride.NONE);
		callds.setFlowOverride(FlowOverride.BRANCH);
		program.endTransaction(tid, true);

		//verify that pcode for instruction in delay slot is not affected by any overrides
		assertTrue(equalPcodeOpArrays(call.getPcode(true), call.getPcode(false)));
		assertTrue(equalPcodeOpArrays(call.getPcode(false), callUnmodified));

		//verify that requesting no overrides yields the unmodified pcode
		assertTrue(equalPcodeOpArrays(callds.getPcode(false), calldsUnmodified));

		//verify that requesting overrides results in pcode in which the second call instruction
		//(the one not in the delay slot) has been changed to a BRANCH 
		//verify no additional changes
		PcodeOp[] overriddenCallds = callds.getPcode(true);
		assertTrue(equalPcodeOps(overriddenCallds[0], calldsUnmodified[0]));
		assertTrue(equalPcodeOps(overriddenCallds[1], calldsUnmodified[1]));
		assertTrue(equalPcodeOps(overriddenCallds[2], calldsUnmodified[2]));
		assertTrue(overriddenCallds[3].getOpcode() == PcodeOp.BRANCH);
		assertTrue(equalInputsAndOutput(overriddenCallds[3], calldsUnmodified[3]));
	}

	//reference on the call instruction should do nothing to the call in the delay slot
	//should apply when the pcode for the call is generated directly

	//reference on the callds instruction should apply to the call in the delay slot
	//an additional CALL_OVERRIDE_UNCONDITIONAL ref should have no effect
	//but if you remove the simple ref it should take effect
	//TODO: fix javadoc
	/**
	 * note: for callds, the delayslot directive occurs before the call
	 * so a call in the delay slot wil end up being the first call of the callds instruction
	 * @throws AddressFormatException if {@code AddressSpace.getAddress throws it}
	 */
	@Test
	public void testSimpleRefsAndDelaySlots() throws AddressFormatException {
		//verify that the test program contains the instructions for the test
		Address calldsAddr = defaultSpace.getAddress(CALLDS_FUNC3_10002a);
		Instruction callds = program.getListing().getInstructionAt(calldsAddr);
		assertNotNull(callds);
		assertEquals("callds 0x" + func3Addr.toString(), callds.toString());

		Address callAddr = defaultSpace.getAddress(CALL_FUNC1_10002c);
		Instruction call = program.getListing().getInstructionAt(callAddr);
		assertNotNull(call);
		assertEquals("_call 0x" + func1Addr.toString(), call.toString());

		//grab pcode for both instructions before any overrides applied
		PcodeOp[] calldsUnmodified = callds.getPcode(false);
		assertTrue(calldsUnmodified.length == 4);
		assertTrue(calldsUnmodified[0].getOpcode() == PcodeOp.COPY);  //from inst in delay slot
		assertTrue(calldsUnmodified[1].getOpcode() == PcodeOp.CALL);  //from inst in delay slot
		assertTrue(calldsUnmodified[1].getInput(0).getOffset() == func1Addr.getOffset());
		assertTrue(calldsUnmodified[2].getOpcode() == PcodeOp.COPY);  //save ret address to lr
		assertTrue(calldsUnmodified[3].getInput(0).getOffset() == func3Addr.getOffset());
		assertTrue(calldsUnmodified[3].getOpcode() == PcodeOp.CALL);  //call to func3
		PcodeOp[] callUnmodified = call.getPcode(false);
		assertTrue(callUnmodified.length == 2);
		assertTrue(equalPcodeOps(callUnmodified[0], calldsUnmodified[0]));  //save ret address to lr
		assertTrue(equalPcodeOps(callUnmodified[1], calldsUnmodified[1]));  //call to func1

		//verify that pcode is the same whether or not you request overrides for the instruction
		//in the delay slot
		assertTrue(equalPcodeOpArrays(call.getPcode(false), call.getPcode(true)));

		//this is the same corner case discussed in testFlowOverridesAndDelaySlots
		//it demonstrates that a simple ref override on an instruction with a delay slot
		//can apply to the pcode generated by the delayslot directive
		PcodeOp[] cornerCase = callds.getPcode(true);
		assertFalse(equalPcodeOpArrays(callds.getPcode(false), cornerCase));
		assertTrue(cornerCase[0].getOpcode() == PcodeOp.COPY);  //from inst in delay slot
		assertTrue(cornerCase[1].getOpcode() == PcodeOp.CALL);  //from inst in delay slot, overridden
		assertTrue(cornerCase[1].getInput(0).getOffset() == func3Addr.getOffset());
		assertTrue(cornerCase[2].getOpcode() == PcodeOp.COPY);  //save ret address to lr
		assertTrue(cornerCase[3].getOpcode() == PcodeOp.CALL);  //call to func3
		assertTrue(cornerCase[3].getInput(0).getOffset() == func3Addr.getOffset());

		//apply a simple ref on the call in the delay slot
		int id = program.startTransaction("test");
		Reference simpleCallRef = refManager.addMemoryReference(callAddr, func1Addr,
			RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
		//default reference is primary; set simpleCallRef to primary to unseat it
		refManager.setPrimary(simpleCallRef, true);
		program.endTransaction(id, true);

		//verify the pcode generated for the call instruction without overrides
		assertTrue(equalPcodeOpArrays(call.getPcode(false), callUnmodified));

		//verify the pcode generated for the call instruction with overrides
		PcodeOp[] callModifiedSimpleRef = call.getPcode(true);
		assertTrue(callModifiedSimpleRef.length == 2);
		assertTrue(equalPcodeOps(callModifiedSimpleRef[0], callUnmodified[0]));
		assertTrue(callModifiedSimpleRef[1].getOpcode() == PcodeOp.CALL);
		assertTrue(callModifiedSimpleRef[1].getInput(0).getOffset() == func1Addr.getOffset());

		//verify that nothing changes when generating the pcode for callds
		assertTrue(equalPcodeOpArrays(callds.getPcode(false), calldsUnmodified));
		assertTrue(equalPcodeOpArrays(callds.getPcode(true), cornerCase));

		//apply a non-primary CALL_OVERRIDE_UNCONDITIONAL ref
		id = program.startTransaction("test");
		Reference callOverrideRef = refManager.addMemoryReference(callAddr, func2Addr,
			RefType.CALL_OVERRIDE_UNCONDITIONAL, SourceType.USER_DEFINED, 0);
		program.endTransaction(id, true);

		//verify no effect (since simpleCallRef has precedence)
		assertTrue(equalPcodeOpArrays(call.getPcode(false), callUnmodified));
		assertTrue(equalPcodeOpArrays(call.getPcode(true), callModifiedSimpleRef));
		assertTrue(equalPcodeOpArrays(callds.getPcode(false), calldsUnmodified));
		assertTrue(equalPcodeOpArrays(callds.getPcode(true), cornerCase));

		//make callOverrideRef primary
		id = program.startTransaction("test");
		refManager.setPrimary(callOverrideRef, true);
		program.endTransaction(id, true);

		//verify no effect on pcode for call when overrides not requested
		assertTrue(equalPcodeOpArrays(call.getPcode(false), callUnmodified));

		//verify that the call target is changed to func2addr when overrides are requested
		PcodeOp[] callModifiedoverrideRef = call.getPcode(true);
		assertTrue(equalPcodeOps(callModifiedoverrideRef[0], callUnmodified[0]));
		assertTrue(callModifiedoverrideRef[1].getOpcode() == PcodeOp.CALL);
		assertTrue(callModifiedoverrideRef[1].getInput(0).getOffset() == func2Addr.getOffset());

		//verify no effect on the pcode for callds
		assertTrue(equalPcodeOpArrays(callds.getPcode(false), calldsUnmodified));
		assertTrue(equalPcodeOpArrays(callds.getPcode(true), cornerCase));
	}

	/**
	 * Test pcode emitted in the presence of a branch override
	 * @throws AddressFormatException if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testBranchOverride() throws AddressFormatException {
		initializeAndVerifyFlowOverrideFuncs();
		applyFlowOverride(FlowOverride.BRANCH);

		//shouldn't change skeq
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(true), skeq_10002e.getPcode(false)));
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(), skeq_10002e.getPcode(false)));

		//shouldn't change user_one
		assertTrue(
			equalPcodeOpArrays(user_one_100030.getPcode(true), user_one_100030.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user_one_100030.getPcode(), user_one_100030.getPcode(false)));

		//shouldn't change br
		assertTrue(equalPcodeOpArrays(br_100032.getPcode(true), br_100032.getPcode(false)));
		assertTrue(equalPcodeOpArrays(br_100032.getPcode(), br_100032.getPcode(false)));

		//shouldn't change breq
		assertTrue(equalPcodeOpArrays(breq_100034.getPcode(true), breq_100034.getPcode(false)));
		assertTrue(equalPcodeOpArrays(breq_100034.getPcode(), breq_100034.getPcode(false)));

		//shouldn't change br r0
		assertTrue(equalPcodeOpArrays(br_r0_100036.getPcode(true), br_r0_100036.getPcode(false)));
		assertTrue(equalPcodeOpArrays(br_r0_100036.getPcode(), br_r0_100036.getPcode(false)));

		//should change CALL to BRANCH
		PcodeOp[] callUnmodified = call_100038.getPcode(false);
		assertTrue(equalPcodeOpArrays(call_100038.getPcode(), callUnmodified));
		PcodeOp[] callOverridden = call_100038.getPcode(true);
		assertTrue(callOverridden.length == 2);
		assertTrue(equalPcodeOps(callOverridden[0], callUnmodified[0]));
		assertTrue(callOverridden[1].getOpcode() == PcodeOp.BRANCH);
		assertTrue(equalInputsAndOutput(callOverridden[1], callUnmodified[1]));

		//should change CALLIND to BRANCHIND
		PcodeOp[] callindUnmodified = call_r0_10003a.getPcode(false);
		assertTrue(equalPcodeOpArrays(callindUnmodified, call_r0_10003a.getPcode()));
		PcodeOp[] callindOverridden = call_r0_10003a.getPcode(true);
		assertTrue(callindOverridden.length == 2);
		assertTrue(equalPcodeOps(callindUnmodified[0], callindOverridden[0]));
		assertTrue(callindOverridden[1].getOpcode() == PcodeOp.BRANCHIND);
		assertTrue(equalInputsAndOutput(callindOverridden[1], callindUnmodified[1]));

		//should change RETURN to BRANCHIND
		PcodeOp[] returnUnmodified = ret_10003c.getPcode(false);
		assertTrue(equalPcodeOpArrays(returnUnmodified, ret_10003c.getPcode()));
		PcodeOp[] returnOverridden = ret_10003c.getPcode(true);
		assertTrue(returnOverridden.length == 1);
		assertTrue(returnOverridden[0].getOpcode() == PcodeOp.BRANCHIND);
		assertTrue(equalInputsAndOutput(returnOverridden[0], returnUnmodified[0]));
	}

	/**
	 * Tests pcode emitted in the presence of a call override
	 * @throws AddressFormatException  if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testCallOverride() throws AddressFormatException {
		initializeAndVerifyFlowOverrideFuncs();
		applyFlowOverride(FlowOverride.CALL);

		//shouldn't change skeq
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(true), skeq_10002e.getPcode(false)));
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(), skeq_10002e.getPcode(false)));

		//shouldn't change user_one
		assertTrue(
			equalPcodeOpArrays(user_one_100030.getPcode(true), user_one_100030.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user_one_100030.getPcode(), user_one_100030.getPcode(false)));

		//should change BRANCH to CALL
		PcodeOp[] brUnmodified = br_100032.getPcode(false);
		assertTrue(equalPcodeOpArrays(br_100032.getPcode(), brUnmodified));
		PcodeOp[] brOverridden = br_100032.getPcode(true);
		assertTrue(brOverridden.length == 1);
		assertTrue(brOverridden[0].getOpcode() == PcodeOp.CALL);
		assertTrue(equalInputsAndOutput(brOverridden[0], brUnmodified[0]));

		//should change CBRANCH to BOOL_NEGATE, CBRANCH, CALL
		//however, the CBRANCH in the pcode for breq is to the next instruction
		//which the flow override code explicitly skips.  So the final 
		//branch will be changed to a call
		//looks like the toy language does not have an instruction with a CBRANCH
		//that would be affected by a CALL override
		PcodeOp[] cbranchUnmodified = breq_100034.getPcode(false);
		assertTrue(equalPcodeOpArrays(cbranchUnmodified, breq_100034.getPcode()));
		PcodeOp[] cbranchOverridden = breq_100034.getPcode(true);
		assertTrue(cbranchOverridden.length == 3);
		assertTrue(equalPcodeOps(cbranchUnmodified[0], cbranchOverridden[0]));
		assertTrue(equalPcodeOps(cbranchUnmodified[1], cbranchOverridden[1]));
		assertTrue(cbranchOverridden[2].getOpcode() == PcodeOp.CALL);
		assertTrue(equalInputsAndOutput(cbranchOverridden[2], cbranchUnmodified[2]));

		//should change BRANCHIND to CALLIND
		PcodeOp[] branchindUnmodified = br_r0_100036.getPcode(false);
		assertTrue(equalPcodeOpArrays(branchindUnmodified, br_r0_100036.getPcode()));
		PcodeOp[] branchindOverridden = br_r0_100036.getPcode(true);
		assertTrue(branchindOverridden.length == 1);
		assertTrue(branchindOverridden[0].getOpcode() == PcodeOp.CALLIND);
		assertTrue(equalInputsAndOutput(branchindOverridden[0], branchindUnmodified[0]));

		//shouldn't change CALL
		assertTrue(equalPcodeOpArrays(call_100038.getPcode(true), call_100038.getPcode(false)));
		assertTrue(equalPcodeOpArrays(call_100038.getPcode(), call_100038.getPcode(false)));

		//shouldn't change CALLIND
		assertTrue(
			equalPcodeOpArrays(call_r0_10003a.getPcode(true), call_r0_10003a.getPcode(false)));
		assertTrue(equalPcodeOpArrays(call_r0_10003a.getPcode(), call_r0_10003a.getPcode(false)));

		//should change RETURN to CALLIND
		PcodeOp[] returnUnmodified = ret_10003c.getPcode(false);
		assertTrue(equalPcodeOpArrays(returnUnmodified, ret_10003c.getPcode()));
		PcodeOp[] returnOverridden = ret_10003c.getPcode(true);
		assertTrue(returnOverridden.length == 1);
		assertTrue(returnOverridden[0].getOpcode() == PcodeOp.CALLIND);
		assertTrue(equalInputsAndOutput(returnOverridden[0], returnUnmodified[0]));
	}

	/**
	 * Tests pcode emitted in the presence of a call_return override
	 * @throws AddressFormatException  if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testCallReturnOverride() throws AddressFormatException {
		initializeAndVerifyFlowOverrideFuncs();
		applyFlowOverride(FlowOverride.CALL_RETURN);

		//shouldn't change skeq
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(true), skeq_10002e.getPcode(false)));
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(), skeq_10002e.getPcode(false)));

		//shouldn't change user_one
		assertTrue(
			equalPcodeOpArrays(user_one_100030.getPcode(true), user_one_100030.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user_one_100030.getPcode(), user_one_100030.getPcode(false)));

		//should change BRANCH to CALL, RETURN
		PcodeOp[] brUnmodified = br_100032.getPcode(false);
		assertTrue(equalPcodeOpArrays(br_100032.getPcode(), brUnmodified));
		PcodeOp[] brOverridden = br_100032.getPcode(true);
		assertTrue(brOverridden.length == brUnmodified.length + 1);
		assertTrue(brOverridden[0].getOpcode() == PcodeOp.CALL);
		assertTrue(equalInputsAndOutput(brOverridden[0], brUnmodified[0]));
		assertTrue(brOverridden[1].getOpcode() == PcodeOp.RETURN);

		//CBRANCH in this pcode is unaffected - see comment in testCallOverride()
		PcodeOp[] cbranchUnmodified = breq_100034.getPcode(false);
		assertTrue(equalPcodeOpArrays(cbranchUnmodified, breq_100034.getPcode()));
		PcodeOp[] cbranchOverridden = breq_100034.getPcode(true);
		assertTrue(cbranchOverridden.length == cbranchUnmodified.length + 1);
		assertTrue(equalPcodeOps(cbranchUnmodified[0], cbranchOverridden[0]));
		assertTrue(equalPcodeOps(cbranchUnmodified[1], cbranchOverridden[1]));
		assertTrue(cbranchOverridden[2].getOpcode() == PcodeOp.CALL);
		assertTrue(equalInputsAndOutput(cbranchOverridden[2], cbranchUnmodified[2]));
		assertTrue(cbranchOverridden[3].getOpcode() == PcodeOp.RETURN);

		//should change BRANCHIND to CALL, RETURN
		PcodeOp[] branchindUnmodified = br_r0_100036.getPcode(false);
		assertTrue(equalPcodeOpArrays(branchindUnmodified, br_r0_100036.getPcode()));
		PcodeOp[] branchindOverridden = br_r0_100036.getPcode(true);
		assertTrue(branchindOverridden.length == branchindUnmodified.length + 1);
		assertTrue(branchindOverridden[0].getOpcode() == PcodeOp.CALLIND);
		assertTrue(equalInputsAndOutput(branchindOverridden[0], branchindUnmodified[0]));
		assertTrue(branchindOverridden[1].getOpcode() == PcodeOp.RETURN);

		//should change CALL to CALL, RETURN
		PcodeOp[] callUnmodified = call_100038.getPcode(false);
		assertTrue(equalPcodeOpArrays(callUnmodified, call_100038.getPcode()));
		PcodeOp[] callOverridden = call_100038.getPcode(true);
		assertTrue(callOverridden.length == callUnmodified.length + 1);
		assertTrue(equalPcodeOps(callUnmodified[0], callOverridden[0]));
		assertTrue(equalPcodeOps(callUnmodified[1], callOverridden[1]));
		assertTrue(callOverridden[2].getOpcode() == PcodeOp.RETURN);

		//should change CALLIND to CALLIND, RETURN
		PcodeOp[] callindUnmodified = call_r0_10003a.getPcode(false);
		assertTrue(equalPcodeOpArrays(call_r0_10003a.getPcode(), callindUnmodified));
		PcodeOp[] callindOverridden = call_r0_10003a.getPcode(true);
		assertTrue(callindOverridden.length == callindUnmodified.length + 1);
		assertTrue(equalPcodeOps(callindOverridden[0], callindUnmodified[0]));
		assertTrue(equalPcodeOps(callindOverridden[1], callindUnmodified[1]));

		//should change RETURN to CALLIND, RETURN
		PcodeOp[] returnUnmodified = ret_10003c.getPcode(false);
		assertTrue(equalPcodeOpArrays(returnUnmodified, ret_10003c.getPcode()));
		PcodeOp[] returnOverridden = ret_10003c.getPcode(true);
		assertTrue(returnOverridden.length == returnUnmodified.length + 1);
		assertTrue(returnOverridden[0].getOpcode() == PcodeOp.CALLIND);
		assertTrue(equalInputsAndOutput(returnOverridden[0], returnUnmodified[0]));
		assertTrue(returnOverridden[1].getOpcode() == PcodeOp.RETURN);
	}

	/**
	 * Tests pcode emitted in the presence of a return
	 * @throws AddressFormatException  if {@code AddressSpace.getAddress} throws it
	 */
	@Test
	public void testReturnOverride() throws AddressFormatException {
		initializeAndVerifyFlowOverrideFuncs();
		applyFlowOverride(FlowOverride.RETURN);

		//shouldn't change skeq
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(true), skeq_10002e.getPcode(false)));
		assertTrue(equalPcodeOpArrays(skeq_10002e.getPcode(), skeq_10002e.getPcode(false)));

		//shouldn't change user_one
		assertTrue(
			equalPcodeOpArrays(user_one_100030.getPcode(true), user_one_100030.getPcode(false)));
		assertTrue(equalPcodeOpArrays(user_one_100030.getPcode(), user_one_100030.getPcode(false)));

		//should change BRANCH to COPY, RETURN
		PcodeOp[] brUnmodified = br_100032.getPcode(false);
		assertTrue(equalPcodeOpArrays(br_100032.getPcode(), brUnmodified));
		PcodeOp[] brOverridden = br_100032.getPcode(true);
		assertTrue(brOverridden.length == brUnmodified.length + 1);
		assertTrue(brOverridden[0].getOpcode() == PcodeOp.COPY);
		assertTrue(brOverridden[1].getOpcode() == PcodeOp.RETURN);

		//CBRANCH in this pcode is unaffected - see comment in testCallOverride()
		PcodeOp[] cbranchUnmodified = breq_100034.getPcode(false);
		assertTrue(equalPcodeOpArrays(cbranchUnmodified, breq_100034.getPcode()));
		PcodeOp[] cbranchOverridden = breq_100034.getPcode(true);
		assertTrue(cbranchOverridden.length == cbranchUnmodified.length + 1);
		assertTrue(equalPcodeOps(cbranchUnmodified[0], cbranchOverridden[0]));
		assertTrue(equalPcodeOps(cbranchUnmodified[1], cbranchOverridden[1]));
		assertTrue(cbranchOverridden[2].getOpcode() == PcodeOp.COPY);
		assertTrue(cbranchOverridden[3].getOpcode() == PcodeOp.RETURN);

		//should change BRANCHIND to RETURN
		PcodeOp[] branchindUnmodified = br_r0_100036.getPcode(false);
		assertTrue(equalPcodeOpArrays(branchindUnmodified, br_r0_100036.getPcode()));
		PcodeOp[] branchindOverridden = br_r0_100036.getPcode(true);
		assertTrue(branchindOverridden.length == 1);
		assertTrue(branchindOverridden[0].getOpcode() == PcodeOp.RETURN);
		assertTrue(equalInputsAndOutput(branchindOverridden[0], branchindUnmodified[0]));

		//should change CALL to COPY, RETURN
		PcodeOp[] callUnmodified = call_100038.getPcode(false);
		assertTrue(equalPcodeOpArrays(callUnmodified, call_100038.getPcode()));
		PcodeOp[] callOverridden = call_100038.getPcode(true);
		assertTrue(callOverridden.length == callUnmodified.length + 1);
		assertTrue(equalPcodeOps(callOverridden[0], callUnmodified[0]));
		assertTrue(callOverridden[1].getOpcode() == PcodeOp.COPY);
		assertTrue(callOverridden[2].getOpcode() == PcodeOp.RETURN);

		//should change CALLIND to RETURN
		PcodeOp[] callindUnmodified = call_r0_10003a.getPcode(false);
		assertTrue(equalPcodeOpArrays(call_r0_10003a.getPcode(), callindUnmodified));
		PcodeOp[] callindOverridden = call_r0_10003a.getPcode(true);
		assertTrue(callindOverridden.length == callindUnmodified.length);
		assertTrue(equalPcodeOps(callindOverridden[0], callindUnmodified[0]));
		assertTrue(callindOverridden[1].getOpcode() == PcodeOp.RETURN);

		//shouldn't change RETURN
		PcodeOp[] returnUnmodified = ret_10003c.getPcode(false);
		assertTrue(equalPcodeOpArrays(returnUnmodified, ret_10003c.getPcode()));
		PcodeOp[] returnOverridden = ret_10003c.getPcode(true);
		assertTrue(equalPcodeOpArrays(returnOverridden, returnUnmodified));
	}

	private void initializeAndVerifyFlowOverrideFuncs() throws AddressFormatException {
		skeq_10002e = program.getListing().getInstructionAt(defaultSpace.getAddress(SK_EQ_10002e));
		assertEquals("skeq", skeq_10002e.toString());
		user_one_100030 =
			program.getListing().getInstructionAt(defaultSpace.getAddress(USER_ONE_100030));
		assertEquals("user_one r0", user_one_100030.toString());
		br_100032 = program.getListing()
				.getInstructionAt(defaultSpace.getAddress(UNCONDITIONAL_JUMP_100032));
		assertEquals("br 0x00100036", br_100032.toString());
		breq_100034 =
			program.getListing().getInstructionAt(defaultSpace.getAddress(CONDITIONAL_JUMP_100034));
		assertEquals("breq 0x00100038", breq_100034.toString());
		br_r0_100036 =
			program.getListing().getInstructionAt(defaultSpace.getAddress(INDIRECT_JUMP_100036));
		assertEquals("br r0", br_r0_100036.toString());
		call_100038 =
			program.getListing().getInstructionAt(defaultSpace.getAddress(CALL_FUNC1_100038));
		assertEquals("call 0x00100100", call_100038.toString());
		call_r0_10003a =
			program.getListing().getInstructionAt(defaultSpace.getAddress(INDIRECT_CALL_10003a));
		assertEquals("call r0", call_r0_10003a.toString());
		ret_10003c = program.getListing().getInstructionAt(defaultSpace.getAddress(RETURN_10003c));
		assertEquals("ret", ret_10003c.toString());
	}

	private void applyFlowOverride(FlowOverride flowOver) {
		int tid = program.startTransaction("applyFlowOverride");
		skeq_10002e.setFlowOverride(flowOver);
		user_one_100030.setFlowOverride(flowOver);
		br_100032.setFlowOverride(flowOver);
		breq_100034.setFlowOverride(flowOver);
		br_r0_100036.setFlowOverride(flowOver);
		call_100038.setFlowOverride(flowOver);
		call_r0_10003a.setFlowOverride(flowOver);
		ret_10003c.setFlowOverride(flowOver);
		program.endTransaction(tid, true);
	}

	private boolean equalPcodeOpArrays(PcodeOp[] array1, PcodeOp[] array2) {
		if (array1 == null && array2 == null) {
			return true;
		}
		if (array1 == null || array2 == null) {
			return false;
		}
		if (array1.length != array2.length) {
			return false;
		}
		for (int i = 0; i < array1.length; ++i) {
			if (!equalPcodeOps(array1[i], array2[i])) {
				return false;
			}
		}
		return true;
	}

	private boolean equalPcodeOps(PcodeOp op1, PcodeOp op2) {
		if (op1.getOpcode() != op2.getOpcode()) {
			return false;
		}
		return equalInputsAndOutput(op1, op2);
	}

	//for testing modifications that can the pcode op but nothing else
	private boolean equalInputsAndOutput(PcodeOp op1, PcodeOp op2) {
		if (!Objects.equals(op1.getOutput(), op2.getOutput())) {
			return false;
		}
		if (op1.getNumInputs() != op2.getNumInputs()) {
			return false;
		}
		for (int i = 0; i < op1.getNumInputs(); ++i) {
			if (!Objects.equals(op1.getInput(i), op2.getInput(i))) {
				return false;
			}
		}
		return true;
	}

}
