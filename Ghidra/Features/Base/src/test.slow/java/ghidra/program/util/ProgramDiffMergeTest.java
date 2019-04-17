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
import static ghidra.program.util.ProgramDiffFilter.*;

import java.util.Arrays;

import ghidra.program.model.address.*;
import ghidra.program.model.data.Pointer16DataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import org.junit.*;

public class ProgramDiffMergeTest extends AbstractGhidraHeadlessIntegrationTest {

	private ToyProgramBuilder programBuilder1;
	private Program program1;
	private Listing listing1;
	private ToyProgramBuilder programBuilder2;
	private Program program2;
	private Listing listing2;

	///////// setup and tear down /////////
	@Before
	public void setUp() throws Exception {
		programBuilder1 = createProgramBuilder("TestProgram1");
		program1 = programBuilder1.getProgram();
		listing1 = program1.getListing();

		programBuilder2 = createProgramBuilder("TestProgram2");
		program2 = programBuilder2.getProgram();
		listing2 = program2.getListing();
	}

	private ToyProgramBuilder createProgramBuilder(String name) throws Exception {
		ToyProgramBuilder programBuilder = new ToyProgramBuilder(name, true, true, null);
		int txID = programBuilder.getProgram().startTransaction("Set Execute on Memory");
		try {
			programBuilder.createMemory(".text", "0x01001000", 64).setExecute(true);// initialized

			// Function1 from 01001010 to 0100101f.
			// has call from 01001018 to 01001030. // 2 bytes
			// Function2 from 01001030 to 0100103d.

			programBuilder.createEmptyFunction("First", "0x01001010", 16, new Pointer16DataType());
			programBuilder.createEmptyFunction("Second", "0x01001030", 14, new Pointer16DataType());
			programBuilder.addBytesCall(0x01001018, 0x01001030);
			programBuilder.disassemble("0x01001018", 2);
			programBuilder.addBytesReturn(0x0100101f);
			programBuilder.disassemble("0x0100101f", 1);
		}
		finally {
			programBuilder.getProgram().endTransaction(txID, true);
		}

		return programBuilder;
	}

	@After
	public void tearDown() throws Exception {
		if (programBuilder1 != null) {
			programBuilder1.dispose();
		}
	}

	///////// Tests /////////

	@Test
	public void testDiffSrcFlowOverrideWithUserRefs() throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		Instruction p1CallInstr = listing1.getInstructionAt(p1CallFromAddr);
		int txID = program1.startTransaction("add flow override");
		try {
			p1CallInstr.setFlowOverride(FlowOverride.BRANCH);
		}
		finally {
			program1.endTransaction(txID, true);
		}

		AddressSet expectedDiffs = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		ProgramDiffFilter diffFilter = new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS);
		AddressSetView actualDiffs = programDiff.getDifferences(diffFilter, TaskMonitor.DUMMY);
		assertEquals(expectedDiffs, actualDiffs);
	}

	@Test
	public void testDiffDestFlowOverrideWithUserRefs() throws Exception {

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		int txID = program2.startTransaction("add flow override");
		try {
			p2CallInstr.setFlowOverride(FlowOverride.BRANCH);
		}
		finally {
			program2.endTransaction(txID, true);
		}

		AddressSet expectedDiffs = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		ProgramDiffFilter diffFilter = new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS);
		AddressSetView actualDiffs = programDiff.getDifferences(diffFilter, TaskMonitor.DUMMY);
		assertEquals(expectedDiffs, actualDiffs);
	}

	@Test
	public void testMergeDestFlowOverrideWithNonDefaultRefs_CodeUnitsOnly() throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		ReferenceManager refMgr1 = program1.getReferenceManager();
		int txID1 = program1.startTransaction("Set up program1");
		try {
			refMgr1.addMemoryReference(p1CallFromAddr, addr1(0x0100101c), RefType.READ,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program1.endTransaction(txID1, true);
		}

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		ReferenceManager refMgr2 = program2.getReferenceManager();
		int txID2 = program2.startTransaction("Set up program2");
		try {
			p2CallInstr.setFlowOverride(FlowOverride.BRANCH);
			refMgr2.addMemoryReference(p2CallFromAddr, addr2(0x0100101a), RefType.READ_WRITE,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program2.endTransaction(txID2, true);
		}

		AddressSet mergeSet = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		mergeCodeUnitsOnly(mergeSet);

		// Should still have differences here due to the mem refs.
		checkDiffCodeUnitsOnly(new AddressSet());
		checkDiffCodeUnitsAndRefs(mergeSet);

		// Is Flow Override as expected?
		validateFlowOverride(0x01001018, FlowOverride.BRANCH);

		// Do we have the expected references.
		ReferenceManager refManager1 = program1.getReferenceManager();
		Reference[] referencesFrom = refManager1.getReferencesFrom(addr1(0x01001018));
		Arrays.sort(referencesFrom);
		assertEquals(2, referencesFrom.length);
		validateReference(referencesFrom[0], 0x01001018, 0x0100101c, RefType.READ,
			SourceType.IMPORTED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[1], 0x01001018, 0x01001030, RefType.UNCONDITIONAL_JUMP,
			SourceType.DEFAULT, 0);
	}

	@Test
	public void testMergeDestFlowOverrideWithNonDefaultRefs_CodeUnitsAndRefs() throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		ReferenceManager refMgr1 = program1.getReferenceManager();
		int txID1 = program1.startTransaction("Set up program1");
		try {
			refMgr1.addMemoryReference(p1CallFromAddr, addr1(0x0100101c), RefType.READ,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program1.endTransaction(txID1, true);
		}

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		ReferenceManager refMgr2 = program2.getReferenceManager();
		int txID2 = program2.startTransaction("Set up program2");
		try {
			p2CallInstr.setFlowOverride(FlowOverride.BRANCH);
			refMgr2.addMemoryReference(p2CallFromAddr, addr2(0x0100101a), RefType.READ_WRITE,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program2.endTransaction(txID2, true);
		}

		AddressSet mergeSet = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		mergeCodeUnitsAndRefs(mergeSet);

		// No more differences.
		checkDiffCodeUnitsOnly(new AddressSet());
		checkDiffCodeUnitsAndRefs(new AddressSet());

		// Is Flow Override as expected?
		validateFlowOverride(0x01001018, FlowOverride.BRANCH);

		// Do we have the expected references.
		ReferenceManager refManager1 = program1.getReferenceManager();
		Reference[] referencesFrom = refManager1.getReferencesFrom(addr1(0x01001018));
		Arrays.sort(referencesFrom);
		assertEquals(2, referencesFrom.length);
		validateReference(referencesFrom[0], 0x01001018, 0x0100101a, RefType.READ_WRITE,
			SourceType.IMPORTED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[1], 0x01001018, 0x01001030, RefType.UNCONDITIONAL_JUMP,
			SourceType.DEFAULT, 0);
	}

	@Test
	public void testMergeSrcFlowOverrideWithNonDefaultRefs_CodeUnitsOnly() throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		Instruction p1CallInstr = listing1.getInstructionAt(p1CallFromAddr);
		ReferenceManager refMgr1 = program1.getReferenceManager();
		int txID1 = program1.startTransaction("Set up program1");
		try {
			p1CallInstr.setFlowOverride(FlowOverride.BRANCH);
			refMgr1.addMemoryReference(p1CallFromAddr, addr1(0x0100101c), RefType.READ,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program1.endTransaction(txID1, true);
		}

		Address p2CallFromAddr = addr2(0x01001018);
		ReferenceManager refMgr2 = program2.getReferenceManager();
		int txID2 = program2.startTransaction("Set up program2");
		try {
			refMgr2.addMemoryReference(p2CallFromAddr, addr2(0x0100101a), RefType.READ_WRITE,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program2.endTransaction(txID2, true);
		}

		AddressSet mergeSet = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		mergeCodeUnitsOnly(mergeSet);

		// Should still have differences here due to the mem refs.
		checkDiffCodeUnitsOnly(new AddressSet());
		checkDiffCodeUnitsAndRefs(mergeSet);

		// Is Flow Override as expected?
		validateFlowOverride(0x01001018, FlowOverride.NONE);

		// Do we have the expected references.
		ReferenceManager refManager1 = program1.getReferenceManager();
		Reference[] referencesFrom = refManager1.getReferencesFrom(addr1(0x01001018));
		Arrays.sort(referencesFrom);
		assertEquals(2, referencesFrom.length);
		validateReference(referencesFrom[0], 0x01001018, 0x0100101c, RefType.READ,
			SourceType.IMPORTED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[1], 0x01001018, 0x01001030, RefType.UNCONDITIONAL_CALL,
			SourceType.DEFAULT, 0);
	}

	@Test
	public void testMergeSrcFlowOverrideWithNonDefaultRefs_CodeUnitsAndRefs() throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		Instruction p1CallInstr = listing1.getInstructionAt(p1CallFromAddr);
		ReferenceManager refMgr1 = program1.getReferenceManager();
		int txID1 = program1.startTransaction("Set up program1");
		try {
			p1CallInstr.setFlowOverride(FlowOverride.BRANCH);
			refMgr1.addMemoryReference(p1CallFromAddr, addr1(0x0100101c), RefType.READ,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program1.endTransaction(txID1, true);
		}

		Address p2CallFromAddr = addr2(0x01001018);
		ReferenceManager refMgr2 = program2.getReferenceManager();
		int txID2 = program2.startTransaction("Set up program2");
		try {
			refMgr2.addMemoryReference(p2CallFromAddr, addr2(0x0100101a), RefType.READ_WRITE,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program2.endTransaction(txID2, true);
		}

		AddressSet mergeSet = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		mergeCodeUnitsAndRefs(mergeSet);

		// No more differences.
		checkDiffCodeUnitsOnly(new AddressSet());
		checkDiffCodeUnitsAndRefs(new AddressSet());

		// Is Flow Override as expected?
		validateFlowOverride(0x01001018, FlowOverride.NONE);

		// Do we have the expected references.
		ReferenceManager refManager1 = program1.getReferenceManager();
		Reference[] referencesFrom = refManager1.getReferencesFrom(addr1(0x01001018));
		Arrays.sort(referencesFrom);
		assertEquals(2, referencesFrom.length);
		validateReference(referencesFrom[0], 0x01001018, 0x0100101a, RefType.READ_WRITE,
			SourceType.IMPORTED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[1], 0x01001018, 0x01001030, RefType.UNCONDITIONAL_CALL,
			SourceType.DEFAULT, 0);
	}

	@Test
	public void testCUDiffDestFallthroughOverrideWithUserRefs() throws Exception {

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		int txID = program2.startTransaction("add fallthrough");
		try {
			p2CallInstr.setFallThrough(addr2(0x0100101e));
		}
		finally {
			program2.endTransaction(txID, true);
		}

		Address fallThrough = p2CallInstr.getFallThrough();
		assertEquals(addr2(0x0100101e), fallThrough);

		AddressSet expectedDiffs = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		ProgramDiffFilter diffFilter = new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS);
		AddressSetView actualDiffs = programDiff.getDifferences(diffFilter, TaskMonitor.DUMMY);
		assertEquals(expectedDiffs, actualDiffs);
	}

	@Test
	public void testRefDiffDestFallthroughOverrideWithUserRefs() throws Exception {

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		int txID = program2.startTransaction("add fallthrough");
		try {
			p2CallInstr.setFallThrough(addr2(0x0100101e));
		}
		finally {
			program2.endTransaction(txID, true);
		}

		Address fallThrough = p2CallInstr.getFallThrough();
		assertEquals(addr2(0x0100101e), fallThrough);

		AddressSet expectedDiffs = new AddressSet();
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		ProgramDiffFilter diffFilter = new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS);
		AddressSetView actualDiffs = programDiff.getDifferences(diffFilter, TaskMonitor.DUMMY);
		assertEquals(expectedDiffs, actualDiffs);
	}

	@Test
	public void testDiffDestRemoveFallthroughOverrideWithUserRefs() throws Exception {

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		int txID = program2.startTransaction("remove fallthrough");
		try {
			p2CallInstr.setFallThrough(null);
		}
		finally {
			program2.endTransaction(txID, true);
		}

		Address fallThrough = p2CallInstr.getFallThrough();
		assertNull(fallThrough);

		AddressSet expectedDiffs = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		ProgramDiffFilter diffFilter = new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS);
		AddressSetView actualDiffs = programDiff.getDifferences(diffFilter, TaskMonitor.DUMMY);
		assertEquals(expectedDiffs, actualDiffs);
	}

	@Test
	public void testMergeDestFallthroughOverrideWithNonDefaultRefs_CodeUnitsOnly() throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		ReferenceManager refMgr1 = program1.getReferenceManager();
		int txID1 = program1.startTransaction("Set up program1");
		try {
			refMgr1.addMemoryReference(p1CallFromAddr, addr1(0x0100101c), RefType.READ,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program1.endTransaction(txID1, true);
		}

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		ReferenceManager refMgr2 = program2.getReferenceManager();
		int txID2 = program2.startTransaction("Set up program2");
		try {
			p2CallInstr.setFallThrough(addr2(0x0100101e));
			refMgr2.addMemoryReference(p2CallFromAddr, addr2(0x0100101a), RefType.READ_WRITE,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program2.endTransaction(txID2, true);
		}

		AddressSet mergeSet = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		mergeCodeUnitsOnly(mergeSet);

		// Should still have differences here due to the mem refs.
		checkDiffCodeUnitsOnly(new AddressSet());
		checkDiffCodeUnitsAndRefs(mergeSet);
		checkDiffRefsOnly(mergeSet);

		// Is Fallthrough as expected?
		validateFallThrough(0x01001018, true, 0x0100101e);

		// Do we have the expected references.
		ReferenceManager refManager1 = program1.getReferenceManager();
		Reference[] referencesFrom = refManager1.getReferencesFrom(addr1(0x01001018));
		Arrays.sort(referencesFrom);
		assertEquals(3, referencesFrom.length);
		validateReference(referencesFrom[0], 0x01001018, 0x0100101c, RefType.READ,
			SourceType.IMPORTED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[1], 0x01001018, 0x0100101e, RefType.FALL_THROUGH,
			SourceType.USER_DEFINED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[2], 0x01001018, 0x01001030, RefType.UNCONDITIONAL_CALL,
			SourceType.DEFAULT, 0);
	}

	@Test
	public void testMergeDestFallthroughOverrideWithNonDefaultRefs_RefsOnly() throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		ReferenceManager refMgr1 = program1.getReferenceManager();
		int txID1 = program1.startTransaction("Set up program1");
		try {
			refMgr1.addMemoryReference(p1CallFromAddr, addr1(0x0100101c), RefType.READ,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program1.endTransaction(txID1, true);
		}

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		ReferenceManager refMgr2 = program2.getReferenceManager();
		int txID2 = program2.startTransaction("Set up program2");
		try {
			p2CallInstr.setFallThrough(addr2(0x0100101e));
			refMgr2.addMemoryReference(p2CallFromAddr, addr2(0x0100101a), RefType.READ_WRITE,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program2.endTransaction(txID2, true);
		}

		AddressSet mergeSet = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		mergeRefsOnly(mergeSet);

		// Should still have code unit differences here due to fallthrough.
		AddressSet expectedCodeUnitDiffs = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		AddressSet expectedRefDiffs = new AddressSet();
		checkDiffCodeUnitsOnly(expectedCodeUnitDiffs);
		checkDiffCodeUnitsAndRefs(expectedCodeUnitDiffs.union(expectedRefDiffs));
		checkDiffRefsOnly(expectedRefDiffs);

		// Is Fallthrough as expected? Not an override.
		validateFallThrough(0x01001018, true, 0x0100101a);

		// Do we have the expected references. No fallthrough ref.
		ReferenceManager refManager1 = program1.getReferenceManager();
		Reference[] referencesFrom = refManager1.getReferencesFrom(addr1(0x01001018));
		Arrays.sort(referencesFrom);
		assertEquals(2, referencesFrom.length);
		validateReference(referencesFrom[0], 0x01001018, 0x0100101a, RefType.READ_WRITE,
			SourceType.IMPORTED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[1], 0x01001018, 0x01001030, RefType.UNCONDITIONAL_CALL,
			SourceType.DEFAULT, 0);
	}

	@Test
	public void testMergeDestFallthroughOverrideWithNonDefaultRefs_CodeUnitsAndRefs()
			throws Exception {

		Address p1CallFromAddr = addr1(0x01001018);
		ReferenceManager refMgr1 = program1.getReferenceManager();
		int txID1 = program1.startTransaction("Set up program1");
		try {
			refMgr1.addMemoryReference(p1CallFromAddr, addr1(0x0100101c), RefType.READ,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program1.endTransaction(txID1, true);
		}

		Address p2CallFromAddr = addr2(0x01001018);
		Instruction p2CallInstr = listing2.getInstructionAt(p2CallFromAddr);
		ReferenceManager refMgr2 = program2.getReferenceManager();
		int txID2 = program2.startTransaction("Set up program2");
		try {
			p2CallInstr.setFallThrough(addr2(0x0100101e));
			refMgr2.addMemoryReference(p2CallFromAddr, addr2(0x0100101a), RefType.READ_WRITE,
				SourceType.IMPORTED, CodeUnit.MNEMONIC);
		}
		finally {
			program2.endTransaction(txID2, true);
		}

		AddressSet mergeSet = new AddressSet(addr1(0x01001018), addr1(0x01001019));
		mergeCodeUnitsAndRefs(mergeSet);

		// Should still have differences here due to the mem refs.
		checkDiffCodeUnitsOnly(new AddressSet());
		checkDiffCodeUnitsAndRefs(new AddressSet());
		checkDiffRefsOnly(new AddressSet());

		// Is Fallthrough as expected?
		validateFallThrough(0x01001018, true, 0x0100101e);

		// Do we have the expected references.
		ReferenceManager refManager1 = program1.getReferenceManager();
		Reference[] referencesFrom = refManager1.getReferencesFrom(addr1(0x01001018));
		Arrays.sort(referencesFrom);
		assertEquals(3, referencesFrom.length);
		validateReference(referencesFrom[0], 0x01001018, 0x0100101a, RefType.READ_WRITE,
			SourceType.IMPORTED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[1], 0x01001018, 0x0100101e, RefType.FALL_THROUGH,
			SourceType.USER_DEFINED, CodeUnit.MNEMONIC);
		validateReference(referencesFrom[2], 0x01001018, 0x01001030, RefType.UNCONDITIONAL_CALL,
			SourceType.DEFAULT, 0);
	}

	///////// private helper functions /////////

	private void validateFlowOverride(int instructionOffset, FlowOverride flowOverride) {
		Instruction inst1 = listing1.getInstructionAt(addr1(instructionOffset));
		assertEquals(flowOverride, inst1.getFlowOverride());
	}

	private void validateFallThrough(int instructionOffset, boolean hasFallThrough,
			int fallthroughOffset) {
		Instruction inst1 = listing1.getInstructionAt(addr1(instructionOffset));
		assertEquals(hasFallThrough, inst1.hasFallthrough());
		Address fallThrough = addr1(fallthroughOffset);
		assertEquals(fallThrough, inst1.getFallThrough());
	}

	private void validateReference(Reference reference, int fromOffset, int toOffset,
			RefType refType, SourceType sourceType, int operandIndex) {
		assertEquals(addr1(fromOffset), reference.getFromAddress());
		assertEquals(addr1(toOffset), reference.getToAddress());
		assertEquals(refType, reference.getReferenceType());
		assertEquals(sourceType, reference.getSource());
		assertEquals(operandIndex, reference.getOperandIndex());
	}

	private void checkDiffCodeUnitsOnly(AddressSet expectedDiffs) throws ProgramConflictException,
			IllegalArgumentException, CancelledException {
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		programDiff.setFilter(new ProgramDiffFilter(CODE_UNIT_DIFFS));
		assertEquals(expectedDiffs, programDiff.getDifferences(TaskMonitor.DUMMY));
	}

	private void checkDiffCodeUnitsAndRefs(AddressSet expectedDiffs)
			throws ProgramConflictException, IllegalArgumentException, CancelledException {
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		programDiff.setFilter(new ProgramDiffFilter(CODE_UNIT_DIFFS | REFERENCE_DIFFS));
		assertEquals(expectedDiffs, programDiff.getDifferences(TaskMonitor.DUMMY));
	}

	private void checkDiffRefsOnly(AddressSet expectedDiffs) throws ProgramConflictException,
			IllegalArgumentException, CancelledException {
		ProgramDiff programDiff = new ProgramDiff(program1, program2);
		programDiff.setFilter(new ProgramDiffFilter(REFERENCE_DIFFS));
		assertEquals(expectedDiffs, programDiff.getDifferences(TaskMonitor.DUMMY));
	}

	private ProgramMergeManager mergeCodeUnitsOnly(AddressSet mergeSet)
			throws ProgramConflictException, MemoryAccessException, CancelledException {
		ProgramMergeFilter programMergeFilter = 
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS, ProgramMergeFilter.REPLACE);
		return mergeUsingFilter(mergeSet, programMergeFilter);
	}
	
	private ProgramMergeManager mergeCodeUnitsAndRefs(AddressSet mergeSet)
			throws ProgramConflictException, MemoryAccessException, CancelledException {
		ProgramMergeFilter programMergeFilter =
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS | ProgramMergeFilter.REFERENCES,
				ProgramMergeFilter.REPLACE);
		return mergeUsingFilter(mergeSet, programMergeFilter);
	}
	
	private ProgramMergeManager mergeRefsOnly(AddressSet mergeSet) throws ProgramConflictException,
			MemoryAccessException, CancelledException {
		ProgramMergeFilter programMergeFilter =
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE);
		return mergeUsingFilter(mergeSet, programMergeFilter);
	}

	private ProgramMergeManager mergeUsingFilter(AddressSet mergeSet, ProgramMergeFilter programMergeFilter)
			throws ProgramConflictException, MemoryAccessException, CancelledException {
		ProgramMergeManager programMerge =
			new ProgramMergeManager(program1, program2, null, TaskMonitor.DUMMY); // null means entire program
		int txId = program1.startTransaction("Merge into Program 1");
		boolean commit = false;
		try {

			programMerge.setDiffFilter(new ProgramDiffFilter(CODE_UNIT_DIFFS));
			programMerge.setMergeFilter(programMergeFilter);
			assertTrue(programMerge.getFilteredDifferences().contains(mergeSet));

			programMerge.merge(mergeSet, TaskMonitor.DUMMY);

			commit = true;
		}
		finally {
			program1.endTransaction(txId, commit);
		}
		return programMerge;
	}

	private Address addr1(long offset) {
		return programBuilder1.addr(offset);
	}

	private Address addr2(long offset) {
		return programBuilder2.addr(offset);
	}
}
