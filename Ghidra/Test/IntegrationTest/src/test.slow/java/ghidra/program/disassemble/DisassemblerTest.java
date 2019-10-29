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
package ghidra.program.disassemble;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import org.junit.*;

import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitorAdapter;
import util.CollectionUtils;

public class DisassemblerTest extends AbstractGhidraHeadlessIntegrationTest {

	// TODO: Disassembler Concerns
	// - Unsure we can detect context inconsistencies where context produces constant and
	//   does not influence parse decision (i.e., prototypes are equal)
	// - Once CodeManager detects block overlap it stops processing instructions within the 
	//   block at the point of duplication causing inconsistent prototypes not to be detected
	//   in some cases (see testDisassemblerMidBlockOverlapWithProgramAndConflictDetection)
	// - InstructionBlock holds only one conflict - this may cause 
	//   some conflicts to get lost - CodeManager also sets conflicts which
	//   can wipe a previous conflict
	// - Conflicting context setting (via globalset) are not detected - last one wins
	// - We are inconsistent in our treatment of uninitialized memory and undefined memory
	//   in terms of conflict/error bookmarks

	// TODO: Change error handling of unintialized memory and EXTERNAL block

	// TODO: Add test where internal conflict occurs on top of different program
	// code units - CODE_UNIT conflict handling assumes real code unit exists at conflictAddress

	private ToyProgramBuilder programBuilder;// Instructions are 2-byte aligned 
	private Program program;
	private Listing listing;
	private Disassembler disassembler;

	private int txId;

	@Before
	public void setUp() throws Exception {
		programBuilder = new ToyProgramBuilder("Test", true, true, null);
		program = programBuilder.getProgram();
		txId = program.startTransaction("Add Memory");// leave open until tearDown
		programBuilder.createMemory(".text", "0", 64).setExecute(true);// initialized
		programBuilder.createUninitializedMemory(".unint", "0x40", 64).setExecute(true);// uninitialized
		programBuilder.createUninitializedMemory(".dat", "0x80", 64);// no-execute
		programBuilder.createMemory(".text2", "0x3e0", 0x800).setExecute(true);// initialized

		listing = program.getListing();
		disassembler = new Disassembler(program, TaskMonitorAdapter.DUMMY_MONITOR, null);
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

	/**
	 * ** Diagnostic Aid ** Dump context register values
	 */
//	private void dumpContextRanges(long min, long max, String regName) {
//		Msg.info(this, "Context ranges: " + regName);
//		Register fctxReg = program.getRegister(regName);
//		ProgramContext programContext = program.getProgramContext();
//		AddressRangeIterator ranges =
//			programContext.getRegisterValueAddressRanges(fctxReg, addr(min), addr(max));
//		for (AddressRange range : ranges) {
//			Msg.info(this,
//				range + ": " + programContext.getValue(fctxReg, range.getMinAddress(), false));
//		}
//		assertFalse(ranges.hasNext());
//	}

	private Address addr(long offset) {
		return programBuilder.getAddress(offset);
	}

	private AddressRange range(long start, long end) {
		return new AddressRangeImpl(addr(start), addr(end));
	}

	private AddressSet addrset(AddressRange... ranges) {
		AddressSet addrset = new AddressSet();
		for (AddressRange range : ranges) {
			addrset.add(range);
		}
		return addrset;
	}

	private void verifyInstructionPresence() {
		verifyInstructionPresence(null);
	}

	private void verifyInstructionPresence(Set<Address> exclusions) {
//		InstructionIterator instructions = listing.getInstructions(true);
//		while (instructions.hasNext()) {
//			Instruction instr = instructions.next();
//			System.out.println("Instruction at " + instr.getAddress());
//		}
		List<Address> instrAddrs = programBuilder.getDefinedInstructionAddress();
		int expectedCnt = instrAddrs.size();
		if (exclusions != null) {
			expectedCnt -= exclusions.size();
		}
		assertEquals(expectedCnt, listing.getNumInstructions());
		for (Address addr : instrAddrs) {
			if (exclusions != null && exclusions.contains(addr)) {
				continue;
			}
			assertNotNull("Expected instruction at " + addr, listing.getInstructionAt(addr));
		}
	}

	private void verifyNoBookmarks() {
		assertEquals("unexpected bookmarks exist", 0,
			program.getBookmarkManager().getBookmarkCount());
	}

	private void verifyErrorBookmark(Address addr, String text) {
		assertEquals("Expected error bookmark at " + addr, 1,
			program.getBookmarkManager().getBookmarkCount());

		Bookmark errMark = program.getBookmarkManager().getBookmark(addr, BookmarkType.ERROR,
			Disassembler.ERROR_BOOKMARK_CATEGORY);
		assertNotNull("Expected error bookmark at " + addr, errMark);

		if (text != null) {
			assertTrue("Expected error bookmark at " + addr + " to contain text: " + text,
				errMark.getComment().indexOf(text) >= 0);
		}

	}

	private static class ContextRangeValue {
		long startOffset;
		long endOffset;
		int value;

		ContextRangeValue(long start, long end, int value) {
			startOffset = start;
			endOffset = end;
			this.value = value;
		}
	}

	private void verifyContextRanges(long min, long max, String regName,
			ContextRangeValue... valueRanges) {
		Register fctxReg = program.getRegister(regName);
		ProgramContext programContext = program.getProgramContext();
		AddressRangeIterator ranges =
			programContext.getRegisterValueAddressRanges(fctxReg, addr(min), addr(max));
		for (ContextRangeValue valueRange : valueRanges) {
			assertTrue(ranges.hasNext());
			AddressRange range = ranges.next();
			assertEquals(valueRange.startOffset, range.getMinAddress().getOffset());
			assertEquals(valueRange.endOffset, range.getMaxAddress().getOffset());
			BigInteger val = programContext.getValue(fctxReg, range.getMinAddress(), false);
			assertNotNull("Expected flow context at " + range.getMinAddress());
			assertEquals(valueRange.value, val.longValue());
		}
		assertFalse(ranges.hasNext());
	}

	/**
	 * 
	 * +-> 10: breq 20 --+ (start)
	 * |   12: ret       |
	 * |                 |
	 * +-- 20: breq 10 <-+
	 *     22: ret
	 *     
	 * Test circular flow
	 * 
	 */
	@Test
	public void testDisassemblerCircularFlow() throws Exception {

		programBuilder.addBytesBranchConditional(10, 20);
		programBuilder.addBytesReturn(12);

		programBuilder.addBytesBranchConditional(20, 10);
		programBuilder.addBytesReturn(22);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 13), range(20, 23)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

	/**
	 * 
	 *     10: call 20 --+ (start)
	 *     12: ret       |
	 *                   |
	 *     20: or   <----+
	 *     22: ret
	 *     
	 * Test call
	 * 
	 */
	@Test
	public void testDisassemblerCallFlow() throws Exception {

		programBuilder.addBytesCall(10, 20);
		programBuilder.addBytesReturn(12);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesReturn(22);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 13), range(20, 23)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

	/**
	 * 
	 *     10: call 20 --+ (start)
	 *     12: ret       | (should not disassemble)
	 *                   |
	 *     20: or   <----+ (no-return)
	 *     22: ret
	 *     
	 * Test call
	 * 
	 */
	@Test
	public void testDisassemblerCallFlowNoReturn() throws Exception {

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesReturn(22);

		AddressSetView disAddrs = disassembler.disassemble(addr(20), null);
		AddressSet funcBody = addrset(range(20, 23));
		assertEquals(funcBody, disAddrs);

		verifyInstructionPresence();

		Function func = listing.createFunction("Foo", addr(20), funcBody, SourceType.USER_DEFINED);
		func.setNoReturn(true);

		programBuilder.addBytesCall(10, 20);
		programBuilder.addBytesReturn(12);// should not disassemble

		disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 11)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(12)));

		verifyNoBookmarks();

	}

	/**
	 *   +--10: breq 20 (start)
	 *   |  12: call 30 --+
	 *   |	14: ret       |
	 *   |	              |
	 *   +->	20: or        |
	 *	 +--	22: bral 40   |
	 *	 |	              |
	 *	 |	30: or   <----+
	 *	 |	32: bral 40 -+
	 *	 |	             |
	 *	 +->40: ret  <---+
	 * 
	 */
	@Test
	public void testDisassemblerMultipath() throws Exception {

		programBuilder.addBytesBranchConditional(10, 20);
		programBuilder.addBytesCall(12, 30);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranch(22, 40);

		programBuilder.addBytesFallthrough(30);
		programBuilder.addBytesBranch(32, 40);

		programBuilder.addBytesReturn(40);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15), range(20, 23), range(30, 33), range(40, 41)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

	/**
	 * 
	 *     10: callds 20 --+ (start)
	 *     12: _or         |
	 *     14: ret         |
	 *                     |
	 *     20: or   <------+
	 *     22: ret
	 *     
	 * Test simple delay slot flow
	 * 
	 */
	@Test
	public void testDisassemblerDelaySlot() throws Exception {

		programBuilder.addBytesCallWithDelaySlot(10, 20);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesReturn(22);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15), range(20, 23)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

	/**
	 *     10: or          (start)
	 *  +- 12: brds   20   
	 *  |  14: _or   <-----+
	 *  |  16: ret         |
	 *  |                  |
	 *  +->20: or          |
	 *     22: breq 14 ----+
	 *     24: ret
	 *     
	 * Test branch into delay slot already in InstructionSet
	 * 
	 */
	@Test
	public void testDisassemblerBranchIntoDelaySlot() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranchConditional(22, 14);
		programBuilder.addBytesReturn(24);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 17), range(20, 25)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(12));
		assertEquals(1, instr.getDelaySlotDepth());
		instr = listing.getInstructionAt(addr(14));
		assertTrue(instr.isInDelaySlot());

	}

	/**
	 *      4: bral 14 ----+   (start2)
	 *                     |
	 *     10: or          |   (start1)
	 *  +- 12: brds   20   |
	 *  |  14: _or   <-----+     
	 *  |  16: ret            (part of second run)
	 *  |         
	 *  +->20: ret   
	 *     
	 * Test branch into delay slot already in Program
	 * 
	 */
	@Test
	public void testDisassemblerBranchIntoDelaySlotInProgram() throws Exception {

		programBuilder.addBytesBranch(4, 14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchWithDelaySlot(12, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15), range(20, 21)), disAddrs);

		disAddrs = disassembler.disassemble(addr(4), null);
		assertEquals(addrset(range(4, 5), range(16, 17)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(12));
		assertEquals(1, instr.getDelaySlotDepth());
		instr = listing.getInstructionAt(addr(14));
		assertTrue(instr.isInDelaySlot());

	}

	/**
	 * +--  6: bral   12   (start)
	 * |
	 * |   10: callds 30 <-+ -+
	 * +-> 12: _or         |  |
	 *     14: breq 20 --+ |  |
	 *     16: ret       | |  |
	 *                   | |  |
	 *     20: or   <----+ |  |
	 *     22: bral 10 ----+  |
	 *                        |
	 *     30: ret  <---------+
	 *     
	 * Test delay slot disassembled first
	 * 
	 */
	@Test
	public void testDisassemblerDelaySlotFirst() throws Exception {

		programBuilder.addBytesBranch(6, 12);

		programBuilder.addBytesCallWithDelaySlot(10, 30);
		programBuilder.addBytesBranchConditional(14, 20);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranch(22, 10);

		programBuilder.addBytesReturn(30);

		AddressSetView disAddrs = disassembler.disassemble(addr(6), null);
		assertEquals(addrset(range(6, 7), range(10, 17), range(20, 23), range(30, 31)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(10));
		assertEquals(1, instr.getDelaySlotDepth());
		instr = listing.getInstructionAt(addr(12));
		assertTrue(instr.isInDelaySlot());

	}

	/**
	 * +--  6: bral 12  (start1)
	 * |
	 * |                   10: callds 20 <-+ (start2)
	 * +-> 12: or          12: _or         |
	 *     14: ret                         |
	 *                                     |
	 *                     20: ret  <------+
	 *     
	 * Test delay slot disassembled first in program
	 * 
	 */
	@Test
	public void testDisassemblerDelaySlotFirstInProgram() throws Exception {

		programBuilder.addBytesBranch(6, 12);

		programBuilder.addBytesCallWithDelaySlot(10, 20);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesReturn(20);

		AddressSetView disAddrs = disassembler.disassemble(addr(6), null);
		assertEquals(addrset(range(6, 7), range(12, 15)), disAddrs);

		disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 13), range(20, 21)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(10));
		assertEquals(1, instr.getDelaySlotDepth());
		instr = listing.getInstructionAt(addr(12));
		assertTrue(instr.isInDelaySlot());

	}

	/**
	 *      4: fctx   #2   (start)
	 * +--  6: bral   14 
	 * |
	 * |   10: nfctx  #3 <-+
	 * |   12: callds 30   |  --+
	 * +-> 14: _or         |    |
	 *     16: breq 10 ----+    |
	 *     18: ret              |
	 *                          |
	 *     30: ret  <-----------+
	 *     
	 * Test delay slot disassembled first w/ context
	 * 
	 */
	@Test
	public void testDisassemblerDelaySlotFirstWithContext() throws Exception {

		programBuilder.addBytesFallthroughSetFlowContext(4, 2);
		programBuilder.addBytesBranch(6, 14);

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3);
		programBuilder.addBytesCallWithDelaySlot(12, 30);
		programBuilder.addBytesBranchConditional(16, 10);
		programBuilder.addBytesReturn(18);

		programBuilder.addBytesReturn(30);

		AddressSetView disAddrs = disassembler.disassemble(addr(4), null);
		assertEquals(addrset(range(4, 7), range(10, 19), range(30, 31)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(12));
		assertEquals(1, instr.getDelaySlotDepth());
		instr = listing.getInstructionAt(addr(14));
		assertTrue(instr.isInDelaySlot());

		//dumpContextRanges(0, 40, "fctx");
		//dumpContextRanges(0, 40, "nfctx");

		//openProgramInTool();

		//@formatter:off
		verifyContextRanges(0, 40, "fctx", 
			new ContextRangeValue(6, 7, 2),
			new ContextRangeValue(10, 11, 2),
			new ContextRangeValue(12, 12, 2), // range split due to nfctx set @ 12
			new ContextRangeValue(13, 19, 2),
			new ContextRangeValue(30, 31, 2));
		verifyContextRanges(0, 40, "nfctx", 
			new ContextRangeValue(12, 12, 3));
		//@formatter:on

	}

	/**
	 *      4: fctx   #2   (start)
	 * +--  6: bral   14 
	 * |
	 * |   10: nfctx  #3 <-+
	 * |   12: call 30     |  --+
	 * +-> 14: breq 10 ----+    |
	 *     16: ret              |
	 *                          |
	 *     30: ret  <-----------+
	 *     
	 * Test disassembly w/ context (without delay slot)
	 * 
	 */
	@Test
	public void testDisassemblerWithContext() throws Exception {

		programBuilder.addBytesFallthroughSetFlowContext(4, 2);
		programBuilder.addBytesBranch(6, 14);

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3);
		programBuilder.addBytesCall(12, 30);
		programBuilder.addBytesBranchConditional(14, 10);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(30);

		AddressSetView disAddrs = disassembler.disassemble(addr(4), null);
		assertEquals(addrset(range(4, 7), range(10, 17), range(30, 31)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		//@formatter:off
		verifyContextRanges(0, 40, "fctx", 
			new ContextRangeValue(6, 7, 2),
			new ContextRangeValue(10, 11, 2), 
			new ContextRangeValue(12, 12, 2), // range split due to nfctx set @ 12
			new ContextRangeValue(13, 17, 2),
			new ContextRangeValue(30, 31, 2));
		verifyContextRanges(0, 40, "nfctx", 
			new ContextRangeValue(12, 12, 3));
		//@formatter:on

	}

	/**
	 *     10: nfctx  #3 
	 *     12: cop3
	 *     14: ret
	 *     
	 * Test use of non-flow context in disassembly
	 * 
	 */
	@Test
	public void testDisassemblerNonFlowContextParse() throws Exception {

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesReturn(14);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		//@formatter:off
		verifyContextRanges(0, 40, "nfctx", 
			new ContextRangeValue(12, 12, 3));
		//@formatter:on

		Instruction instr = listing.getInstructionAt(addr(12));
		assertEquals("cop3", instr.getMnemonicString());
	}

	/**
	 *     10: or 
	 *     12: cop3
	 *     14: ret
	 *     
	 * Test use of non-flow context in disassembly (previously set)
	 * 
	 */
	@Test
	public void testDisassemblerNonFlowContextParsePreset() throws Exception {

		program.getProgramContext().setValue(program.getRegister("nfctx"), addr(12), addr(12),
			BigInteger.valueOf(3));

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesReturn(14);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(12));
		assertEquals("cop3", instr.getMnemonicString());
	}

	/**
	 *     10: or 
	 *     12: cop3
	 *     14: ret
	 *     
	 * Test use of non-flow context in disassembly (previously set - mid-range)
	 * 
	 */
	@Test
	public void testDisassemblerNonFlowContextParsePresetRange() throws Exception {

		program.getProgramContext().setValue(program.getRegister("nfctx"), addr(10), addr(12),
			BigInteger.valueOf(3));

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesReturn(14);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(12));
		assertEquals("cop3", instr.getMnemonicString());
	}

	//
	// TEST RESTRICTED DISASSEMBLY
	//

	/**
	 * 
	 *     10: call 30 ----+ (start)
	 *     12: breq 20 --+ |
	 *     14: ret       | |
	 * +-> 16: ret       | | (should not disassemble)
	 * |  ^^ restrict ^^ | |
	 * |                 | |
	 * +-- 20: breq 16 <-+ | (should not disassemble)
	 *     22: ret         | (should not disassemble)
	 *                     |
	 *     30: ret     <---+ (should not disassemble)
	 *     
	 * Test restricted disassembly
	 * 
	 */
	@Test
	public void testDisassemblerRestricted() throws Exception {

		programBuilder.addBytesCall(10, 30);
		programBuilder.addBytesBranchConditional(12, 20);
		programBuilder.addBytesReturn(14);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesBranchConditional(20, 16);
		programBuilder.addBytesReturn(22);

		programBuilder.addBytesReturn(30);

		AddressSet restrictSet = addrset(range(0, 19));

		AddressSetView disAddrs = disassembler.disassemble(addr(10), restrictSet);
		assertEquals(addrset(range(10, 15)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(16), addr(20), addr(22), addr(30)));

		verifyNoBookmarks();

	}

	/**
	 * 
	 *     10: or
	 *     12: breq 14 --+
	 *     14: or   <----+
	 *     16: or 
	 *     18: ret   (should not disassemble)
	 *     
	 * Test restricted disassembly
	 * 
	 */
	@Test
	public void testDisassemblerRestricted2() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBranchConditional(12, 14);
		programBuilder.addBytesFallthrough(14);
		programBuilder.addBytesFallthrough(16);
		programBuilder.addBytesReturn(18);

		AddressSet restrictSet = addrset(range(0, 17));

		AddressSetView disAddrs = disassembler.disassemble(addr(10), restrictSet);
		assertEquals(addrset(range(10, 17)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(18)));

		verifyNoBookmarks();

	}

	//
	// TEST INSTRUCTION-SET LIMIT - FRAGMENTED DISASSEMBLY
	//

	/**
	 * +--  6: bral   12   (start)
	 * |
	 * |   10: callds 20 <-+  --+
	 * +-> 12: _or         |    |
	 *     14: breq 10 ----+    |
	 *     16: ret              |
	 *                          |
	 *     20: ret  <-----------+
	 *     
	 * Test fragmented disassembly with InstructionSet size limit of 1
	 * 
	 */
	@Test
	public void testDisassemblerLimit1() throws Exception {

		// Override instruction set limit
		disassembler.setInstructionSetSizeLimit(1);

		programBuilder.addBytesBranch(6, 12);

		programBuilder.addBytesCallWithDelaySlot(10, 20);
		programBuilder.addBytesBranchConditional(14, 10);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		AddressSetView disAddrs = disassembler.disassemble(addr(6), null);
		assertEquals(addrset(range(6, 7), range(10, 17), range(20, 21)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(10));
		assertEquals(1, instr.getDelaySlotDepth());
		instr = listing.getInstructionAt(addr(12));
		assertTrue(instr.isInDelaySlot());

	}

	/**
	 * +--  6: bral   12   (start)
	 * |
	 * |   10: callds 20 <-+  --+
	 * +-> 12: _or         |    |
	 *     14: breq 10 ----+    |
	 *     16: ret              |
	 *                          |
	 *     20: ret  <-----------+
	 *     
	 * Test fragmented disassembly with InstructionSet size limit of 2
	 * 
	 */
	@Test
	public void testDisassemblerLimit2() throws Exception {

		// Override instruction set limit
		disassembler.setInstructionSetSizeLimit(2);

		programBuilder.addBytesBranch(6, 12);

		programBuilder.addBytesCallWithDelaySlot(10, 20);
		programBuilder.addBytesBranchConditional(14, 10);
		programBuilder.addBytesReturn(16);

		programBuilder.addBytesReturn(20);

		AddressSetView disAddrs = disassembler.disassemble(addr(6), null);
		assertEquals(addrset(range(6, 7), range(10, 17), range(20, 21)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

		Instruction instr = listing.getInstructionAt(addr(10));
		assertEquals(1, instr.getDelaySlotDepth());
		instr = listing.getInstructionAt(addr(12));
		assertTrue(instr.isInDelaySlot());

	}

	/**
	 *   +--10: breq 20 (start)
	 *   |  12: call 30 --+
	 *   |	14: ret       |
	 *   |	              |
	 *   +->	20: or        |
	 *	 +--	22: bral 40   |
	 *	 |	              |
	 *	 |	30: or   <----+
	 *	 |	32: bral 40 -+
	 *	 |	             |
	 *	 +->40: ret  <---+
	 *
	 * Test fragmented disassembly with InstructionSet size limit of 2
	 * 
	 */
	@Test
	public void testDisassemblerLimit3() throws Exception {

		// Override instruction set limit
		disassembler.setInstructionSetSizeLimit(2);

		programBuilder.addBytesBranchConditional(10, 20);
		programBuilder.addBytesCall(12, 30);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranch(22, 40);

		programBuilder.addBytesFallthrough(30);
		programBuilder.addBytesBranch(32, 40);

		programBuilder.addBytesReturn(40);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15), range(20, 23), range(30, 33), range(40, 41)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

	/**
	 *   1000: or
	 *   1002: or
	 *   ...
	 *   2000: or
	 *   2002: ret
	 *
	 * Test fragmented disassembly with InstructionSet size limit of 2
	 * 
	 */
	@Test
	public void testDisassemblerLimit4() throws Exception {

		// Override instruction set limit
		disassembler.setInstructionSetSizeLimit(2);

		for (long offset = 1000; offset <= 2000; offset += 2) {
			programBuilder.addBytesFallthrough(offset);
		}
		programBuilder.addBytesReturn(2002);

		AddressSetView disAddrs = disassembler.disassemble(addr(1000), null);
		assertEquals(addrset(range(1000, 2003)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

	/**
	 *     10: nfctx #3   (start) -- writes no-flow context =3 @ 30
	 * +-- 14: br     22
	 * |    
	 * |   20: nop       <-+
	 * +-> 22: breq   30 - | -+
	 *     24: br     20 --+  |
	 *                        |
	 *     30: cop3   <-------+
	 *     32: ret
	 *     
	 * Limit Size: 4
	 * InstructionSet Order: 10,14,22,24/20,(22),(24),(30)/30,32
	 * () - indicates instructions blocked by those already added to program
	 *     
	 * Test fragmented disassembly with InstructionSet size limit of 4
	 * and flow priority given to code blocks already added to program.
	 * Flow priority is needed to ensure that block which consumes context
	 * is assured of being added.
	 * 
	 */
	@Test
	public void testDisassemblerFlowPriority() throws Exception {

		// Override instruction set limit
		disassembler.setInstructionSetSizeLimit(4);

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3, 30);
		programBuilder.addBytesBranch(14, 22);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesBranchConditional(22, 30);
		programBuilder.addBytesBranch(24, 20);

		programBuilder.addBytesCopInstruction(30);
		programBuilder.addBytesReturn(32);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);

//		openProgramInTool();

		assertEquals(addrset(range(10, 15), range(20, 25), range(30, 33)), disAddrs);

		verifyContextRanges(30, 30, "nfctx", new ContextRangeValue(30, 30, 3));

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

	//
	// TEST DUPLICATION WITH INSTRUCTIONS IN PROGRAM
	//

	/**
	 * 
	 * +-> 10: breq 20 --+ (start1)
	 * |   12: ret       |
	 * |                 |     18: breq 30 -+ (start2)
	 * +-- 20: breq 10 <-+         ...      |
	 *     22: ret                          |
	 *                                      |
	 *                         30: ret  <---+
	 *                         
	 * Test bumping into existing instructions in Program mid-block
	 * 
	 */
	@Test
	public void testDisassemblerMidBlockOverlapWithProgram() throws Exception {

		programBuilder.addBytesBranchConditional(10, 20);
		programBuilder.addBytesReturn(12);

		programBuilder.addBytesBranchConditional(20, 10);
		programBuilder.addBytesReturn(22);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 13), range(20, 23)), disAddrs);

		programBuilder.addBytesBranchConditional(18, 30);

		programBuilder.addBytesReturn(30);

		disAddrs = disassembler.disassemble(addr(18), null);
		assertEquals(addrset(range(18, 19), range(30, 31)), disAddrs);

		verifyInstructionPresence();

		verifyNoBookmarks();

	}

//	public void testDisassemblerMidBlockOverlapWithProgramAndConflictPreservation()
//			throws Exception {
//		// TODO: having difficult time coming up with valid test case
//	}

//	public void testDisassemblerMidBlockOverlapWithProgramAndConflictDetection() throws Exception {
//		// TODO: having difficult time coming up with valid test case
//	}

	//
	// TEST BAD PARSE CASES
	//

	/**
	 *     10: or 
	 *     12: BAD  (Unable to resolve constructor)
	 *     14: ret  (Not parsed due to parse error @ 12)
	 *     
	 * Test parse error
	 * 
	 */
	@Test
	public void testDisassemblerBadParse1() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesBadInstruction(12);
		programBuilder.addBytesReturn(14);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 11)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(14)));

		verifyErrorBookmark(addr(12), "Unable to resolve constructor");

	}

	/**
	 *     10: or 
	 *     12: cop#  (Unable to resolve constructor without context)
	 *     14: ret   (Not parsed due to parse error @ 12)
	 *     
	 * Test use of non-flow context in disassembly with expected parse error (not set)
	 * 
	 */
	@Test
	public void testDisassemblerBadParse2() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesReturn(14);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 11)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(12), addr(14)));

		verifyErrorBookmark(addr(12), "Unable to resolve constructor");

	}

	//
	//  TEST CONFLICT CASES
	//

	/**
	 *     10: or    
	 *     12: ret   (Not parsed due to data conflict @ 13)
	 *     
	 * Test data conflict error
	 * 
	 */
	@Test
	public void testDisassemblerDataConflict() throws Exception {

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesReturn(12);

		listing.createData(addr(13), ByteDataType.dataType);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);

		assertEquals(addrset(range(10, 11)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(12)));

		verifyErrorBookmark(addr(12), "conflicting data");

	}

	/**
	 *      10: or    (start2) 
	 *      12: nfctx 20,2   (4-byte instr not parsed due to instruction conflict @ 14)
	 *   +->16: ret
	 *   |  
	 *   |  14: imm   (start1) (parsed tail of 4-byte nfctx instr)
	 *   +--+
	 *     
	 * Test instruction conflict error
	 * 
	 */
	@Test
	public void testDisassemblerInstructionConflict() throws Exception {

		// instr at 14 is tail of nfctx but we need to add to program builder to register
		// instruction location for verification purpose only 
		programBuilder.addBytesFallthrough(14);

		programBuilder.addBytesFallthrough(10);
		programBuilder.addBytesFallthroughSetNoFlowContext(12, 2, 30);// overwrites instr bytes at 14
		programBuilder.addBytesReturn(16);

		AddressSetView disAddrs = disassembler.disassemble(addr(14), null);
		assertEquals(addrset(range(14, 17)), disAddrs);

		disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 11)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(12)));

		verifyErrorBookmark(addr(12), "conflicting instruction");

	}

	/**
	 *   +--10: breq 20
	 *   |  12: breq 30 ---+
	 *   |	14: ret        |
	 *   |	               |
	 *   +->	20: or         |
	 *      22: nfctx 18,2 | 24: imm (forced conflict)
	 *	 +--	26: bral 40    | 
	 *	 |	               |
	 *	 |	30: or   <-----+
	 *	 |  32: nfctx 28,2   
	 *	 |	36: bral 40 ---+
	 *	 |	               |
	 *	 +->40: ret  <-----+ (clear after first dis to allow flow from 36)
	 * 
	 */
	@Test
	public void testDisassemblerMultipathInstructionConflict1() throws Exception {

		// instr at 24 is tail of nfctx but we need to add to program builder to register
		// instruction location for verification purpose only 
		programBuilder.addBytesFallthrough(24);

		programBuilder.addBytesBranchConditional(10, 20);
		programBuilder.addBytesBranchConditional(12, 30);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesFallthroughSetNoFlowContext(22, 2, 18);// overwrites instr bytes at 24
		programBuilder.addBytesBranch(26, 40);

		programBuilder.addBytesFallthrough(30);
		programBuilder.addBytesFallthroughSetNoFlowContext(32, 2, 18);
		programBuilder.addBytesBranch(36, 40);

		programBuilder.addBytesReturn(40);

		AddressSetView disAddrs = disassembler.disassemble(addr(24), null);
		assertEquals(addrset(range(24, 27), range(40, 41)), disAddrs);

		// clear instruction at 40 to allow flow from 36
		program.getListing().clearCodeUnits(addr(40), addr(40), true);

		disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15), range(20, 21), range(30, 37), range(40, 41)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(22)));

		verifyErrorBookmark(addr(22), "conflicting instruction");

	}

	/**
	 *   +--10: breq 20
	 *   |  12: breq 30 ---+
	 *   |	14: ret        |
	 *   |	               |
	 *   +->	20: or         |
	 *      22: nfctx 18,2 |
	 *	 +--	26: bral 40    | 
	 *	 |	               |
	 *	 |	30: or   <-----+
	 *	 |  32: nfctx 28,2   34: imm (forced conflict)
	 *	 |	36: bral 40 ---+
	 *	 |	               |
	 *	 +->40: ret  <-----+ (clear after first dis to allow flow from 26)
	 * 
	 */
	@Test
	public void testDisassemblerMultipathInstructionConflict2() throws Exception {

		// instr at 24 is tail of nfctx but we need to add to program builder to register
		// instruction location for verification purpose only 
		programBuilder.addBytesFallthrough(34);

		programBuilder.addBytesBranchConditional(10, 20);
		programBuilder.addBytesBranchConditional(12, 30);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthrough(20);
		programBuilder.addBytesFallthroughSetNoFlowContext(22, 2, 18);
		programBuilder.addBytesBranch(26, 40);

		programBuilder.addBytesFallthrough(30);
		programBuilder.addBytesFallthroughSetNoFlowContext(32, 2, 18);// overwrites instr bytes at 34
		programBuilder.addBytesBranch(36, 40);

		programBuilder.addBytesReturn(40);

		AddressSetView disAddrs = disassembler.disassemble(addr(34), null);
		assertEquals(addrset(range(34, 37), range(40, 41)), disAddrs);

		// clear instruction at 40 to allow flow from 26
		program.getListing().clearCodeUnits(addr(40), addr(40), true);

		disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15), range(20, 27), range(30, 31), range(40, 41)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(32)));

		verifyErrorBookmark(addr(32), "conflicting instruction");

	}

	/**
	 *       10: nfctx #3   (start)
	 *       12: cop #    <-----+ (conflict due to varying context)
	 *       14: bral 20 -----+ |
	 *                        | |
	 *       20: nfctx 12,2 <-+ | (4-byte instr)
	 *       24: breq 12  ------+ 
	 *       26: ret
	 *     
	 * Test use of non-flow context in disassembly with expected parse error
	 * 
	 */
	@Test
	public void testDisassemblerInconsistentStartBlock() throws Exception {

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesBranch(14, 20);

		programBuilder.addBytesFallthroughSetNoFlowContext(20, 2, 12);
		programBuilder.addBytesBranchConditional(24, 12);
		programBuilder.addBytesReturn(26);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15), range(20, 27)), disAddrs);

		verifyInstructionPresence();

		verifyErrorBookmark(addr(12), "inconsistent instruction prototype");

	}

	/**
	 *       6: bral 12  --+ (start w/ nfctx=2 @ 12)
	 *                     |
	 *  +-> 10: nfctx #3   | 
	 *  |   12: cop3    <--+ (conflict due to varying context)
	 *  +-- 14: bral 10
	 *     
	 * Test use of non-flow context in disassembly with expected parse error
	 * 
	 */
	@Test
	public void testDisassemblerInconsistentMidBlock() throws Exception {

		program.getProgramContext().setValue(program.getRegister("nfctx"), addr(12), addr(12),
			BigInteger.valueOf(2));

		programBuilder.addBytesBranch(6, 12);

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesBranch(14, 10);

		AddressSetView disAddrs = disassembler.disassemble(addr(6), null);
		assertEquals(addrset(range(6, 7), range(10, 15)), disAddrs);

		verifyInstructionPresence();

		verifyErrorBookmark(addr(12), "inconsistent instruction prototype");

	}

	/**
	 *       10: nfctx #3   (start1)
	 *       12: cop #    <-----+ (conflict due to varying context)
	 *       14: ret            |
	 *                          |
	 *       20: nfctx 12,2     | (start2) (4-byte instr)
	 *       24: breq 12  ------+ 
	 *       26: ret
	 *     
	 * Test use of non-flow context in disassembly with expected parse error
	 * 
	 */
	@Test
	public void testDisassemblerInconsistentStartBlockInProgram() throws Exception {

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesReturn(14);

		programBuilder.addBytesFallthroughSetNoFlowContext(20, 2, 12);
		programBuilder.addBytesBranchConditional(24, 12);
		programBuilder.addBytesReturn(26);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 15)), disAddrs);

		disAddrs = disassembler.disassemble(addr(20), null);
		assertEquals(addrset(range(20, 27)), disAddrs);

		verifyInstructionPresence();

		verifyErrorBookmark(addr(12), "inconsistent instruction prototype");

	}

	/**
	 *       6: bral 12  --+ (start1 w/ nfctx=2 @ 12)
	 *                     |
	 *      10: nfctx #3   | (start2) 
	 *      12: cop3    <--+ (conflict due to varying context)
	 *      14: ret
	 *     
	 * Test use of non-flow context in disassembly with expected parse error
	 * 
	 */
	@Test
	public void testDisassemblerInconsistentMidBlockInProgram() throws Exception {

		program.getProgramContext().setValue(program.getRegister("nfctx"), addr(12), addr(12),
			BigInteger.valueOf(2));

		programBuilder.addBytesBranch(6, 12);

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 3);
		programBuilder.addBytesCopInstruction(12);
		programBuilder.addBytesReturn(14);

		AddressSetView disAddrs = disassembler.disassemble(addr(6), null);
		assertEquals(addrset(range(6, 7), range(12, 15)), disAddrs);

		disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 11)), disAddrs);

		verifyInstructionPresence();

		verifyErrorBookmark(addr(12), "inconsistent instruction prototype");

	}

//	public void testDisassemblerMultipleConflictsWithinBlock() throws Exception {
//		// TODO: having difficult time coming up with valid test case
//	}

	//
	// TEST MEMORY RESTRICTIONS
	//

	/**
	 * 	+-- 4: breq 11 (error bookmark on unaligned flow)
	 *  |   6: ret     (not disassembled - due to halted flow)
	 *  |
	 *  +-> 11: ret (not allowed - unaligned)
	 *     
	 * Test unaligned disassembly
	 * 
	 */
	@Test
	public void testDisassemblerUnaligned() throws Exception {

		programBuilder.addBytesBranchConditional(4, 11);
		programBuilder.addBytesReturn(6);

		programBuilder.addBytesReturn(11);

		AddressSetView disAddrs = disassembler.disassemble(addr(4), null);
		assertEquals(addrset(range(4, 5)), disAddrs);

		verifyInstructionPresence(CollectionUtils.asSet(addr(6), addr(11)));

		verifyErrorBookmark(addr(4), "violates 2-byte instruction alignment");

	}

	/**
	 * 	+-- 4: bral 10 
	 *  |
	 *  +-> 10: nfctx 20,2  (4-byte instr)
	 *      14: bral 20 --+ | (offcut conflict error @ 12)
	 *                    | |
	 *      20: cop #2  <-+ |
	 *      22: bral 12 ----+    (offcut conflict error)
	 *     
	 * Test offcut-conflict disassembly
	 * 
	 */
	@Test
	public void testDisassemblerOffcutConflict() throws Exception {

		programBuilder.addBytesBranch(4, 10);

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 2, 20);
		programBuilder.addBytesBranch(14, 20);

		programBuilder.addBytesCopInstruction(20);
		programBuilder.addBytesBranch(22, 12);

		AddressSetView disAddrs = disassembler.disassemble(addr(4), null);
		assertEquals(addrset(range(4, 5), range(10, 15), range(20, 23)), disAddrs);

		verifyInstructionPresence();

		verifyErrorBookmark(addr(12), "conflicting instruction");

	}

	/**
	 * 	+-- 4: bral 10 
	 *  |
	 *  +-> 10: nfctx 20,2  (4-byte instr)
	 *      14: bral 20 --+ | (offcut conflict error @ 12)
	 *                    | |
	 *      20: cop #2  <-+ |
	 *      22: ret         | 
	 *                      |
	 *      30: bral 12 ----+ 
	 *     
	 * Test offcut-conflict disassembly
	 * 
	 */
	@Test
	public void testDisassemblerOffcutConflictInProgram() throws Exception {

		programBuilder.addBytesBranch(4, 10);

		programBuilder.addBytesFallthroughSetNoFlowContext(10, 2, 20);
		programBuilder.addBytesBranch(14, 20);

		programBuilder.addBytesCopInstruction(20);
		programBuilder.addBytesReturn(22);

		programBuilder.addBytesBranch(30, 12);

		AddressSetView disAddrs = disassembler.disassemble(addr(4), null);
		assertEquals(addrset(range(4, 5), range(10, 15), range(20, 23)), disAddrs);

		disAddrs = disassembler.disassemble(addr(30), null);
		assertEquals(addrset(range(30, 31)), disAddrs);

		verifyInstructionPresence();

		verifyErrorBookmark(addr(12), "conflicting instruction");

	}

	/**
	 *     10: bral 200  (error on flow to non-existing memory)
	 *     
	 * Test flow into non-existing memory
	 * 
	 */
	@Test
	public void testDisassemblerNoMemory() throws Exception {

		programBuilder.addBytesBranch(10, 0xffffffe0L);

		AddressSetView disAddrs = disassembler.disassemble(addr(10), null);
		assertEquals(addrset(range(10, 11)), disAddrs);

		verifyInstructionPresence();

		verifyErrorBookmark(addr(10), "non-existing memory");

	}

//	public void testDisassemblerNonInitializedMemory() throws Exception {
//		// TODO: currently we ignore attempts to disassemble into Non-Intialized Memory
//	}

	@Test
	public void testDisassemblerNoExecuteMemory() throws Exception {
		// TODO: need to do this in master branch
	}

}
