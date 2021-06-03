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

import org.junit.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.ToyProgramBuilder;
import ghidra.util.task.TaskMonitorAdapter;

public class DisassemblerLargeSetTest extends AbstractGhidraHeadlessIntegrationTest {

	private static final int MEMORY_SIZE = 1024 * 128;

	private static final int CASESIZE = 12;

	private static final long NUMCASES = MEMORY_SIZE / CASESIZE;

	private static byte disBlock[] = { (byte) 0xf5, 0x0c, 0x03, 0x04, (byte) 0xf4, 0x00,
		(byte) 0xdf, 0x34, (byte) 0xf4, 0x00, (byte) 0xf4, 0x00 };

	private ToyProgramBuilder programBuilder;// Instructions are 2-byte aligned 
	private Program program;
	private Disassembler disassembler;

	private int txId;

	private long startTime = 0;

	@Before
	public void setUp() throws Exception {
		programBuilder = new ToyProgramBuilder("Test", true, true, null);
		program = programBuilder.getProgram();
		txId = program.startTransaction("Add Memory");// leave open until tearDown
		programBuilder.createMemory(".text", "0", MEMORY_SIZE).setExecute(true);// initialized

		// Fill memory
		MemoryBlock block = programBuilder.getProgram().getMemory().getBlock(addr(0x0));
		long numCases = MEMORY_SIZE / CASESIZE;
		for (long i = 0; i < numCases; i++) {
			block.putBytes(addr(i * CASESIZE), disBlock);
		}

		disassembler = new Disassembler(program, TaskMonitorAdapter.DUMMY_MONITOR, null);

		startTime = System.currentTimeMillis();
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			program.endTransaction(txId, true);
		}
		if (programBuilder != null) {
			programBuilder.dispose();
		}

		long endTime = System.currentTimeMillis();
		System.out.println("Time: " + ((double) endTime - (double) startTime) / 1000.0);
	}

	private Address addr(long offset) {
		return programBuilder.getAddress(offset);
	}

	private void verifyBookmarks(int cnt) {
		assertEquals("unexpected bookmarks exist", cnt,
			program.getBookmarkManager().getBookmarkCount());
	}

	@Test
	public void testLargeDisjointPointsNoPredisassembledPoints() throws Exception {

		// disassemble the threaded flow
		AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassemble1.contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE + 6));
		}

		AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);

		assertTrue(disassemble2.contains(disLocs2));

		verifyBookmarks(1);
	}

	@Test
	public void testLargeDisjointPointsWithAlreadyDiassembledPoints() throws Exception {
		// disassemble the threaded flow
		AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassemble1.contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE));
			disLocs2.add(addr(i * CASESIZE + 6));
		}

		AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);

		assertTrue(disassemble2.contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testLargeDisjointRange() throws Exception {
		// disassemble the threaded flow
		AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassemble1.contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE));
			disLocs2.add(addr(i * CASESIZE + 6), addr(i * CASESIZE + 10));
		}

		AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);

		assertTrue(disassemble2.contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testLargeDisjointRangePartialOverlap() throws Exception {
		// disassemble the threaded flow
		AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassemble1.contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE));
			disLocs2.add(addr(i * CASESIZE + 6), addr(i * CASESIZE + 11));
		}

		AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);

		assertTrue(disassemble2.contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testLargeDisjointRangeFullOverlap() throws Exception {
		// disassemble the threaded flow
		AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE), addr(i * CASESIZE + 3));
		}
		assertTrue(disassemble1.contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE), addr(i * CASESIZE + 3));
			disLocs2.add(addr(i * CASESIZE + 6), addr(i * CASESIZE + 11));
		}

		AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);

		assertTrue(disassemble2.contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testSingleRange() throws Exception {
		AddressSet disLocs2 = new AddressSet(addr(0x0), addr(CASESIZE * (NUMCASES)));

		AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);

		assertTrue(disassemble2.contains(disLocs2));
	}

	@Test
	public void testSingleRangeDisjoint() throws Exception {
		// disassemble the threaded flow
		AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);

		AddressSet disLocs2 = new AddressSet(addr(0x0), addr(CASESIZE * (NUMCASES)));

		AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(!disassemble2.contains(disLocs));
	}

	@Test
	public void testLargeDisjointPointsNoPredisassembledPointsCmd() throws Exception {

		// disassemble the threaded flow
		//AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);
		DisassembleCommand disassembleCommand = new DisassembleCommand(addr(0x0), null, true);
		disassembleCommand.applyTo(program);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassembleCommand.getDisassembledAddressSet().contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE + 6));
		}

		//AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);
		disassembleCommand = new DisassembleCommand(disLocs2, null, true);
		disassembleCommand.applyTo(program);

		assertTrue(disassembleCommand.getDisassembledAddressSet().contains(disLocs2));

		verifyBookmarks(1);
	}

	@Test
	public void testLargeDisjointPointsWithAlreadyDiassembledPointsCmd() throws Exception {
		// disassemble the threaded flow
		//AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);
		DisassembleCommand disassembleCommand = new DisassembleCommand(addr(0x0), null, true);
		disassembleCommand.applyTo(program);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassembleCommand.getDisassembledAddressSet().contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE));
			disLocs2.add(addr(i * CASESIZE + 6));
		}

		//AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);
		disassembleCommand = new DisassembleCommand(disLocs2, null, true);
		disassembleCommand.applyTo(program);

		assertTrue(
			disassembleCommand.getDisassembledAddressSet().contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testLargeDisjointRangeCmd() throws Exception {
		// disassemble the threaded flow
		// AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);
		DisassembleCommand disassembleCommand = new DisassembleCommand(addr(0x0), null, true);
		disassembleCommand.applyTo(program);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassembleCommand.getDisassembledAddressSet().contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE));
			disLocs2.add(addr(i * CASESIZE + 6), addr(i * CASESIZE + 10));
		}

		//AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);
		disassembleCommand = new DisassembleCommand(disLocs2, null, true);
		disassembleCommand.applyTo(program);

		assertTrue(
			disassembleCommand.getDisassembledAddressSet().contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testLargeDisjointRangePartialOverlapCmd() throws Exception {
		// disassemble the threaded flow
		//AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);
		DisassembleCommand disassembleCommand = new DisassembleCommand(addr(0x0), null, true);
		disassembleCommand.applyTo(program);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(disassembleCommand.getDisassembledAddressSet().contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE));
			disLocs2.add(addr(i * CASESIZE + 6), addr(i * CASESIZE + 11));
		}

		//AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);
		disassembleCommand = new DisassembleCommand(disLocs2, null, true);
		disassembleCommand.applyTo(program);

		assertTrue(
			disassembleCommand.getDisassembledAddressSet().contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testLargeDisjointRangeFullOverlapCmd() throws Exception {
		// disassemble the threaded flow
		//AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);
		DisassembleCommand disassembleCommand = new DisassembleCommand(addr(0x0), null, true);
		disassembleCommand.applyTo(program);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE), addr(i * CASESIZE + 3));
		}
		assertTrue(disassembleCommand.getDisassembledAddressSet().contains(disLocs));

		AddressSet disLocs2 = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs2.add(addr(i * CASESIZE), addr(i * CASESIZE + 3));
			disLocs2.add(addr(i * CASESIZE + 6), addr(i * CASESIZE + 11));
		}

		//AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);
		disassembleCommand = new DisassembleCommand(disLocs2, null, true);
		disassembleCommand.applyTo(program);

		assertTrue(
			disassembleCommand.getDisassembledAddressSet().contains(disLocs2.subtract(disLocs)));
	}

	@Test
	public void testSingleRangeCmd() throws Exception {
		AddressSet disLocs2 = new AddressSet(addr(0x0), addr(CASESIZE * (NUMCASES)));

		//AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);
		DisassembleCommand disassembleCommand = new DisassembleCommand(disLocs2, null, true);
		disassembleCommand.applyTo(program);

		assertTrue(disassembleCommand.getDisassembledAddressSet().contains(disLocs2));
	}

	@Test
	public void testSingleRangeDisjointCmd() throws Exception {
		// disassemble the threaded flow
		//AddressSet disassemble1 = disassembler.disassemble(addr(0x0), null, true);
		DisassembleCommand disassembleCommand = new DisassembleCommand(addr(0x0), null, true);
		disassembleCommand.applyTo(program);

		AddressSet disLocs2 = new AddressSet(addr(0x0), addr(CASESIZE * (NUMCASES)));

		//AddressSet disassemble2 = disassembler.disassemble(disLocs2, null, true);
		disassembleCommand = new DisassembleCommand(disLocs2, null, true);
		disassembleCommand.applyTo(program);

		AddressSet disLocs = new AddressSet();
		for (long i = 0; i < NUMCASES; i++) {
			disLocs.add(addr(i * CASESIZE));
		}
		assertTrue(!disassembleCommand.getDisassembledAddressSet().contains(disLocs));
	}
}
