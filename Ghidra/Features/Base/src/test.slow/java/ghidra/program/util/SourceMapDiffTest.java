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

import java.util.*;

import org.junit.*;

import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.database.sourcemap.SourceFileIdType;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.sourcemap.SourceFileManager;
import ghidra.program.model.sourcemap.SourceMapEntry;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.SourceFileUtils;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SourceMapDiffTest extends AbstractProgramDiffTest {

	private static final String COMMON_FILE = "/common";

	// differing files will have the same path but different identifiers
	private static final String DIFFERENT = "/different";
	private static final String TEST_FUNC_ADDR_STRING = "0x01002239";

	private SourceFile common;
	private SourceFile p1Only;
	private SourceFile p2Only;

	private SourceFileManager p1Manager;
	private SourceFileManager p2Manager;

	private List<Instruction> p1Insts;
	private List<Instruction> p2Insts;

	private AddressSet p1InstBodies;
	private AddressSet p1DiffInsts;

	@Before
	public void setUp() throws Exception {
		programBuilder1 = new ClassicSampleX86ProgramBuilder(false);
		programBuilder2 = new ClassicSampleX86ProgramBuilder(false);

		p1 = programBuilder1.getProgram();
		p2 = programBuilder2.getProgram();

		p1Insts = new ArrayList<>();
		p2Insts = new ArrayList<>();

		p1Manager = p1.getSourceFileManager();
		p2Manager = p2.getSourceFileManager();

		p1InstBodies = new AddressSet();
		p1DiffInsts = new AddressSet();

		int p1_txID = p1.startTransaction("setup");
		int p2_txID = p2.startTransaction("setup");

		common = new SourceFile(COMMON_FILE);
		byte[] p1Val = SourceFileUtils.longToByteArray(0x11111111);
		p1Only =
			new SourceFile(DIFFERENT, SourceFileIdType.TIMESTAMP_64, p1Val);
		byte[] p2Val = SourceFileUtils.longToByteArray(0x22222222);
		p2Only =
			new SourceFile(DIFFERENT, SourceFileIdType.TIMESTAMP_64, p2Val);

		try {
			p1Manager.addSourceFile(common);
			p1Manager.addSourceFile(p1Only);

			p2Manager.addSourceFile(common);
			p2Manager.addSourceFile(p2Only);
			Address prog1start = p1.getFunctionManager()
					.getFunctionAt(p1.getAddressFactory().getAddress(TEST_FUNC_ADDR_STRING))
					.getEntryPoint();
			InstructionIterator p1Iter = p1.getListing().getInstructions(prog1start, true);

			Address prog2start = p2.getFunctionManager()
					.getFunctionAt(p2.getAddressFactory().getAddress(TEST_FUNC_ADDR_STRING))
					.getEntryPoint();
			InstructionIterator p2Iter = p2.getListing().getInstructions(prog2start, true);
			/**
			 * 0)  no entries
			 * 1)  p1 yes, p2 no
			 * 2)  no entries
			 * 3)  p1 no,  p2 yes
			 * 4)  no entries
			 * 5)  files and lines different
			 * 6)  no entries
			 * 7)  files different, lines not
			 * 8)  no entries
			 * 9) files agree, lines different
			 * 10) no entries
			 * 11) files and lines agree
			 * 12) no entries
			 * 13) p1 two entries two files, p2 one of them
			 * 14) no entries
			 * 15) p2 two entries two files, p1 one of them
			 * 16) no entries
			 * 17) p1 two entries one file, p2 two entries one file, one line number diff
			 * 18) no entries
			 * 19) length difference
			 * 20) no entries
			 * 21) length 0 entry in p1, nothing in p2
			 * 22) no entries
			 * 23) nothing in p1, length 0 entry in p2
			 * 24) no entries
			 * 25) equal length 0 entries
			 * 26) no entries
			 * 
			 */
			// 0
			Instruction inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 1
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(common, 1, getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 2
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 3
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1DiffInsts.add(inst.getAddress());
			p1Insts.add(inst);
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(common, 3, getBody(inst));
			p2Insts.add(inst);

			// 4
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 5
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(p1Only, 51, getBody(inst));
			p1Insts.add(inst);
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(p2Only, 52, getBody(inst));
			p2Insts.add(inst);

			// 6
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 7
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(p1Only, 7, getBody(inst));
			p1Insts.add(inst);
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(p2Only, 7, getBody(inst));
			p2Insts.add(inst);

			// 8
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 9
			// XOR EAX,EAX length 2
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(common, 91, getBody(inst));
			p1Insts.add(inst);
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(common, 92, getBody(inst));
			p2Insts.add(inst);

			// 10
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 11
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			// files,lines, and lengths agree - not a diff
			p1Manager.addSourceMapEntry(common, 11, getBody(inst));
			p1Insts.add(inst);
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(common, 11, getBody(inst));
			p2Insts.add(inst);

			// 12
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 13
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(common, 13, getBody(inst));
			p1Manager.addSourceMapEntry(p1Only, 13, getBody(inst));
			inst = p2Iter.next();
			p2Insts.add(inst);
			p2Manager.addSourceMapEntry(common, 13, getBody(inst));

			// 14
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 15
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(common, 15, getBody(inst));
			inst = p2Iter.next();
			p2Insts.add(inst);
			p2Manager.addSourceMapEntry(common, 15, getBody(inst));
			p2Manager.addSourceMapEntry(p2Only, 15, getBody(inst));

			// 16
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 17 
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(common, 17, getBody(inst));
			p1Manager.addSourceMapEntry(common, 18, getBody(inst));
			inst = p2Iter.next();
			p2Insts.add(inst);
			p2Manager.addSourceMapEntry(common, 17, getBody(inst));
			p1Manager.addSourceMapEntry(common, 19, getBody(inst));

			// 18
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 19
			inst = p1Iter.next();
			// length of this instruction is 2
			p1InstBodies.add(getBody(inst));
			p1Manager.addSourceMapEntry(common, 1000, inst.getAddress(), 1);
			p1Insts.add(inst);
			p1DiffInsts.add(inst.getAddress());
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(common, 1000, inst.getAddress(), 2);
			p2Insts.add(inst);

			// 20
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 21
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1DiffInsts.add(inst.getAddress());
			p1Manager.addSourceMapEntry(p1Only, 1, inst.getAddress(), 0);
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 22
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 23
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1DiffInsts.add(inst.getAddress());
			p1Insts.add(inst);
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(p2Only, 3, inst.getAddress(), 0);
			p2Insts.add(inst);

			// 24
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

			// 25
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			// files,lines, and lengths agree - not a diff
			p1Manager.addSourceMapEntry(common, 25, inst.getAddress(), 0);
			p1Insts.add(inst);
			inst = p2Iter.next();
			p2Manager.addSourceMapEntry(common, 25, inst.getAddress(), 0);
			p2Insts.add(inst);

			// 26
			inst = p1Iter.next();
			p1InstBodies.add(getBody(inst));
			p1Insts.add(inst);
			p2Insts.add(p2Iter.next());

		}

		finally {
			p1.endTransaction(p1_txID, true);
			p2.endTransaction(p2_txID, true);
		}
	}

	@After
	public void tearDown() throws Exception {
		if (programBuilder1 != null) {
			programBuilder1.dispose();
		}
		if (programBuilder2 != null) {
			programBuilder2.dispose();
		}
	}

	@Test
	public void simpleDiffTest()
			throws ProgramConflictException, IllegalArgumentException, CancelledException {
		assertEquals(p1Insts.size(), p2Insts.size());
		AddressSet testSet = new AddressSet();
		p1Insts.forEach(i -> testSet.add(getBody(i)));
		assertEquals(testSet, p1InstBodies);
		programDiff = new ProgramDiff(p1, p2, p1InstBodies);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SOURCE_MAP_DIFFS));
		// verify that the differences found by progamDiff.getDifferences are exactly
		// the differences created in the setUp method
		assertEquals(p1DiffInsts,
			programDiff.getDifferences(programDiff.getFilter(), TaskMonitor.DUMMY));
	}

	@Test
	public void testReplace()
			throws ProgramConflictException, MemoryAccessException, CancelledException {
		ProgramMergeManager programMerge =
			new ProgramMergeManager(p1, p2, p1InstBodies);
		ProgramMergeFilter mergeFilter =
			new ProgramMergeFilter(ProgramMergeFilter.SOURCE_MAP, ProgramMergeFilter.REPLACE);

		// for good measure, verify one of the differences before merge
		SourceMapEntry p1Info = p1Manager.getSourceMapEntries(p1Insts.get(5).getAddress()).get(0);
		SourceMapEntry p2Info = p2Manager.getSourceMapEntries(p2Insts.get(5).getAddress()).get(0);

		assertNotEquals(p1Info.getSourceFile(), p2Info.getSourceFile());
		assertNotEquals(p1Info.getLineNumber(), p2Info.getLineNumber());

		int txId = p1.startTransaction("merging");
		try {
			boolean success = programMerge.merge(p1InstBodies, mergeFilter, TaskMonitor.DUMMY);
			assertTrue(success);
		}
		finally {
			p1.endTransaction(txId, true);
		}

		// now verify that source map info is the same for all addresses (not just beginnings of
		// instructions)
		AddressSet p2InstBodies = new AddressSet();
		p2Insts.forEach(i -> p2InstBodies.add(getBody(i)));
		assertEquals(p1InstBodies.getNumAddresses(), p2InstBodies.getNumAddresses());
		AddressIterator p1Iter = p1InstBodies.getAddresses(true);
		AddressIterator p2Iter = p2InstBodies.getAddresses(true);
		while (p1Iter.hasNext()) {
			Address p1Addr = p1Iter.next();
			Address p2Addr = p2Iter.next();
			List<SourceMapEntry> p1Entries = p1Manager.getSourceMapEntries(p1Addr);
			List<SourceMapEntry> p2Entries = p2Manager.getSourceMapEntries(p2Addr);
			assertEquals(p1Entries.size(), p2Entries.size());
			for (SourceMapEntry p1Entry : p1Entries) {
				int index = Collections.binarySearch(p2Entries, p1Entry);
				assertTrue(index >= 0);
			}
		}
	}

	@Test
	public void testIgnoreFilter()
			throws ProgramConflictException, MemoryAccessException, CancelledException {
		ProgramMergeManager programMerge =
			new ProgramMergeManager(p1, p2, p1InstBodies);
		ProgramMergeFilter mergeFilter =
			new ProgramMergeFilter(ProgramMergeFilter.SOURCE_MAP, ProgramMergeFilter.IGNORE);

		// verify one of the differences before merge
		SourceMapEntry p1Info = p1Manager.getSourceMapEntries(p1Insts.get(5).getAddress()).get(0);
		SourceMapEntry p2Info = p2Manager.getSourceMapEntries(p2Insts.get(5).getAddress()).get(0);

		assertNotEquals(p1Info.getSourceFile(), p2Info.getSourceFile());
		assertNotEquals(p1Info.getLineNumber(), p2Info.getLineNumber());

		int txId = p1.startTransaction("merging");
		try {
			boolean success = programMerge.merge(p1InstBodies, mergeFilter, TaskMonitor.DUMMY);
			assertTrue(success);
		}
		finally {
			p1.endTransaction(txId, true);
		}

		// verify the difference is still there
		p1Info = p1Manager.getSourceMapEntries(p1Insts.get(5).getAddress()).get(0);
		p2Info = p2Manager.getSourceMapEntries(p2Insts.get(5).getAddress()).get(0);

		assertNotEquals(p1Info.getSourceFile(), p2Info.getSourceFile());
		assertNotEquals(p1Info.getLineNumber(), p2Info.getLineNumber());

	}

	@Test
	public void testIgnoreOverlappingEntriesInDiff()
			throws ProgramConflictException, IllegalArgumentException, CancelledException {
		Address p1Inst9Addr = p1.getAddressFactory().getDefaultAddressSpace().getAddress(0x1002257);
		Instruction p1Inst9 = p1.getListing().getInstructionAt(p1Inst9Addr);
		assertNotNull(p1Inst9);
		assertEquals(2, p1Inst9.getLength());
		assertEquals("XOR EAX,EAX", p1Inst9.toString());

		AddressSet testSet = new AddressSet();
		testSet.add(getBody(p1Inst9));
		programDiff = new ProgramDiff(p1, p2, testSet);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SOURCE_MAP_DIFFS));
		//verify that there is a difference at p1Inst9Addr
		assertEquals(new AddressSet(p1Inst9Addr),
			programDiff.getDifferences(programDiff.getFilter(), TaskMonitor.DUMMY));

		testSet.clear();
		testSet.add(p1Inst9Addr.add(1));

		programDiff = new ProgramDiff(p1, p2, testSet);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SOURCE_MAP_DIFFS));
		//verify that no differences are reported, since the beginning of the source map entry
		//is not in testSet
		assertTrue(
			programDiff.getDifferences(programDiff.getFilter(), TaskMonitor.DUMMY).isEmpty());
	}

	@Test
	public void testMergeFilterChanged() {
		ProgramMergeFilter mergeFilter =
			new ProgramMergeFilter(ProgramMergeFilter.SOURCE_MAP, ProgramMergeFilter.MERGE);
		// MERGE not valid for source files - should be changed to REPLACE by the ProgramMergeFilter
		// constructor
		assertEquals(ProgramMergeFilter.REPLACE,
			mergeFilter.getFilter(ProgramMergeFilter.SOURCE_MAP));
	}

	private AddressRange getBody(CodeUnit cu) {
		return new AddressRangeImpl(cu.getMinAddress(), cu.getMaxAddress());
	}

}
