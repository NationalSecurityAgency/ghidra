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

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.*;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import junit.framework.TestCase;

/**
 * <CODE>ProgramMergeTest</CODE> tests the <CODE>ProgramMerge</CODE> class
 * to verify it correctly applies various types of program differences from
 * program2 to program1.
 * The setup for this test class loads two programs that were saved to the
 * testdata directory as XML. The tests will verify that differences get
 * applied properly from program2 to program1.
 */
public class ProgramMerge3Test extends AbstractGhidraHeadedIntegrationTest {

	private ProgramMergeManager programMerge;
	ClassicSampleX86ProgramBuilder programBuilder1;
	ClassicSampleX86ProgramBuilder programBuilder2;
	private Program p1;
	private Program p2;
	int txId1;
	int txId2;

	/** Creates new ProgramDiffTest */
	public ProgramMerge3Test() {
		super();
	}

	/**
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		programBuilder1 = new ClassicSampleX86ProgramBuilder(false);
		programBuilder2 = new ClassicSampleX86ProgramBuilder(false);
		p1 = programBuilder1.getProgram();
		p2 = programBuilder2.getProgram();
		txId1 = p1.startTransaction("Modify Program1");
		txId2 = p2.startTransaction("Modify Program2");
	}

	/**
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		p1.endTransaction(txId1, false);
		p2.endTransaction(txId2, false);
		programMerge = null;
		p1 = null;
		p2 = null;
		programBuilder1.dispose();
		programBuilder2.dispose();
		programBuilder1 = null;
		programBuilder2 = null;

	}

	/**
	 * Test that programMerge can determine the blank format line user defined property
	 * differences between Program1 and Program2.
	 */
	@Test
	public void testApplyBlankFormatLineDifferences() throws Exception {
		// 0x100248c: p2 has format line indicating function exit.
		// 0x1002428: p1 and p2 both have a format line.
		programBuilder1.setIntProperty("0x1002428", "Space", 1);
	
		programBuilder2.setIntProperty("0x100248c", "Space", 1);
		programBuilder2.setIntProperty("0x1002428", "Space", 1);
	
		AddressSet addrSet = new AddressSet(addr(0x1002488), addr(0x1002492));
		addrSet.addRange(addr(0x01002428), addr(0x0100242c));
		programMerge = new ProgramMergeManager(p1, p2, addrSet, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x100248c), addr(0x100248e));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.USER_DEFINED_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.PROPERTIES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
		 * Test that programMerge can determine the bookmark user defined property
		 * differences between Program1 and Program2.
		 */
		@Test
		public void testApplyBookmarkDifferences() throws Exception {
			// 0x1002306: p1 and p2 have same bookmarks.
			programBuilder1.createBookmark("0x1002306", BookmarkType.INFO, "Cat1", "My bookmark");
			programBuilder2.createBookmark("0x1002306", BookmarkType.INFO, "Cat1", "My bookmark");
	
			// 0x100230b: p1 and p2 have bookmarks with different categories.
			programBuilder1.createBookmark("0x100230b", BookmarkType.INFO, "Cat1", "My bookmark");
			programBuilder2.createBookmark("0x100230b", BookmarkType.INFO, "Stuff", "My bookmark");
	
			// 0x100230c: p1 has bookmark, p2 doesn't.
			programBuilder1.createBookmark("0x100230c", BookmarkType.INFO, "", "Something different");
	
			// 0x100230d: p2 has bookmark, p1 doesn't.
			programBuilder2.createBookmark("0x100230d", BookmarkType.INFO, "", "My bookmark");
	
			// 0x1002312: p1 and p2 have bookmarks with no category and different descriptions.
			programBuilder1.createBookmark("0x1002312", BookmarkType.INFO, "", "Something different");
			programBuilder2.createBookmark("0x1002312", BookmarkType.INFO, "", "My bookmark");
	
			// 0x1002318: p1 and p2 have bookmarks with same category and different descriptions.
			programBuilder1.createBookmark("0x1002318", BookmarkType.INFO, "stuff",
				"Something different");
			programBuilder2.createBookmark("0x1002318", BookmarkType.INFO, "stuff", "My bookmark");
	
			// 0x100231d: p1 and p2 have same NOTE bookmarks.
			programBuilder1.createBookmark("0x100231d", BookmarkType.NOTE, "stuff", "My bookmark");
			programBuilder2.createBookmark("0x100231d", BookmarkType.NOTE, "stuff", "My bookmark");
	
			// 0x1002323: p1 and p2 have same INFO bookmarks.
			programBuilder1.createBookmark("0x1002323", BookmarkType.INFO, "stuff", "My bookmark");
			programBuilder2.createBookmark("0x1002323", BookmarkType.INFO, "stuff", "My bookmark");
	
			programMerge = new ProgramMergeManager(p1, p2,
				new AddressSet(addr(0x1002306), addr(0x100232f)), TaskMonitorAdapter.DUMMY_MONITOR);
			AddressSet as = new AddressSet(addr(0x100230b), addr(0x100231c));
			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.BOOKMARK_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.BOOKMARKS, ProgramMergeFilter.REPLACE));
	//		printAddressSet(as);
	//		printAddressSet(programMerge.getFilteredDifferences());
			assertEquals(as, programMerge.getFilteredDifferences());
			programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
		}

	/**
	 * Test that ProgramMerge can apply the byte differences between Program1
	 * and Program2 when merging bytes and code units both when the bytes differ for an
	 * instruction but its prototype doesn't.
	 */
	@Test
	public void testApplyByteAndCodeUnitDifferencesSamePrototypeDiffByte() throws Exception {
	
		programBuilder1.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder1.setBytes("0x01002cf8", "3b 74 24 08", true);
	
		programBuilder2.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder2.setBytes("0x01002cf8", "3b 74 24 0c", true);
	
		// p1 & p2 differ at byte at 0x01002cfb.
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(
			ProgramDiffFilter.BYTE_DIFFS | ProgramDiffFilter.CODE_UNIT_DIFFS));
		programMerge.setMergeFilter(new ProgramMergeFilter(
			ProgramMergeFilter.BYTES | ProgramMergeFilter.CODE_UNITS, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01002cf8), addr(0x01002cfb));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
	
		AddressSet unMergableByteAddresses = new AddressSet();// None that can't merge.
		assertEquals(unMergableByteAddresses, programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the byte differences between Program1
	 * and Program2.
	 */
	@Test
	public void testApplyByteDifferences() throws Exception {
	
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
	
		// p1 has 0x100 to 0x1ff with byte values of 0xCF, but in p2 of 0xAF.
		// p1 has changed byte at 0x1002b45 from 0x8b to 0xee.
		// p2 has changed byte at 0x1002b49 from 0x57 to 0xee.
	
		programBuilder1.setBytes("0x1002b45", "ee");
		programBuilder1.setBytes("0x1002b49", "ee");
	
		programBuilder2.setBytes("0x1002b45", "8b");
		programBuilder2.setBytes("0x1002b49", "57");
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.BYTES, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x100), addr(0x1ff));
		as.addRange(addr(0x01002b45), addr(0x01002b45));
		as.addRange(addr(0x01002b49), addr(0x01002b49));
		// Add the bytes for the blocks that are in program1 and not in program2.
		as.addRange(addr(0x00000200), addr(0x000002ff));
		// Add the blocks that are in program2 and not program1 that are compatible.
		as.addRange(addr(0x00000400), addr(0x000004ff));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
	
		AddressSet unMergableByteAddresses = new AddressSet();
		// Add the bytes for the blocks that are in program1 and not in program2.
		unMergableByteAddresses.addRange(addr(0x00000200), addr(0x000002ff));
		// Add the blocks that are in program2 and not program1 that are compatible.
		unMergableByteAddresses.addRange(addr(0x00000400), addr(0x000004ff));
		assertEquals(unMergableByteAddresses, programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the code unit differences between
	 * Program1 and Program2.
	 */
	@Test
	public void testApplyCodeUnitDifferences() throws Exception {
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
		programBuilder1.createLabel("0x01006420", "Function1");
		programBuilder1.createComment("0x010059a3", "Here we are.", CodeUnit.EOL_COMMENT);
		programBuilder1.setBytes("0x01002b45", "ee");
		programBuilder1.setBytes("0x01002b49", "57", true);
		programBuilder1.clearCodeUnits("0x01002cf5", "0x01002d6d", true);
		programBuilder1.setBytes("0x01002951", "45 10 83 e8 00 74 12", true);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
		programBuilder2.createLabel("0x01006420", "Function2");
		programBuilder2.createComment("0x010059a3", "There you have it.", CodeUnit.EOL_COMMENT);
		programBuilder2.setBytes("0x01002b45", "8b");
		programBuilder2.setBytes("0x01002b49", "ee", true);
		programBuilder2.clearCodeUnits("0x01002239", "0x0100248e", true);
		programBuilder2.disassemble("0x10024b8", 19);
		programBuilder2.setBytes("0x01002950", "8b 45 10 83 e8 00 74 12", true);
	
		// p2 has code units cleared from 0x1005887 to 0x1005fbd.
		// p1 has code unit at 0x1005912 cleared only.
		// p1 & p2 have different bytes causing different instructions at 0x01002b49.
		// static disassembly from 10024b8-10024ca in p2 & from 10024b9-10024ca in p1 (p1 offcut from p2).
		AddressSet as = new AddressSet();
		as.addRange(addr(0x1001000), addr(0x1003abf));
		as.addRange(addr(0x1003bed), addr(0x10075ff));
		programMerge = new ProgramMergeManager(p1, p2, as, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS, ProgramMergeFilter.REPLACE));
		AddressSet addrSet = new AddressSet();
		addrSet.addRange(addr(p1, 0x01002239), addr(p1, 0x0100248e));
		addrSet.addRange(addr(p1, 0x01002cf5), addr(p1, 0x01002d6d));
		addrSet.addRange(addr(p1, 0x01002b49), addr(p1, 0x01002b49));
		addrSet.addRange(addr(p1, 0x01002950), addr(p1, 0x01002957));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(addrSet, diffAs);
	
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can apply a conflicting data type difference in
	 * Program1 and Program2.
	 */
	@Test
	public void testApplyConflictingDataTypeDifferences() throws Exception {
	
		// 0x01003b02: different unions with differing structures inside.
	
		Structure struct_b1 = new StructureDataType("struct_a", 0);
		struct_b1.add(new ByteDataType());
		struct_b1.add(new PointerDataType(new DWordDataType()));
	
		Union union_a1 = new UnionDataType("union_1");
		union_a1.add(new ByteDataType());
		union_a1.add(struct_b1);
		programBuilder1.applyDataType("0x01003b02", union_a1, 1);
	
		Structure struct_b2 = new StructureDataType("struct_a", 0);
		struct_b2.add(new ByteDataType());
		struct_b2.add(new PointerDataType(new CharDataType()));
	
		Union union_a2 = new UnionDataType("union_1");
		union_a2.add(new CharDataType());
		union_a2.add(struct_b1);
		programBuilder2.applyDataType("0x01003b02", union_a2, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS, ProgramMergeFilter.REPLACE));
	
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01003b02), addr(0x01003b06));
		assertEquals(as, programMerge.getFilteredDifferences());
		CodeUnit cu1 = p1.getListing().getCodeUnitAt(addr(0x01003b02));
		CodeUnit cu2 = p2.getListing().getCodeUnitAt(addr(0x01003b02));
		assertTrue(cu1 instanceof Data);
		assertTrue(cu2 instanceof Data);
		Data d1 = (Data) cu1;
		Data d2 = (Data) cu2;
		DataType dt1 = d1.getDataType();
		DataType dt2 = d2.getDataType();
		assertTrue(dt1 instanceof Union);
		assertTrue(dt2 instanceof Union);
		Union u1 = (Union) dt1;
		Union u2 = (Union) dt2;
		assertEquals("union_1", u1.getName());
		assertEquals("union_1", u2.getName());
		assertEquals(false, u1.isEquivalent(u2));
	
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
	
		assertEquals(as, programMerge.getFilteredDifferences());
		cu1 = p1.getListing().getCodeUnitAt(addr(0x01003b02));
		cu2 = p2.getListing().getCodeUnitAt(addr(0x01003b02));
		assertTrue(cu1 instanceof Data);
		assertTrue(cu2 instanceof Data);
		d1 = (Data) cu1;
		d2 = (Data) cu2;
		dt1 = d1.getDataType();
		dt2 = d2.getDataType();
		assertTrue(dt1 instanceof Union);
		assertTrue(dt2 instanceof Union);
		u1 = (Union) dt1;
		u2 = (Union) dt2;
		assertEquals("union_1.conflict", u1.getName());
		assertEquals("union_1", u2.getName());
		assertTrue(u1.isEquivalent(u2));
		assertEquals(stripConflictDtSuffixes(u1.getPathName()),
			stripConflictDtSuffixes(u2.getPathName()));
	
		// Try to apply it again. Should get same result.
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
	
		assertEquals(as, programMerge.getFilteredDifferences());
		cu1 = p1.getListing().getCodeUnitAt(addr(0x01003b02));
		cu2 = p2.getListing().getCodeUnitAt(addr(0x01003b02));
		assertTrue(cu1 instanceof Data);
		assertTrue(cu2 instanceof Data);
		d1 = (Data) cu1;
		d2 = (Data) cu2;
		dt1 = d1.getDataType();
		dt2 = d2.getDataType();
		assertTrue(dt1 instanceof Union);
		assertTrue(dt2 instanceof Union);
		u1 = (Union) dt1;
		u2 = (Union) dt2;
		assertEquals("union_1.conflict", u1.getName());
		assertEquals("union_1", u2.getName());
		assertTrue(u1.isEquivalent(u2));
		assertEquals(stripConflictDtSuffixes(u1.getPathName()),
			stripConflictDtSuffixes(u2.getPathName()));
	}

	@Test
	public void testApplyDataDifference1() throws Exception {
	
		// 0x01003ac8: same size and named struct with different components.
	
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
		programBuilder1.applyDataType("0x01003ac8", struct_a1, 1);
	
		Structure struct_a2 = new StructureDataType("struct_a", 0);
		struct_a2.add(new CharDataType());
		struct_a2.add(new DWordDataType());
		programBuilder2.applyDataType("0x01003ac8", struct_a2, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003ac8), addr(0x01003acc)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003ac8, 0x01003acc);
		// Will result in a conflict named copy.
		assertEquals(new AddressSet(addr(0x01003ac8), addr(0x01003acc)),
			programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference10() throws Exception {
	
		// 0x01003b29: different type of pointers.
	
		programBuilder1.applyDataType("0x01003b29", new PointerDataType(new WordDataType()), 1);
	
		programBuilder2.applyDataType("0x01003b29", new PointerDataType(new ByteDataType()), 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b29), addr(0x01003b2c)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b29, 0x01003b2c);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference11() throws Exception {
	
		// 0x01003b31: 5 bytes vs an array of 5 bytes.
	
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
	
		programBuilder2.applyDataType("0x01003b31", new ArrayDataType(new ByteDataType(), 5, 1), 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b31), addr(0x01003b35)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b31, 0x01003b35);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference12() throws Exception {
	
		// 0x01003b3a: p2 has a double.
	
		programBuilder2.applyDataType("0x1003b3a", new DoubleDataType(), 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b3a), addr(0x01003b41)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b3a, 0x01003b41);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference13() throws Exception {
	
		// 0x01003b45: p1 and p2 have the same nested structure.
	
		Structure inner = new StructureDataType("inner", 0);
		inner.add(new ByteDataType());
		inner.add(new PointerDataType(new DWordDataType()));
	
		Structure outer = new StructureDataType("outer", 0);
		outer.add(new ByteDataType());
		outer.add(inner);
	
		programBuilder1.applyDataType("0x01003b45", outer, 1);
	
		programBuilder2.applyDataType("0x01003b45", outer, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference14() throws Exception {
	
		// 0x01003b5e - 0x01003b62: p1 has instructions and p2 has structure
	
		programBuilder1.setBytes("0x01003b5e", "75 12 39 75 08", true);
	
		programBuilder2.setBytes("0x01003b5e", "75 12 39 75 08", false);
	
		Structure struct_a2 = new StructureDataType("struct_a", 0);
		struct_a2.add(new CharDataType());
		struct_a2.add(new DWordDataType());
		programBuilder2.applyDataType("0x01003b5e", struct_a2, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b5e), addr(0x01003b62)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b5e, 0x01003b62);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference2() throws Exception {
	
		// 0x01003ad5: same structs except different pointer type component.
	
		Structure struct_b1 = new StructureDataType("struct_a", 0);
		struct_b1.add(new ByteDataType());
		struct_b1.add(new PointerDataType(new DWordDataType()));
		programBuilder1.applyDataType("0x01003ad5", struct_b1, 1);
	
		Structure struct_b2 = new StructureDataType("struct_a", 0);
		struct_b2.add(new ByteDataType());
		struct_b2.add(new PointerDataType(new CharDataType()));
		programBuilder2.applyDataType("0x01003ad5", struct_b2, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003ad5), addr(0x01003ad9)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003ad5, 0x01003ad9);
		// Will result in a conflict named copy.
		assertEquals(new AddressSet(addr(0x01003ad5), addr(0x01003ad9)),
			programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference3() throws Exception {
	
		// 0x01003ae1: struct vs union
	
		Structure struct_c1 = new StructureDataType("struct_c", 0);
		struct_c1.add(new WordDataType());
		struct_c1.add(new FloatDataType());
		programBuilder1.applyDataType("0x01003ae1", struct_c1, 1);
	
		Union union_c2 = new UnionDataType("union_c");
		union_c2.add(new ByteDataType());
		union_c2.add(new PointerDataType(new DWordDataType()));
		union_c2.add(new DWordDataType());
		programBuilder2.applyDataType("0x01003ae1", union_c2, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003ae1), addr(0x01003ae6)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003ae1, 0x01003ae6);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference4() throws Exception {
	
		// 0x01003aec & 0x1003aed: same struct positioned 0ne byte address different.
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
	
		programBuilder1.applyDataType("0x01003aec", struct_a1, 1);
	
		programBuilder2.applyDataType("0x1003aed", struct_a1, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003aec), addr(0x01003af1)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003aec, 0x01003af1);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference5() throws Exception {
	
		// 0x01003af7: same struct with different names.
	
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
	
		programBuilder1.applyDataType("0x01003af7", struct_a1, 1);
	
		Structure struct_altName_a1 = new StructureDataType("my_struct_a", 0);
		struct_altName_a1.add(new ByteDataType());
		struct_altName_a1.add(new DWordDataType());
		programBuilder2.applyDataType("0x1003af7", struct_altName_a1, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003af7), addr(0x01003afb)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003af7, 0x01003afb);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference6() throws Exception {
	
		// 0x01003b02: same struct, different category
	
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
		programBuilder1.applyDataType("0x01003b02", struct_a1, 1);
	
		Structure struct_sub1_a1 = new StructureDataType(new CategoryPath("/sub1"), "struct_a", 0);
		struct_sub1_a1.add(new ByteDataType());
		struct_sub1_a1.add(new DWordDataType());
		programBuilder2.applyDataType("0x1003b02", struct_sub1_a1, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b02), addr(0x01003b06)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b02, 0x01003b06);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference7() throws Exception {
	
		// 0x01003b0d: different data type with different size
	
		programBuilder1.applyDataType("0x01003b0d", new WordDataType(), 1);
	
		programBuilder2.applyDataType("0x1003b0d", new ByteDataType(), 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b0d), addr(0x01003b0e)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b0d, 0x01003b0e);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference8() throws Exception {
	
		// 0x01003b14: different data type, same size
	
		programBuilder1.applyDataType("0x01003b14", new CharDataType(), 1);
	
		programBuilder2.applyDataType("0x1003b14", new ByteDataType(), 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b14), addr(0x01003b14)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b14, 0x01003b14);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyDataDifference9() throws Exception {
	
		// 0x01003b1c: different variable length data types, same size
	
		programBuilder1.applyDataType("0x01003b1c", new StringDataType(), 1);
	
		programBuilder2.applyDataType("0x1003b1c", new UnicodeDataType(), 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x01003b1c), addr(0x01003b1d)),
			programMerge.getFilteredDifferences());
		mergeCodeUnitDifference(0x01003b1c, 0x01003b1d);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the equate differences between
	 * Program1 and Program2.
	 */
	@Test
	public void testApplyEquateDifferences() throws Exception {
	
		// 0x100650e: Both have same equates. op2 is 0x22.
	
		// 0x100643d: p1 has an equate op 2 is -0x68. p2 doesn't.
		// 0x100644d: p2 has an equate op 1 is 0x2. p1 doesn't.
		// 0x1006455: Both have different named equates. op2 is 0x4.
		// 0x10064c5: p1 has MY_EQUATE. op2 is 0x8.
		// 0x10064ee: p2 has MY_EQUATE. op2 is 0x14.
	
		programBuilder1.createEquate("0x100650e", "Pos22", 0x22, 2);
		programBuilder1.createEquate("0x100643d", "Minus68", -0x68, 2);
		programBuilder1.createEquate("0x1006455", "Pos4", 0x4, 2);
		programBuilder1.createEquate("0x10064c5", "MY_EQUATE", 0x8, 2);
	
		programBuilder2.createEquate("0x100650e", "Pos22", 0x22, 2);
		programBuilder2.createEquate("0x100644d", "Two", 0x2, 2);
		programBuilder2.createEquate("0x100643d", "Four", 0x4, 2);
		programBuilder2.createEquate("0x10064ee", "MY_EQUATE", 0x14, 2);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x100643d), addr(0x100643d));
		as.addRange(addr(0x100644d), addr(0x100644d));
		as.addRange(addr(0x1006455), addr(0x1006455));
		as.addRange(addr(0x10064c5), addr(0x10064c5));
		as.addRange(addr(0x10064ee), addr(0x10064ee));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.EQUATE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testApplyExtRefDiff1() throws Exception {
		// 0x1001028: p2 changed external ref to mem ref on operand 0.
	
		programBuilder1.applyDataType("0x01001028", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x01001028", "ADVAPI32.dll", "IsTextUnicode", 0);
	
		programBuilder2.applyDataType("0x01001028", new Pointer32DataType(), 1);
		programBuilder2.createMemoryReference("0x01001028", "0x01001000", RefType.INDIRECTION,
			SourceType.DEFAULT);
	
		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x01001000), addr(0x010017ff)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x01001028), addr(0x0100102b));
	
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the function bodies are different.
	 */
	@Test
	public void testApplyFunctionBodyDiff() throws Exception {
		int transactionID = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(0x100299e));
		function2.setBody(new AddressSet(addr(0x100299e), addr(0x1002a89)));
		p2.endTransaction(transactionID, true);
	
		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x0100299e), addr(0x01002a90)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x0100299e), addr(0x0100299e));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine that function default stack params are
	 * different.
	 */
	@Test
	public void testApplyFunctionDefaultStackLocalDiff() throws Exception {
	
		// 0x010048a3: created default stack local_1 in p2.
	
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x010048a3));
		programBuilder2.createLocalVariable(function2, null, DataType.DEFAULT, 0x1);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x010048a3), addr(0x010048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine that function default stack params are
	 * different.
	 */
	@Test
	public void testApplyFunctionDefaultStackParamDiff() throws Exception {
	
		// 0x1002cf5: created default stack param in p2.
		int transactionID = p2.startTransaction("Test Transaction");
		Function function = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		Variable var = new ParameterImpl("variable", DataType.DEFAULT, 0x1c, p2);
		function.addParameter(var, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x1002cf5), addr(0x1002cf5));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine that function local names are
	 * different.
	 */
	@Test
	public void testApplyFunctionLocalNameDiff() throws Exception {
	
		// 0x10059a3: renamed local_18 to numAvailable in p1.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10059a3));
		Variable[] localVariables = function1.getLocalVariables();
		assertEquals(5, localVariables.length);
		assertEquals(-0x18, localVariables[4].getStackOffset());
		localVariables[4].setName("numAvailable", SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10059a3), addr(0x10059a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine that function parameter names are
	 * different.
	 */
	@Test
	public void testApplyFunctionLocalsDiff() throws Exception {
	
		// 0x10059a3: removed local_18 in p1.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10059a3));
		Variable[] localVariables = function1.getLocalVariables();
		assertEquals(5, localVariables.length);
		assertEquals(-0x18, localVariables[4].getStackOffset());
		function1.removeVariable(localVariables[4]);
		p1.endTransaction(transactionID1, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10059a3), addr(0x10059a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine that function local types are
	 * different.
	 */
	@Test
	public void testApplyFunctionLocalTypeDiff() throws Exception {
	
		// 0x10059a3: in p1 local_8 is a Undefined, in p2 it's Pointer.
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10059a3));
		Variable[] localVariables = function1.getLocalVariables();
		assertEquals(5, localVariables.length);
		assertEquals(-0x8, localVariables[0].getStackOffset());
		localVariables[0].setDataType(DataType.DEFAULT, SourceType.DEFAULT);
		p1.endTransaction(transactionID1, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10059a3));
		Variable[] localVariables2 = function2.getLocalVariables();
		assertEquals(5, localVariables2.length);
		assertEquals(-0x8, localVariables2[0].getStackOffset());
		localVariables2[0].setDataType(new PointerDataType(), SourceType.DEFAULT);
		p2.endTransaction(transactionID2, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10059a3), addr(0x10059a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the function names are different.
	 */
	@Test
	public void testApplyFunctionNameDiff() throws Exception {
	
		// 0x010048a3: function names differ.
		// 0x01002239: function names same.
		int transactionID = p1.startTransaction("Test Transaction");
		FunctionManager functionManager1 = p1.getFunctionManager();
		Function function1 = functionManager1.getFunctionAt(addr(0x010048a3));
		assertNotNull(function1);
		function1.setName("MyFunction48a3", SourceType.USER_DEFINED);
		function1 = functionManager1.getFunctionAt(addr(0x01002239));
		assertNotNull(function1);
		function1.setName("Function2239", SourceType.USER_DEFINED);
		p1.endTransaction(transactionID, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		FunctionManager functionManager2 = p2.getFunctionManager();
		Function function2 = functionManager2.getFunctionAt(addr(0x010048a3));
		assertNotNull(function2);
		function2.setName("Other48a3", SourceType.USER_DEFINED);
		function2 = functionManager2.getFunctionAt(addr(0x01002239));
		assertNotNull(function2);
		function2.setName("Function2239", SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(
			ProgramDiffFilter.FUNCTION_DIFFS | ProgramDiffFilter.SYMBOL_DIFFS));
		programMerge.setMergeFilter(new ProgramMergeFilter(
			ProgramMergeFilter.FUNCTIONS | ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine there is a function difference when
	 * the function is only in Program1.
	 */
	@Test
	public void testApplyFunctionOnlyInP1() throws Exception {
		// In p1 not in p2.
		int transactionID = p2.startTransaction("Test Transaction");
		p2.getFunctionManager().removeFunction(addr(0x10030d2));
		p2.endTransaction(transactionID, true);
	
		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x10030d2), addr(0x10030d7)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x10030d2), addr(0x10030d2));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine there is a function difference when
	 * the function is only in Program2.
	 */
	@Test
	public void testApplyFunctionOnlyInP2() throws Exception {
		// In p2 and not in p1.
		int transactionID = p1.startTransaction("Test Transaction");
		p1.getFunctionManager().removeFunction(addr(0x10030d2));
		p1.endTransaction(transactionID, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x10030d2), addr(0x10030d2));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine that function parameter names are
	 * different.
	 */
	@Test
	public void testApplyFunctionParamNameDiff() throws Exception {
	
		// 0x01002cf5: renamed parm_2 to value in p1.
		int transactionID = p1.startTransaction("Test Transaction");
		Function function = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function.getParameter(0).setName("value", SourceType.USER_DEFINED);
		p1.endTransaction(transactionID, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x01002cf5), addr(0x01002cf5));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
		 * Test that programMerge can determine that function param offsets are
		 * different.
		 */
		@Test
		public void testApplyFunctionParamOffsetDiff() throws Exception {
	
			// 0x010032d5: changed param offset from 0x8 to 0x4 in p2.
	
			AddressSet as = new AddressSet();
			as.addRange(addr(0x010032d5), addr(0x010033f5));
			programMerge = new ProgramMergeManager(p1, p2, as, TaskMonitorAdapter.DUMMY_MONITOR);
			AddressSet diffAs = new AddressSet();
	// For now, we are not allowing you to set the parameter offset or local size outright.
	//        diffAs.addRange(addr(0x010032d5), addr(0x010032d5));
			programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
			programMerge.setMergeFilter(
				new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
			assertEquals(diffAs, programMerge.getFilteredDifferences());
			programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
			assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
		}

	/**
	 * Test that programMerge can determine that function parameters are
	 * different.
	 */
	@Test
	public void testApplyFunctionParamsDiff() throws Exception {
	
		// 0x01002cf5: removed parm_2 from p1.
		int transactionID = p1.startTransaction("Test Transaction");
		Function function = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function.removeParameter(0);
		p1.endTransaction(transactionID, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x01002cf5), addr(0x01002cf5));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine that function parameter types are
	 * different.
	 */
	@Test
	public void testApplyFunctionParamTypeDiff() throws Exception {
	
		// 0x010059a3: in p1 parm_2 is a Word, in p2 it's Undefined.
		int transactionID = p1.startTransaction("Test Transaction");
		FunctionManager functionManager1 = p1.getFunctionManager();
		Function function1 = functionManager1.getFunctionAt(addr(0x010059a3));
		assertEquals(3, function1.getParameterCount());
		Parameter f1p0 = function1.getParameter(0);
		f1p0.setDataType(new WordDataType(), SourceType.USER_DEFINED);
		p1.endTransaction(transactionID, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		FunctionManager functionManager2 = p2.getFunctionManager();
		Function function2 = functionManager2.getFunctionAt(addr(0x010059a3));
		assertEquals(3, function2.getParameterCount());
		Parameter f2p0 = function2.getParameter(0);
		f2p0.setDataType(DataType.DEFAULT, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x010059a3), addr(0x010059a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the function return types are
	 * different.
	 */
	@Test
	public void testApplyFunctionReturnDiff() throws Exception {
	
		// 0x010048a3: p1 returns DWord, p2 returns Float.
		// 0x010059a3: p1 returns Byte, p2 returns Word.
		// 0x01002239: functions  are the same, both return Ascii.
	
		int transactionID = p1.startTransaction("Test Transaction");
		FunctionManager functionManager1 = p1.getFunctionManager();
		Function function1 = functionManager1.getFunctionAt(addr(0x010048a3));
		assertNotNull(function1);
		function1.setReturnType(new DWordDataType(), SourceType.USER_DEFINED);
		function1 = functionManager1.getFunctionAt(addr(0x010059a3));
		assertNotNull(function1);
		function1.setReturnType(new ByteDataType(), SourceType.USER_DEFINED);
		function1 = functionManager1.getFunctionAt(addr(0x01002239));
		assertNotNull(function1);
		function1.setReturnType(new CharDataType(), SourceType.USER_DEFINED);
		p1.endTransaction(transactionID, true);
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		FunctionManager functionManager2 = p2.getFunctionManager();
		Function function2 = functionManager2.getFunctionAt(addr(0x010048a3));
		assertNotNull(function2);
		function2.setReturnType(new FloatDataType(), SourceType.USER_DEFINED);
		function2 = functionManager2.getFunctionAt(addr(0x010059a3));
		assertNotNull(function2);
		function2.setReturnType(new WordDataType(), SourceType.USER_DEFINED);
		function2 = functionManager2.getFunctionAt(addr(0x01002239));
		assertNotNull(function2);
		function2.setReturnType(new CharDataType(), SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x010048a3), addr(0x010048a3));
		diffAs.addRange(addr(0x010059a3), addr(0x010059a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can replace the symbol differences between
	 * Program1 and Program2 when program1 and program2 have the same variables
	 * at differing places that would cause a duplicate name when applied
	 * individually but not if all are applied.
	 */
	@Test
	public void testApplyLabelsInCycle() throws Exception {
		// Diff/Merge symbols from 1002950 to 100299b
	
		SymbolTable symtab1 = p1.getSymbolTable();
		symtab1.createLabel(addr(0x100295d), "ONE", SourceType.USER_DEFINED);
		symtab1.createLabel(addr(0x1002969), "TWO", SourceType.USER_DEFINED);
		symtab1.createLabel(addr(0x1002973), "THREE", SourceType.USER_DEFINED);
		SymbolTable symtab2 = p2.getSymbolTable();
		symtab2.createLabel(addr(0x100295d), "THREE", SourceType.USER_DEFINED);
		symtab2.createLabel(addr(0x1002969), "ONE", SourceType.USER_DEFINED);
		symtab2.createLabel(addr(0x1002973), "TWO", SourceType.USER_DEFINED);
		AddressSet as;
		AddressSet limitedAddrSet = new AddressSet(addr(0x1002950), addr(0x100299b));
		programMerge =
			new ProgramMergeManager(p1, p2, limitedAddrSet, TaskMonitorAdapter.DUMMY_MONITOR);
	
		as = new AddressSet();
		as.addRange(addr(0x100295d), addr(0x100295d));
		as.addRange(addr(0x1002969), addr(0x1002969));
		as.addRange(addr(0x1002973), addr(0x1002973));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the memory reference differences
	 * between Program1 and Program2 with reference on different op index.
	 */
	@Test
	public void testApplyMemRefOpIndexDiff() throws Exception {
		// 0x1002d0f: p1 and p2 have mem refs on different op indices.
	
		programBuilder1.createMemoryReference("0x1002d0f", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programBuilder2.createMemoryReference("0x1002d0f", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x1002d0f), addr(0x1002d10));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the memory reference differences
	 * between Program1 and Program2 with mnemonic reference only in P1.
	 */
	@Test
	public void testApplyMemRefP1MnemonicDiff() throws Exception {
		// 0x1002cfc: p1 has mem ref on mnemonic and p2 doesn't.
		// 0x1002d03: p2 has mem ref on mnemonic and p1 doesn't.
	
		programBuilder1.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, -1);
		programBuilder2.createMemoryReference("0x1002d03", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, -1);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		as.add(addr(0x1002d03), addr(0x1002d03));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the memory reference differences
	 * between Program1 and Program2 with reference only on P2 op index.
	 */
	@Test
	public void testApplyMemRefP2OpDiff() throws Exception {
		// 0x1002d25: p2 has operand 1 mem ref and p1 doesn't.
	
		programBuilder2.createMemoryReference("0x1002d25", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 1);
	
		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x1002d25), addr(0x1002d26));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the memory reference differences
	 * between Program1 and Program2 when one refernce is a primary ref and the
	 * other isn't.
	 */
	@Test
	public void testApplyMemRefPrimaryDiff() throws Exception {
		// 0x1002cfc: p1 and p2 have mem refs, but different ref is primary.
	
		programBuilder1.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder1.createMemoryReference("0x1002cfc", "0x10064a0", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x10064a0", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the memory reference differences
	 * between Program1 and Program2 with same "from" address but different "to"
	 * address.
	 */
	@Test
	public void testApplyMemRefToAddrDiff() throws Exception {
		// 0x1002cfc: p1 and p2 have mem refs to different addresses.
	
		programBuilder1.createMemoryReference("0x1002cfc", "0x10064a0", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the offset memory reference
	 * differences between Program1 and Program2.
	 */
	@Test
	public void testApplyOffsetRefDiff() throws Exception {
		// 0x1002cfc: p1 and p2 have mem refs, but p1 has offset.
	
		programBuilder1.createOffsetMemReference("0x1002cfc", "0x1006488", 2, RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that ProgramMerge can apply the byte differences between Program1
	 * and Program2 when the bytes differ for an instruction but its prototype doesn't.
	 */
	@Test
	public void testApplyOnlyByteDifferencesSamePrototype() throws Exception {
	
		programBuilder1.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder1.setBytes("0x01002cf8", "3b 74 24 08", true);
	
		programBuilder2.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder2.setBytes("0x01002cf8", "3b 74 24 0c", true);
	
		// p1 & p2 differ at byte at 0x01002cfb.
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(
			ProgramDiffFilter.BYTE_DIFFS | ProgramDiffFilter.CODE_UNIT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.BYTES, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01002cf8), addr(0x01002cfb));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
	
		AddressSet unMergableByteAddresses = new AddressSet();// None that can't merge.
		assertEquals(unMergableByteAddresses, programMerge.getFilteredDifferences());
	}

	/**
	 * Test that ProgramMerge can apply the byte differences between Program1
	 * and Program2 as part of code unit merge when the bytes differ for an instruction
	 * but its prototype doesn't.
	 */
	@Test
	public void testApplyOnlyCodeUnitDifferencesSamePrototypeDiffByte() throws Exception {
	
		programBuilder1.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder1.setBytes("0x01002cf8", "3b 74 24 08", true);
	
		programBuilder2.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder2.setBytes("0x01002cf8", "3b 74 24 0c", true);
	
		// p1 & p2 differ at byte at 0x01002cfb.
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(
			ProgramDiffFilter.BYTE_DIFFS | ProgramDiffFilter.CODE_UNIT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01002cf8), addr(0x01002cfb));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
	
		AddressSet unMergableByteAddresses = new AddressSet();// None that can't merge.
		assertEquals(unMergableByteAddresses, programMerge.getFilteredDifferences());
	}

	private Address addr(Program program, int offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Address addr(int offset) {
		return addr(p1, offset);
	}

	/**
	 * @param pathName
	 * @return
	 */
	private String stripConflictDtSuffixes(String pathName) {
		int suffixLen = DataType.CONFLICT_SUFFIX.length();
		while (pathName.endsWith(DataType.CONFLICT_SUFFIX)) {
			pathName = pathName.substring(0, pathName.length() - suffixLen);
		}
		return pathName;
	}

	private void mergeCodeUnitDifference(int diffStart, int diffEnd)
			throws CancelledException, MemoryAccessException {
		AddressSet addrSet = new AddressSet();
		addrSet.addRange(addr(p1, diffStart), addr(p1, diffEnd));

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS, ProgramMergeFilter.REPLACE));

		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(addrSet, diffAs);
		programMerge.merge(addrSet, TaskMonitorAdapter.DUMMY_MONITOR);
	}

}
