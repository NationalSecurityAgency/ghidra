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
/*
 * ProgramDiffTest.java
 *
 * Created on January 3, 2002, 9:55 AM
 */

package ghidra.program.util;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.*;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <CODE>ProgramDiffTest</CODE> tests the <CODE>ProgramDiff</CODE> class
 * to verify it correctly determines various types of program differences.
 * The setup for this test class loads two programs that were saved to the 
 * testdata directory as XML. The tests will determine the differences between
 * these two programs.
 */
public class ProgramDiff4Test extends AbstractProgramDiffTest {

	/** Creates new ProgramDiffTest */
	public ProgramDiff4Test() {
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
	}

	/**
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		programDiff = null;
		p1 = null;
		p2 = null;
		programBuilder1.dispose();
		programBuilder2.dispose();
		programBuilder1 = null;
		programBuilder2 = null;
	}
	/**
	 * Test that ProgramDiff can determine the blank format line user defined property
	 * differences between Program1 and Program2.
	 */
	@Test
	public void testBlankFormatLineDifferences() throws Exception {
		// 0x100248c: p2 has format line indicating function exit.
		// 0x1002428: p1 and p2 both have a format line.
		programBuilder1.setIntProperty("0x1002428", "Space", 1);
	
		programBuilder2.setIntProperty("0x100248c", "Space", 1);
		programBuilder2.setIntProperty("0x1002428", "Space", 1);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet(addr(0x100248c), addr(0x100248e));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.USER_DEFINED_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff catches differences in Address spaces
	 * between programs.
	 */
	@Test
	public void testCompareDifferentAddressSpaces() throws Exception {
	
		try {
			ProgramBuilder programBuilder3 = new ProgramBuilder("program3", ProgramBuilder._8051);
			Program p3 = programBuilder3.getProgram();
	
			programDiff = new ProgramDiff(p1, p3);
			assertNull(programDiff);
		}
		catch (ProgramConflictException e) {
			assertNull(e.getMessage(), programDiff);
		}
	}

	/**
	 * Test that ProgramDiff can determine if two programs have different memory addresses..
	 */
	@Test
	public void testCompareDifferentMemory() throws Exception {
	
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
	
		try {
			programDiff = new ProgramDiff(p1, p2);
			assertTrue("Memory in program 1 and program 2 should have been different.",
				!programDiff.memoryMatches());
		}
		catch (ProgramConflictException e) {
			Assert.fail("Address spaces in program 1 and program 2 should have been the same.");
		}
	}

	/**
	 * Test that ProgramDiff recognizes that the 2 programs have the same
	 * address spaces.
	 */
	@Test
	public void testCompareSameAddressSpaces() throws Exception {
	
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
	
		try {
			programDiff = new ProgramDiff(p1, p2);
		}
		catch (ProgramConflictException e) {
			Assert.fail("Address spaces in program 1 and program 2 should have been the same.");
		}
	}

	/**
	 * Test that ProgramDiff recognizes that the 2 programs have the same
	 * address spaces.
	 */
	@Test
	public void testCompareSameMemory() throws Exception {
	
		try {
			programDiff = new ProgramDiff(p1, p2);
			assertTrue("Memory in program 1 and program 2 should have been the same.",
				programDiff.memoryMatches());
		}
		catch (ProgramConflictException e) {
			assertNull(e.getMessage(), programDiff);
		}
	}

	@Test
	public void testDataDifference1() throws Exception {
	
		// 0x01003ac8: same size and named struct with different components.
	
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
		programBuilder1.applyDataType("0x01003ac8", struct_a1, 1);
	
		//===========
	
		Structure struct_a2 = new StructureDataType("struct_a", 0);
		struct_a2.add(new CharDataType());
		struct_a2.add(new DWordDataType());
		programBuilder2.applyDataType("0x01003ac8", struct_a2, 1);
	
		verifyDifference(0x01003ac8, 0x01003acc);
	}

	@Test
	public void testDataDifference10() throws Exception {
	
		// 0x01003b29: different type of pointers.
	
		programBuilder1.applyDataType("0x01003b29", new PointerDataType(new WordDataType()), 1);
	
		//===========
	
		programBuilder2.applyDataType("0x01003b29", new PointerDataType(new ByteDataType()), 1);
	
		verifyDifference(0x01003b29, 0x01003b2c);
	}

	@Test
	public void testDataDifference11() throws Exception {
	
		// 0x01003b31: 5 bytes vs an array of 5 bytes.
	
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
		programBuilder1.applyDataType("0x01003b31", new WordDataType(), 1);
	
		//===========
	
		programBuilder2.applyDataType("0x01003b31", new ArrayDataType(new ByteDataType(), 5, 1), 1);
	
		verifyDifference(0x01003b31, 0x01003b35);
	}

	@Test
	public void testDataDifference12() throws Exception {
	
		// 0x01003b3a: p2 has a double.
	
		//===========
	
		programBuilder2.applyDataType("0x1003b3a", new DoubleDataType(), 1);
	
		verifyDifference(0x01003b3a, 0x01003b41);
	}

	@Test
	public void testDataDifference13() throws Exception {
	
		// 0x01003b45: p1 and p2 have the same nested structure.
	
		Structure inner = new StructureDataType("inner", 0);
		inner.add(new ByteDataType());
		inner.add(new PointerDataType(new DWordDataType()));
	
		Structure outer = new StructureDataType("outer", 0);
		outer.add(new ByteDataType());
		outer.add(inner);
	
		programBuilder1.applyDataType("0x01003b45", outer, 1);
	
		//===========
	
		programBuilder2.applyDataType("0x01003b45", outer, 1);
	
		p1 = programBuilder1.getProgram();
		p2 = programBuilder2.getProgram();
	
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01003ac0), addr(p1, 0x01003bec));
		programDiff = new ProgramDiff(p1, p2, as);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS));
		AddressSet addrSet = new AddressSet();
	
		AddressSetView diffAs = programDiff.getDifferences(programDiff.getFilter(), null);
		assertEquals(addrSet, diffAs);
	}

	@Test
	public void testDataDifference14() throws Exception {
	
		// 0x01003b5e - 0x01003b62: p1 has instructions and p2 has structure
	
		programBuilder1.setBytes("0x01003b5e", "75 12 39 75 08", true);
	
		//===========
	
		programBuilder2.setBytes("0x01003b5e", "75 12 39 75 08", false);
	
		Structure struct_a2 = new StructureDataType("struct_a", 0);
		struct_a2.add(new CharDataType());
		struct_a2.add(new DWordDataType());
		programBuilder2.applyDataType("0x01003b5e", struct_a2, 1);
	
		verifyDifference(0x01003b5e, 0x01003b62);
	}

	@Test
	public void testDataDifference2() throws Exception {
	
		// 0x01003ad5: same structs except different pointer type component.
	
		Structure struct_b1 = new StructureDataType("struct_a", 0);
		struct_b1.add(new ByteDataType());
		struct_b1.add(new PointerDataType(new DWordDataType()));
		programBuilder1.applyDataType("0x01003ad5", struct_b1, 1);
	
		//===========
	
		Structure struct_b2 = new StructureDataType("struct_a", 0);
		struct_b2.add(new ByteDataType());
		struct_b2.add(new PointerDataType(new CharDataType()));
		programBuilder2.applyDataType("0x01003ad5", struct_b2, 1);
	
		verifyDifference(0x01003ad5, 0x01003ad9);
	}

	@Test
	public void testDataDifference3() throws Exception {
	
		// 0x01003ae1: struct vs union 
	
		Structure struct_c1 = new StructureDataType("struct_c", 0);
		struct_c1.add(new WordDataType());
		struct_c1.add(new FloatDataType());
		programBuilder1.applyDataType("0x01003ae1", struct_c1, 1);
	
		//===========
	
		Union union_c2 = new UnionDataType("union_c");
		union_c2.add(new ByteDataType());
		union_c2.add(new PointerDataType(new DWordDataType()));
		union_c2.add(new DWordDataType());
		programBuilder2.applyDataType("0x01003ae1", union_c2, 1);
	
		verifyDifference(0x01003ae1, 0x01003ae6);
	}

	@Test
	public void testDataDifference4() throws Exception {
	
		// 0x01003aec & 0x1003aed: same struct positioned 0ne byte address different.
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
	
		programBuilder1.applyDataType("0x01003aec", struct_a1, 1);
	
		//===========
	
		programBuilder2.applyDataType("0x1003aed", struct_a1, 1);
	
		verifyDifference(0x01003aec, 0x01003af1);
	}

	@Test
	public void testDataDifference5() throws Exception {
	
		// 0x01003af7: same struct with different names.
	
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
	
		programBuilder1.applyDataType("0x01003af7", struct_a1, 1);
	
		//===========
	
		Structure struct_altName_a1 = new StructureDataType("my_struct_a", 0);
		struct_altName_a1.add(new ByteDataType());
		struct_altName_a1.add(new DWordDataType());
		programBuilder2.applyDataType("0x1003af7", struct_altName_a1, 1);
	
		verifyDifference(0x01003af7, 0x01003afb);
	}

	@Test
	public void testDataDifference6() throws Exception {
	
		// 0x01003b02: same struct, different category
	
		Structure struct_a1 = new StructureDataType("struct_a", 0);
		struct_a1.add(new ByteDataType());
		struct_a1.add(new DWordDataType());
		programBuilder1.applyDataType("0x01003b02", struct_a1, 1);
	
		//===========
	
		Structure struct_sub1_a1 = new StructureDataType(new CategoryPath("/sub1"), "struct_a", 0);
		struct_sub1_a1.add(new ByteDataType());
		struct_sub1_a1.add(new DWordDataType());
		programBuilder2.applyDataType("0x1003b02", struct_sub1_a1, 1);
	
		verifyDifference(0x01003b02, 0x01003b06);
	}

	@Test
	public void testDataDifference7() throws Exception {
	
		// 0x01003b0d: different data type with different size
	
		programBuilder1.applyDataType("0x01003b0d", new WordDataType(), 1);
	
		//===========
	
		programBuilder2.applyDataType("0x1003b0d", new ByteDataType(), 1);
	
		verifyDifference(0x01003b0d, 0x01003b0e);
	}

	@Test
	public void testDataDifference8() throws Exception {
	
		// 0x01003b14: different data type, same size
	
		programBuilder1.applyDataType("0x01003b14", new CharDataType(), 1);
	
		//===========
	
		programBuilder2.applyDataType("0x1003b14", new ByteDataType(), 1);
	
		verifyDifference(0x01003b14, 0x01003b14);
	}

	@Test
	public void testDataDifference9() throws Exception {
	
		// 0x01003b1c: different variable length data types, same size
	
		programBuilder1.applyDataType("0x01003b1c", new StringDataType(), 1);
	
		//===========
	
		programBuilder2.applyDataType("0x1003b1c", new UnicodeDataType(), 1);
	
		verifyDifference(0x01003b1c, 0x01003b1d);
	}

	@Test
	public void testExtRefDiff1() throws Exception {
		// 0x1001028: p2 changed external ref to mem ref on operand 0.
	
		programBuilder1.applyDataType("0x01001028", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x01001028", "ADVAPI32.dll", "IsTextUnicode", 0);
	
		programBuilder2.applyDataType("0x01001028", new Pointer32DataType(), 1);
		programBuilder2.createMemoryReference("0x01001028", "0x01001000", RefType.INDIRECTION,
			SourceType.DEFAULT);
	
		programDiff =
			new ProgramDiff(p1, p2, new AddressSet(addr(p1, 0x01001000), addr(p1, 0x010017ff)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01001028), addr(p1, 0x0100102b));
	
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testExtRefDiff2() throws Exception {
		// 0x100102c: p1 changed external ref to mem ref on operand 0.
	
		programBuilder1.applyDataType("0x0100102c", new Pointer32DataType(), 1);
		programBuilder1.createMemoryReference("0x0100102c", "0x01001000", RefType.INDIRECTION,
			SourceType.DEFAULT);
	
		programBuilder2.applyDataType("0x0100102c", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x0100102c", "ADVAPI32.dll", "IsTextUnicode", 0);
	
		programDiff =
			new ProgramDiff(p1, p2, new AddressSet(addr(p1, 0x01001000), addr(p1, 0x010017ff)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x0100102c), addr(p1, 0x0100102f));
	
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff correctly ignores addresses.
	 */
	@Test
	public void testIgnoreAddressSet() throws Exception {
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
		programBuilder1.createLabel("0x01006420", "Function1");
		programBuilder1.createComment("0x010059a3", "Here we are.", CodeUnit.EOL_COMMENT);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
		programBuilder2.createLabel("0x01006420", "Function2");
		programBuilder2.createComment("0x010059a3", "There you have it.", CodeUnit.EOL_COMMENT);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSetView diffs;
	
		// before ignore it should detect diffs.
		diffs = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(diffs.contains(addr(p1, 0x01006420)));
		assertTrue(diffs.contains(addr(p1, 0x010059a3)));
	
		// ignore is initially empty.
		assertEquals(new AddressSet(), programDiff.getIgnoreAddressSet());
	
		// ignore returns what has been ignored.
		programDiff.ignore(new AddressSet(addr(p1, 0x01006420), addr(p1, 0x01006580)));
		programDiff.ignore(new AddressSet(addr(p1, 0x010059a3), addr(p1, 0x01005c6d)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01006420), addr(p1, 0x01006580));
		as.addRange(addr(p1, 0x010059a3), addr(p1, 0x01005c6d));
		assertEquals(as, programDiff.getIgnoreAddressSet());
	
		// ignore set is used by the Diff.
		diffs = programDiff.getDifferences(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS),
			TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(!diffs.contains(addr(p1, 0x01006420)) && !diffs.contains(addr(p1, 0x010059a3)));
	
		// ignore set can be cleared.
		programDiff.clearIgnoreAddressSet();
		assertEquals(new AddressSet(), programDiff.getIgnoreAddressSet());
	}

	/**
	 * Test that ProgramDiff correctly uses the address set that limits the Diff.
	 */
	@Test
	public void testLimitedAddressSet() throws Exception {
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
		programBuilder1.createLabel("0x01006420", "Function1");
		programBuilder1.createComment("0x010059a3", "Here we are.", CodeUnit.EOL_COMMENT);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
		programBuilder2.createLabel("0x01006420", "Function2");
		programBuilder2.createComment("0x010059a3", "There you have it.", CodeUnit.EOL_COMMENT);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSetView diffs;
	
		// before limiting it should detect diffs.
		diffs = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(diffs.contains(addr(p1, 0x01006420)));
		assertTrue(diffs.contains(addr(p1, 0x010059a3)));
	
		// Program Diff only determines differences within the limited set.
		programDiff.setLimitedAddressSet(
			new AddressSet(addr(p1, 0x01002239), addr(p1, 0x0100248c)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01002239), addr(p1, 0x0100248c));
		assertEquals(as, programDiff.getLimitedAddressSet());
	
		// ignore set is used by the Diff.
		diffs = programDiff.getDifferences(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS),
			TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(!diffs.contains(addr(p1, 0x01006420)) && !diffs.contains(addr(p1, 0x010059a3)));
	}

	/**
	 * Test that ProgramDiff can determine the memory reference differences
	 * between Program1 and Program2 with reference on different op index.
	 */
	@Test
	public void testMemRefOpIndexDiff() throws Exception {
		// 0x1002d0f: p1 and p2 have mem refs on different op indices.
	
		programBuilder1.createMemoryReference("0x1002d0f", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programBuilder2.createMemoryReference("0x1002d0f", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 1);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x1002d0f), addr(0x1002d10));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the memory reference differences
	 * between Program1 and Program2 with mnemonic reference only in P1.
	 */
	@Test
	public void testMemRefP1MnemonicDiff() throws Exception {
		// 0x1002cfc: p1 has mem ref on mnemonic and p2 doesn't.
		// 0x1002d03: p2 has mem ref on mnemonic and p1 doesn't.
	
		programBuilder1.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, -1);
		programBuilder2.createMemoryReference("0x1002d03", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, -1);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		as.add(addr(0x1002d03), addr(0x1002d03));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the memory reference differences
	 * between Program1 and Program2 with reference only on P2 op index.
	 */
	@Test
	public void testMemRefP2OpDiff() throws Exception {
		// 0x1002d25: p2 has operand 1 mem ref and p1 doesn't.
	
		programBuilder2.createMemoryReference("0x1002d25", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 1);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet(addr(0x1002d25), addr(0x1002d26));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the memory reference differences
	 * between Program1 and Program2 when one refernce is a primary ref and the
	 * other isn't.
	 */
	@Test
	public void testMemRefPrimaryDiff() throws Exception {
		// 0x1002cfc: p1 and p2 have mem refs, but different ref is primary.
	
		programBuilder1.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder1.createMemoryReference("0x1002cfc", "0x10064a0", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x10064a0", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the memory reference differences
	 * between Program1 and Program2 with same "from" address but different "to"
	 * address.
	 */
	@Test
	public void testMemRefToAddrDiff() throws Exception {
		// 0x1002cfc: p1 and p2 have mem refs to different addresses.
	
		programBuilder1.createMemoryReference("0x1002cfc", "0x10064a0", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
	public void testNoCommentDifference() throws Exception {
		// 0x1002040: p1 has Plate, Pre, EOL, Post, & Repeatable comment.
		programBuilder1.createComment("0x1002040", "Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder1.createComment("0x1002040", "Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder1.createComment("0x1002040", "EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder1.createComment("0x1002040", "Post Comment", CodeUnit.POST_COMMENT);
		programBuilder1.createComment("0x1002040", "Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002040", "Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x1002040", "Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x1002040", "EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x1002040", "Post Comment", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x1002040", "Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
	
		checkNoCommentDifference();
	}

	/**
	 * Test that ProgramDiff can determine the offset memory reference
	 * differences between Program1 and Program2.
	 */
	@Test
	public void testOffsetRefDiff() throws Exception {
		// 0x1002cfc: p1 and p2 have mem refs, but p1 has offset.
	
		programBuilder1.createOffsetMemReference("0x1002cfc", "0x1006488", 2, RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createMemoryReference("0x1002cfc", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet(addr(0x1002cfc), addr(0x1002cfc));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff determines addresses in Program1 that are not in
	 * Program2.
	 */
	@Test
	public void testOnlyInOne() throws Exception {
	
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSetView as = programDiff.getAddressesOnlyInOne();
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(p1, 0x200), addr(p1, 0x2ff)));
		assertEquals(as, as1);
	}

	/**
	 * Test that ProgramDiff determines addresses in Program2 that are not in
	 * Program1.
	 */
	@Test
	public void testOnlyInTwo() throws Exception {
	
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSetView as = programDiff.getAddressesOnlyInTwo();
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(p1, 0x400), addr(p1, 0x4ff)));
		assertEquals(as, as1);
	}

	/**
	 * Test that ProgramDiff can determine the label differences between
	 * Program1 and Program2.
	 */
	@Test
	public void testPrimarySymbolDifferences() throws Exception {
	
		// 0x1002d1d: p1 has "Foo" & "Bar" symbols. "Foo" is primary.
		//            p2 has "Foo" & "Bar" symbols. "Bar" is primary.
	
		int transactionID = p1.startTransaction("Test Transaction");
		Namespace namespace = p1.getSymbolTable().getNamespace(addr(p1, 0x1002cf5));
		String namespaceStr = namespace.getName();
		programBuilder1.createLabel("1002d1d", "Foo", namespaceStr);
		programBuilder1.createLabel("1002d1d", "Bar", namespaceStr);
		p1.endTransaction(transactionID, true);
	
		transactionID = p2.startTransaction("Test Transaction");
		namespace = p2.getSymbolTable().getNamespace(addr(p2, 0x1002cf5));
		namespaceStr = namespace.getName();
		programBuilder2.createLabel("1002d1d", "Bar", namespaceStr);
		programBuilder2.createLabel("1002d1d", "Foo", namespaceStr);
		p2.endTransaction(transactionID, true);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet(addr(0x1002d1d), addr(0x1002d1d));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the stack reference differences
	 * between Program1 and Program2.
	 */
	@Test
	public void testRegisterRefDiffs() throws Exception {
		// 0x10018a6: p1 has reg ref to esi.
		// 0x100295a: p2 has reg ref to cx.
		// 0x1002cf5: p1 has reg ref to edi; p2 has reg ref to eax.
		// 0x10033f6: p1 & p2 both have reg ref to edi.
	
		Register esiReg1 = p1.getRegister("ESI");
		Register ediReg1 = p1.getRegister("EDI");
	
		int transactionID1 = p1.startTransaction("Test Transaction");
		ReferenceManager refManager1 = p1.getReferenceManager();
		refManager1.addRegisterReference(addr(p1, "0x10018a6"), 0, esiReg1, RefType.DATA,
			SourceType.USER_DEFINED);
	
		refManager1.addRegisterReference(addr(p1, "0x1002cf5"), 0, ediReg1, RefType.DATA,
			SourceType.USER_DEFINED);
	
		refManager1.addRegisterReference(addr(p1, "0x10033f6"), 0, ediReg1, RefType.DATA,
			SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);
	
		ReferenceManager referenceManager2 = p2.getReferenceManager();
		Register cxReg2 = p2.getRegister("CX");
		Register ediReg2 = p2.getRegister("EDI");
		Register eaxReg2 = p2.getRegister("EAX");
	
		int transactionID2 = p2.startTransaction("Test Transaction");
		referenceManager2.addRegisterReference(addr(p2, "0x100295a"), 0, cxReg2, RefType.DATA,
			SourceType.USER_DEFINED);
	
		referenceManager2.addRegisterReference(addr(p2, "0x1002cf5"), 0, eaxReg2, RefType.DATA,
			SourceType.USER_DEFINED);
	
		referenceManager2.addRegisterReference(addr(p2, "0x10033f6"), 0, ediReg2, RefType.DATA,
			SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		AddressSet expectedDiffs = new AddressSet();
		expectedDiffs.addRange(addr(0x010018a6), addr(0x010018a6));
		expectedDiffs.addRange(addr(0x1002cf5), addr(0x1002cf5));
		expectedDiffs.addRange(addr(0x0100295a), addr(0x0100295a));
		assertEquals(expectedDiffs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff correctly restricts the Diff results to an address set.
	 */
	@Test
	public void testRestrictedAddressSet() throws Exception {
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
		programBuilder1.createLabel("0x01006420", "Function1");
		programBuilder1.createComment("0x010059a3", "Here we are.", CodeUnit.EOL_COMMENT);
	
		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
		programBuilder2.createLabel("0x01006420", "Function2");
		programBuilder2.createComment("0x010059a3", "There you have it.", CodeUnit.EOL_COMMENT);
	
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSetView diffs;
	
		// before restricting it should detect diffs.
		diffs = programDiff.getDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(diffs.contains(addr(p1, 0x01006420)));
		assertTrue(diffs.contains(addr(p1, 0x010059a3)));
	
		// restricted set is initially null.
		assertNull(programDiff.getRestrictedAddressSet());
	
		// must be in restricted set to be returned.
		programDiff.setRestrictedAddressSet(
			new AddressSet(addr(p1, 0x01002239), addr(p1, 0x0100248c)));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01002239), addr(p1, 0x0100248c));
		assertEquals(as, programDiff.getRestrictedAddressSet());
	
		// ignore set is used by the Diff.
		diffs = programDiff.getDifferences(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS),
			TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(!diffs.contains(addr(p1, 0x01006420)) && !diffs.contains(addr(p1, 0x010059a3)));
	
		// restricted set can be cleared.
		programDiff.removeRestrictedAddressSet();
		assertNull(programDiff.getRestrictedAddressSet());
	}

	/**
	 * Test that ProgramDiff can determine the stack reference differences
	 * between Program1 and Program2.
	 */
	@Test
	public void testStackRefDiffs() throws Exception {
		// 0x1006443: p1  stack ref on op 0.
		// 0x1006446: p2  stack ref on op 0.
		// 0x10064ce: p1 has stack ref on op 0; p2 stack ref on op 1.
		// 0x1006480: p1 has mem ref on op 0; p2 has stack ref on op 0.
	
		programBuilder1.createStackReference("0x1006443", RefType.READ, -0x18,
			SourceType.USER_DEFINED, 0);
	
		programBuilder2.createStackReference("0x1006446", RefType.READ, -0x4,
			SourceType.USER_DEFINED, 0);
	
		programBuilder1.createStackReference("0x10064ce", RefType.READ, -0x6c,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createStackReference("0x10064ce", RefType.READ, -0x6c,
			SourceType.USER_DEFINED, 1);
	
		programBuilder1.createMemoryReference("0x1006480", "0x1006488", RefType.READ,
			SourceType.USER_DEFINED, 0);
		programBuilder2.createStackReference("0x1006480", RefType.READ, -0x6c,
			SourceType.USER_DEFINED, 0);
	
		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x1006443), addr(0x1006445));
		as.addRange(addr(0x1006446), addr(0x100644c));
		as.addRange(addr(0x10064ce), addr(0x10064d0));
		as.addRange(addr(0x1006480), addr(0x1006485));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	private void verifyDifference(int diffStart, int diffEnd)
			throws ProgramConflictException, CancelledException {
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01003ac0), addr(p1, 0x01003bec));
		programDiff = new ProgramDiff(p1, p2, as);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS));
		AddressSet addrSet = new AddressSet();

		addrSet.addRange(addr(p1, diffStart), addr(p1, diffEnd));

		AddressSetView diffAs = programDiff.getDifferences(programDiff.getFilter(), null);
		assertEquals(addrSet, diffAs);
	}
}
