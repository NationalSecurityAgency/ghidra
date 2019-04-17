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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.*;

import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * <CODE>ProgramDiffTest</CODE> tests the <CODE>ProgramDiff</CODE> class
 * to verify it correctly determines various types of program differences.
 * The setup for this test class loads two programs that were saved to the 
 * testdata directory as XML. The tests will determine the differences between
 * these two programs.
 */
public class ProgramDiff1Test extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDiff programDiff;
	ClassicSampleX86ProgramBuilder programBuilder1;
	ClassicSampleX86ProgramBuilder programBuilder2;
	private Program p1;
	private Program p2;

	/** Creates new ProgramDiffTest */
	public ProgramDiff1Test() {
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
	 * Test that ProgramDiff correctly returns program1 and program2.
	 */
	@Test
    public void testGetPrograms() throws Exception {
		programDiff = new ProgramDiff(p1, p2);
		assertEquals(p1, programDiff.getProgramOne());
		assertEquals(p2, programDiff.getProgramTwo());
	}

	/**
	 * Test that ProgramDiff can correctly determine the union of all addresses
	 * in Program1 and Program2.
	 */
	@Test
    public void testGetCombinedAddresses() throws Exception {

		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(p1, 0x100), addr(p1, 0x1ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x200), addr(p1, 0x2ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x400), addr(p1, 0x4ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01001000), addr(p1, 0x010075ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01008000), addr(p1, 0x010085ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x0100a000), addr(p1, 0x0100f3ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0000248), addr(p1, 0xf00002ef)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0001300), addr(p1, 0xf000131b)));
		AddressSetView as2 = programDiff.getCombinedAddresses();
		assertEquals(as1, as2);
	}

	/**
	 * Test that ProgramDiff can correctly determine which addresses are
	 * in common between Program1 and Program2.
	 */
	@Test
    public void testGetAddressesInCommon() throws Exception {
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(p1, 0x100), addr(p1, 0x1ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01001000), addr(p1, 0x010075ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01008000), addr(p1, 0x010085ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x0100a000), addr(p1, 0x0100f3ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0000248), addr(p1, 0xf00002ef)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0001300), addr(p1, 0xf000131b)));
		AddressSetView as2 = programDiff.getAddressesInCommon();
		assertEquals(as1, as2);
	}

	/**
	 * Test that ProgramDiff can correctly determine which addresses with
	 * initialized data are in common between Program1 and Program2.
	 */
	@Test
    public void testGetInitializedInCommon() throws Exception {

		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(p1, 0x100), addr(p1, 0x1ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01001000), addr(p1, 0x010075ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01008000), addr(p1, 0x010085ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x0100a000), addr(p1, 0x0100f3ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0000248), addr(p1, 0xf00002ef)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0001300), addr(p1, 0xf000131b)));
		AddressSetView as2 = programDiff.getInitializedInCommon();
		assertEquals(as1, as2);
	}

	/**
	 * Test that ProgramDiff can determine the byte differences between Program1
	 * and Program2.
	 */
	@Test
    public void testGetByteDifferences() throws Exception {
		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);
		programBuilder1.createLabel("0x01006420", "Function1");
		programBuilder1.createComment("0x010059a3", "Here we are.", CodeUnit.EOL_COMMENT);
		programBuilder1.setBytes("0x01002b45", "ee");
		programBuilder1.setBytes("0x01002b49", "57");

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);
		programBuilder2.createLabel("0x01006420", "Function2");
		programBuilder2.createComment("0x010059a3", "There you have it.", CodeUnit.EOL_COMMENT);
		programBuilder2.setBytes("0x01002b45", "8b");
		programBuilder2.setBytes("0x01002b49", "ee");

		// p1 has 0x100 to 0x1ff with byte values of 0xCF, but in p2 of 0xAF.
		// p1 has changed byte at 0x1002b45 from 0x8b to 0xee.
		// p2 has changed byte at 0x1002b49 from 0x57 to 0xee.
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x100), addr(p1, 0x1ff));// byte values differ
		as.addRange(addr(p1, 0x200), addr(p1, 0x2ff));// no bytes (no memory) for program2.
		as.addRange(addr(p1, 0x400), addr(p1, 0x4ff));// no bytes (no memory) for program1.
		as.addRange(addr(p1, 0x01002b45), addr(p1, 0x01002b45));
		as.addRange(addr(p1, 0x01002b49), addr(p1, 0x01002b49));
		checkAddressSet(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the byte differences between Program1
	 * and Program2 when the bytes differ for an instruction but its prototype doesn't.
	 */
	@Test
    public void testGetByteDifferencesSamePrototype() throws Exception {

		programBuilder1.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder1.setBytes("0x01002cf8", "3b 74 24 08", true);

		programBuilder2.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder2.setBytes("0x01002cf8", "3b 74 24 0c", true);

		// p1 & p2 differ at byte at 0x01002cfb.
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.BYTE_DIFFS));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01002cfb), addr(p1, 0x01002cfb));
		checkAddressSet(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the code unit differences between Program1
	 * and Program2 when the bytes differ for an instruction but its prototype doesn't.
	 */
	@Test
    public void testGetCodeUnitDifferencesSamePrototypeDiffByte() throws Exception {

		programBuilder1.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder1.setBytes("0x01002cf8", "3b 74 24 08", true);

		programBuilder2.clearCodeUnits("0x01002cf8", "0x01002cfb", false);
		programBuilder2.setBytes("0x01002cf8", "3b 74 24 0c", true);

		// p1 & p2 differ at byte at 0x01002cfb.
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS));
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x01002cf8), addr(p1, 0x01002cfb));
		checkAddressSet(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	private void checkAddressSet(AddressSet expectedSet, AddressSetView actualSet) {
		if (expectedSet == null) {
			if (actualSet != null) {
				Assert.fail("Expected set is null, but the actual set isn't null.");
			}
		}
		else if (actualSet == null) {
			Assert.fail("Expected set isn't null, but the actual set is null.");
		}
		MultiAddressRangeIterator multiIter =
			new MultiAddressRangeIterator(new AddressRangeIterator[] {
				expectedSet.getAddressRanges(), actualSet.getAddressRanges() });
		while (multiIter.hasNext()) {
			AddressRange nextRange = multiIter.next();
			Address minAddress = nextRange.getMinAddress();
			AddressRange expectedRange = expectedSet.getRangeContaining(minAddress);
			AddressRange actualRange = actualSet.getRangeContaining(minAddress);
			assertEquals(expectedRange, actualRange);
		}
	}

	/**
	 * Test that ProgramDiff can determine the code unit differences between
	 * Program1 and Program2.
	 */
	@Test
    public void testGetCodeUnitDifferences() throws Exception {
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

		// p2 has code units cleared from 0x1002239 to 0x100248e.
		// p1 has code units cleared from 0x1002cf5 to 0x1002d6b.
		// p1 & p2 have different bytes causing different instructions at 0x01002b49.
		// static disassembly from 10024a1-10024a7 in p2 & from 10024a0-10024a7 in p1 (p1 offcut from p2).
		AddressSet as = new AddressSet();
		as.addRange(addr(p1, 0x1001000), addr(p1, 0x1003abf));
		as.addRange(addr(p1, 0x1003bed), addr(p1, 0x10075ff));
		programDiff = new ProgramDiff(p1, p2, as);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.CODE_UNIT_DIFFS));
		AddressSet addrSet = new AddressSet();
		addrSet.addRange(addr(p1, 0x01002239), addr(p1, 0x0100248e));
		addrSet.addRange(addr(p1, 0x01002cf5), addr(p1, 0x01002d6d));
		addrSet.addRange(addr(p1, 0x01002b49), addr(p1, 0x01002b49));
		addrSet.addRange(addr(p1, 0x01002950), addr(p1, 0x01002957));
		AddressSetView diffAs = programDiff.getDifferences(programDiff.getFilter(), null);
//		AddressRangeIterator addressRanges = diffAs.getAddressRanges();
//		for (AddressRange addressRange : addressRanges) {
//			System.out.println("[" + addressRange.getMinAddress() + ", " +
//				addressRange.getMaxAddress() + "]");
//		}
		assertEquals(addrSet, diffAs);
	}

	@Test
    public void testGetCommentDifference1() throws Exception {
		// 0x1002040: p1 has Plate, Pre, EOL, Post, & Repeatable comment.
		programBuilder1.createComment("0x1002040", "My Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder1.createComment("0x1002040", "My Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder1.createComment("0x1002040", "My EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder1.createComment("0x1002040", "My Post Comment", CodeUnit.POST_COMMENT);
		programBuilder1.createComment("0x1002040", "My Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);

		checkCommentDifference(0x1002040);
	}

	@Test
    public void testGetCommentDifference2() throws Exception {
		// 0x100204c: p2 has Plate, Pre, EOL, Post, & Repeatable comment.
		programBuilder2.createComment("0x100204c", "Other Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x100204c", "Other EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Post Comment", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);

		checkCommentDifference(0x100204c);
	}

	@Test
    public void testGetCommentDifference3() throws Exception {
		// 0x1002304: p1 has EOL comment.
		programBuilder1.createComment("0x1002304", "My EOL Comment", CodeUnit.EOL_COMMENT);

		checkCommentDifference(0x1002304);
	}

	@Test
    public void testGetCommentDifference4() throws Exception {
		// 0x1002306: p1 has pre-comment.
		programBuilder1.createComment("0x1002306", "My Pre Comment", CodeUnit.PRE_COMMENT);

		checkCommentDifference(0x1002306);
	}

	@Test
    public void testGetCommentDifference5() throws Exception {
		// 0x100230b: p1 has plate and post comments.
		programBuilder1.createComment("0x100230b", "My Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder1.createComment("0x100230b", "My Post Comment", CodeUnit.POST_COMMENT);

		checkCommentDifference(0x100230b);
	}

	@Test
    public void testGetCommentDifference6() throws Exception {
		// p2 plate comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Plate Comment", CodeUnit.PLATE_COMMENT);

		checkCommentDifference(0x100230d);
	}

	@Test
    public void testGetCommentDifference7() throws Exception {
		// p2 pre comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Pre Comment", CodeUnit.PRE_COMMENT);

		checkCommentDifference(0x100230d);
	}

	@Test
    public void testGetCommentDifference8() throws Exception {
		// p2 eol comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100230d", "Other EOL Comment", CodeUnit.EOL_COMMENT);

		checkCommentDifference(0x100230d);
	}

	@Test
    public void testGetCommentDifference9() throws Exception {
		// p2 post comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Post Comment", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Post Comment", CodeUnit.POST_COMMENT);

		checkCommentDifference(0x100230d);
	}

	@Test
    public void testGetCommentDifference10() throws Exception {
		// p2 repeatable comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);

		checkCommentDifference(0x100230d);
	}

	@Test
    public void testGetCommentDifference11() throws Exception {
		// 0x1002336: Different Repeatable comments.
		programBuilder1.createComment("0x1002336", "Once upon a time,",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002336", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);

		checkCommentDifference(0x1002336);
	}

	@Test
    public void testGetCommentDifference12() throws Exception {
		// 0x1002346: P1 Repeatable comment contains P2 Repeatable comment.
		programBuilder1.createComment("0x1002346", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002346", "This is a sample", CodeUnit.REPEATABLE_COMMENT);

		checkCommentDifference(0x1002346);
	}

	@Test
    public void testGetCommentDifference13() throws Exception {
		// 0x1002350: P1 Repeatable comment contained within P2 Repeatable comment.
		programBuilder1.createComment("0x1002350", "This is a sample", CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002350", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);

		checkCommentDifference(0x1002350);
	}

	@Test
    public void testGetCommentDifference14() throws Exception {
		// 0x100238f: Different EOL comments.
		programBuilder1.createComment("0x100238f", "Once upon a time,", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100238f", "This is a sample comment.",
			CodeUnit.EOL_COMMENT);

		checkCommentDifference(0x100238f);
	}

	@Test
    public void testGetCommentDifference15() throws Exception {
		// 0x1002395: Different Pre comments.
		programBuilder1.createComment("0x1002395", "Once upon a time,", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x1002395", "This is a sample comment.",
			CodeUnit.PRE_COMMENT);

		checkCommentDifference(0x1002395);
	}

	@Test
    public void testGetCommentDifference16() throws Exception {
		// 0x100239d: Different Plate comments.
		programBuilder1.createComment("0x100239d", "Once upon a time,", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100239d", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);

		checkCommentDifference(0x100239d);
	}

	@Test
    public void testGetCommentDifference17() throws Exception {
		// 0x100239d: Different Post comments.
		programBuilder1.createComment("0x100239d", "Once upon a time,", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100239d", "This is a sample comment.",
			CodeUnit.POST_COMMENT);

		checkCommentDifference(0x100239d);
	}

	@Test
    public void testGetCommentDifference18() throws Exception {
		// 0x1002a91: p2 has a plate comment.
		programBuilder2.createComment("0x1002a91", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);

		checkCommentDifference(0x1002a91);
	}

	@Test
    public void testGetCommentDifference19() throws Exception {
		// 0x100248f: p1 has function comment.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");

		checkCommentDifference(0x100248f);
	}

	@Test
    public void testGetCommentDifference20() throws Exception {
		// 0x100248f: p2 has function comment.
		programBuilder2.createFunctionComment("0x100248f", "Other function comment.");

		checkCommentDifference(0x100248f);
	}

	@Test
    public void testGetCommentDifference21() throws Exception {
		// 0x100248f: p1 and p2 have same function comment.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");
		programBuilder2.createFunctionComment("0x100248f", "Sample function comment.");

		checkNoCommentDifference();
	}

	@Test
    public void testGetCommentDifference22() throws Exception {
		// 0x100248f: p1 and p2 have different function comments.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");
		programBuilder2.createFunctionComment("0x100248f", "Other function comment.");

		checkCommentDifference(0x100248f);
	}

	private void checkCommentDifference(int commentAddress) throws Exception {
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		AddressSet as = new AddressSet();
		as.addRange(addr(commentAddress), addr(commentAddress));
		AddressSetView diffAs = programDiff.getDifferences(programDiff.getFilter(), null);
		assertEquals(as, diffAs);
	}

	private void checkNoCommentDifference() throws Exception {
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		AddressSet as = new AddressSet();
		AddressSetView diffAs = programDiff.getDifferences(programDiff.getFilter(), null);
		assertEquals(as, diffAs);
	}

	@Test
    public void testGetBookmarkDifference1() throws Exception {
		// 0x1002306: p1 and p2 have same bookmarks.
		programBuilder1.createBookmark("0x1002306", BookmarkType.INFO, "Cat1", "My bookmark");
		programBuilder2.createBookmark("0x1002306", BookmarkType.INFO, "Cat1", "My bookmark");

		AddressSet checkAddressSet = new AddressSet(addr(0x1002306), addr(0x100232f));
		AddressSet expectedDiffs = new AddressSet();
		checkDiff(checkAddressSet, expectedDiffs, ProgramDiffFilter.BOOKMARK_DIFFS);
	}

	@Test
    public void testGetBookmarkDifference2() throws Exception {
		// 0x100230b: p1 and p2 have bookmarks with different categories.
		programBuilder1.createBookmark("0x100230b", BookmarkType.INFO, "Cat1", "My bookmark");
		programBuilder2.createBookmark("0x100230b", BookmarkType.INFO, "Stuff", "My bookmark");

		AddressSet checkAddressSet = new AddressSet(addr(0x1002306), addr(0x100232f));
		AddressSet expectedDiffs = new AddressSet(addr(0x100230b), addr(0x100230b));
		checkDiff(checkAddressSet, expectedDiffs, ProgramDiffFilter.BOOKMARK_DIFFS);
	}

	@Test
    public void testGetBookmarkDifference3() throws Exception {
		// 0x100230c: p1 has bookmark, p2 doesn't.
		programBuilder1.createBookmark("0x100230c", BookmarkType.INFO, "", "Something different");

		AddressSet checkAddressSet = new AddressSet(addr(0x1002306), addr(0x100232f));
		AddressSet expectedDiffs = new AddressSet(addr(0x100230c), addr(0x100230c));
		checkDiff(checkAddressSet, expectedDiffs, ProgramDiffFilter.BOOKMARK_DIFFS);
	}

	@Test
    public void testGetBookmarkDifference4() throws Exception {
		// 0x100230d: p2 has bookmark, p1 doesn't.
		programBuilder2.createBookmark("0x100230d", BookmarkType.INFO, "", "My bookmark");

		AddressSet checkAddressSet = new AddressSet(addr(0x1002306), addr(0x100232f));
		AddressSet expectedDiffs = new AddressSet(addr(0x100230d), addr(0x1002311));
		checkDiff(checkAddressSet, expectedDiffs, ProgramDiffFilter.BOOKMARK_DIFFS);
	}

	@Test
    public void testGetBookmarkDifference5() throws Exception {
		// 0x1002312: p1 and p2 have bookmarks with no category and different descriptions.
		programBuilder1.createBookmark("0x1002312", BookmarkType.INFO, "", "Something different");
		programBuilder2.createBookmark("0x1002312", BookmarkType.INFO, "", "My bookmark");

		AddressSet checkAddressSet = new AddressSet(addr(0x1002306), addr(0x100232f));
		AddressSet expectedDiffs = new AddressSet(addr(0x1002312), addr(0x1002317));
		checkDiff(checkAddressSet, expectedDiffs, ProgramDiffFilter.BOOKMARK_DIFFS);
	}

	@Test
    public void testGetBookmarkDifference6() throws Exception {
		// 0x1002318: p1 and p2 have bookmarks with same category and different descriptions.
		programBuilder1.createBookmark("0x1002318", BookmarkType.INFO, "stuff",
			"Something different");
		programBuilder2.createBookmark("0x1002318", BookmarkType.INFO, "stuff", "My bookmark");

		AddressSet checkAddressSet = new AddressSet(addr(0x1002306), addr(0x100232f));
		AddressSet expectedDiffs = new AddressSet(addr(0x1002318), addr(0x100231c));
		checkDiff(checkAddressSet, expectedDiffs, ProgramDiffFilter.BOOKMARK_DIFFS);
	}

	@Test
    public void testGetBookmarkDifference7() throws Exception {
		// 0x100231d: p1 and p2 have same NOTE bookmarks.
		programBuilder1.createBookmark("0x100231d", BookmarkType.NOTE, "stuff", "My bookmark");
		programBuilder2.createBookmark("0x100231d", BookmarkType.NOTE, "stuff", "My bookmark");

		AddressSet checkAddressSet = new AddressSet(addr(0x1002306), addr(0x100232f));
		AddressSet expectedDiffs = new AddressSet();
		checkDiff(checkAddressSet, expectedDiffs, ProgramDiffFilter.BOOKMARK_DIFFS);
	}

	@Test
    public void testGetBookmarkDifference8() throws Exception {
		// 0x1002323: p1 and p2 have same INFO bookmarks.
		programBuilder1.createBookmark("0x1002323", BookmarkType.INFO, "stuff", "My bookmark");
		programBuilder2.createBookmark("0x1002323", BookmarkType.INFO, "stuff", "My bookmark");

		programDiff = new ProgramDiff(p1, p2, new AddressSet(addr(0x1002323), addr(0x1002323)));
		AddressSet as = new AddressSet();
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.BOOKMARK_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	private void checkDiff(AddressSetView checkAddressSet, AddressSet expectedDiffs, int diffType)
			throws ProgramConflictException, CancelledException {
		programDiff = new ProgramDiff(p1, p2, checkAddressSet);
		programDiff.setFilter(new ProgramDiffFilter(diffType));
		assertEquals(expectedDiffs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	private void checkDiff(AddressSet expectedDiffs, int diffType)
			throws ProgramConflictException, CancelledException {
		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(diffType));
		assertEquals(expectedDiffs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
    public void testGetUserDefinedPropertyDifferences() throws Exception {
		// SPACE property
		// 0x10018ae: p1 has space=1.
		// 0x10018ba: p1 and p2 have space=1.
		// 0x10018ce: p2 has space=2.
		// 0x10018ff: p1 has space=1 & p2 has space=2.

		programBuilder1.setIntProperty("0x10018ae", "Space", 1);
		programBuilder1.setIntProperty("0x10018ba", "Space", 1);
		programBuilder1.setIntProperty("0x10018ff", "Space", 1);

		programBuilder2.setIntProperty("0x10018ba", "Space", 1);
		programBuilder2.setIntProperty("0x10018ce", "Space", 2);

		// testColor property
		// 0x100248c: p1=CYAN  & p2=WHITE.
		// 0x10039dd: p1=BLACK.
		// 0x10039f1: p2=BLACK.
		// 0x10039f8: p1=BLACK & p2=BLACK.

		programBuilder1.setStringProperty("0x100248c", "testColor", "CYAN");
		programBuilder1.setStringProperty("0x10039dd", "testColor", "BLACK");
		programBuilder1.setStringProperty("0x10039f8", "testColor", "BLACK");

		programBuilder2.setStringProperty("0x100248c", "testColor", "WHITE");
		programBuilder2.setStringProperty("0x10039f1", "testColor", "BLACK");
		programBuilder2.setStringProperty("0x10039f8", "testColor", "BLACK");

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x10018ae), addr(0x10018ae));
		as.addRange(addr(0x10018ce), addr(0x10018ce));
		as.addRange(addr(0x10018ff), addr(0x10018ff));
		as.addRange(addr(0x100248c), addr(0x100248c));
		as.addRange(addr(0x10039dd), addr(0x10039dd));
		as.addRange(addr(0x10039f1), addr(0x10039f1));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.USER_DEFINED_DIFFS));
		AddressSetView expectedSet = (AddressSet) invokeInstanceMethod("adjustCodeUnitAddressSet",
			programDiff, new Class[] { AddressSetView.class, Listing.class, TaskMonitor.class },
			new Object[] { as, p1.getListing(), TaskMonitorAdapter.DUMMY_MONITOR });
		AddressSetView diffSet = programDiff.getDifferences(programDiff.getFilter(), null);
		assertEquals(expectedSet, diffSet);
	}

	/**
	 * Test that ProgramDiff can determine the label differences between
	 * Program1 and Program2.
	 */
	@Test
    public void testGetSymbolDifferences() throws Exception {

		// p1 and p2 have same default label  1002d11-1002d13  LAB...
		// p1 and p2 have same symbols and same primary.  1002d14-1002d15  bar, baz, bam
		// p1 and p2 have same symbols, different primary.  1002d16-1002d17 var01, var02

		// 0x1002d18: p1 has "foo" symbol.  1002d18-1002d1b
		// 0x1002d1c: p2 has "foo" symbol.  1002d1c-1002d1c
		// 0x1002d1d: p1 has subset of p2.  1002d1d-1002d1e
		// 0x1002d1f: p1 and p2 have different symbols.  1002d1f-1002d24
		// 0x1002d25: p1 has local and p2 has same name global. 1002d25-1002d26

		int transactionID = p1.startTransaction("Test Transaction");
		Namespace namespace = p1.getSymbolTable().getNamespace(addr(p1, 0x1002cf5));
		String namespaceStr = namespace.getName();
		programBuilder1.createLabel("1002d14", "bar", namespaceStr);
		programBuilder1.createLabel("1002d14", "bam", namespaceStr);
		programBuilder1.createLabel("1002d14", "baz", namespaceStr);
		programBuilder1.createLabel("1002d16", "var01", namespaceStr);
		programBuilder1.createLabel("1002d16", "var02", namespaceStr);
		programBuilder1.createLabel("1002d18", "foo", namespaceStr);
		programBuilder1.createLabel("1002d1d", "tmp1", namespaceStr);
		programBuilder1.createLabel("1002d1f", "mySymbol", namespaceStr);
		programBuilder1.createLabel("1002d1f", "getStuff", namespaceStr);
		programBuilder1.createLabel("1002d25", "junk", namespaceStr);
		p1.endTransaction(transactionID, true);

		transactionID = p2.startTransaction("Test Transaction");
		namespace = p2.getSymbolTable().getNamespace(addr(p2, 0x1002cf5));
		namespaceStr = namespace.getName();
		programBuilder2.createLabel("1002d14", "bar", namespaceStr);
		programBuilder2.createLabel("1002d14", "baz", namespaceStr);
		programBuilder2.createLabel("1002d14", "bam", namespaceStr);
		programBuilder2.createLabel("1002d16", "var02", namespaceStr);
		programBuilder2.createLabel("1002d16", "var01", namespaceStr);
		programBuilder2.createLabel("1002d1c", "foo", namespaceStr);
		programBuilder2.createLabel("1002d1d", "tmp1", namespaceStr);
		programBuilder2.createLabel("1002d1d", "tmp2", namespaceStr);
		programBuilder2.createLabel("1002d1d", "stuff", namespaceStr);
		programBuilder2.createLabel("1002d1f", "begin", namespaceStr);
		programBuilder2.createLabel("1002d1f", "fooBar234", namespaceStr);
		programBuilder2.createLabel("1002d25", "junk", p2.getGlobalNamespace().getName());
		p2.endTransaction(transactionID, true);

		AddressSet expectedDiffs = new AddressSet();
		expectedDiffs.addRange(addr(0x1002d16), addr(0x1002d16));
		expectedDiffs.addRange(addr(0x1002d18), addr(0x1002d18));
		expectedDiffs.addRange(addr(0x1002d1c), addr(0x1002d1c));
		expectedDiffs.addRange(addr(0x1002d1d), addr(0x1002d1d));
		expectedDiffs.addRange(addr(0x1002d1f), addr(0x1002d1f));
		expectedDiffs.addRange(addr(0x1002d25), addr(0x1002d25));
		checkDiff(expectedDiffs, ProgramDiffFilter.SYMBOL_DIFFS);
	}

	/**
	 * Test that ProgramDiff can determine the equate differences between
	 * Program1 and Program2.
	 */
	@Test
    public void testGetEquateDifferences() throws Exception {

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

		programDiff = new ProgramDiff(p1, p2);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x100643d), addr(0x100643d));
		as.addRange(addr(0x100644d), addr(0x100644d));
		as.addRange(addr(0x1006455), addr(0x1006455));
		as.addRange(addr(0x10064c5), addr(0x10064c5));
		as.addRange(addr(0x10064ee), addr(0x10064ee));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.EQUATE_DIFFS));
		assertEquals(as, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff doesn't indicate a difference when the functions
	 * are the same in Program1 and Program2.
	 */
	@Test
    public void testFunctionsSame() throws Exception {
		programDiff = new ProgramDiff(p1, p2, new AddressSet(addr(0x1002239), addr(0x100248c)));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		assertEquals(new AddressSet(), programDiff.getDifferences(programDiff.getFilter(), null));
	}

	@Test
    public void testFunctionRegParamDiff9() throws Exception {

		// added register param in program2

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		Register dr0Reg = p1.getRegister("DR0");
		Variable var2 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p2);
		function2.addParameter(var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		AddressSet expectedDiffs = new AddressSet(addr(0x10048a3), addr(0x10048a3));
		checkDiff(expectedDiffs, ProgramDiffFilter.FUNCTION_DIFFS);
	}

	/**
	 * Test that ProgramDiff can determine the function return types are
	 * different.
	 */
	@Test
    public void testFunctionReturnDiff() throws Exception {

		// 0x010048a3: p1 returns DWord, p2 returns Float.
		// 0x010059a3: p1 returns Byte, p2 returns Undefined.
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
		function2.setReturnType(DataType.DEFAULT, SourceType.USER_DEFINED);
		function2 = functionManager2.getFunctionAt(addr(0x01002239));
		assertNotNull(function2);
		function2.setReturnType(new CharDataType(), SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		programDiff = new ProgramDiff(p1, p2);
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x010048a3), addr(0x010048a3));
		diffAs.addRange(addr(0x010059a3), addr(0x010059a3));
		assertEquals(diffAs, programDiff.getDifferences(programDiff.getFilter(), null));
	}

	/**
	 * Test that ProgramDiff can determine the program context differences
	 * between Program1 and Program2.
	 */
	@Test
    public void testGetProgramContextDifferences() throws Exception {

		// C0 is 1 bit
		// AH is 8 bits
		// AL is 8 bits
		// AX is 16 bits
		// DR0 is 32 bits

		// 100230b - 100231c: p1 and p2 have same register values defined.
		// 10022d4 - 10022e5: p1 has register defined.
		// 10022ee - 10022fc: p2 has register defined.
		// 1002329 - 100233b && 1002330 - 1002345: p1 and p2 have same register value with edges overlapping.
		// 1002378 - 100238f && 100238a - 1002396: p1 and p2 have different register value with edges overlapping.
		// 1003bfc - 1003c10 && 1003c02 - 1003c07: same values.
		// 1003c1c - 1003c36 && 1003c23 - 1003c2a: different values.
		// 1003c52 - 1003c57 && 1003c40 - 1003c61: same values.
		// 1003cd0 - 1003cdc && 1003c9c - 1003cf2: different values.
		// 1005e4f - 1005e53: 1 bit register differs.
		// 1005e5d - 1005e61: 16 bit register differs.
		// 1005e64 - 1005e68: 8 bit register differs.
		// 1005e7b - 1005e83: 32 bit register differs.
		// 1005e8d: zero value in p1.

		String C0_REGISTER = "C0";
		String AH_REGISTER = "AH";
		String AL_REGISTER = "AL";
		String AX_REGISTER = "AX";
		String DR0_REGISTER = "DR0";

		programBuilder1.setRegisterValue(AH_REGISTER, "0x100230b", "0x100231c", 0x12);
		programBuilder1.setRegisterValue(AL_REGISTER, "0x10022d4", "0x10022e5", 0x12);
		programBuilder1.setRegisterValue(AH_REGISTER, "0x1002329", "0x100233b", 0xa1);
		programBuilder1.setRegisterValue(AH_REGISTER, "0x1002378", "0x100238f", 0xb1);
		programBuilder1.setRegisterValue(DR0_REGISTER, "0x1003bfc", "0x1003c10", 0x23);
		programBuilder1.setRegisterValue(DR0_REGISTER, "0x1003c1c", "0x1003c36", 0x1212);
		programBuilder1.setRegisterValue(AH_REGISTER, "0x1003c52", "0x1003c57", 0x22);
		programBuilder1.setRegisterValue(AH_REGISTER, "0x1003cd0", "0x1003cdc", 0x55);
		programBuilder1.setRegisterValue(C0_REGISTER, "0x1005e4f", "0x1005e53", 0x1);
		programBuilder1.setRegisterValue(AX_REGISTER, "0x1005e5d", "0x1005e61", 0x1);
		programBuilder1.setRegisterValue(AL_REGISTER, "0x1005e64", "0x1005e68", 0x7);
		programBuilder1.setRegisterValue(DR0_REGISTER, "0x1005e7b", "0x1005e83", 0x123456);
		programBuilder1.setRegisterValue(AX_REGISTER, "0x1005e8d", "0x1005e8d", 0x0);

		programBuilder2.setRegisterValue(AH_REGISTER, "0x100230b", "0x100231c", 0x12);
		programBuilder2.setRegisterValue(AX_REGISTER, "0x10022ee", "0x10022fc", 0x1234);
		programBuilder2.setRegisterValue(AH_REGISTER, "0x1002330", "0x1002345", 0xa1);
		programBuilder2.setRegisterValue(AH_REGISTER, "0x100238a", "0x1002396", 0xc1);
		programBuilder2.setRegisterValue(DR0_REGISTER, "0x1003c02", "0x1003c07", 0x23);
		programBuilder2.setRegisterValue(DR0_REGISTER, "0x1003c23", "0x1003c2a", 0x3344);
		programBuilder2.setRegisterValue(AH_REGISTER, "0x1003c40", "0x1003c61", 0x22);
		programBuilder2.setRegisterValue(AH_REGISTER, "0x1003c9c", "0x1003cf2", 0x66);
		programBuilder1.setRegisterValue(C0_REGISTER, "0x1005e4f", "0x1005e53", 0x0);
		programBuilder1.setRegisterValue(AX_REGISTER, "0x1005e5d", "0x1005e61", 0x1122);
		programBuilder1.setRegisterValue(AL_REGISTER, "0x1005e64", "0x1005e68", 0x5);
		programBuilder1.setRegisterValue(DR0_REGISTER, "0x1005e7b", "0x1005e83", 0x85678);

		AddressSet as;
		programDiff = new ProgramDiff(p1, p2);

		as = new AddressSet();
		as.addRange(addr(0x010022d4), addr(0x010022e5));
		as.addRange(addr(0x010022ee), addr(0x010022fc));
		as.addRange(addr(0x01002329), addr(0x0100232f));
		as.addRange(addr(0x0100233c), addr(0x01002345));
		as.addRange(addr(0x01002378), addr(0x01002396));
		as.addRange(addr(0x01003bfc), addr(0x01003c01));
		as.addRange(addr(0x01003c08), addr(0x01003c10));
		as.addRange(addr(0x01003c1c), addr(0x01003c36));
		as.addRange(addr(0x01003c40), addr(0x01003c51));
		as.addRange(addr(0x01003c58), addr(0x01003c61));
		as.addRange(addr(0x01003c9c), addr(0x01003cf2));
		as.addRange(addr(0x01005e4f), addr(0x01005e53));
		as.addRange(addr(0x01005e5d), addr(0x01005e61));
		as.addRange(addr(0x01005e64), addr(0x01005e68));
		as.addRange(addr(0x01005e7b), addr(0x01005e83));
		as.addRange(addr(0x01005e8d), addr(0x01005e8d));
		programDiff.setFilter(new ProgramDiffFilter(ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS));
		AddressSetView diffAs = programDiff.getDifferences(programDiff.getFilter(), null);
//        System.out.println("ProgramContext:     as="+as.toString());
//        System.out.println("ProgramContext: diffAs="+diffAs.toString());
		assertEquals(as, diffAs);
	}

	private Address addr(int offset) {
		AddressSpace space = p1.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	private Address addr(Program program, int offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

}
