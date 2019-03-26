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

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.test.ClassicSampleX86ProgramBuilder;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
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
public class ProgramMerge1Test extends AbstractGhidraHeadedIntegrationTest {

	private ProgramMergeManager programMerge;
	ClassicSampleX86ProgramBuilder programBuilder1;
	ClassicSampleX86ProgramBuilder programBuilder2;
	private Program p1;
	private Program p2;
	int txId1;
	int txId2;

	/** Creates new ProgramDiffTest */
	public ProgramMerge1Test() {
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
	 * Test that programMerge recognizes that the 2 programs have the same
	 * address spaces.
	 */
	@Test
	public void testCompareSameAddressSpaces() throws Exception {
		try {
			programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		}
		catch (ProgramConflictException e) {
			Assert.fail("Address spaces in program 1 and program 2 should have been the same.");
		}
	}

	/**
	 * Test that programMerge catches differences in Address spaces
	 * between programs.
	 */
	@Test
	public void testCompareDifferentAddressSpaces() throws Exception {
		Program p3 = null;
		try {
			ProgramBuilder programBuilder3 = new ProgramBuilder("program3", ProgramBuilder._8051);
			p3 = programBuilder3.getProgram();

			programMerge = new ProgramMergeManager(p1, p3, TaskMonitorAdapter.DUMMY_MONITOR);
			assertNull(programMerge);
		}
		catch (ProgramConflictException e) {
			assertNull(e.getMessage(), programMerge);
		}
	}

	/**
	 * Test that programMerge recognizes that the 2 programs have the same
	 * address spaces.
	 */
	@Test
	public void testCompareSameMemory() throws Exception {
		try {
			programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
			assertTrue("Memory in program 1 and program 2 should have been the same.",
				programMerge.memoryMatches());
		}
		catch (ProgramConflictException e) {
			assertNull(e.getMessage(), programMerge);
		}
	}

	/**
	 * Test that programMerge can determine if two programs have different memory addresses..
	 */
	@Test
	public void testCompareDifferentMemory() throws Exception {

		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		try {
			programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
			assertTrue("Memory in program 1 and program 2 should have been different.",
				!programMerge.memoryMatches());
		}
		catch (ProgramConflictException e) {
			Assert.fail("Address spaces in program 1 and program 2 should have been the same.");
		}
	}

	/**
	 * Test that programMergeFilter works as expected.
	 */
	@Test
	public void testDiffFilter() throws Exception {
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		// Check that default filter has all difference types set.
		assertEquals(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS),
			programMerge.getDiffFilter());

		// See if we set it to no differences, that is what we get.
		programMerge.setDiffFilter(new ProgramDiffFilter());
		assertEquals(new ProgramDiffFilter(), programMerge.getDiffFilter());

		// See if we set it to specific differences, that is what we get.
		programMerge.setDiffFilter(new ProgramDiffFilter(
			ProgramDiffFilter.CODE_UNIT_DIFFS | ProgramDiffFilter.COMMENT_DIFFS));
		assertEquals(
			new ProgramDiffFilter(
				ProgramDiffFilter.CODE_UNIT_DIFFS | ProgramDiffFilter.COMMENT_DIFFS),
			programMerge.getDiffFilter());
	}

	/**
	 * Test that programMergeFilter works as expected.
	 */
	@Test
	public void testMergeFilter() throws Exception {
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		// Check that default filter has all difference types set.
		assertEquals(new ProgramMergeFilter(), programMerge.getMergeFilter());

		// See if we set it to all differences and merging, that is what we get.
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.ALL, ProgramMergeFilter.MERGE));
		assertEquals(new ProgramMergeFilter(ProgramMergeFilter.ALL, ProgramMergeFilter.MERGE),
			programMerge.getMergeFilter());

		// See if we set it to all differences with no merging, that is what we get.
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.ALL, ProgramMergeFilter.REPLACE));
		assertEquals(new ProgramMergeFilter(ProgramMergeFilter.ALL, ProgramMergeFilter.REPLACE),
			programMerge.getMergeFilter());

		// See if we set it to specific differences, that is what we get.
		programMerge.setMergeFilter(new ProgramMergeFilter(
			ProgramMergeFilter.CODE_UNITS | ProgramMergeFilter.COMMENTS, ProgramMergeFilter.MERGE));
		assertEquals(
			new ProgramMergeFilter(ProgramMergeFilter.CODE_UNITS | ProgramMergeFilter.COMMENTS,
				ProgramMergeFilter.MERGE),
			programMerge.getMergeFilter());
	}

	/**
	 * Test that programMerge correctly returns program1 and program2.
	 */
	@Test
	public void testGetPrograms() throws Exception {
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(p1, programMerge.getProgramOne());
		assertEquals(p2, programMerge.getProgramTwo());
	}

	/**
	 * Test that programMerge determines addresses in Program1 that are not in
	 * Program2.
	 */
	@Test
	public void testOnlyInOne() throws Exception {

		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSetView as = programMerge.getAddressesOnlyInOne();
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(0x200), addr(0x2ff)));
		assertEquals(as, as1);
	}

	/**
	 * Test that programMerge determines addresses in Program2 that are not in
	 * Program1.
	 */
	@Test
	public void testOnlyInTwo() throws Exception {

		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSetView as = programMerge.getAddressesOnlyInTwo();
		AddressSet as2 = new AddressSet();
		as2.add(new AddressRangeImpl(addr(0x400), addr(0x4ff)));
		assertEquals(as, as2);
	}

	/**
	 * Test that programMerge can correctly determine the union of all addresses
	 * in Program1 and Program2.
	 */
	@Test
	public void testGetCombinedAddresses() throws Exception {

		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(0x100), addr(0x1ff)));
		as1.add(new AddressRangeImpl(addr(0x200), addr(0x2ff)));
		as1.add(new AddressRangeImpl(addr(0x400), addr(0x4ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01001000), addr(p1, 0x010075ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01008000), addr(p1, 0x010085ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x0100a000), addr(p1, 0x0100f3ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0000248), addr(p1, 0xf00002ef)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0001300), addr(p1, 0xf000131b)));
		AddressSetView as2 = programMerge.getCombinedAddresses();
		assertEquals(as1, as2);
	}

	/**
	 * Test that programMerge can correctly determine which addresses are
	 * in common between Program1 and Program2.
	 */
	@Test
	public void testGetAddressesInCommon() throws Exception {

		programBuilder1.createMemory("d1", "0x100", 0x100, null, (byte) 0xAC);
		programBuilder1.createMemory("d2", "0x200", 0x100);

		programBuilder2.createMemory("d1", "0x100", 0x100, null, (byte) 0xAF);
		programBuilder2.createMemory("d4", "0x400", 0x100);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as1 = new AddressSet();
		as1.add(new AddressRangeImpl(addr(0x100), addr(0x1ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01001000), addr(p1, 0x010075ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x01008000), addr(p1, 0x010085ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0x0100a000), addr(p1, 0x0100f3ff)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0000248), addr(p1, 0xf00002ef)));
		as1.add(new AddressRangeImpl(addr(p1, 0xf0001300), addr(p1, 0xf000131b)));
		AddressSetView as2 = programMerge.getAddressesInCommon();
		assertEquals(as1, as2);
	}

	/**
	 * Test that programMerge correctly uses the address set that limits the Diff.
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

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSetView diffs;

		// before limiting it should detect diffs.
		diffs = programMerge.getFilteredDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(diffs.contains(addr(p1, 0x01006420)));
		assertTrue(diffs.contains(addr(p1, 0x010059a3)));

		// Program Diff only determines differences within the limited set.
		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x01002239), addr(0x0100248c)), TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01002239), addr(0x0100248c));
		assertEquals(as, programMerge.getLimitedAddressSet());

		// limited set is used by the Diff.
		diffs = programMerge.getFilteredDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(!diffs.contains(addr(0x01006420)) && !diffs.contains(addr(0x010059a3)));
	}

	/**
	 * Test that programMerge correctly ignores addresses.
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

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSetView diffs;

		// before ignore it should detect diffs.
		diffs = programMerge.getFilteredDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(diffs.contains(addr(0x01006420)));
		assertTrue(diffs.contains(addr(0x010059a3)));

		// ignore is initially empty.
		assertEquals(new AddressSet(), programMerge.getIgnoreAddressSet());

		// ignore returns what has been ignored.
		programMerge.ignore(new AddressSet(addr(0x01006420), addr(0x01006420)));
		programMerge.ignore(new AddressSet(addr(0x010059a3), addr(0x010059a3)));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01006420), addr(0x01006420));
		as.addRange(addr(0x010059a3), addr(0x010059a3));
		assertEquals(as, programMerge.getIgnoreAddressSet());

		// ignore set is used by the Diff.
		diffs = programMerge.getFilteredDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(!diffs.contains(addr(0x01006420)) && !diffs.contains(addr(0x010059a3)));
	}

	/**
	 * Test that programMerge correctly restricts the Diff results to an address set.
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

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		AddressSetView diffs;

		// before restricting it should detect diffs.
		diffs = programMerge.getFilteredDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(diffs.contains(addr(0x01006420)));
		assertTrue(diffs.contains(addr(0x010059a3)));

		// restricted set is initially null.
		assertNull(programMerge.getRestrictedAddressSet());

		// must be in restricted set to be returned.
		programMerge.restrictResults(new AddressSet(addr(0x01005500), addr(0x01006000)));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01005500), addr(0x01006000));
		assertEquals(as, programMerge.getRestrictedAddressSet());

		// restricted set is used by the Diff.
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.ALL_DIFFS));
		diffs = programMerge.getFilteredDifferences(TaskMonitorAdapter.DUMMY_MONITOR);
		assertTrue(!diffs.contains(addr(0x01006420)) && diffs.contains(addr(0x010059a3)));

		// restricted set can be cleared.
		programMerge.removeResultRestrictions();
		assertNull(programMerge.getRestrictedAddressSet());
	}

	/**
	 * Test that programMerge can determine where comments differ
	 * between Program1 and Program2.
	 */
	@Test
	public void testReplaceCommentDifferences() throws Exception {
		// 0x1002040: p1 has Plate, Pre, EOL, Post, & Repeatable comment.
		programBuilder1.createComment("0x1002040", "My Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder1.createComment("0x1002040", "My Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder1.createComment("0x1002040", "My EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder1.createComment("0x1002040", "My Post Comment", CodeUnit.POST_COMMENT);
		programBuilder1.createComment("0x1002040", "My Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x100204c: p2 has Plate, Pre, EOL, Post, & Repeatable comment.
		programBuilder2.createComment("0x100204c", "Other Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x100204c", "Other EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Post Comment", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x1002304: p1 has EOL comment.
		programBuilder1.createComment("0x1002304", "My EOL Comment", CodeUnit.EOL_COMMENT);
		// 0x1002306: p1 has pre-comment.
		programBuilder1.createComment("0x1002306", "My Pre Comment", CodeUnit.PRE_COMMENT);
		// 0x100230b: p1 has plate and post comments.
		programBuilder1.createComment("0x100230b", "My Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder1.createComment("0x100230b", "My Post Comment", CodeUnit.POST_COMMENT);
		// 0x100230d: p2 plate comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Plate Comment", CodeUnit.PLATE_COMMENT);
		// 0x100230d: p2 pre comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Pre Comment", CodeUnit.PRE_COMMENT);
		// 0x100230d: p2 eol comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100230d", "Other EOL Comment", CodeUnit.EOL_COMMENT);
		// 0x100230d: p2 post comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Post Comment", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Post Comment", CodeUnit.POST_COMMENT);
		// 0x100230d: p2 repeatable comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x1002336: Different Repeatable comments.
		programBuilder1.createComment("0x1002336", "Once upon a time,",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002336", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x1002346: P1 Repeatable comment contains P2 Repeatable comment.
		programBuilder1.createComment("0x1002346", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002346", "This is a sample", CodeUnit.REPEATABLE_COMMENT);
		// 0x1002350: P1 Repeatable comment contained within P2 Repeatable comment.
		programBuilder1.createComment("0x1002350", "This is a sample", CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002350", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x100238f: Different EOL comments.
		programBuilder1.createComment("0x100238f", "Once upon a time,", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100238f", "This is a sample comment.",
			CodeUnit.EOL_COMMENT);
		// 0x1002395: Different Pre comments.
		programBuilder1.createComment("0x1002395", "Once upon a time,", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x1002395", "This is a sample comment.",
			CodeUnit.PRE_COMMENT);
		// 0x100239d: Different Plate comments.
		programBuilder1.createComment("0x100239d", "Once upon a time,", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100239d", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);
		// 0x100239d: Different Post comments.
		programBuilder1.createComment("0x100239d", "Once upon a time,", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100239d", "This is a sample comment.",
			CodeUnit.POST_COMMENT);
		// 0x1002a91: p2 has a plate comment.
		programBuilder2.createComment("0x1002a91", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);
		// 0x10030d2: p1 has plate comment.
		programBuilder1.createComment("0x10030d2", "Once upon a time,", CodeUnit.PLATE_COMMENT);
		// 0x10030d8: p2 has plate comment.
		programBuilder2.createComment("0x10030d8", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);
		// 0x100355f: p1 has plate comment.
		programBuilder1.createComment("0x100355f", "Plate Comment", CodeUnit.PLATE_COMMENT);
		// 0x100415a: p1 and p2 have same plate comments.
		programBuilder1.createComment("0x100415a", "Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100415a", "Plate Comment", CodeUnit.PLATE_COMMENT);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x01002040), addr(0x01002040));
		as.addRange(addr(0x0100204c), addr(0x0100204c));
		as.addRange(addr(0x01002304), addr(0x01002304));
		as.addRange(addr(0x01002306), addr(0x01002306));
		as.addRange(addr(0x0100230b), addr(0x0100230b));
		as.addRange(addr(0x0100230d), addr(0x0100230d));
		as.addRange(addr(0x01002336), addr(0x01002336));
		as.addRange(addr(0x01002346), addr(0x01002346));
		as.addRange(addr(0x01002350), addr(0x01002350));
		as.addRange(addr(0x0100238f), addr(0x0100238f));
		as.addRange(addr(0x01002395), addr(0x01002395));
		as.addRange(addr(0x0100239d), addr(0x0100239d));
		as.addRange(addr(0x01002a91), addr(0x01002a91));
		as.addRange(addr(0x010030d2), addr(0x010030d2));
		as.addRange(addr(0x010030d8), addr(0x010030d8));
		as.addRange(addr(0x0100355f), addr(0x0100355f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
//		printAddressSet(as);
//		printAddressSet(diffAs);
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testReplaceFunctionCommentDifferences1() throws Exception {
		// 0x100248f: p1 has function comment.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testReplaceFunctionCommentDifferences2() throws Exception {
		// 0x100248f: p2 has function comment.
		programBuilder2.createFunctionComment("0x100248f", "Other function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testReplaceFunctionCommentDifferences3() throws Exception {
		// 0x100248f: p1 and p2 have same function comment.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");
		programBuilder2.createFunctionComment("0x100248f", "Sample function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(new AddressSet(), diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testReplaceFunctionCommentDifferences4() throws Exception {
		// 0x100248f: p1 and p2 have different function comments.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");
		programBuilder2.createFunctionComment("0x100248f", "Other function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.REPLACE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

//	private void printAddressSet(AddressSetView diffAs) {
//		System.out.println("=====");
//		for (AddressRange addressRange : diffAs) {
//			System.out.println("[" + addressRange.getMinAddress() + "," +
//				addressRange.getMaxAddress() + "]");
//		}
//		System.out.println("-----");
//	}

	/**
	 * Test that programMerge can determine where comments differ
	 * between Program1 and Program2.
	 */
	@Test
	public void testMergeCommentDifferences() throws Exception {
		// 0x1002040: p1 has Plate, Pre, EOL, Post, & Repeatable comment.
		programBuilder1.createComment("0x1002040", "My Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder1.createComment("0x1002040", "My Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder1.createComment("0x1002040", "My EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder1.createComment("0x1002040", "My Post Comment", CodeUnit.POST_COMMENT);
		programBuilder1.createComment("0x1002040", "My Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x100204c: p2 has Plate, Pre, EOL, Post, & Repeatable comment.
		programBuilder2.createComment("0x100204c", "Other Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x100204c", "Other EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Post Comment", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100204c", "Other Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x1002304: p1 has EOL comment.
		programBuilder1.createComment("0x1002304", "My EOL Comment", CodeUnit.EOL_COMMENT);
		// 0x1002306: p1 has pre-comment.
		programBuilder1.createComment("0x1002306", "My Pre Comment", CodeUnit.PRE_COMMENT);
		// 0x100230b: p1 has plate and post comments.
		programBuilder1.createComment("0x100230b", "My Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder1.createComment("0x100230b", "My Post Comment", CodeUnit.POST_COMMENT);
		// 0x100230d: p2 plate comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Plate Comment", CodeUnit.PLATE_COMMENT);
		// 0x100230d: p2 pre comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Pre Comment", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Pre Comment", CodeUnit.PRE_COMMENT);
		// 0x100230d: p2 eol comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "EOL Comment", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100230d", "Other EOL Comment", CodeUnit.EOL_COMMENT);
		// 0x100230d: p2 post comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Post Comment", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Post Comment", CodeUnit.POST_COMMENT);
		// 0x100230d: p2 repeatable comments contain the p1 comment string.
		programBuilder1.createComment("0x100230d", "Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x100230d", "Other Repeatable Comment",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x1002336: Different Repeatable comments.
		programBuilder1.createComment("0x1002336", "Once upon a time,",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002336", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x1002346: P1 Repeatable comment contains P2 Repeatable comment.
		programBuilder1.createComment("0x1002346", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002346", "This is a sample", CodeUnit.REPEATABLE_COMMENT);
		// 0x1002350: P1 Repeatable comment contained within P2 Repeatable comment.
		programBuilder1.createComment("0x1002350", "This is a sample", CodeUnit.REPEATABLE_COMMENT);
		programBuilder2.createComment("0x1002350", "This is a sample comment.",
			CodeUnit.REPEATABLE_COMMENT);
		// 0x100238f: Different EOL comments.
		programBuilder1.createComment("0x100238f", "Once upon a time,", CodeUnit.EOL_COMMENT);
		programBuilder2.createComment("0x100238f", "This is a sample comment.",
			CodeUnit.EOL_COMMENT);
		// 0x1002395: Different Pre comments.
		programBuilder1.createComment("0x1002395", "Once upon a time,", CodeUnit.PRE_COMMENT);
		programBuilder2.createComment("0x1002395", "This is a sample comment.",
			CodeUnit.PRE_COMMENT);
		// 0x100239d: Different Plate comments.
		programBuilder1.createComment("0x100239d", "Once upon a time,", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100239d", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);
		// 0x100239d: Different Post comments.
		programBuilder1.createComment("0x100239d", "Once upon a time,", CodeUnit.POST_COMMENT);
		programBuilder2.createComment("0x100239d", "This is a sample comment.",
			CodeUnit.POST_COMMENT);
		// 0x1002a91: p2 has a plate comment.
		programBuilder2.createComment("0x1002a91", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);
		// 0x10030d2: p1 has plate comment.
		programBuilder1.createComment("0x10030d2", "Once upon a time,", CodeUnit.PLATE_COMMENT);
		// 0x10030d8: p2 has plate comment.
		programBuilder2.createComment("0x10030d8", "This is a sample comment.",
			CodeUnit.PLATE_COMMENT);
		// 0x100355f: p1 has plate comment.
		programBuilder1.createComment("0x100355f", "Plate Comment", CodeUnit.PLATE_COMMENT);
		// 0x100415a: p1 and p2 have same plate comments.
		programBuilder1.createComment("0x100415a", "Plate Comment", CodeUnit.PLATE_COMMENT);
		programBuilder2.createComment("0x100415a", "Plate Comment", CodeUnit.PLATE_COMMENT);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.MERGE));

		AddressSet as = new AddressSet();
		as.addRange(addr(0x01002040), addr(0x01002040));
		as.addRange(addr(0x0100204c), addr(0x0100204c));
		as.addRange(addr(0x01002304), addr(0x01002304));
		as.addRange(addr(0x01002306), addr(0x01002306));
		as.addRange(addr(0x0100230b), addr(0x0100230b));
		as.addRange(addr(0x0100230d), addr(0x0100230d));
		as.addRange(addr(0x01002336), addr(0x01002336));
		as.addRange(addr(0x01002346), addr(0x01002346));
		as.addRange(addr(0x01002350), addr(0x01002350));
		as.addRange(addr(0x0100238f), addr(0x0100238f));
		as.addRange(addr(0x01002395), addr(0x01002395));
		as.addRange(addr(0x0100239d), addr(0x0100239d));
		as.addRange(addr(0x01002a91), addr(0x01002a91));
		as.addRange(addr(0x010030d2), addr(0x010030d2));
		as.addRange(addr(0x010030d8), addr(0x010030d8));
		as.addRange(addr(0x0100355f), addr(0x0100355f));

		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		diffAs = programMerge.getFilteredDifferences();
		as = new AddressSet();
		as.addRange(addr(0x01002040), addr(0x01002040));
		as.addRange(addr(0x01002304), addr(0x01002304));
		as.addRange(addr(0x01002306), addr(0x01002306));
		as.addRange(addr(0x0100230b), addr(0x0100230b));
		as.addRange(addr(0x01002336), addr(0x01002336));
		as.addRange(addr(0x01002346), addr(0x01002346));
		as.addRange(addr(0x0100238f), addr(0x0100238f));
		as.addRange(addr(0x01002395), addr(0x01002395));
		as.addRange(addr(0x0100239d), addr(0x0100239d));
		as.addRange(addr(0x010030d2), addr(0x010030d2));
		as.addRange(addr(0x0100355f), addr(0x0100355f));

//		printAddressSet(as);
//		printAddressSet(diffAs);

		assertEquals(as, diffAs);
	}

	@Test
	public void testMergeFunctionCommentDifferences1() throws Exception {
		// 0x100248f: p1 has function comment.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.MERGE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x0100248f), addr(0x0100248f)),
			programMerge.getFilteredDifferences());
	}

	@Test
	public void testMergeFunctionCommentDifferences2() throws Exception {
		// 0x100248f: p2 has function comment.
		programBuilder2.createFunctionComment("0x100248f", "Other function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.MERGE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testMergeFunctionCommentDifferences3() throws Exception {
		// 0x100248f: p1 and p2 have same function comment.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");
		programBuilder2.createFunctionComment("0x100248f", "Sample function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.MERGE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(new AddressSet(), diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testMergeFunctionCommentDifferences4() throws Exception {
		// 0x100248f: p1 and p2 have different function comments.
		programBuilder1.createFunctionComment("0x100248f", "Sample function comment.");
		programBuilder2.createFunctionComment("0x100248f", "Other function comment.");

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.COMMENT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.COMMENTS, ProgramMergeFilter.MERGE));
		AddressSet as = new AddressSet();
		as.addRange(addr(0x0100248f), addr(0x0100248f));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(addr(0x0100248f), addr(0x0100248f)),
			programMerge.getFilteredDifferences());
	}

	@Test
	public void testExtRefDiff2() throws Exception {
		// 0x100102c: p1 changed external ref to mem ref on operand 0.

		programBuilder1.applyDataType("0x0100102c", new Pointer32DataType(), 1);
		programBuilder1.createMemoryReference("0x0100102c", "0x01001000", RefType.INDIRECTION,
			SourceType.DEFAULT);

		programBuilder2.applyDataType("0x0100102c", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x0100102c", "ADVAPI32.dll", "IsTextUnicode", 0);

		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x01001000), addr(0x010017ff)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x0100102c), addr(0x0100102f));

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testExtRefDiff3() throws Exception {
		// 0x1001034: p2 set ExternalName to myGDI32.dll.

		programBuilder1.applyDataType("0x01001034", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x01001034", "GDI32.dll", "SomePlace", 0);

		programBuilder2.applyDataType("0x01001034", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x01001034", "myGDI32.dll", "SomePlace", 0);

		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x01001000), addr(0x010017ff)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x01001034), addr(0x01001037));

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testExtRefDiff4() throws Exception {
		// 0x1001038: p2 set ToLabel to ABC12345.

		programBuilder1.applyDataType("0x01001038", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x01001038", "GDI32.dll", "ABC", 0);

		programBuilder2.applyDataType("0x01001038", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x01001038", "GDI32.dll", "ABC12345", 0);

		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x01001000), addr(0x010017ff)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x01001038), addr(0x0100103b));

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testExtRefDiff5() throws Exception {
		// 0x100103c: p2 set ToAddress to 0x77f4abcd.

		programBuilder1.applyDataType("0x0100103c", new Pointer32DataType(), 1);
		programBuilder1.createExternalReference("0x0100103c", "GDI32.dll", "XYZ", "0x77f4cdef", 0);

		programBuilder2.applyDataType("0x0100103c", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x0100103c", "GDI32.dll", "XYZ", "0x77f4abcd", 0);

		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x01001000), addr(0x010017ff)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x0100103c), addr(0x0100103f));

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testExtRefDiff6() throws Exception {
		// 0x1001044: p2 added external ref.

		programBuilder1.applyDataType("0x01001044", new Pointer32DataType(), 1);

		programBuilder2.applyDataType("0x01001044", new Pointer32DataType(), 1);
		programBuilder2.createExternalReference("0x01001044", "GDI32.dll", "MNM", 0);

		programMerge = new ProgramMergeManager(p1, p2,
			new AddressSet(addr(0x01001000), addr(0x010017ff)), TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x01001044), addr(0x01001047));

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the stack reference differences
	 * between Program1 and Program2.
	 */
	@Test
	public void testApplyStackRefDiffs() throws Exception {
		// 0x1006443: p1 has stack ref on op 0.
		// 0x1006446: p has stack ref on op 0.
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

		programMerge = new ProgramMergeManager(p1, p2, null, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x1006443), addr(0x1006445));
		as.addRange(addr(0x1006446), addr(0x100644c));
		as.addRange(addr(0x10064ce), addr(0x10064d0));
		as.addRange(addr(0x1006480), addr(0x1006485));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
//		printAddressSet(as);
//		printAddressSet(programMerge.getFilteredDifferences());
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
//		printAddressSet(programMerge.getFilteredDifferences());
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the register reference differences
	 * between Program1 and Program2.
	 */
	@Test
	public void testApplyRegisterRefDiffs() throws Exception {
		// 0x10018a6: p1 has reg ref to esi.
		// 0x100295a: p2 has reg ref to cx.
		// 0x1002d0b: p1 has reg ref to edi; p2 has reg ref to eax.
		// 0x10033fe: p1 & p2 both have reg ref to edi.

		Register esiReg1 = p1.getRegister("ESI");
		Register ediReg1 = p1.getRegister("EDI");

		int transactionID1 = p1.startTransaction("Test Transaction");
		ReferenceManager refManager1 = p1.getReferenceManager();
		refManager1.addRegisterReference(addr(p1, 0x10018a6), 0, esiReg1, RefType.DATA,
			SourceType.USER_DEFINED);

		refManager1.addRegisterReference(addr(p1, 0x1002cf5), 0, ediReg1, RefType.DATA,
			SourceType.USER_DEFINED);

		refManager1.addRegisterReference(addr(p1, 0x10033f6), 0, ediReg1, RefType.DATA,
			SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		ReferenceManager referenceManager2 = p2.getReferenceManager();
		Register cxReg2 = p2.getRegister("CX");
		Register ediReg2 = p2.getRegister("EDI");
		Register eaxReg2 = p2.getRegister("EAX");

		int transactionID2 = p2.startTransaction("Test Transaction");
		referenceManager2.addRegisterReference(addr(p2, 0x100295a), 0, cxReg2, RefType.DATA,
			SourceType.USER_DEFINED);

		referenceManager2.addRegisterReference(addr(p2, 0x1002cf5), 0, eaxReg2, RefType.DATA,
			SourceType.USER_DEFINED);

		referenceManager2.addRegisterReference(addr(p2, 0x10033f6), 0, ediReg2, RefType.DATA,
			SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		AddressSet as = new AddressSet();
		as.addRange(addr(0x010018a0), addr(0x010018ab));
		as.addRange(addr(0x01002cf5), addr(0x01002d0c));
		as.addRange(addr(0x01002950), addr(0x0100295c));
		as.addRange(addr(0x010033f6), addr(0x010033fe));
		programMerge = new ProgramMergeManager(p1, p2, as, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet expectedDiffs = new AddressSet();
		expectedDiffs.addRange(addr(0x010018a6), addr(0x010018a6));
		expectedDiffs.addRange(addr(0x0100295a), addr(0x0100295a));
		expectedDiffs.addRange(addr(0x01002cf5), addr(0x01002cf5));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.REFERENCE_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.REFERENCES, ProgramMergeFilter.REPLACE));
//		printAddressSet(expectedDiffs);
//		printAddressSet(programMerge.getFilteredDifferences());
		assertEquals(expectedDiffs, programMerge.getFilteredDifferences());
		programMerge.merge(expectedDiffs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the user defined property
	 * differences between Program1 and Program2.
	 */
	@Test
	public void testApplyUserDefinedDifferences() throws Exception {
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

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet();
		as.addRange(addr(0x10018ae), addr(0x10018ae));
		as.addRange(addr(0x10018ce), addr(0x10018ce));
		as.addRange(addr(0x10018ff), addr(0x10018ff));
		as.addRange(addr(0x100248c), addr(0x100248c));
		as.addRange(addr(0x10039dd), addr(0x10039dd));
		as.addRange(addr(0x10039f1), addr(0x10039f1));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.USER_DEFINED_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.PROPERTIES, ProgramMergeFilter.REPLACE));
		AddressSetView expectedSet = DiffUtility.getCodeUnitSet(as, p1);
		AddressSetView diffSet = programMerge.getFilteredDifferences();
		assertEquals(expectedSet, diffSet);
		assertEquals(expectedSet, programMerge.getFilteredDifferences());
		programMerge.merge(expectedSet, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can determine the label differences between
	 * Program1 and Program2.
	 */
	@Test
	public void testApplySymbolDifferences() throws Exception {
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

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet expectedDiffs = new AddressSet();
		expectedDiffs.addRange(addr(0x1002d16), addr(0x1002d16));
		expectedDiffs.addRange(addr(0x1002d18), addr(0x1002d18));
		expectedDiffs.addRange(addr(0x1002d1c), addr(0x1002d1c));
		expectedDiffs.addRange(addr(0x1002d1d), addr(0x1002d1d));
		expectedDiffs.addRange(addr(0x1002d1f), addr(0x1002d1f));
		expectedDiffs.addRange(addr(0x1002d25), addr(0x1002d25));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
		assertEquals(expectedDiffs, programMerge.getFilteredDifferences());
		programMerge.merge(programMerge.getFilteredDifferences(), TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that ProgramDiff can determine the label differences between
	 * Program1 and Program2.
	 */
	@Test
	public void testApplyPrimarySymbolDifferences() throws Exception {

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

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet as = new AddressSet(addr(0x1002d1d), addr(0x1002d1d));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.REPLACE));
		assertEquals(as, programMerge.getFilteredDifferences());
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff1() throws Exception {

		// program1 has reg param and program2 doesn't.

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff2() throws Exception {

		// different named registers as param_1

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function1.removeParameter(0);
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("example", new DWordDataType(), dr0Reg, p1);
		function1.removeParameter(0);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		function2.removeParameter(0);
		dr0Reg = p2.getRegister("DR0");
		Variable var2 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p2);
		function2.removeParameter(0);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

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

	@Test
	public void testFunctionRegParamDiff3() throws Exception {

		// program2 has reg param and program1 doesn't.

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		Register eaxReg = p2.getRegister("EAX");
		Variable var2 = new ParameterImpl("count", new DWordDataType(), eaxReg, p2);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff4() throws Exception {

		// same named registers for params 0,1,2 but different name for 0.

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register eaxReg = p1.getRegister("EAX");
		Register ecxReg = p1.getRegister("ECX");
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1A = new ParameterImpl("Units", new DWordDataType(), eaxReg, p1);
		function1.addParameter(var1A, SourceType.USER_DEFINED);
		Variable var1B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p1);
		function1.addParameter(var1B, SourceType.USER_DEFINED);
		Variable var1C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p1);
		function1.addParameter(var1C, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		eaxReg = p2.getRegister("EAX");
		ecxReg = p2.getRegister("ECX");
		dr0Reg = p2.getRegister("DR0");
		Variable var2A = new ParameterImpl("One", new DWordDataType(), eaxReg, p2);
		function2.addParameter(var2A, SourceType.USER_DEFINED);
		Variable var2B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p2);
		function2.addParameter(var2B, SourceType.USER_DEFINED);
		Variable var2C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p2);
		function2.addParameter(var2C, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff5() throws Exception {

		// same named registers for params 0,1,2 but different dt for 1.

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register eaxReg = p1.getRegister("EAX");
		Register ecxReg = p1.getRegister("ECX");
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1A = new ParameterImpl("One", new DWordDataType(), eaxReg, p1);
		function1.addParameter(var1A, SourceType.USER_DEFINED);
		Variable var1B =
			new ParameterImpl("Two", new PointerDataType(new WordDataType()), ecxReg, p1);
		function1.addParameter(var1B, SourceType.USER_DEFINED);
		Variable var1C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p1);
		function1.addParameter(var1C, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		eaxReg = p2.getRegister("EAX");
		ecxReg = p2.getRegister("ECX");
		dr0Reg = p2.getRegister("DR0");
		Variable var2A = new ParameterImpl("One", new DWordDataType(), eaxReg, p2);
		function2.addParameter(var2A, SourceType.USER_DEFINED);
		Variable var2B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p2);
		function2.addParameter(var2B, SourceType.USER_DEFINED);
		Variable var2C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p2);
		function2.addParameter(var2C, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff6() throws Exception {

		// same named registers for params 0,1,2 but different comment for 2.

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register eaxReg = p1.getRegister("EAX");
		Register ecxReg = p1.getRegister("ECX");
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1A = new ParameterImpl("One", new DWordDataType(), eaxReg, p1);
		function1.addParameter(var1A, SourceType.USER_DEFINED);
		Variable var1B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p1);
		function1.addParameter(var1B, SourceType.USER_DEFINED);
		Variable var1C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p1);
		var1C.setComment("Third Param");
		function1.addParameter(var1C, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		eaxReg = p2.getRegister("EAX");
		ecxReg = p2.getRegister("ECX");
		dr0Reg = p2.getRegister("DR0");
		Variable var2A = new ParameterImpl("One", new DWordDataType(), eaxReg, p2);
		function2.addParameter(var2A, SourceType.USER_DEFINED);
		Variable var2B = new ParameterImpl("Two", new FloatDataType(), ecxReg, p2);
		function2.addParameter(var2B, SourceType.USER_DEFINED);
		Variable var2C = new ParameterImpl("Three", new Pointer32DataType(), dr0Reg, p2);
		function2.addParameter(var2C, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff7() throws Exception {

		// different named registers as different params.

		int transactionID1 = p1.startTransaction("Test Transaction");
		Register clReg = p1.getRegister("CL");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		function1.setCustomVariableStorage(true);
		Variable var1 = new ParameterImpl(null, DataType.DEFAULT, clReg, p1);
		function1.addParameter(var1, SourceType.USER_DEFINED);
		var1 = new ParameterImpl(null, DataType.DEFAULT, 0x8, p1);
		function1.addParameter(var1, SourceType.USER_DEFINED);
		var1 = new ParameterImpl(null, DataType.DEFAULT, 0xc, p1);
		function1.addParameter(var1, SourceType.USER_DEFINED);
		assertEquals(3, function1.getParameterCount());
		p1.endTransaction(transactionID1, true);

		int transactionID = p2.startTransaction("Test Transaction");
		Register dlReg = p2.getRegister("DL");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x10048a3));
		function2.setCustomVariableStorage(true);
		Variable var2 = new ParameterImpl(null, DataType.DEFAULT, 0x4, p2);
		function2.addParameter(var2, SourceType.USER_DEFINED);
		var2 = new ParameterImpl(null, DataType.DEFAULT, 0x8, p2);
		function2.addParameter(var2, SourceType.USER_DEFINED);
		var2 = new ParameterImpl(null, DataType.DEFAULT, dlReg, p2);
		function2.addParameter(var2, SourceType.USER_DEFINED);
		assertEquals(3, function2.getParameterCount());
		p2.endTransaction(transactionID, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff8() throws Exception {

		// added register param in program1

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x10048a3));
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.addParameter(var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
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

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(diffAs, programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff10() throws Exception {

		// same reg param in program 1 and 2

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		function1.removeParameter(0);
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.removeParameter(0);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		function2.removeParameter(0);
		dr0Reg = p2.getRegister("DR0");
		Variable var2 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p2);
		function2.removeParameter(0);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x1002cf5), addr(0x1002cf5));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff11() throws Exception {

		// no params in program 1 or 2

		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSet diffAs = new AddressSet();
		diffAs.addRange(addr(0x10048a3), addr(0x10048a3));
		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.FUNCTION_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.FUNCTIONS, ProgramMergeFilter.REPLACE));
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
		programMerge.merge(diffAs, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	@Test
	public void testFunctionRegParamDiff12() throws Exception {

		// changed param from stack to register in program2

		int transactionID2 = p2.startTransaction("Test Transaction");
		Function function2 = p2.getFunctionManager().getFunctionAt(addr(p2, 0x1002cf5));
		Register dr0Reg = p2.getRegister("DR0");
		Variable var2 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p2);
		function2.removeParameter(0);
		function2.insertParameter(0, var2, SourceType.USER_DEFINED);
		p2.endTransaction(transactionID2, true);

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

	@Test
	public void testFunctionRegParamDiff13() throws Exception {

		// changed param from stack to register in program1

		int transactionID1 = p1.startTransaction("Test Transaction");
		Function function1 = p1.getFunctionManager().getFunctionAt(addr(p1, 0x1002cf5));
		Register dr0Reg = p1.getRegister("DR0");
		Variable var1 = new ParameterImpl("variable", new DWordDataType(), dr0Reg, p1);
		function1.removeParameter(0);
		function1.insertParameter(0, var1, SourceType.USER_DEFINED);
		p1.endTransaction(transactionID1, true);

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
	 * Test that programMerge can determine the program context differences
	 * between Program1 and Program2.
	 */
	@Test
	public void testApplyProgramContextDifferences() throws Exception {

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
		programMerge = new ProgramMergeManager(p1, p2, TaskMonitorAdapter.DUMMY_MONITOR);

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

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.PROGRAM_CONTEXT_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.PROGRAM_CONTEXT, ProgramMergeFilter.REPLACE));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
//        System.out.println("ProgramContext:     as="+as.toString());
//        System.out.println("ProgramContext: diffAs="+diffAs.toString());
		assertEquals(as, diffAs);
		programMerge.merge(as, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(new AddressSet(), programMerge.getFilteredDifferences());
	}

	/**
	 * Test that programMerge can replace the symbol differences between
	 * Program1 and Program2 when program1 and program2 have the same variables
	 * at differing places that would cause a duplicate name when applied
	 * individually but not if all are applied.
	 */
	@Test
	public void testMergeConflictingLabel() throws Exception {
		// Diff/Merge symbols from 1002950 to 100299b

		SymbolTable symtab1 = p1.getSymbolTable();
		symtab1.createLabel(addr(0x100295d), "ONE", SourceType.USER_DEFINED);
		SymbolTable symtab2 = p2.getSymbolTable();
		symtab2.createLabel(addr(0x1002969), "ONE", SourceType.USER_DEFINED);
		AddressSet limitedAddrSet = new AddressSet(addr(0x1002950), addr(0x100299b));
		programMerge =
			new ProgramMergeManager(p1, p2, limitedAddrSet, TaskMonitorAdapter.DUMMY_MONITOR);

		AddressSet as = new AddressSet(addr(0x100295d));
		AddressSet as2 = new AddressSet(addr(0x1002969));

		programMerge.setDiffFilter(new ProgramDiffFilter(ProgramDiffFilter.SYMBOL_DIFFS));
		programMerge.setMergeFilter(
			new ProgramMergeFilter(ProgramMergeFilter.SYMBOLS, ProgramMergeFilter.MERGE));
		AddressSetView diffAs = programMerge.getFilteredDifferences();
		assertEquals(as.union(as2), diffAs);

		programMerge.merge(as2, TaskMonitorAdapter.DUMMY_MONITOR);
		assertEquals(as, programMerge.getFilteredDifferences());
		Symbol[] symbols = symtab1.getSymbols(addr(0x1002969));
		assertEquals(1, symbols.length);
		assertEquals("ONE", symbols[0].getName());
		assertEquals(p1.getGlobalNamespace(), symbols[0].getParentNamespace());
	}

	private Address addr(Program program, int offset) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
	}

	private Address addr(int offset) {
		return addr(p1, offset);
	}
}
