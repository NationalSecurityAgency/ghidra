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
package ghidra.features.base.memsearch;

import static org.junit.Assert.*;

import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.GhidraOptions;
import ghidra.app.services.MarkerSet;
import ghidra.app.util.viewer.field.BytesFieldFactory;
import ghidra.features.base.memsearch.bytesource.ProgramSearchRegion;
import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.framework.options.Options;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Tests for the Hex format in searching memory.
 */
public class MemSearchHexTest extends AbstractMemSearchTest {

	public MemSearchHexTest() {
		super();
	}

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();
		setSearchFormat(SearchFormat.HEX);
	}

	@Override
	protected Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);
		MemoryBlock overlayBlock = builder.createOverlayMemory("otherOverlay", "OTHER:0", 100);

		//create and disassemble a function
		builder.setBytes("0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 eb 02 33 " +
				"ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 85 f6 74 27 " +
				"56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15 04 12 00 " +
				"01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75 08 ff 15 04 " +
				"12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		builder.createFunction("0x01002cf5");

		//create and disassemble some code not in a function
		builder.setBytes("0x010029bd", "ff 15 c4 10 00 01 8b d8 33 f6 3b de 74 06");
		builder.disassemble("0x10029bd", 0xe, true);

		builder.setBytes("0x10035f5", "f3 a5 99 b9 30 fd ff ff ff 75 08 f7 f9");
		builder.disassemble("0x10035f5", 0xd, true);

		builder.setBytes("0x10040d9", "8b 0d 58 80 00 01");
		builder.disassemble("0x10040d9", 0x6, true);

		//create some data

		builder.setBytes("0x1001004", "85 4f dc 77");
		builder.applyDataType("0x1001004", new Pointer32DataType(), 1);
		builder.createEncodedString("0x01001708", "Notepad", StandardCharsets.UTF_16BE, true);
		builder.createEncodedString("0x01001740", "something else", StandardCharsets.UTF_16BE,
			true);
		builder.createEncodedString("0x010013cc", "notepad.exe", StandardCharsets.US_ASCII, true);

		//create some undefined data
		builder.setBytes("0x1001500", "4e 00 65 00 77 00");
		builder.setBytes("0x1003000", "55 00");

		builder.setBytes("0x1004100", "64 00 00 00");//100 dec
		builder.setBytes("0x1004120", "50 ff 75 08");//7.4027124e-34 float
		builder.setBytes("0x1004135", "64 00 00 00");//100 dec
		builder.setBytes("0x1004200", "50 ff 75 08 e8 8d 3c 00");//1.588386874245921e-307
		builder.setBytes("0x1004247", "50 ff 75 08");//7.4027124e-34 float
		builder.setBytes("0x1004270", "65 00 6e 00 64 00 69 00");//29555302058557541 qword

		builder.setBytes(overlayBlock.getStart().toString(), "00 01 02 03 04 05 06 07 08 09");

		return builder.getProgram();
	}

	@Test
	public void testDisplayDialog() throws Exception {
		assertTrue(searchAction.isEnabled());
		assertTrue(searchProvider.isVisible());
	}

	@Test
	public void testHexInvalidEntry() {
		// enter a non-hex digit; the search field should not accept it
		setInput("z");

		assertEquals("", getInput());
	}

	@Test
	public void testHexEnterSpaces() {
		// verify that more than 16 digits are allowed if spaces are entered
		setInput("01 23 45 67 89 a b c d e f 1 2 3");
		assertEquals("01 23 45 67 89 a b c d e f 1 2 3", getInput());
	}

	@Test
	public void testHexPasteNumberWithPrefixAndSuffix() {
		// paste a number with a hex prefix;
		// the prefix should be removed before the insertion
		setInput("0xabcdef");
		assertEquals("abcdef", getInput());

		setInput("$68000");
		assertEquals("68000", getInput());

		// same for 'h' the suffix
		setInput("ABCDEFh");
		assertEquals("ABCDEF", getInput());

		// should also somehow work with leading and trailing white spaces
		setInput("  0X321  ");
		assertEquals("321", getInput().strip());
		setInput("  123H ");
		assertEquals("123", getInput().strip());
	}

	@Test
	public void testHexSearch() throws Exception {

		goTo(0x01001000);

		List<Address> addrs = addrs(0x1002d06, 0x1002d2c, 0x1002d50);

		setInput("14 ff");

		performSearchNext(addrs);
	}

	@Test
	public void testHexSearchNext() throws Exception {
		// hit the enter key in the values field;
		// should go to next match found

		goTo(0x01001000);

		//@formatter:off
		List<Address> addrs = addrs(
			0x01002d06,
			0x01002d11,
			0x01002d2c,
			0x01002d2f,
			0x01002d37,
			0x01002d3a,
			0x01002d3e,
			0x01002d52,
			0x01002d55,
			0x01002d58,
			0x01002d5b,
			0x010035fd,
			0x01004122,
			0x01004202,
			0x01004249
		);
		//@formatter:on

		setInput("75");

		performSearchNext(addrs);

	}

	@Test
	public void testHexContiguousSelection() throws Exception {
		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d));

		assertSearchSelectionSelected();

		setInput("50");

		performSearchNext(addrs(0x01002d1c));
	}

	@Test
	public void testHexNonContiguousSelection() throws Exception {

		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d), range(0x01004100, 0x01004300));

		assertSearchSelectionSelected();

		setInput("50");

		List<Address> addrs = addrs(0x01002d1c, 0x01004120, 0x01004200, 0x01004247);

		performSearchNext(addrs);
	}

	@Test
	public void testHexSelectionNotOn() throws Exception {

		goTo(0x0100106c);

		// make a selection but turn off the Selection checkbox;
		// the search should go outside the selection

		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d), range(0x01004100, 0x010041ff));

		assertSearchSelectionSelected();
		setSearchSelectionOnly(false);

		List<Address> addrs = addrs(0x01002d1c, 0x01004120, 0x01004200, 0x01004247);

		setInput("50");

		performSearchNext(addrs);
	}

	@Test
	public void testHexSearchAll() throws Exception {
		// QueryResults should get displayed
		// test the marker stuff
		goTo(0x1004180);

		setInput("50");

		performSearchAll();

		waitForSearch(4);

		List<Address> addrs = addrs(0x01002d1c, 0x01004120, 0x01004200, 0x01004247);

		checkMarkerSet(addrs);
	}

	@Test
	public void testHexSearchAll2() throws Exception {
		// enter search string for multiple byte match

		setInput("ff 15");
		performSearchAll();

		waitForSearch(5);

		List<Address> addrs = addrs(0x01002d1f, 0x01002d41, 0x01002d4a, 0x01002d5e, 0x010029bd);

		checkMarkerSet(addrs);
	}

	@Test
	public void testHexSearchAllAlign8() throws Exception {
		setAlignment(8);
		setInput("8b");
		performSearchAll();

		waitForSearch(1);

		checkMarkerSet(addrs(0x01002d48));
	}

	@Test
	public void testHexHighlight() throws Exception {

		setInput("80 00 01");

		performSearchAll();

		waitForSearch(1);

		Highlight[] h = getByteHighlights(addr(0x10040d9), "8b 0d 58 80 00 01");
		assertEquals(1, h.length);
		assertEquals(9, h[0].getStart());
		assertEquals(16, h[0].getEnd());
	}

	@Test
	public void testHexHighlight2() throws Exception {
		setInput("01 8b");
		performSearchAll();

		waitForSearch(3);

		Highlight[] h = getByteHighlights(addr(0x10029bd), "ff 15 d4 10 00 01");
		assertEquals(1, h.length);
		assertEquals(15, h[0].getStart());
		// end is not important since the match crosses code units
	}

	@Test
	public void testHexHighlight3() throws Exception {
		setInput("d8 33 f6 3b");
		performSearchAll();

		waitForSearch(1);

		Highlight[] h = getByteHighlights(addr(0x10029c3), "8b d8");
		assertEquals(1, h.length);
		assertEquals(3, h[0].getStart());
		// end is not important since the match crosses code units

	}

	@Test
	public void testHexHighlight4() throws Exception {
		setInput("fd ff ff");
		performSearchAll();

		waitForSearch(1);

		Highlight[] h = getByteHighlights(addr(0x10035f8), "b9 30 fd ff ff");
		assertEquals(1, h.length);
		assertEquals(6, h[0].getStart());
		assertEquals(13, h[0].getEnd());
	}

	@Test
	public void testHighlightGroupSize() throws Exception {
		Options opt = tool.getOptions(GhidraOptions.CATEGORY_BROWSER_FIELDS);
		opt.setInt(BytesFieldFactory.BYTE_GROUP_SIZE_MSG, 3);
		opt.setString(BytesFieldFactory.DELIMITER_MSG, "#@#");

		setInput("fd ff ff");
		performSearchAll();

		waitForSearch(1);

		Highlight[] h = getByteHighlights(addr(0x10035f8), "b930fd#@#ffff");
		assertEquals(1, h.length);
		assertEquals(4, h[0].getStart());
		assertEquals(12, h[0].getEnd());

	}

	@Test
	public void testMarkersRemoved() throws Exception {
		setInput("ff 15");
		performSearchAll();
		waitForSearch(5);

		String title = searchProvider.getTitle();

		MarkerSet markerSet = markerService.getMarkerSet(title, program);
		assertNotNull(markerSet);

		//close it
		runSwing(() -> searchProvider.closeComponent());

		markerSet = markerService.getMarkerSet("Memory Search Results", program);
		assertNull(markerSet);
	}

	@Test
	public void testHexSearchPreviousNotFound() throws Exception {

		goTo(0x01001000);

		setInput("75");

		performSearchPrevious(Collections.emptyList());
	}

	@Test
	public void testHexSearchPrevious() throws Exception {
		// enter search string for multiple byte match
		// ff 15

		//start at 1002d6d and search backwards
		goTo(0x1002d6d);

		setInput("ff 15");

		List<Address> addrs = addrs(0x01002d5e, 0x01002d4a, 0x01002d41, 0x01002d1f, 0x010029bd);

		performSearchPrevious(addrs);
	}

	@Test
	public void testHexSearchPreviousAlign2() throws Exception {
		// enter search string for multiple byte match
		// ff 15

		goTo(0x1002d6d);

		setAlignment(2);

		setInput("ff 15");

		List<Address> addrs = addrs(0x01002d5e, 0x01002d4a);

		performSearchPrevious(addrs);
	}

	@Test
	public void testHexSearchBackwardsInSelection() throws Exception {

		goTo(0x01003000);

		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d));

		assertSearchSelectionSelected();

		setInput("50");

		performSearchPrevious(addrs(0x01002d1c));
	}

	@Test
	public void testHexSearchBackwardsNonContiguousSelection() throws Exception {

		goTo(0x01005000);

		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d), range(0x01004100, 0x01004300));

		assertSearchSelectionSelected();

		List<Address> addrs = addrs(0x01004247, 0x01004200, 0x01004120, 0x01002d1c);

		setInput("50");

		performSearchPrevious(addrs);
	}

	@Test
	public void testHexWildcardSearch() throws Exception {
		goTo(0x01001000);

		List<Address> addrs = addrs(0x01002d0b, 0x01002d25, 0x01002d48, 0x01002d64);

		setInput("8b f?");

		performSearchNext(addrs);
	}

	@Test
	public void testHexWildcardSearch_SingleWildcardCharacter_QuestionMark() throws Exception {

		//
		// This tests that a single wildcard character will get converted to a value of '00' and
		// a mast of 'FF'.   This allows a single '?' character to be used in place of '??'.
		//

		goTo(0x01001000);

		List<Address> addrs = addrs(0x01001004, 0x01002d27);

		setInput("85 ?");

		performSearchNext(addrs);
	}

	@Test
	public void testHexWildcardSearch_SingleWildcardCharacter_Dot() throws Exception {

		//
		// This tests that a single wildcard character will get converted to a value of '00' and
		// a mast of 'FF'.   This allows a single '.' character to be used in place of '..'.
		//

		goTo(0x01001000);

		List<Address> addrs = addrs(0x01001004, 0x01002d27);

		setInput("85 .");

		performSearchNext(addrs);
	}

	@Test
	public void testHexWildcardSearchBackwards() throws Exception {

		goTo(0x01005000);

		List<Address> addrs = addrs(0x01002d64, 0x01002d48, 0x01002d25, 0x01002d0b);

		setInput("8b f?");

		performSearchPrevious(addrs);
	}

	@Test
	public void testHexWildcardSearchAll() throws Exception {
		// QueryResults should get displayed
		// test the marker stuff

		setInput("8b f?");
		performSearchAll();
		waitForSearch(4);

		List<Address> addrs = addrs(0x01002d64, 0x01002d48, 0x01002d25, 0x01002d0b);

		checkMarkerSet(addrs);
	}

	@Test
	public void testHexByteOrder() throws Exception {
		setBigEndian(true);

		goTo(0x01001000);

		setInput("8bec");

		performSearchNext(addrs(0x01002cf6));
	}

	@Test
	public void testSearchInOtherSpace() throws Exception {
		goTo(0x01001000);

		setInput("01 02 03 04 05 06 07 08 09");

		addSearchRegion(ProgramSearchRegion.OTHER, true);

		List<Address> addrs = addrs(program.getAddressFactory().getAddress("otherOverlay:1"));
		performSearchNext(addrs);
	}

	@Test
	public void testRepeatSearchForwardThenBackwards() throws Exception {

		setInput("8b f8");
		performSearchNext(addr(0x01002d0b));

		repeatSearchForward();

		assertEquals(addr(0x01002d48), currentAddress());

		repeatSearchBackward();

		assertEquals(addr(0x01002d0b), currentAddress());
	}
}
