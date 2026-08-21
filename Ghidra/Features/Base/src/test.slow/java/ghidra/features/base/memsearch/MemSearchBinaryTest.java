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
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.Program;

/**
 * Tests for the Binary format in searching memory.
 */
public class MemSearchBinaryTest extends AbstractMemSearchTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		setSearchFormat(SearchFormat.BINARY);
	}

	@Override
	protected Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("TestX86", ProgramBuilder._X86);
		builder.createMemory(".text", Long.toHexString(0x1001000), 0x6600);
		builder.createMemory(".data", Long.toHexString(0x1008000), 0x600);
		builder.createMemory(".rsrc", Long.toHexString(0x100A000), 0x5400);
		builder.createMemory(".bound_import_table", Long.toHexString(0xF0000248), 0xA8);
		builder.createMemory(".debug_data", Long.toHexString(0xF0001300), 0x1C);

		//create and disassemble a function
		builder.setBytes(
			"0x01002cf5",
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 eb 02 33 " +
				"ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 85 f6 74 27 " +
				"56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15 04 12 00 " +
				"01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75 08 ff 15 04 " +
				"12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		builder.createFunction("0x01002cf5");

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

		return builder.getProgram();
	}

	@Test
	public void testBinaryInvalidEntry() {
		// enter a non-binary digit; the search field should not accept it
		setInput("2");

		assertEquals("", getInput());
	}

	@Test
	public void testBinaryEnterSpaces() {
		// verify that more than 8 digits are allowed if spaces are entered
		setInput("01110000 01110000");
		assertEquals("01110000 01110000", getInput());
	}

	@Test
	public void testBinaryPasteNumberWithPrefix() {
		// paste a number with a binary prefix;
		// the prefix should be removed before the insertion
		setInput("0b00101010");
		assertEquals("00101010", getInput());

		setInput("0B1010 10");
		assertEquals("1010 10", getInput());
	}

	@Test
	public void testBinarySearch() throws Exception {

		goTo(0x01001000);

		setInput("00010100 11111111");

		performSearchNext(addr(0x01002d06));

	}

	@Test
	public void testBinarySearchNext() throws Exception {

		goTo(0x01001000);

		setInput("01110101");

		//@formatter:off
		List<Address> addrs = addrs(0x01002d06,
									0x01002d11,
									0x01002d2c,
									0x01002d2f,
									0x01002d37,
									0x01002d3a,
									0x01002d3e,
									0x01002d52,
									0x01002d55,
									0x01002d58,
									0x01002d5b);		
		//@formatter:on

		performSearchNext(addrs);
	}

	@Test
	public void testBinarySearchNextAlign4() throws Exception {
		goTo(0x01001000);
		setInput("01110101");

		setAlignment(4);

		//the bytes are at the right alignment value but the code units are not
		List<Address> addrs = addrs(0x01002d2f, 0x01002d37, 0x01002d5b);
		performSearchNext(addrs);
	}

	@Test
	public void testBinarySearchAll() throws Exception {
		setInput("11110110");

		performSearchAll();
		waitForSearch(1);

		checkMarkerSet(addrs(0x1002d28));
	}

	@Test
	public void testBinarySearchAllAlign4() throws Exception {
		setInput("11111111 01110101");

		setAlignment(4);

		performSearchAll();
		waitForSearch(2);

		List<Address> startList = addrs(0x1002d2c, 0x1002d58);

		checkMarkerSet(startList);
	}

	@Test
	public void testCodeUnitScope_DefinedData() throws Exception {
		//
		// Turn on Defined Data scope and make sure only that scope yields matches
		//
		goTo(0x1001000);// start of program; pointer data

		setCodeTypeFilters(false, true, false);

		setInput("10000101");
		performSearchNext(addr(0x1001004));

		// Turn off Defined Data scope and make sure we have no match at the expected address
		goTo(0x1001000);// start of program; pointer data
		setCodeTypeFilters(true, false, true);
		performSearchNext(addr(0x1002d27)); // this is in an instruction past the data match

		// try backwards
		goTo(0x1002000);
		setCodeTypeFilters(false, true, false);

		performSearchPrevious(addrs(0x1001004));
	}

	@Test
	public void testCodeUnitScope_UndefinedData() throws Exception {
		//
		// Turn on Undefined Data scope and make sure only that scope yields matches
		//
		goTo(0x1001000);
		setCodeTypeFilters(false, false, true);

		setInput("01100101");
		performSearchNext(addr(0x1001502));

		// Turn off Undefined Data scope and make sure we have no match at the expected address
		goTo(0x1001500);
		setCodeTypeFilters(true, true, false);
		performSearchNext(addr(0x1001708));
		// try backwards

		goTo(0x1003000);
		setCodeTypeFilters(false, false, true);

		performSearchPrevious(addrs(0x1001502));
	}

	@Test
	public void testBinarySearchPrevious() throws Exception {
		goTo(0x01002d6b);

		setInput("11111111 00010101");

		List<Address> addrs = addrs(0x01002d5e, 0x01002d4a, 0x01002d41, 0x01002d1f);

		performSearchPrevious(addrs);
	}

	@Test
	public void testBinaryWildcardSearch() throws Exception {
		goTo(0x01001000);

		setInput("010101xx 10001011");

		List<Address> addrs = addrs(0x01002cf5, 0x01002cfc, 0x01002d47);

		performSearchNext(addrs);
	}

	@Test
	public void testBinaryWildcardSearchAll() throws Exception {

		setInput("10001011 1111xxxx");
		performSearchAll();
		waitForSearch(4);

		List<Address> addrs = addrs(0x1002d0b, 0x1002d25, 0x1002d48, 0x1002d64);

		checkMarkerSet(addrs);
	}

}
