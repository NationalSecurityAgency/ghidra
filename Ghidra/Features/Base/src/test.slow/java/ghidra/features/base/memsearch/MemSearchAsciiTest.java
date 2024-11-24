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

import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;

/**
 * Tests for searching memory for ascii.
 */
public class MemSearchAsciiTest extends AbstractMemSearchTest {

	@Before
	@Override
	public void setUp() throws Exception {
		super.setUp();
		setSearchFormat(SearchFormat.STRING);
	}

	@Override
	protected Program buildProgram() throws Exception {
		ToyProgramBuilder builder = new ToyProgramBuilder("Test", false, ProgramBuilder._TOY);

		builder.createMemory(".text", "0x1001000", 0x6600);
		builder.createMemory(".data", "0x1008000", 0x600);
		builder.createMemory(".rsrc", "0x100a000", 0x5400);
		//create some strings
		builder.createEncodedString("0x010016ec", "something", StandardCharsets.UTF_16LE, true);
		builder.createEncodedString("0x01001708", "Notepad", StandardCharsets.UTF_16LE, true);
		builder.createEncodedString("0x01001740", "something else", StandardCharsets.UTF_16LE,
			true);
		builder.createEncodedString("0x01001840", "\u039d\u03bf\u03c4\u03b5\u03c0\u03b1\u03bd",
			StandardCharsets.UTF_16LE, true);
		builder.createEncodedString("0x0100186a",
			"\u03c1\u03b8\u03c4\u03b5\u03c0\u03b1\u03bd\u03c2\u03b2", StandardCharsets.UTF_16LE,
			true);
		builder.createEncodedString("0x0100196a",
			"\u03c1\u03b8\u03c4\u03b5\u03c0\u03b1\u03bd\u03c2\u03b2", StandardCharsets.UTF_8, true);
		builder.createEncodedString("0x0100189d", "\"Hello world!\"\n\t-new programmer",
			StandardCharsets.US_ASCII, true);
		builder.createEncodedString("0x0100198e", "\"Hello world!\"\n\t-new programmer",
			StandardCharsets.UTF_16LE, true);
		builder.createEncodedString("0x010013cc", "notepad.exe", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x010013e0", "notepad.exe", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x1006c6a", "GetLocaleInfoW", StandardCharsets.US_ASCII,
			false);
		builder.createEncodedString("0x1006f26", "GetCPInfo", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x0100dde0", "NOTEPAD.EXE", StandardCharsets.UTF_16LE, true);
		builder.createEncodedString("0x0100eb90",
			"This string contains notepad twice. Here is the second NotePad.",
			StandardCharsets.UTF_16LE, true);
		builder.createEncodedString("0x0100ed00", "Another string", StandardCharsets.UTF_16LE,
			true);

		return builder.getProgram();
	}

	@Test
	public void testCaseSensitiveOff() throws Exception {

		setCaseSensitive(false);

		setInput("notepad");

		List<Address> addrs = addrs(0x010013cc, 0x010013e0);

		performSearchNext(addrs);
	}

	@Test
	public void testCaseSensitiveOn() throws Exception {

		setCaseSensitive(true);

		setInput("NOTEpad");

		performSearchNext(Collections.emptyList());
	}

	@Test
	public void testUnicodeNotCaseSensitive() throws Exception {

		setCaseSensitive(false);
		setCharset(StandardCharsets.UTF_16);
		setInput("NOTEpad");

		List<Address> addrs = addrs(0x01001708, 0x0100dde0, 0x0100eb90, 0x0100eb90); // this code unit contains two notepads in one string

		performSearchNext(addrs);
	}

	@Test
	public void testGreekUnicodeSearch() throws Exception {
		setCaseSensitive(false);
		setCharset(StandardCharsets.UTF_16);
		setInput("\u03c4\u03b5\u03c0\u03b1\u03bd");

		List<Address> addrs = addrs(0x01001840, 0x0100186a);

		performSearchNext(addrs);

		setCharset(StandardCharsets.UTF_8);

		addrs = addrs(0x0100196a);

		performSearchNext(addrs);
	}

	@Test
	public void testRepeatUnicodeNotCaseSensitive() throws Exception {
		setCaseSensitive(false);
		setCharset(StandardCharsets.UTF_16);
		setInput("NOTEpad");

		performSearchNext(addr(0x01001708));

		// this code unit contains two notepads in one string
		List<Address> addrs = addrs(0x0100dde0, 0x0100eb90, 0x0100eb90);

		for (Address address : addrs) {
			repeatSearchForward();
			assertEquals(address, codeBrowser.getCurrentLocation().getAddress());

		}
		repeatSearchForward();
		assertEquals(addrs.get(2), codeBrowser.getCurrentLocation().getAddress());
	}

	@Test
	public void testUnicodeCaseSensitive() throws Exception {
		setCaseSensitive(true);
		setCharset(StandardCharsets.UTF_16);
		setInput("Notepad");

		performSearchNext(addrs(0x01001708));
	}

	@Test
	public void testSearchAllUnicodeNotCaseSensitive() throws Exception {
		setCaseSensitive(false);

		setCharset(StandardCharsets.UTF_16);
		setInput("NOTEpad");

		performSearchAll();
		waitForSearch(4);

		List<Address> addrs = addrs(0x01001708, 0x0100dde0, 0x0100ebba, 0x0100ebfe);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllUnicodeCaseSensitive() throws Exception {
		setCaseSensitive(true);
		setCharset(StandardCharsets.UTF_16);
		setInput("Notepad");

		performSearchAll();
		waitForSearch(1);

		checkMarkerSet(addrs(0x01001708));
	}

	@Test
	public void testSearchAllNotCaseSensitive() throws Exception {
		setCaseSensitive(false);

		setInput("NOTEpad");
		performSearchAll();
		waitForSearch(2);

		List<Address> addrs = addrs(0x010013cc, 0x010013e0);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllCaseSensitive() throws Exception {
		byte[] b = new byte[] { 'N', 'O', 'T', 'E', 'p', 'a', 'd' };

		int transactionID = program.startTransaction("test");
		memory.setBytes(addr(0x0100b451), b);
		program.endTransaction(transactionID, true);

		setCaseSensitive(true);
		setInput("NOTEpad");
		performSearchAll();

		waitForSearch(1);

		checkMarkerSet(addrs(0x0100b451));
	}

	@Test
	public void testSearchAllCaseSensitiveAlign8() throws Exception {
		setAlignment(8);

		setCaseSensitive(true);

		setInput("notepad");
		performSearchAll();
		waitForSearch(1);

		checkMarkerSet(addrs(0x010013e0));
	}

	@Test
	public void testSearchSelection() throws Exception {

		makeSelection(tool, program, addr(0x01006c73), addr(0x01006f02));

		assertSearchSelectionSelected();

		setCaseSensitive(false);

		setInput("Info");

		performSearchNext(addrs(0x01006c6a));
	}

	@Test
	public void testSearchNonContiguousSelection() throws Exception {

		makeSelection(tool, program, range(0x01006c70, 0x01006c80), range(0x01006f2b, 0x01006f37));

		assertSearchSelectionSelected();

		setCaseSensitive(false);

		setInput("Info");

		List<Address> addrs = addrs(0x01006c6a, 0x01006f26);

		performSearchNext(addrs);
	}

	@Test
	public void testSearchBackward() throws Exception {

		goTo(tool, program, addr(0x1006f56));

		setCaseSensitive(true);

		setInput("Info");

		List<Address> addrs = addrs(0x01006f26, 0x01006c6a);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchBackwardInSelection() throws Exception {

		goTo(tool, program, addr(0x01006f02));

		makeSelection(tool, program, addr(0x01006c73), addr(0x01006f02));

		assertSearchSelectionSelected();

		setCaseSensitive(false);

		setInput("Info");

		List<Address> addrs = addrs(0x01006c6a);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchBackwardAlign4() throws Exception {

		goTo(tool, program, addr(0x1006f56));

		setCaseSensitive(true);

		setAlignment(8);

		setInput("notepad");

		List<Address> addrs = addrs(0x010013e0);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchBackwardAlign4NoneFound() throws Exception {

		goTo(tool, program, addr(0x1006f56));

		setCaseSensitive(true);

		setAlignment(8);

		setInput("Info");

		performSearchPrevious(Collections.emptyList());
	}

	@Test
	public void testSearchEscapeSequences() throws Exception {
		setCaseSensitive(true);
		setEscapeSequences(true);

		setCharset(StandardCharsets.US_ASCII);
		setInput("\"Hello world!\"\\n\\t-new programmer");

		List<Address> addrs = addrs(0x0100189d);
		performSearchNext(addrs);

		setBigEndian(false);
		setCharset(StandardCharsets.UTF_16);

		addrs = addrs(0x0100198e);
		performSearchNext(addrs);
	}
}
