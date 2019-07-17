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
package ghidra.app.plugin.core.searchmem;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.swing.JComboBox;

import org.junit.Before;
import org.junit.Test;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.ToyProgramBuilder;

/**
 * Tests for searching memory for ascii.
 */
public class MemSearchAsciiTest extends AbstractMemSearchTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		selectRadioButton("String");
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
	public void testStringFormatSelected() throws Exception {
		// verify that String options are showing: case sensitive, unicode,
		// regular expression check boxes.
		assertButtonState("Case Sensitive", true, false);

		@SuppressWarnings("unchecked")
		JComboBox<Charset> comboBox =
			(JComboBox<Charset>) findComponentByName(pane, "Encoding Options");
		assertNotNull(comboBox);
	}

	@Test
	public void testCaseSensitiveOff() throws Exception {

		selectCheckBox("Case Sensitive", false);

		setValueText("notepad");

		List<Address> addrs = addrs(0x010013cc, 0x010013e0);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testCaseSensitiveOn() throws Exception {

		selectCheckBox("Case Sensitive", true);

		setValueText("NOTEpad");

		pressSearchButton("Next");

		assertEquals("Not Found", statusLabel.getText());
	}

	@Test
	public void testUnicodeNotCaseSensitive() throws Exception {

		selectCheckBox("Case Sensitive", false);

		setEncoding(StandardCharsets.UTF_16);
		setValueText("NOTEpad");

		List<Address> addrs = addrs(0x01001708, 0x0100dde0, 0x0100eb90, 0x0100eb90); // this code unit contains two notepads in one string

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testGreekUnicodeSearch() throws Exception {
		selectCheckBox("Case Sensitive", false);

		setEncoding(StandardCharsets.UTF_16);
		setValueText("\u03c4\u03b5\u03c0\u03b1\u03bd");

		List<Address> addrs = addrs(0x01001840, 0x0100186a);

		performSearchTest(addrs, "Next");

		addrs.add(addr(0x0100196a));

		setEncoding(StandardCharsets.UTF_8);
		pressSearchButton("Next");
		assertEquals("Found", statusLabel.getText());
		assertEquals(addrs.get(2), cb.getCurrentLocation().getAddress());

		pressSearchButton("Next");
		assertEquals("Not Found", statusLabel.getText());
	}

	@Test
	public void testRepeatUnicodeNotCaseSensitive() throws Exception {
		selectCheckBox("Case Sensitive", false);

		setEncoding(StandardCharsets.UTF_16);
		setValueText("NOTEpad");

		List<Address> startList = addrs(0x01001708, 0x0100dde0, 0x0100eb90, 0x0100eb90); // this code unit contains two notepads in one string

		for (int i = 0; i < startList.size(); i++) {
			Address start = startList.get(i);
			if (i == 0) {
				pressSearchButton("Next");
			}
			else {
				repeatSearch();
			}
			assertEquals(start, cb.getCurrentLocation().getAddress());
			assertEquals("Found", statusLabel.getText());
		}
		pressSearchButton("Next");
		assertEquals("Not Found", statusLabel.getText());
	}

	@Test
	public void testUnicodeCaseSensitive() throws Exception {
		selectCheckBox("Case Sensitive", true);

		setEncoding(StandardCharsets.UTF_16);
		setValueText("Notepad");

		performSearchTest(addrs(0x01001708), "Next");
	}

	@Test
	public void testUnicodeBigEndian() throws Exception {

		// with Big Endian selected, unicode bytes should be reversed
		setEndianess("Big Endian");

		setEncoding(StandardCharsets.UTF_16);
		setValueText("start");

		assertEquals("00 73 00 74 00 61 00 72 00 74 ", hexLabel.getText());

		selectRadioButton("Little Endian");
		assertEquals("73 00 74 00 61 00 72 00 74 00 ", hexLabel.getText());
	}

	@Test
	public void testSearchAllUnicodeNotCaseSensitive() throws Exception {
		// test for markers

		// QueryResults should get displayed
		// test the marker stuff
		selectCheckBox("Case Sensitive", false);

		setEncoding(StandardCharsets.UTF_16);
		setValueText("NOTEpad");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 4);

		List<Address> addrs = addrs(0x01001708, 0x0100dde0, 0x0100ebba, 0x0100ebfe);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllUnicodeCaseSensitive() throws Exception {
		// test for markers

		// QueryResults should get displayed
		// test the marker stuff
		selectCheckBox("Case Sensitive", true);

		setEncoding(StandardCharsets.UTF_16);
		setValueText("Notepad");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x01001708));
	}

	@Test
	public void testSearchAllNotCaseSensitive() throws Exception {
		// QueryResults should get displayed
		// test the marker stuff
		selectCheckBox("Case Sensitive", false);

		setValueText("NOTEpad");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 2);

		List<Address> addrs = addrs(0x010013cc, 0x010013e0);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllCaseSensitive() throws Exception {
		// QueryResults should get displayed
		// test the marker stuff
		// create an set of ascii bytes to do this test
		byte[] b = new byte[] { 'N', 'O', 'T', 'E', 'p', 'a', 'd' };

		int transactionID = program.startTransaction("test");
		memory.setBytes(addr(0x0100b451), b);
		program.endTransaction(transactionID, true);

		selectCheckBox("Case Sensitive", true);

		setValueText("NOTEpad");
		pressSearchAllButton();

		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x0100b451));
	}

	@Test
	public void testSearchAllCaseSensitiveAlign8() throws Exception {
		// QueryResults should get displayed
		// test the marker stuff
		// create an set of ascii bytes to do this test

		setAlignment("8");

		selectCheckBox("Case Sensitive", true);

		setValueText("notepad");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x010013e0));
	}

	@Test
	public void testSearchSelection() throws Exception {

		makeSelection(tool, program, addr(0x01006c73), addr(0x01006f02));

		assertSearchSelectionSelected();

		selectCheckBox("Case Sensitive", false);

		setValueText("Info");

		performSearchTest(addrs(0x01006c6a), "Next");
	}

	@Test
	public void testSearchNonContiguousSelection() throws Exception {

		makeSelection(tool, program, range(0x01006c70, 0x01006c80), range(0x01006f2b, 0x01006f37));

		assertSearchSelectionSelected();

		selectCheckBox("Case Sensitive", false);

		setValueText("Info");

		List<Address> addrs = addrs(0x01006c6a, 0x01006f26);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testSearchBackward() throws Exception {

		goTo(tool, program, addr(0x1006f56));

		selectCheckBox("Case Sensitive", true);

		setValueText("Info");

		List<Address> addrs = addrs(0x01006f26, 0x01006c6a);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchBackwardInSelection() throws Exception {

		goTo(tool, program, addr(0x01006f02));

		makeSelection(tool, program, addr(0x01006c73), addr(0x01006f02));

		assertSearchSelectionSelected();

		selectCheckBox("Case Sensitive", false);

		setValueText("Info");

		List<Address> addrs = addrs(0x01006c6a);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchBackwardAlign4() throws Exception {

		goTo(tool, program, addr(0x1006f56));

		selectCheckBox("Case Sensitive", true);

		setAlignment("8");

		setValueText("notepad");

		List<Address> addrs = addrs(0x010013e0);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testSearchBackwardAlign4NoneFound() throws Exception {

		goTo(tool, program, addr(0x1006f56));

		selectCheckBox("Case Sensitive", true);

		setAlignment("8");

		setValueText("Info");

		pressSearchButton("Previous");
		assertEquals("Not Found", statusLabel.getText());
	}

	@Test
	public void testSearchEscapeSequences() throws Exception {
		selectCheckBox("Case Sensitive", true);
		selectCheckBox("Escape Sequences", true);

		setEncoding(StandardCharsets.US_ASCII);
		setValueText("\"Hello world!\"\\n\\t-new programmer");

		List<Address> addrs = addrs(0x0100189d, 0x0100198e);

		pressSearchButton("Next");
		assertEquals(addrs.get(0), cb.getCurrentLocation().getAddress());
		assertEquals("Found", statusLabel.getText());

		pressSearchButton("Next");
		assertEquals("Not Found", statusLabel.getText());

		setEncoding(StandardCharsets.UTF_16LE);
		pressSearchButton("Next");
		assertEquals("Found", statusLabel.getText());

		pressSearchButton("Next");
		assertEquals("Not Found", statusLabel.getText());
	}

//==================================================================================================
// Private Methods
//==================================================================================================

	@SuppressWarnings("unchecked")
	private void setEncoding(Charset encoding) throws Exception {
		JComboBox<Charset> encodingOptions =
			(JComboBox<Charset>) findComponentByName(pane, "Encoding Options", false);

		// Makes encoding UTF_16 in case encoding is UTF_16BE or UTF_16LE
		// BE and LE are not choices in the combo box.
		if (encoding == StandardCharsets.UTF_16BE || encoding == StandardCharsets.UTF_16LE) {
			encoding = StandardCharsets.UTF_16;
		}

		for (int i = 0; i < encodingOptions.getItemCount(); i++) {
			if (encodingOptions.getItemAt(i) == encoding) {
				int index = i;
				runSwing(() -> encodingOptions.setSelectedIndex(index));
				break;
			}
		}
	}
}
