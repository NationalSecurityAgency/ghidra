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
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;

import javax.swing.DefaultComboBoxModel;

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.app.events.ProgramLocationPluginEvent;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.*;
import ghidra.program.util.ProgramLocation;

/**
 * Tests for the Binary format in searching memory.
 */
public class MemSearchBinaryTest extends AbstractMemSearchTest {

	public MemSearchBinaryTest() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		selectRadioButton("Binary");
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
		builder.createEncodedString("0x01001740", "something else", StandardCharsets.UTF_16BE, true);
		builder.createEncodedString("0x010013cc", "notepad.exe", StandardCharsets.US_ASCII, true);

		//create some undefined data
		builder.setBytes("0x1001500", "4e 00 65 00 77 00");
		builder.setBytes("0x1003000", "55 00");

		return builder.getProgram();
	}

	@Test
	public void testBinaryInvalidEntry() {
		// enter a non-binary digit; the search field should not accept it
		setValueText("2");

		assertEquals("", valueField.getText());
	}

	@Test
	public void testBinaryMoreThan8Chars() throws Exception {
		// try entering more than 8 binary digits (no spaces); the dialog 
		// should not accept the 9th digit.
		myTypeText("010101010");
		assertEquals("01010101", valueField.getText());
	}

	@Test
	public void testBinaryEnterSpaces() {
		// verify that more than 8 digits are allowed if spaces are entered
		myTypeText("01110000 01110000");
		assertEquals("01110000 01110000", valueField.getText());
	}

	@Test
	public void testBinarySearch() throws Exception {

		goTo(0x01001000);

		setValueText("00010100 11111111");

		pressButtonByText(pane, "Next");

		waitForSearchTask();

		Address currentAddress = currentAddress();
		CodeUnit cu = codeUnitContaining(addr(0x01002d08));
		assertEquals(cu.getMinAddress(), currentAddress);
		assertEquals("Found", statusLabel.getText());
	}

	@Test
	public void testBinarySearchNext() throws Exception {

		goTo(0x01001000);

		setValueText("01110101");

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

		for (int i = 0; i < addrs.size(); i++) {
			Address start = addrs.get(i);
			pressSearchButton("Next");
			CodeUnit cu = listing.getCodeUnitContaining(start);
			assertEquals(cu.getMinAddress(), cb.getCurrentLocation().getAddress());
			assertEquals("Found", statusLabel.getText());
		}
		pressSearchButton("Next");
		assertEquals("Not Found", statusLabel.getText());

	}

	@Test
	public void testBinarySearchNextAlign4() throws Exception {
		// hit the enter key in the values field;
		// should go to next match found

		Address addr = addr(0x01001000);
		tool.firePluginEvent(new ProgramLocationPluginEvent("test", new ProgramLocation(program,
			addr), program));
		waitForPostedSwingRunnables();

		// enter a Binary value and hit the search button
		setValueText("01110101");

		setAlignment("4");

		//the bytes are at the right alignment value but the code units are not
		List<Address> addrs = addrs(0x01002d2f, 0x01002d37, 0x01002d5b);

		for (int i = 0; i < addrs.size(); i++) {
			Address start = addrs.get(i);
			pressSearchButton("Next");
			CodeUnit cu = listing.getCodeUnitContaining(start);
			assertEquals(cu.getMinAddress(), cb.getCurrentLocation().getAddress());
			assertEquals("Found", statusLabel.getText());
		}
		pressSearchButton("Next");
		assertEquals("Not Found", statusLabel.getText());
	}

	@Test
	public void testBinaryContiguousSelection() throws Exception {

		goTo(0x01001070);

		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d));

		assertSearchSelectionSelected();

		setValueText("11110110");

		// the bytes are at the right alignment value but the code units are not
		performSearchTest(addrs(0x01002d27), "Next");
	}

	@Test
	public void testBinaryNonContiguousSelection() throws Exception {

		makeSelection(tool, program, range(0x01002cf5, 0x01002d0e), range(0x01002d47, 0x01002d51));

		assertSearchSelectionSelected();

		setValueText("01010110");

		// the bytes are at the right alignment value but the code units are not
		List<Address> addrs = addrs(0x01002cfc, 0x01002d47);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testBinarySelectionNotOn() throws Exception {

		goTo(0x01002cf5);

		// make a selection but turn off the Selection checkbox;
		// the search should go outside the selection

		makeSelection(tool, program, range(0x01002cf5, 0x01002d0d), range(0x01002d37, 0x01002d47));

		// select Search All option to turn off searching only in selection
		assertButtonState("Search All", true, false);

		// Note: this is 'Search All' for the search type, not the JButton on the button panel
		pressButtonByText(pane, "Search All");

		setValueText("11110110");

		pressButtonByText(pane, "Next");
		waitForSearchTask();

		Address resultAddr = addr(0x1002d27);

		// verify the code browser goes to resulting address
		CodeUnit cu = codeUnitContaining(resultAddr);
		assertEquals(cu.getMinAddress(), currentAddress());
		assertEquals("Found", statusLabel.getText());
	}

	@Test
	public void testBinarySearchAll() throws Exception {
		// QueryResults should get displayed
		// test the marker stuff		
		setValueText("11110110");
		
		pressSearchAllButton();
		
		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x1002d28));
	}

	@Test
	public void testBinarySearchAll2() throws Exception {
		// enter search string for multiple byte match
		// ff d6
		setValueText("11111111 11010110");

		pressSearchAllButton();

		waitForSearch("Search Memory - ", 2);

		List<Address> addrs = addrs(0x1002d09, 0x1002d14);

		checkMarkerSet(addrs);
	}

	@Test
	public void testBinarySearchAllAlign4() throws Exception {
		// QueryResults should get displayed
		// test the marker stuff
		setValueText("11111111 01110101");

		setAlignment("4");

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 2);

		List<Address> startList = addrs(0x1002d2c, 0x1002d58);

		checkMarkerSet(startList);
	}

	@Test
	public void testBinaryHighlight() throws Exception {

		setValueText("00010000 00000000 00000001");

		pressSearchAllButton();

		waitForSearch("Search Memory - ", 3);

		Highlight[] h = getByteHighlights(addr(0x1002cfd), "8b 35 e0 10 00 01");
		assertEquals(1, h.length);
		assertEquals(9, h[0].getStart());
		assertEquals(16, h[0].getEnd());
	}

	@Test
	public void testBinarySearchSelection() throws Exception {

		goTo(0x01001074);

		makeSelection(tool, program, range(0x01002cf5, 0x01002d6d));

		assertSearchSelectionSelected();

		setValueText("11110110");

		performSearchTest(addrs(0x01002d27), "Next");
	}

	@Test
	public void testBinarySearchPreviousNotFound() throws Exception {

		goTo(0x01001000);

		setValueText("00000111");
		pressButtonByText(pane, "Previous");
		waitForSearchTask();

		assertEquals("Not Found", statusLabel.getText());
	}

	@Test
	public void testCodeUnitScope_Instructions() throws Exception {
		//
		// Turn on Instructions scope and make sure only that scope yields matches
		//
		goTo(0x1002cf5);

		selectCheckBox("Instructions", true);
		selectCheckBox("Defined Data", false);
		selectCheckBox("Undefined Data", false);

		setValueText("01010101");
		pressSearchButton("Next");

		Address expectedSearchAddressHit = addr(0x1002cf5);
		assertEquals(
			"Did not find a hit at the next matching Instruction when we are searching Instructions",
			expectedSearchAddressHit, currentAddress());

		// Turn off Instructions scope and make sure we have no match at the expected address
		goTo(0x1002cf5);

		selectCheckBox("Instructions", false);
		selectCheckBox("Defined Data", true);
		selectCheckBox("Undefined Data", true);
		pressSearchButton("Next");

		assertTrue(
			"Found a search match at an Instruction, even though no Instruction should be searched",
			!expectedSearchAddressHit.equals(currentAddress()));

		CodeUnit codeUnit = currentCodeUnit();
		assertTrue("Did not find a data match when searching instructions is disabled",
			codeUnit instanceof Data);
	}

	@Test
	public void testCodeUnitScope_DefinedData() throws Exception {
		//
		// Turn on Defined Data scope and make sure only that scope yields matches
		//
		goTo(0x1001000);// start of program; pointer data

		selectCheckBox("Instructions", false);
		selectCheckBox("Defined Data", true);
		selectCheckBox("Undefined Data", false);

		setValueText("10000101");
		pressSearchButton("Next");
		Address expectedSearchAddressHit = addr(0x1001004);

		assertEquals(
			"Did not find a hit at the next matching Defined Data when we are searching Defined Data",
			expectedSearchAddressHit, currentAddress());

		// Turn off Defined Data scope and make sure we have no match at the expected address
		goTo(0x1001000);// start of program; pointer data

		selectCheckBox("Instructions", true);
		selectCheckBox("Defined Data", false);
		selectCheckBox("Undefined Data", true);
		pressSearchButton("Next");
		assertTrue(
			"Found a search match at a Defined Data, even though no Defined Data should be searched",
			!expectedSearchAddressHit.equals(currentAddress()));

		CodeUnit codeUnit = currentCodeUnit();
		assertTrue("Did not find a instruction match when searching defined data is disabled",
			codeUnit instanceof Instruction);

		// try backwards
		goTo(0x1002000);
		assertEquals(
			"Did not find a hit at the next matching Defined Data when we are searching Defined Data",
			addr(0x1002000), currentAddress());

		selectCheckBox("Instructions", false);
		selectCheckBox("Defined Data", true);
		selectCheckBox("Undefined Data", false);

		pressSearchButton("Previous");
		expectedSearchAddressHit = addr(0x01001004);
		assertEquals(
			"Did not find a hit at the previous matching Defined Data when we are searching Defined Data",
			expectedSearchAddressHit, currentAddress());
	}

	@Test
	public void testCodeUnitScope_UndefinedData() throws Exception {
		//
		// Turn on Undefined Data scope and make sure only that scope yields matches
		//
		goTo(0x1001000);
		
		selectCheckBox("Instructions", false);
		selectCheckBox("Defined Data", false);
		selectCheckBox("Undefined Data", true);

		setValueText("01100101");
		pressSearchButton("Next");
		
		Address expectedSearchAddressHit = addr(0x1001502);
		assertEquals(
			"Did not find a hit at the next matching Undefined Data when we are searching Undefined Data",
			expectedSearchAddressHit, currentAddress());

		// Turn off Undefined Data scope and make sure we have no match at the expected address
		goTo(0x1001000);

		selectCheckBox("Instructions", true);
		selectCheckBox("Defined Data", true);
		selectCheckBox("Undefined Data", false);
		pressSearchButton("Next");
		assertTrue(
			"Found a search match at an Undefined Data, even though no Undefined Data should be searched",
			!expectedSearchAddressHit.equals(currentAddress()));

		CodeUnit codeUnit = listing.getCodeUnitAt(cb.getCurrentLocation().getAddress());
		assertTrue("Did not find a instruction match when searching defined data is disabled",
			codeUnit instanceof Data);

		// try backwards

		goTo(0x1003000);

		selectCheckBox("Instructions", false);
		selectCheckBox("Defined Data", false);
		selectCheckBox("Undefined Data", true);

		pressSearchButton("Previous");
		expectedSearchAddressHit = addr(0x1001502);
		assertEquals(
			"Did not find a hit at the previous matching Undefined Data when we are searching Undefined Data",
			expectedSearchAddressHit, currentAddress());
	}

	@Test
	public void testBinarySearchPrevious() throws Exception {
		// enter search string for multiple byte match
		// ff 15

		// start at 01002d6b
		goTo(0x01002d6b);

		setValueText("11111111 00010101");

		List<Address> addrs = addrs(0x01002d5e, 0x01002d4a, 0x01002d41, 0x01002d1f);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testBinarySearchPreviousAlign4() throws Exception {
		// enter search string for multiple byte match
		// ff 15

		goTo(0x1002d6d);

		setValueText("11111111 01110101");

		setAlignment("4");

		List<Address> addrs = addrs(0x1002d58, 0x1002d2c);

		performSearchTest(addrs, "Previous");
	}

	@Test
	public void testBinaryWildcardSearch() throws Exception {
		goTo(0x01001000);

		setValueText("010101xx 10001011");

		List<Address> addrs = addrs(0x01002cf5, 0x01002cfc, 0x01002d47);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testBinaryWildcardSearchAll() throws Exception {

		setValueText("10001011 1111xxxx");
		pressSearchAllButton();
		waitForSearch("Search Memory - ", 4);

		List<Address> addrs = addrs(0x1002d0b, 0x1002d25, 0x1002d48, 0x1002d64);

		checkMarkerSet(addrs);
	}

	@SuppressWarnings("rawtypes")
	@Test
	public void testValueComboBox() throws Exception {
		setValueText("1x1xx1x1");

		pressSearchButton("Next");
		setValueText("");

		setValueText("00000");
		pressSearchButton("Next");
		setValueText("");

		setValueText("111");
		pressSearchButton("Next");
		setValueText("");

		// the combo box should list most recently entered values
		DefaultComboBoxModel cbModel = (DefaultComboBoxModel) valueComboBox.getModel();
		assertEquals(3, cbModel.getSize());
		assertEquals("111", cbModel.getElementAt(0));
		assertEquals("00000", cbModel.getElementAt(1));
		assertEquals("1x1xx1x1", cbModel.getElementAt(2));
	}

}
