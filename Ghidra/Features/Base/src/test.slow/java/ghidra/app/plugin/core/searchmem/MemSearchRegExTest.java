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

import org.junit.Before;
import org.junit.Test;

import docking.widgets.fieldpanel.support.Highlight;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.*;

/**
 * Tests for searching memory for hex reg expression.
 */
public class MemSearchRegExTest extends AbstractMemSearchTest {

	public MemSearchRegExTest() {
		super();
	}

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		selectRadioButton("Regular Expression");
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
			"55 8b ec 83 7d 14 00 56 8b 35 e0 10 00 01 57 74 09 ff 75 14 ff d6 8b f8 eb 02 " +
				"33 ff ff 75 10 ff d6 03 c7 8d 44 00 02 50 6a 40 ff 15 dc 10 00 01 8b f0 85 f6 " +
				"74 27 56 ff 75 14 ff 75 10 e8 5c ff ff ff ff 75 18 ff 75 0c 56 ff 75 08 ff 15 " +
				"04 12 00 01 56 8b f8 ff 15 c0 10 00 01 eb 14 ff 75 18 ff 75 0c ff 75 10 ff 75 " +
				"08 ff 15 04 12 00 01 8b f8 8b c7 5f 5e 5d c2 14");
		builder.disassemble("0x01002cf5", 0x121, true);
		builder.createFunction("0x01002cf5");

		//create and disassemble some code not in a function
		builder.setBytes("0x010029bd", "ff 15 c4 10 00 01 8b d8 33 f6 3b de 74 06");
		builder.disassemble("0x10029bd", 0xe, true);

		builder.setBytes("0x10035f5", "f3 a5 99 b9 30 fd ff ff ff 75 08 f7 f9");
		builder.disassemble("0x10035f5", 0xd, true);

		builder.setBytes("0x10040d9", "8b 0d 58 80 00 01");
		builder.disassemble("0x10040d9", 0x6, true);

		builder.setBytes("0x010029cb", "6a 01");
		builder.setBytes("0x010029cd", "6a 01");
		builder.disassemble("0x010029cb", 0x4, true);

		builder.setBytes("0x01002826", "6a 01");
		builder.disassemble("0x01002826", 0x2, true);

		//create some data

		builder.setBytes("0x1001004", "85 4f dc 77");
		builder.applyDataType("0x1001004", new Pointer32DataType(), 1);
		builder.setBytes("0x1001040", "e3 b3 f4 77");
		builder.applyDataType("0x1001004", new Pointer32DataType(), 1);
		builder.setBytes("0x1001044", "3d b6 f4 77");
		builder.applyDataType("0x1001004", new Pointer32DataType(), 1);

		builder.createEncodedString("0x01001708", "Notepad", StandardCharsets.US_ASCII, false);
		builder.createEncodedString("0x01001740", "something else", StandardCharsets.US_ASCII,
			false);
		builder.createEncodedString("0x010013cc", "notepad.exe", StandardCharsets.US_ASCII, false);

		//create some undefined data
		builder.setBytes("0x1001500", "4e 00 65 00 77 00");
		builder.setBytes("0x1003000", "55 00");

		builder.setBytes("0x1004100", "64 00 00 00");//100 dec
		builder.setBytes("0x1004120", "50 ff 75 08");//7.4027124e-34 float
		builder.setBytes("0x1004135", "64 00 00 00");//100 dec
		builder.setBytes("0x1004200", "50 ff 75 08 e8 8d 3c 00");//1.588386874245921e-307
		builder.setBytes("0x1004247", "50 ff 75 08");//7.4027124e-34 float
		builder.setBytes("0x1004270", "65 00 6e 00 64 00 69 00");//29555302058557541 qword

		builder.createEncodedString("0x1004300", "end", StandardCharsets.US_ASCII, false);

		return builder.getProgram();
	}

	@Test
	public void testRegularExpressionSearch() throws Exception {

		// NOTE: the following regular expression searches for 0x8b followed
		// by 0-10 occurrences of any character, followed by 0x56.
		setValueText("\\x8b.{0,10}\\x56");

		assertEquals("", hexLabel.getText());

		List<Address> addrs = addrs(0x01002cf6, 0x01002d25);

		performSearchTest(addrs, "Next");
	}

	@Test
	public void testCodeUnitScope_Instructions() throws Exception {
		//
		// Turn on Instructions scope and make sure only that scope yields matches
		//
		goTo(0x1002cf5); // 'ghidra' function address

		selectCheckBox("Instructions", true);
		selectCheckBox("Defined Data", false);
		selectCheckBox("Undefined Data", false);

		setValueText("\\x55");
		pressSearchButton("Next");
		Address expectedSearchAddressHit = addr(0x1002cf5);
		assertEquals(
			"Did not find a hit at the next matching Instruction when we are searching Instructions",
			expectedSearchAddressHit, cb.getCurrentLocation().getAddress());

		// Turn off Instructions scope and make sure we have no match at the expected address
		goTo(0x1002cf5); // 'ghidra' function address

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
		goTo(0x1001004);// start of program; pointer data

		selectCheckBox("Instructions", false);
		selectCheckBox("Defined Data", true);
		selectCheckBox("Undefined Data", false);

		setValueText("\\x85");
		pressSearchButton("Next");
		Address expectedSearchAddressHit = addr(0x1001004);
		assertEquals(
			"Did not find a hit at the next matching Defined Data when we are searching Defined Data",
			expectedSearchAddressHit, cb.getCurrentLocation().getAddress());

		// Turn off Defined Data scope and make sure we have no match at the expected address
		goTo(0x1001004);// start of program; pointer data

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
	}

	@Test
	public void testCodeUnitScope_UndefinedData() throws Exception {
		//
		// Turn on Undefined Data scope and make sure only that scope yields matches
		//
		goTo(0x1004270);

		selectCheckBox("Instructions", false);
		selectCheckBox("Defined Data", false);
		selectCheckBox("Undefined Data", true);

		setValueText("\\x65");
		pressSearchButton("Next");
		Address expectedSearchAddressHit = addr(0x1004270);
		assertEquals(
			"Did not find a hit at the next matching Undefined Data when we are searching Undefined Data",
			expectedSearchAddressHit, cb.getCurrentLocation().getAddress());

		// Turn off Undefined Data scope and make sure we have no match at the expected address
		goTo(0x1004270);

		selectCheckBox("Instructions", true);
		selectCheckBox("Defined Data", true);
		selectCheckBox("Undefined Data", false);
		pressSearchButton("Next");
		assertTrue(
			"Found a search match at an Undefined Data, even though no Undefined Data should be searched",
			!expectedSearchAddressHit.equals(currentAddress()));

		CodeUnit codeUnit = currentCodeUnit();
		assertTrue("Did not find a data match when searching undefined data is disabled",
			codeUnit instanceof Data);
	}

	@Test
	public void testRegularExpressionSearchAlign4() throws Exception {

		// NOTE: the following regular expression searches for 0x56 followed
		// by 0-10 occurrences of any character, followed by 0x10.
		setValueText("\\x56.{0,10}\\x10");

		assertEquals("", hexLabel.getText());

		setAlignment("4");

		performSearchTest(addrs(0x01002cfc), "Next");
	}

	@Test
	public void testRegularExpressionSearchAll() throws Exception {

		// Note: the following regular expression searches for 0x56 followed
		// 		 by 0-10 occurrences of any character, followed by 0x10.
		setValueText("\\x56.{0,10}\\x10");

		assertEquals("", hexLabel.getText());

		List<Address> addrs = addrs(0x01002cfc, 0x01002d2b, 0x01002d47);

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 3);

		checkMarkerSet(addrs);
	}

	@Test
	public void testRegularExpressionSearchAll2() throws Exception {

		// NOTE: the following regular expression searches for 0xf4 followed
		// by 0x77.
		setValueText("\\xf4\\x77");
		assertEquals("", hexLabel.getText());

		List<Address> addrs = addrs(0x01001042, 0x01001046);

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 2);

		checkMarkerSet(addrs);
	}

	@Test
	public void testRegularExpressionSearchAllAlign4() throws Exception {

		// NOTE: the following regular expression searches for 0x56 followed
		// by 0-10 occurrences of any character, followed by 0x10.
		setValueText("\\x56.{0,10}\\x10");

		assertEquals("", hexLabel.getText());

		setAlignment("4");

		pressSearchAllButton();
		waitForSearch("Search Memory - ", 1);

		checkMarkerSet(addrs(0x01002cfc));
	}

	@Test
	public void testRegExpHighlight() throws Exception {
		setValueText("\\x6a\\x01");
		pressSearchAllButton();

		waitForSearch("Search Memory - ", 3);

		Highlight[] h = getByteHighlights(addr(0x10029cb), "6a 01");
		assertEquals(1, h.length);
		assertEquals(0, h[0].getStart());
		assertEquals(4, h[0].getEnd());
	}

	@Test
	public void testRegExpHighlight2() throws Exception {
		setValueText("\\x6a\\x01");
		pressSearchAllButton();

		waitForSearch("Search Memory - ", 3);

		Highlight[] h = getByteHighlights(addr(0x1002827), "6a 01");
		assertEquals(1, h.length);
	}
}
