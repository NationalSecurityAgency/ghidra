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
 * Tests for searching for decimal values in memory.
 */
public class MemSearchNumbersTest extends AbstractMemSearchTest {

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();
		setSearchFormat(SearchFormat.DECIMAL);
		setDecimalSize(4);
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

		//create some data

		builder.setBytes("0x1001004", "85 4f dc 77");
		builder.applyDataType("0x1001004", new Pointer32DataType(), 1);
		builder.createEncodedString("0x01001708", "Notepad", StandardCharsets.UTF_16BE, true);
		builder.createEncodedString("0x01001740", "something else", StandardCharsets.UTF_16BE,
			true);
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

		return builder.getProgram();
	}

	@Test
	public void testInvalidEntry() throws Exception {
		// enter non-numeric value
		setInput("z");
		assertEquals("", getInput());
	}

	@Test
	public void testValueTooLarge() throws Exception {
		setDecimalSize(1);

		setInput("262");
		assertEquals("", getInput());
	}

	@Test
	public void testNegativeValueEntered() throws Exception {
		// enter a negative value; the hexLabel should show the correct
		// byte sequence
		setSearchFormat(SearchFormat.DECIMAL);
		setDecimalSize(2);
		setInput("-1234");
		assertEquals("2e fb", getByteString());

		setDecimalSize(1);
		assertEquals("46 -5", getInput());

		setInput("-55");
		assertEquals("c9", getByteString());

		setDecimalSize(4);
		assertEquals("-55", getInput());
		assertEquals("c9 ff ff ff", getByteString());

		setDecimalSize(8);
		assertEquals("-55", getInput());
		assertEquals("c9 ff ff ff ff ff ff ff", getByteString());

		setSearchFormat(SearchFormat.FLOAT);
		assertEquals("00 00 5c c2", getByteString());

		setSearchFormat(SearchFormat.DOUBLE);
		assertEquals("00 00 00 00 00 80 4b c0", getByteString());
	}

	@Test
	public void testMulipleValuesEntered() throws Exception {
		// enter values separated by a space; values should be accepted
		setDecimalSize(1);
		setInput("12 34 56 78");
		assertEquals("0c 22 38 4e", getByteString());

		setDecimalSize(2);
		assertEquals("8716 20024", getInput());
		assertEquals("0c 22 38 4e", getByteString());

		setDecimalSize(4);
		assertEquals("1312301580", getInput());
		assertEquals("0c 22 38 4e", getByteString());

		setDecimalSize(8);
		assertEquals("1312301580", getInput());
		assertEquals("0c 22 38 4e 00 00 00 00", getByteString());

		setSearchFormat(SearchFormat.FLOAT);
		assertEquals("1312301580", getInput());
		assertEquals("44 70 9c 4e", getByteString());

		setSearchFormat(SearchFormat.DOUBLE);
		assertEquals("1312301580", getInput());
		assertEquals("00 00 00 83 08 8e d3 41", getByteString());

	}

	@Test
	public void testByteOrder() throws Exception {
		setBigEndian(true);
		setInput("12 34 56 78");
		setDecimalSize(1);
		setBigEndian(true);
		// should be unaffected			
		assertEquals("0c 22 38 4e", getByteString());

		setDecimalSize(2);
		assertEquals("3106 14414", getInput());
		assertEquals("0c 22 38 4e", getByteString());

		setDecimalSize(4);
		assertEquals("203569230", getInput());
		assertEquals("0c 22 38 4e", getByteString());

		setDecimalSize(8);
		assertEquals("203569230", getInput());
		assertEquals("00 00 00 00 0c 22 38 4e", getByteString());

		setSearchFormat(SearchFormat.FLOAT);
		assertEquals("203569230", getInput());
		assertEquals("4d 42 23 85", getByteString());

		setSearchFormat(SearchFormat.DOUBLE);
		assertEquals("203569230", getInput());
		assertEquals("41 a8 44 70 9c 00 00 00", getByteString());
	}

	@Test
	public void testFloatDoubleFormat() throws Exception {
		setSearchFormat(SearchFormat.FLOAT);

		setInput("12.345");
		assertEquals("12.345", getInput());
		assertEquals("1f 85 45 41", getByteString());

		setSearchFormat(SearchFormat.DOUBLE);
		assertEquals("71 3d 0a d7 a3 b0 28 40", getByteString());
	}

	@Test
	public void testSearchByte() throws Exception {
		goTo(program.getMinAddress());

		List<Address> addrs = addrs(0x1002d3e, 0x1002d5b, 0x1004123, 0x1004203, 0x100424a);

		setDecimalSize(1);
		setInput("8");

		performSearchNext(addrs);
	}

	@Test
	public void testSearchByteBackward() throws Exception {

		goTo(0x01002d6d);

		setDecimalSize(1);

		setInput("8");

		List<Address> addrs = addrs(0x1002d5b, 0x1002d3e);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchWord() throws Exception {

		goTo(program.getMinAddress());

		setDecimalSize(2);

		setInput("20");

		List<Address> addrs = addrs(0x1002cf8, 0x1002d6b);

		performSearchNext(addrs);
	}

	@Test
	public void testSearchWordBackward() throws Exception {

		goTo(0x01002d6e);

		setDecimalSize(2);

		setInput("20");

		List<Address> addrs = addrs(0x1002d6b, 0x1002cf8);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchDWord() throws Exception {
		goTo(program.getMinAddress());

		setDecimalSize(4);

		setInput("100");

		List<Address> addrs = addrs(0x1001708, 0x1004100, 0x1004135);

		performSearchNext(addrs);
	}

	@Test
	public void testSearchDWordBackward() throws Exception {
		goTo(0x01005000);

		setDecimalSize(4);

		setInput("100");

		List<Address> addrs = addrs(0x1004135, 0x1004100, 0x1001708);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchQWord() throws Exception {
		goTo(program.getMinAddress());

		setDecimalSize(8);

		setInput("29555302058557541");

		performSearchNext(addrs(0x1004270));
	}

	@Test
	public void testSearchQWordBackward() throws Exception {

		goTo(program.getMaxAddress());

		setDecimalSize(8);

		setInput("29555302058557541");

		performSearchPrevious(addrs(0x1004270));
	}

	@Test
	public void testSearchFloat() throws Exception {

		goTo(program.getMinAddress());

		setSearchFormat(SearchFormat.FLOAT);

		setInput("7.4027124e-34");

		List<Address> addrs = addrs(0x1004120, 0x1004200, 0x1004247);

		performSearchNext(addrs);
	}

	@Test
	public void testSearchFloatBackward() throws Exception {

		goTo(0x01005000);

		setSearchFormat(SearchFormat.FLOAT);

		setInput("7.4027124e-34");

		List<Address> addrs = addrs(0x1004247, 0x1004200, 0x1004120);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchFloatBackwardAlign8() throws Exception {

		goTo(program.getMaxAddress());

		setAlignment(8);
		setSearchFormat(SearchFormat.FLOAT);

		setInput("7.4027124e-34");

		List<Address> addrs = addrs(0x1004200, 0x1004120);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchDouble() throws Exception {

		goTo(program.getMinAddress());

		setSearchFormat(SearchFormat.DOUBLE);

		setInput("1.588386874245921e-307");

		List<Address> addrs = addrs(0x1004200);

		performSearchNext(addrs);
	}

	@Test
	public void testSearchDoubleBackward() throws Exception {

		goTo(program.getMaxAddress());

		setSearchFormat(SearchFormat.DOUBLE);

		setInput("1.588386874245921e-307");

		List<Address> addrs = addrs(0x1004200);

		performSearchPrevious(addrs);
	}

	@Test
	public void testSearchAllByte() throws Exception {

		setDecimalSize(1);

		setInput("8");
		performSearchAll();
		waitForSearch(5);

		List<Address> addrs = addrs(0x1002d40, 0x1002d5d, 0x1004123, 0x1004203, 0x100424a);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllWord() throws Exception {

		setDecimalSize(2);

		setInput("20");

		performSearchAll();
		waitForSearch(2);

		List<Address> addrs = addrs(0x1002cfa, 0x1002d6c);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllWordAlign4() throws Exception {
		setAlignment(4);

		setDecimalSize(2);

		setInput("20");

		performSearchAll();
		waitForSearch(1);

		checkMarkerSet(addrs(0x1002d6c));
	}

	@Test
	public void testSearchAllDWord() throws Exception {

		setDecimalSize(4);

		setInput("100");
		performSearchAll();
		waitForSearch(3);

		List<Address> addrs = addrs(0x1001715, 0x1004100, 0x1004135);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllQWord() throws Exception {

		setDecimalSize(8);

		setInput("29555302058557541");
		performSearchAll();
		waitForSearch(1);

		checkMarkerSet(addrs(0x1004270));
	}

	@Test
	public void testSearchAllFloat() throws Exception {

		setSearchFormat(SearchFormat.FLOAT);

		setInput("7.4027124e-34");

		performSearchAll();
		waitForSearch(3);

		List<Address> addrs = addrs(0x1004120, 0x1004200, 0x1004247);

		checkMarkerSet(addrs);
	}

	@Test
	public void testSearchAllDouble() throws Exception {

		setSearchFormat(SearchFormat.DOUBLE);

		setInput("1.588386874245921e-307");

		performSearchAll();
		waitForSearch(1);

		checkMarkerSet(addrs(0x1004200));
	}
}
