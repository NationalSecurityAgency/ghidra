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

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import ghidra.features.base.memsearch.format.SearchFormat;
import ghidra.features.base.memsearch.scan.Scanner;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.Program;

/**
 * Tests for the search results "scan" feature
 */
public class MemSearchScanTest extends AbstractMemSearchTest {

	public MemSearchScanTest() {
		super();
	}

	@Before
	@Override
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
	public void testScanEquals() throws Exception {

		setInput("100");
		performSearchAll();
		waitForSearch(3);

		List<Address> addrs = addrs(0x1001715, 0x1004100, 0x1004135);
		checkMarkerSet(addrs);

		setValue(addr(0x1004100), 101);

		// only keep values that don't change
		scan(Scanner.EQUALS);
		waitForSearch(2);

		// the address we changed should now be removed from the results
		addrs = addrs(0x1001715, 0x1004135);
		checkMarkerSet(addrs);
	}

	@Test
	public void testScanNotEquals() throws Exception {

		setInput("100");
		performSearchAll();
		waitForSearch(3);

		List<Address> addrs = addrs(0x1001715, 0x1004100, 0x1004135);
		checkMarkerSet(addrs);

		setValue(addr(0x1004100), 101);

		// only keep values that don't change
		scan(Scanner.NOT_EQUALS);
		waitForSearch(1);

		// the address we changed should now be removed from the results
		addrs = addrs(0x1004100);
		checkMarkerSet(addrs);
	}

	@Test
	public void testScanIncrement() throws Exception {

		setInput("100");
		performSearchAll();
		waitForSearch(3);

		List<Address> addrs = addrs(0x1001715, 0x1004100, 0x1004135);
		checkMarkerSet(addrs);

		setValue(addr(0x1004100), 101);
		setValue(addr(0x1004135), 99);

		// only keep values that don't change
		scan(Scanner.INCREASED);
		waitForSearch(1);

		// the address we changed should now be removed from the results
		addrs = addrs(0x1004100);
		checkMarkerSet(addrs);
	}

	@Test
	public void testScanDecrement() throws Exception {

		setInput("100");
		performSearchAll();
		waitForSearch(3);

		List<Address> addrs = addrs(0x1001715, 0x1004100, 0x1004135);
		checkMarkerSet(addrs);

		setValue(addr(0x1004100), 101);
		setValue(addr(0x1004135), 99);

		// only keep values that don't change
		scan(Scanner.DECREASED);
		waitForSearch(1);

		// the address we changed should now be removed from the results
		addrs = addrs(0x1004135);
		checkMarkerSet(addrs);
	}

	private void scan(Scanner scanner) {
		runSwing(() -> searchProvider.scan(scanner));
	}

	private void setValue(Address address, int value) throws Exception {
		byte[] bytes = getBytes(value);

		int transactionID = program.startTransaction("test");
		memory.setBytes(address, bytes);
		program.endTransaction(transactionID, true);
	}

	private byte[] getBytes(int value) {
		byte[] bytes = new byte[4];
		bytes[0] = (byte) (value & 0xff);
		bytes[1] = (byte) ((value >> 8) & 0xff);
		bytes[2] = (byte) ((value >> 16) & 0xff);
		bytes[3] = (byte) ((value >> 24) & 0xff);
		return bytes;
	}
}
