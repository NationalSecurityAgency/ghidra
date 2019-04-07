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
package ghidra.app.cmd.data;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * 
 */
public class CreateDataBackgroundCmdTest extends AbstractGhidraHeadedIntegrationTest {

	private static final long UNDEFINED_AREA = 0x01001000;
	private static final long STRING_AREA1 = 0x01001100;
	private static final long STRING_AREA2 = 0x01001150;
	private static final long UNICODE_AREA1 = 0x01001300;
	private static final long UNICODE_AREA2 = 0x01001400;
	private static final long INSTRUCTION_AREA = 0x01001500;

	private TestEnv env;
	private Program program;
	private Listing listing;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram();
		listing = program.getListing();
		program.startTransaction("TEST");

	}

	private Program buildProgram() throws Exception {
		builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(UNDEFINED_AREA), 0x2000);
		builder.disassemble(Long.toHexString(INSTRUCTION_AREA), 10);

		builder.setBytes(Long.toHexString(STRING_AREA1), "abcd".getBytes());
		builder.setBytes(Long.toHexString(STRING_AREA1 + 6), "defg".getBytes());
		builder.setBytes(Long.toHexString(STRING_AREA2), "ijkl".getBytes());
		builder.setBytes(Long.toHexString(STRING_AREA1 + 6), "mnop".getBytes());

		builder.setBytes(Long.toHexString(UNICODE_AREA1), getUnicodeBytes("abcd"));
		builder.setBytes(Long.toHexString(UNICODE_AREA1 + 10), getUnicodeBytes("efgh"));
		builder.setBytes(Long.toHexString(UNICODE_AREA2), getUnicodeBytes("ijkl"));
		builder.setBytes(Long.toHexString(UNICODE_AREA1 + 10), getUnicodeBytes("mnop"));

		return builder.getProgram();
	}

	private byte[] getUnicodeBytes(String string) {
		byte[] bytes = string.getBytes();
		byte[] unicodeBytes = new byte[bytes.length * 2 + 2];
		for (int i = 0; i < bytes.length; i++) {
			unicodeBytes[2 * i] = bytes[i];
		}
		return unicodeBytes;
	}

	@After
	public void tearDown() {
		env.release(program);
		env.dispose();
	}

	private Address addr(long offset) {
		AddressFactory addressFactory = program.getAddressFactory();
		return addressFactory.getDefaultAddressSpace().getAddress(offset);
	}

	@Test
	public void testCreateDataOnInstruction() {
		// Should NOT be able to create data on top of an instruction
		Instruction instr1 = listing.getInstructionAfter(addr(0));
		Address addr = instr1.getMinAddress();
		AddressSet set = new AddressSet(addr, instr1.getMaxAddress());
		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new ByteDataType());
		cmd.applyTo(program);
		Instruction instr2 = listing.getInstructionAfter(addr(0));
		assertEquals(instr1, instr2);
		assertNull(listing.getDataAt(addr));
	}

	@Test
	public void testCreateDataOnMixedSelection() {

		Address addr1 = addr(UNDEFINED_AREA);
		Data d = listing.getDataAt(addr1);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		Address addr2 = addr(INSTRUCTION_AREA);
		Instruction instr = listing.getInstructionAt(addr2);
		assertNotNull(instr);

		AddressSet set = new AddressSet(addr1, addr(UNDEFINED_AREA + 8));
		set.addRange(addr2, addr(INSTRUCTION_AREA + 8));

		// Mixed selection should not change
		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new ByteDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr1);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		instr = listing.getInstructionAt(addr2);
		assertNotNull(instr);

	}

	@Test
	public void testCreateDataOnDefaultData() {

		Address addr = addr(UNDEFINED_AREA);
		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		AddressSet set = new AddressSet(addr, addr(UNDEFINED_AREA + 8));

		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new ByteDataType());
		cmd.applyTo(program);

		int cnt = 0;
		DataIterator iter = listing.getData(set, true);
		while (iter.hasNext()) {
			d = iter.next();
			assertNotNull(d);
			assertTrue(d.isDefined());
			assertTrue(d.getDataType() instanceof ByteDataType);
			assertEquals(1, d.getLength());
			++cnt;
		}
		assertEquals(9, cnt);

		d = listing.getDataAt(addr(UNDEFINED_AREA + 9));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateDataOnDataWithExpansion() {

		Address addr = addr(UNDEFINED_AREA);
		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		AddressSet set = new AddressSet(addr, addr(UNDEFINED_AREA + 8));

		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new ByteDataType());
		cmd.applyTo(program);

		// 9 Bytes become 5 Words and consumes next Default data byte
		cmd = new CreateDataBackgroundCmd(set, new WordDataType());
		cmd.applyTo(program);

		int cnt = 0;
		DataIterator iter = listing.getData(set, true);
		while (iter.hasNext()) {
			d = iter.next();
			assertNotNull(d);
			assertTrue(d.isDefined());
			assertTrue(d.getDataType() instanceof WordDataType);
			assertEquals(2, d.getLength());
			++cnt;
		}
		assertEquals(5, cnt);

		d = listing.getDataAt(addr(UNDEFINED_AREA + 10));
		assertNotNull(d);
		assertTrue(!d.isDefined());

	}

	@Test
	public void testCreateDataOnDataWithoutExpansion() {

		Address addr = addr(UNDEFINED_AREA);
		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		AddressSet set = new AddressSet(addr, addr(UNDEFINED_AREA + 8));

		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new ByteDataType());
		cmd.applyTo(program);

		CreateDataCmd cmd2 = new CreateDataCmd(addr(UNDEFINED_AREA + 9), new ByteDataType());
		cmd2.applyTo(program);

		// 9 Bytes become 4 Words and a Default data byte
		cmd = new CreateDataBackgroundCmd(set, new WordDataType());
		cmd.applyTo(program);

		int cnt = 0;
		DataIterator iter = listing.getDefinedData(set, true);
		while (iter.hasNext()) {
			d = iter.next();
			assertNotNull(d);
			assertTrue(d.isDefined());
			assertTrue(d.getDataType() instanceof WordDataType);
			assertEquals(2, d.getLength());
			++cnt;
		}
		assertEquals(4, cnt);

		d = listing.getDataAt(addr(UNDEFINED_AREA + 8));
		assertNotNull(d);
		assertTrue(!d.isDefined());

	}

	@Test
	public void testCreateString() {

		Address addr1 = addr(STRING_AREA1);
		Address addr2 = addr(STRING_AREA2);
		AddressSet set = new AddressSet(addr1, addr(STRING_AREA1 + 16));
		set.addRange(addr2, addr(STRING_AREA2 + 4));
		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new StringDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr1);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof StringDataType);
		assertEquals(17, d.getLength());

		d = listing.getDataAt(addr(STRING_AREA1 + 17));
		assertNotNull(d);
		assertTrue(!d.isDefined());

		d = listing.getDataAt(addr2);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof StringDataType);
		assertEquals(5, d.getLength());

		d = listing.getDataAt(addr(STRING_AREA2 + 5));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateTerminatedString() {

		Address addr1 = addr(STRING_AREA1);
		Address addr2 = addr(STRING_AREA2);
		// create selection that starts at first string bytes and ends halfway through second string bytes
		AddressSet set = new AddressSet(addr1, addr(STRING_AREA1 + 10));

		// add range that starts at second string area and does not include entire string
		set.addRange(addr2, addr(STRING_AREA2 + 2));

		CreateDataBackgroundCmd cmd =
			new CreateDataBackgroundCmd(set, new TerminatedStringDataType());
		cmd.applyTo(program);

		// TerminatedStringDataType is a DataTypeInstance factory for StringDataType
		Data d = listing.getDataAt(addr1);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof TerminatedStringDataType);
		assertEquals(5, d.getLength());// "abcd",00

		d = listing.getDataAt(addr1.add(6));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof TerminatedStringDataType);
		assertEquals(5, d.getLength());// "defg",00

		d = listing.getDataAt(addr1.add(15));
		assertNotNull(d);
		assertTrue(!d.isDefined());

		d = listing.getDataAt(addr2);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof TerminatedStringDataType);
		assertEquals(5, d.getLength());// "hijk",00

		d = listing.getDataAt(addr2.add(11));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateUnicodeString() {

		Address addr1 = addr(UNICODE_AREA1);
		Address addr2 = addr(UNICODE_AREA2);
		AddressSet set = new AddressSet(addr1, addr(UNICODE_AREA1 + 32));
		set.addRange(addr2, addr(UNICODE_AREA2 + 11));
		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new UnicodeDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr1);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof UnicodeDataType);
		assertEquals(33, d.getLength());

		d = listing.getDataAt(addr2);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof UnicodeDataType);
		assertEquals(12, d.getLength());

		d = listing.getDataAt(addr(UNICODE_AREA2 + 12));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateTerminatedUnicodeString() {

		Address addr1 = addr(UNICODE_AREA1);
		Address addr2 = addr(UNICODE_AREA2);
		AddressSet set = new AddressSet(addr1, addr(UNICODE_AREA1 + 15));
		set.addRange(addr2, addr(UNICODE_AREA2 + 5));
		CreateDataBackgroundCmd cmd =
			new CreateDataBackgroundCmd(set, new TerminatedUnicodeDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr1);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof TerminatedUnicodeDataType);
		assertEquals(10, d.getLength());

		d = listing.getDataAt(addr1.add(10));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof TerminatedUnicodeDataType);
		assertEquals(10, d.getLength());

		d = listing.getDataAt(addr1.add(25));
		assertNotNull(d);
		assertTrue(!d.isDefined());

		d = listing.getDataAt(addr2);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof TerminatedUnicodeDataType);
		assertEquals(10, d.getLength());

		d = listing.getDataAt(addr(UNICODE_AREA2 + 12));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreatePointersOnDefaultData() {

		Address addr = addr(UNDEFINED_AREA);
		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		AddressSet set = new AddressSet(addr, addr(UNDEFINED_AREA + 8));

		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new PointerDataType(), true);
		cmd.applyTo(program);

		int cnt = 0;
		DataIterator iter = listing.getDefinedData(set, true);
		while (iter.hasNext()) {
			d = iter.next();
			assertNotNull(d);
			assertTrue(d.isDefined());
			assertEquals(4, d.getLength());
			DataType dt = d.getDataType();
			assertTrue(d.getDataType() instanceof Pointer);
			Pointer pdt = (Pointer) dt;
			assertNull(pdt.getDataType());
			++cnt;
		}
		assertEquals(3, cnt);

		d = listing.getDataAt(addr(UNDEFINED_AREA + 12));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreatePointersOnDefinedData() {

		Address addr = addr(UNDEFINED_AREA);
		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		CreateDataCmd cmd = new CreateDataCmd(addr(UNDEFINED_AREA), new PointerDataType());
		cmd.applyTo(program);

		AddressSet set = new AddressSet(addr, addr(UNDEFINED_AREA + 8));

		CreateDataBackgroundCmd cmd2 = new CreateDataBackgroundCmd(set, new ByteDataType(), true);
		cmd2.applyTo(program);

		int cnt = 0;
		DataIterator iter = listing.getDefinedData(set, true);
		while (iter.hasNext()) {
			d = iter.next();
			assertNotNull(d);
			assertTrue(d.isDefined());
			assertEquals(4, d.getLength());
			DataType dt = d.getDataType();
			assertTrue(d.getDataType() instanceof Pointer);
			Pointer pdt = (Pointer) dt;
			assertTrue(pdt.getDataType() instanceof ByteDataType);
			++cnt;
		}
		assertEquals(3, cnt);

		d = listing.getDataAt(addr(UNDEFINED_AREA + 12));
		assertNotNull(d);
		assertTrue(!d.isDefined());

	}

	@Test
	public void testCreateDataOnDefaultPointers() throws Exception {

		Address addr = addr(UNDEFINED_AREA);
		AddressSet set = new AddressSet(addr, addr(UNDEFINED_AREA + 8));

		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new PointerDataType());
		cmd.applyTo(program);

		// Pointers Undefined* become Byte*
		cmd = new CreateDataBackgroundCmd(set, new ByteDataType(), true);
		cmd.applyTo(program);

		int cnt = 0;
		DataIterator iter = listing.getDefinedData(set, true);
		while (iter.hasNext()) {
			Data d = iter.next();
			assertNotNull(d);
			assertTrue(d.isDefined());
			assertEquals(4, d.getLength());
			DataType dt = d.getDataType();
			assertTrue(d.getDataType() instanceof Pointer);
			Pointer pdt = (Pointer) dt;
			assertTrue(pdt.getDataType() instanceof ByteDataType);
			++cnt;
		}
		assertEquals(3, cnt);

		Data d = listing.getDataAt(addr(UNDEFINED_AREA + 12));
		assertNotNull(d);
		assertTrue(!d.isDefined());

	}

	@Test
	public void testCreateDataOnNonDefaultPointer() {

		Address addr = addr(UNDEFINED_AREA);
		AddressSet set = new AddressSet(addr, addr(UNDEFINED_AREA + 8));

		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, new Pointer16DataType());
		cmd.applyTo(program);

		cmd = new CreateDataBackgroundCmd(set, new ByteDataType(), true);
		cmd.applyTo(program);

		int cnt = 0;
		DataIterator iter = listing.getDefinedData(set, true);
		while (iter.hasNext()) {
			Data d = iter.next();
			assertTrue(d.isDefined());
			assertEquals(2, d.getLength());
			DataType dt = d.getDataType();
			assertTrue(dt instanceof Pointer);
			assertEquals(2, dt.getLength());
			Pointer pdt = (Pointer) dt;
			assertTrue(pdt.getDataType() instanceof ByteDataType);
			++cnt;
		}
		assertEquals(5, cnt);

		// Byte* becomes Word*
		cmd = new CreateDataBackgroundCmd(set, new WordDataType(), true);
		cmd.applyTo(program);

		cnt = 0;
		iter = listing.getDefinedData(set, true);
		while (iter.hasNext()) {
			Data d = iter.next();
			assertTrue(d.isDefined());
			assertEquals(2, d.getLength());
			DataType dt = d.getDataType();
			assertTrue(dt instanceof Pointer);
			assertEquals(2, dt.getLength());
			Pointer pdt = (Pointer) dt;
			assertTrue(pdt.getDataType() instanceof WordDataType);
			++cnt;
		}
		assertEquals(5, cnt);

		Data d = listing.getDataAt(addr(UNDEFINED_AREA + 10));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

}
