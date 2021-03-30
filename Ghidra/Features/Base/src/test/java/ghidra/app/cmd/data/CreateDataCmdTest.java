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

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/**
 * 
 */
public class CreateDataCmdTest extends AbstractGenericTest {

	private static final long UNDEFINED_AREA = 0x0150;
	private static final long STRING_AREA = 0x01000;
	private static final long UNICODE_AREA = 0x01100;

	private Program program;
	private Listing listing;
	private ProgramBuilder builder;

	@Before
	public void setUp() throws Exception {
		program = buildProgram();
		listing = program.getListing();
		program.startTransaction("TEST");
	}

	private Program buildProgram() throws Exception {
		builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x100), 0x2000);
		builder.disassemble("0x110", 10);
		builder.setBytes(Long.toHexString(STRING_AREA), "abcd".getBytes());

		builder.setBytes(Long.toHexString(UNICODE_AREA), getUnicodeBytes("abcd"));
		return builder.getProgram();
	}

	private Address addr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	private byte[] getUnicodeBytes(String string) {
		byte[] bytes = string.getBytes();
		byte[] unicodeBytes = new byte[bytes.length * 2 + 2];
		for (int i = 0; i < bytes.length; i++) {
			unicodeBytes[2 * i] = bytes[i];
		}
		return unicodeBytes;
	}

	@Test
	public void testCreateDataOnInstructionFailure() {
		// Should NOT be able to create data on top of an instruction
		Instruction instr1 = listing.getInstructionAfter(addr(0));
		Address addr = instr1.getMinAddress();
		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		cmd.applyTo(program);
		Instruction instr2 = listing.getInstructionAfter(addr(0));
		assertEquals(instr1, instr2);
		assertNull(listing.getDataAt(addr));
	}

	@Test
	public void testCreateDataOnDefaultData() {

		Address addr = addr(UNDEFINED_AREA);
		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);
		assertEquals(1, d.getLength());

		d = listing.getDataAt(addr(UNDEFINED_AREA + 1));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateDataOnSmallerData() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);

		// Byte becomes Word and consumes next Default data byte
		cmd = new CreateDataCmd(addr, new WordDataType(), false, ClearDataMode.CLEAR_SINGLE_DATA);
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof WordDataType);
		assertEquals(2, d.getLength());

		d = listing.getDataAt(addr(UNDEFINED_AREA + 1));
		assertNull(d);

		d = listing.getDataAt(addr(UNDEFINED_AREA + 2));
		assertNotNull(d);
		assertTrue(!d.isDefined());

	}

	@Test
	public void testCreateDataOnBiggerData() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new WordDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof WordDataType);

		// Word becomes Byte immediately followed by Default data
		cmd = new CreateDataCmd(addr, new ByteDataType(), false, ClearDataMode.CLEAR_SINGLE_DATA);
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);
		assertEquals(1, d.getLength());

		d = listing.getDataAt(addr(UNDEFINED_AREA + 1));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateDataOnOffcutData() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new WordDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof WordDataType);

		Address addr2 = addr.add(1);

		// check failure case (force not enabled)
		cmd = new CreateDataCmd(addr2, new ByteDataType());
		assertTrue(!cmd.applyTo(program));

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof WordDataType);

		// check success case with force enabled
		cmd = new CreateDataCmd(addr2, true, true, new ByteDataType());
		assertTrue(cmd.applyTo(program));

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());

		d = listing.getDataAt(addr2);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);
		assertEquals(1, d.getLength());

		d = listing.getDataAt(addr(UNDEFINED_AREA + 2));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateDataNoSpaceFailure() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		cmd.applyTo(program);

		cmd = new CreateDataCmd(addr(UNDEFINED_AREA + 1), new ByteDataType());
		cmd.applyTo(program);

		// Data at location clears - no room for Word
		cmd = new CreateDataCmd(addr, new WordDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());

		d = listing.getDataAt(addr(UNDEFINED_AREA + 1));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);

	}

	@Test
	public void testCreateString() {

		Address addr = addr(STRING_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new StringDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof StringDataType);
		assertEquals(5, d.getLength());// "notepad.chm",00

		d = listing.getDataAt(addr(STRING_AREA + 12));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateStringFailure() {

		Address termAddr = addr(STRING_AREA + 2);
		CreateDataCmd cmd = new CreateDataCmd(termAddr, new ByteDataType());
		cmd.applyTo(program);

		// String not created because terminator not found in Default data
		Address addr = addr(STRING_AREA);
		cmd = new CreateDataCmd(addr, new StringDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(1, d.getLength());

		d = listing.getDataAt(termAddr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);
	}

	@Test
	public void testCreateUnicodeString() {

		Address addr = addr(UNICODE_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new UnicodeDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof UnicodeDataType);
		assertEquals(10, d.getLength());// "NpSaveDialog",00

		d = listing.getDataAt(addr(UNICODE_AREA + 26));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreateUnicodeStringFailure() {

		Address termAddr = addr(UNICODE_AREA + 6);
		CreateDataCmd cmd = new CreateDataCmd(termAddr, new ByteDataType());
		cmd.applyTo(program);

		// Unicode String not created because terminator not found in Default data
		Address addr = addr(UNICODE_AREA);
		cmd = new CreateDataCmd(addr, new UnicodeDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(1, d.getLength());

		d = listing.getDataAt(termAddr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);
	}

	@Test
	public void testCreatePointerOnDefaultData() {

		// Default data becomes Undefined* (i.e., addr)
		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertNull(pdt.getDataType());

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);
	}

	@Test
	public void testCreatePointerOnDefinedData() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		cmd.applyTo(program);

		// Byte becomes Byte*
		cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertNull(pdt.getDataType());

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);

	}

	@Test
	public void testCreatePointerOnMultipleUndefined1Data() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new Undefined1DataType());
		cmd.applyTo(program);
		cmd = new CreateDataCmd(addr.next(), new Undefined1DataType());
		cmd.applyTo(program);

		// two Undefined1 data becomes Pointer
		cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertNull(pdt.getDataType());

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);

	}

	@Test
	public void testCreatePointerOnPointer() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new PointerDataType());
		cmd.applyTo(program);

		cmd = new CreateDataCmd(addr, false, true, new ByteDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof ByteDataType);

		// Byte* becomes Byte**
		cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof ByteDataType);

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);

	}

	@Test
	public void testCreateCompoundUndefinedPointer() {

		DataType dt = PointerDataType.getPointer(null, 4);
		dt = PointerDataType.getPointer(dt, 8);
		dt = PointerDataType.getPointer(dt, 2);
		dt = PointerDataType.getPointer(dt, 1);

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, dt);
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(1, d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(1, dt.getLength());

		Pointer pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(2, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(8, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(4, dt.getLength());

		pdt = (Pointer) dt;
		assertNull(pdt.getDataType());

		cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(addr.getPointerSize(), d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(1, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(2, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(8, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(4, dt.getLength());

		pdt = (Pointer) dt;
		assertNull(pdt.getDataType());

	}

	@Test
	public void testCreateCompoundDefinedPointer() {

		DataType dt = PointerDataType.getPointer(new ByteDataType(), 4);
		dt = PointerDataType.getPointer(dt, 8);
		dt = PointerDataType.getPointer(dt, 2);
		dt = PointerDataType.getPointer(dt, 1);

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, dt);
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(1, d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(1, dt.getLength());

		Pointer pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(2, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(8, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(4, dt.getLength());

		pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof ByteDataType);

		cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(addr.getPointerSize(), d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(1, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(2, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(8, dt.getLength());

		pdt = (Pointer) dt;
		dt = pdt.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(4, dt.getLength());

		pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof ByteDataType);

	}

	@Test
	public void testCreatePointerNoSpace() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, new ByteDataType());
		cmd.applyTo(program);

		Address nextAddr = addr(UNDEFINED_AREA + 2);
		cmd = new CreateDataCmd(nextAddr, new ByteDataType());
		cmd.applyTo(program);

		// Data preserved - no room for pointer
		cmd = new CreateDataCmd(addr, new PointerDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);

		d = listing.getDefinedDataAfter(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(nextAddr, d.getMinAddress());

	}

	@Test
	public void testCreateDataOnDefaultPointer()
			throws InvalidInputException, DuplicateNameException {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		// Add external reference from pointer
		program.getReferenceManager()
				.addExternalReference(addr, "OtherFile", "ExtLabel", null,
					SourceType.USER_DEFINED, 0, RefType.DATA);

		// Undefined* becomes Byte*
		cmd = new CreateDataCmd(addr, false, true, new ByteDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof ByteDataType);

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);

		// Verify that reference is still intact
		CodeUnit cu = listing.getCodeUnitAt(addr);
		assertNotNull(cu.getExternalReference(0));

	}

	@Test
	public void testCreateDataOnNonDefaultPointer() {

		Address addr = addr(UNDEFINED_AREA);
		CreateDataCmd cmd = new CreateDataCmd(addr, false, true, new Pointer16DataType());
		cmd.applyTo(program);

		cmd = new CreateDataCmd(addr, false, true, new ByteDataType());
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(2, d.getLength());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(2, dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof ByteDataType);

		// Byte* becomes Word*
		cmd = new CreateDataCmd(addr, false, true, new WordDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(2, d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(2, dt.getLength());
		pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof WordDataType);

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(2, d.getMinAddress().getOffset() - UNDEFINED_AREA);
	}

	//
	// The following tests utilize other data commands for setup
	//

	@Test
	public void testCreateDataOnArray() {

		Address addr = addr(UNDEFINED_AREA);
		CreateArrayCmd arrayCmd = new CreateArrayCmd(addr, 10, new ByteDataType(), 1);
		arrayCmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Array);
		assertEquals(10, dt.getLength());

		// Byte[] becomes Byte
		CreateDataCmd cmd =
			new CreateDataCmd(addr, new ByteDataType(), false, ClearDataMode.CLEAR_SINGLE_DATA);
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);
		assertEquals(1, d.getLength());

		d = listing.getDataAt(addr(UNDEFINED_AREA + 1));
		assertNotNull(d);
		assertTrue(!d.isDefined());

	}

	@Test
	public void testCreateDataOnArrayPointer() {

		Address addr = addr(UNDEFINED_AREA);
		CreateArrayCmd arrayCmd = new CreateArrayCmd(addr, 10, new ByteDataType(), 1);
		arrayCmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Array);
		assertEquals(10, dt.getLength());

		CreateDataCmd cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		// Byte[]* becomes Word*
		cmd = new CreateDataCmd(addr, false, true, new WordDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof WordDataType);

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);

	}

	@Test
	public void testCreateDataOnComposite() {

		Address addr = addr(UNDEFINED_AREA);
		CreateStructureCmd structCmd = new CreateStructureCmd(addr, 10);
		structCmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Structure);
		assertEquals(10, dt.getLength());

		// struct becomes Byte
		CreateDataCmd cmd =
			new CreateDataCmd(addr, new ByteDataType(), false, ClearDataMode.CLEAR_SINGLE_DATA);
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof ByteDataType);
		assertEquals(1, d.getLength());

		d = listing.getDataAt(addr(UNDEFINED_AREA + 1));
		assertNotNull(d);
		assertTrue(!d.isDefined());
	}

	@Test
	public void testCreatePointerOnComposite() {

		Address addr = addr(UNDEFINED_AREA);
		CreateStructureCmd structCmd = new CreateStructureCmd(addr, 10);
		structCmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Structure);
		assertEquals(10, dt.getLength());

		// struct becomes struct*
		CreateDataCmd cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertNull(pdt.getDataType());

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);
	}

	@Test
	public void testCreateDataOnCompositePointer() {

		Address addr = addr(UNDEFINED_AREA);
		CreateStructureCmd structCmd = new CreateStructureCmd(addr, 10);
		structCmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Structure);
		assertEquals(10, dt.getLength());

		CreateDataCmd cmd = new CreateDataCmd(addr, false, true, new PointerDataType());
		cmd.applyTo(program);

		// struct* becomes Word*
		cmd = new CreateDataCmd(addr, false, true, new WordDataType());
		cmd.applyTo(program);

		d = listing.getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertEquals(4, d.getLength());
		dt = d.getDataType();
		assertTrue(dt instanceof Pointer);
		assertEquals(addr.getPointerSize(), dt.getLength());
		Pointer pdt = (Pointer) dt;
		assertTrue(pdt.getDataType() instanceof WordDataType);

		d = listing.getDataAfter(addr);
		assertNotNull(d);
		assertTrue(!d.isDefined());
		assertEquals(4, d.getMinAddress().getOffset() - UNDEFINED_AREA);
	}

}
