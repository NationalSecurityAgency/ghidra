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

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * 
 */
public class CreateStructureCmdTest extends AbstractGenericTest {

	private static final long UNDEFINED_AREA = 0x01001398;

	private Program program;

	/**
	 * Constructor for CreateStructureCmdTest.
	 * @param arg0
	 */
	public CreateStructureCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = buildProgram();
		program.startTransaction("TEST");
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x2000);
		return builder.getProgram();
	}

	private Address addr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	private long createData(long offset, DataType dt) {
		int len = dt.getLength();
		if (len < 0) {
			Assert.fail();
		}
		CreateDataCmd cmd = new CreateDataCmd(addr(offset), dt);
		cmd.applyTo(program);
		return offset + len;
	}

	private long createData(long offset, int len, DataType dt) {
		if (len < 0) {
			Assert.fail();
		}
		AddressSet set = new AddressSet(addr(offset), addr(offset + len - 1));
		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, dt);
		cmd.applyTo(program);
		return offset + len;
	}

	private long createArray(long offset, int elementCnt, int elementLen, DataType dt) {
		if (elementLen < 0) {
			Assert.fail();
		}
		CreateArrayCmd cmd = new CreateArrayCmd(addr(offset), elementCnt, dt, elementLen);
		cmd.applyTo(program);
		return offset + (elementCnt * elementLen);
	}

	@Test
    public void testCreateStructure() {

		long startOffset = UNDEFINED_AREA;
		long offset = startOffset;
		DataType floatPtr = program.getDataTypeManager().getPointer(new FloatDataType());
		DataType stringPtr = program.getDataTypeManager().getPointer(new StringDataType());
		int defaultPtrLen = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();

		offset = createData(offset, new ByteDataType());
		offset = createData(offset, floatPtr);
		offset = createData(offset, 10, new StringDataType());
		offset = createArray(offset, 8, 4, stringPtr);

		int structLen = (int) (offset - startOffset);
		CreateStructureCmd cmd =
			new CreateStructureCmd("TestStructA", addr(startOffset), structLen);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());

		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		assertEquals(structLen, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(1);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(floatPtr.isEquivalent(comp.getDataType()));

		comp = struct.getComponent(2);
		assertEquals(10, comp.getLength());
		assertTrue(comp.getDataType() instanceof StringDataType);

		comp = struct.getComponent(3);
		assertEquals(8 * defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType() instanceof Array);
		Array a = (Array) comp.getDataType();
		assertEquals(defaultPtrLen, a.getElementLength());
		assertEquals(8, a.getNumElements());
		assertTrue(a.getDataType().isEquivalent(stringPtr));

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);
	}

	/**
	 * This test is the same as {@link #testCreateStructure()} with the 
	 * exception that this test passes an already created structure to the 
	 * command object. 
	 */
	@Test
    public void testCreateStructureFromStructure() {

		long startOffset = UNDEFINED_AREA;
		long offset = startOffset;
		DataType floatPtr = program.getDataTypeManager().getPointer(new FloatDataType());
		DataType stringPtr = program.getDataTypeManager().getPointer(new StringDataType());
		int defaultPtrLen = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();

		offset = createData(offset, new ByteDataType());
		offset = createData(offset, floatPtr);
		offset = createData(offset, 10, new StringDataType());
		offset = createArray(offset, 8, 4, stringPtr);

		int structLen = (int) (offset - startOffset);
		Address address = addr(startOffset);
		Structure structure = StructureFactory.createStructureDataType(program, address, structLen,
			"TestStructA", true);
		CreateStructureCmd cmd = new CreateStructureCmd(structure, address);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(address);
		assertNotNull(d);
		assertTrue(d.isDefined());

		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		assertEquals(structLen, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(1);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(floatPtr.isEquivalent(comp.getDataType()));

		comp = struct.getComponent(2);
		assertEquals(10, comp.getLength());
		assertTrue(comp.getDataType() instanceof StringDataType);

		comp = struct.getComponent(3);
		assertEquals(8 * defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType() instanceof Array);
		Array a = (Array) comp.getDataType();
		assertEquals(defaultPtrLen, a.getElementLength());
		assertEquals(8, a.getNumElements());
		assertTrue(a.getDataType().isEquivalent(stringPtr));

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);
	}

	@Test
    public void testCreateCompoundStructure() {

		// Create structure data type: TestStructA
		testCreateStructure();
		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		DataType structAPtr = program.getDataTypeManager().getPointer(structA);

		long startOffset = UNDEFINED_AREA + structA.getLength();
		long offset = startOffset;

		int defaultPtrLen = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();

		offset = createData(offset, structA);
		offset = createData(offset, structAPtr);

		int structLen = (int) (offset - startOffset);
		CreateStructureCmd cmd =
			new CreateStructureCmd("TestStructB", addr(startOffset), structLen);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		assertEquals(structLen, struct.getLength());
		assertEquals(2, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(structA.getLength(), comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(structA));

		comp = struct.getComponent(1);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(structAPtr));

		DataType structB =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructB");
		assertEquals(struct, structB);
	}
}
