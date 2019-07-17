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
import ghidra.framework.cmd.Command;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * 
 */
public class CreateStructureInStructureCmdTest extends AbstractGenericTest {

	private static final long UNDEFINED_AREA = 0x01001398;

	private Program program;

	/**
	 * Constructor for CreateStructureInStructureCmdTest.
	 * @param arg0
	 */
	public CreateStructureInStructureCmdTest() {
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
    public void testCreateStructureInStructure() {

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
		Command cmd = new CreateStructureCmd("TestStructA", addr(startOffset), structLen);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		assertEquals(structLen, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		cmd = new CreateStructureInStructureCmd("TestStructB", addr(startOffset), new int[] { 1 },
			new int[] { 2 });
		cmd.applyTo(program);

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(1);
		assertEquals(defaultPtrLen + 10, comp.getLength());
		assertTrue(comp.getDataType() instanceof Structure);
		Structure s = (Structure) comp.getDataType();

		comp = struct.getComponent(2);
		assertEquals(8 * defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType() instanceof Array);
		Array a = (Array) comp.getDataType();
		assertEquals(defaultPtrLen, a.getElementLength());
		assertEquals(8, a.getNumElements());
		assertTrue(a.getDataType().isEquivalent(stringPtr));

		assertEquals(2, s.getNumComponents());
		assertEquals(defaultPtrLen + 10, s.getLength());

		comp = s.getComponent(0);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(floatPtr));

		comp = s.getComponent(1);
		assertEquals(10, comp.getLength());
		assertTrue(comp.getDataType() instanceof StringDataType);

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);

		DataType structB =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructB");
		assertEquals(s, structB);
	}

	/**
	 * This method is the same as {@link #testCreateStructureInStructure()} 
	 * with the exception that this method creates a structure before creating
	 * the Command object.
	 * 
	 * @throws Exception If there is a problem setting the names of the
	 *         structures.
	 */
	@Test
    public void testCreateStructureInStructureFromStructure() {

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
		Command cmd = new CreateStructureCmd("TestStructA", addr(startOffset), structLen);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		assertEquals(structLen, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		Address address = addr(startOffset);
		int[] fromPath = new int[] { 1 };
		int[] toPath = new int[] { 2 };
		Structure childStructure = StructureFactory.createStructureDataTypeInStrucuture(program,
			address, fromPath, toPath, "TestStructB", true);
		cmd = new CreateStructureInStructureCmd(childStructure, address, fromPath, toPath);
		cmd.applyTo(program);

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(1);
		assertEquals(defaultPtrLen + 10, comp.getLength());
		assertTrue(comp.getDataType() instanceof Structure);
		Structure s = (Structure) comp.getDataType();

		comp = struct.getComponent(2);
		assertEquals(8 * defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType() instanceof Array);
		Array a = (Array) comp.getDataType();
		assertEquals(defaultPtrLen, a.getElementLength());
		assertEquals(8, a.getNumElements());
		assertTrue(a.getDataType().isEquivalent(stringPtr));

		assertEquals(2, s.getNumComponents());
		assertEquals(defaultPtrLen + 10, s.getLength());

		comp = s.getComponent(0);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(floatPtr));

		comp = s.getComponent(1);
		assertEquals(10, comp.getLength());
		assertTrue(comp.getDataType() instanceof StringDataType);

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);

		DataType structB =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructB");
		assertEquals(s, structB);
	}
}
