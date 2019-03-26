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
import ghidra.framework.cmd.Command;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * 
 */
public class CreateDataInStructureCmdTest extends AbstractGenericTest {

	private static final long UNDEFINED_AREA = 0x0100;

	private Program program;

	/**
	 * Constructor for CreateStructureCmdTest.
	 * @param arg0
	 */
	public CreateDataInStructureCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = buildProgram();
		program.startTransaction("TEST");
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x100), 0x2000);
		return builder.getProgram();
	}

	private Address addr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	@Test
    public void testCreateDataInStructure() throws Exception {

		long startOffset = UNDEFINED_AREA;
		DataType floatPtr = program.getDataTypeManager().getPointer(new FloatDataType());
		int defaultPtrLen = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();

		int structLen = defaultPtrLen + 1;

		Command cmd = new CreateStructureCmd(addr(startOffset), structLen);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureCmd(addr(startOffset), new int[] { 0 }, new ByteDataType());
		cmd.applyTo(program);

		cmd = new CreateDataInStructureCmd(addr(startOffset), new int[] { 1 }, floatPtr);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructA");
		assertEquals(structLen, struct.getLength());
		assertEquals(2, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(1);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(floatPtr.isEquivalent(comp.getDataType()));

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);
	}

	@Test
    public void testCreateDataInCompoundStructure() throws Exception {

		// Create structure data type: TestStructA
		testCreateDataInStructure();
		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		DataType structAPtr = program.getDataTypeManager().getPointer(structA);

		long startOffset = UNDEFINED_AREA + structA.getLength();
		int defaultPtrLen = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();

		int structLen = defaultPtrLen + structA.getLength();

		Command cmd = new CreateStructureCmd(addr(startOffset), structLen);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureCmd(addr(startOffset), new int[] { 0 }, structA);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureCmd(addr(startOffset), new int[] { 1 }, structAPtr);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructB");
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

	@Test
    public void testCreateNoFitData() throws Exception {

		long startOffset = UNDEFINED_AREA;

		int structLen = 1;
		Command cmd = new CreateStructureCmd(addr(startOffset), structLen);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureCmd(addr(startOffset), new int[] { 0 }, new ByteDataType());
		assertTrue(cmd.applyTo(program));

		cmd = new CreateDataInStructureCmd(addr(startOffset), new int[] { 0 }, new WordDataType());
		assertTrue(cmd.applyTo(program));

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(2, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructA");
		assertEquals(2, struct.getLength());
		assertEquals(1, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(2, comp.getLength());
		assertTrue(comp.getDataType() instanceof WordDataType);

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);

	}

	@Test
    public void testBadCircularReference() throws Exception {

		long startOffset = UNDEFINED_AREA;

//		Structure struct1 =
//			(Structure) program.getDataTypeManager().getDataType(
//				new CategoryPath("/Category1/Category2"), "MyStruct");
//		assertNotNull(struct1);
		Structure floatStruct = new StructureDataType("FloatStruct", 0);
		floatStruct.add(new FloatDataType());
		floatStruct.add(new DoubleDataType());
		ArrayDataType adt = new ArrayDataType(floatStruct, 10, floatStruct.getLength());
		Structure struct1 = new StructureDataType("MyStruct", 0);

		struct1.add(adt);
		struct1.add(new WordDataType());

		Command cmd = new CreateDataCmd(addr(startOffset + 1000), struct1);
		cmd.applyTo(program);
		Data dataAt = program.getListing().getDataAt(addr(startOffset + 1000));
		struct1 = (Structure) dataAt.getDataType();

		int structLen = struct1.getLength();
		cmd = new CreateStructureCmd(addr(startOffset), structLen);
		assertTrue(cmd.applyTo(program));

		cmd = new CreateDataInStructureCmd(addr(startOffset), new int[] { 0 }, struct1);
		assertTrue(cmd.applyTo(program));

		cmd = new CreateDataCmd(addr(startOffset + structLen), struct1);
		assertTrue(cmd.applyTo(program));

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		// the last createData() fixed up "MyStruct" and changed its size as a side-effect.
		// The data is still the original struct size because it was restricted by the last data
		// we created.  Probably this test should not use a "bad" structure that can get "fixed up"
		// Anyway for new, get the new structure length for further assertions.
		structLen = struct1.getLength();
		Structure struct = (Structure) d.getDataType();
		assertEquals(structLen, struct.getLength());
		assertEquals(1, struct.getNumComponents());

		assertEquals(structLen, struct1.getLength());
		assertEquals(2, struct1.getNumComponents());
		assertTrue(struct1.getComponent(0).getDataType() instanceof Array);

		// Attempt to add "struct" into "MyStruct", "struct" has "MyStruct" within it
		cmd = new CreateDataInStructureCmd(addr(startOffset + structLen), new int[] { 0 }, struct);
		assertNull(cmd.getStatusMsg());
		assertTrue(!cmd.applyTo(program));

		assertNotNull(cmd.getStatusMsg());
		assertTrue(
			cmd.getStatusMsg().indexOf(struct.getDisplayName() + " has MyStruct within it") > 0);

		assertEquals(structLen, struct1.getLength());
		assertEquals(2, struct1.getNumComponents());
		assertTrue(struct1.getComponent(0).getDataType() instanceof Array);

	}

}
