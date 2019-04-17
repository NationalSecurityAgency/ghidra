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
public class CreateDataInStructureBackgroundCmdTest extends AbstractGenericTest {

	private static final long UNDEFINED_AREA = 0x0100;

	private Program program;

	/**
	 * Constructor for CreateDataInStructureBackgroundCmdTest.
	 * @param arg0
	 */
	public CreateDataInStructureBackgroundCmdTest() {
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

		int structLen = (2 * defaultPtrLen) + 2;

		Command cmd = new CreateStructureCmd(addr(startOffset), structLen);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureBackgroundCmd(addr(startOffset), new int[] { 0 }, 2,
			new ByteDataType());
		cmd.applyTo(program);

		cmd =
			new CreateDataInStructureBackgroundCmd(addr(startOffset), new int[] { 2 }, 8, floatPtr);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructA");
		assertEquals(structLen, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(1);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(2);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(floatPtr.isEquivalent(comp.getDataType()));

		comp = struct.getComponent(3);
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

		int structLen = (2 * defaultPtrLen) + (2 * structA.getLength());

		Command cmd = new CreateStructureCmd(addr(startOffset), structLen);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureBackgroundCmd(addr(startOffset), new int[] { 0 },
			2 * structA.getLength(), structA);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureBackgroundCmd(addr(startOffset), new int[] { 2 },
			2 * defaultPtrLen, structAPtr);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructB");
		assertEquals(structLen, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(structA.getLength(), comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(structA));

		comp = struct.getComponent(1);
		assertEquals(structA.getLength(), comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(structA));

		comp = struct.getComponent(2);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(structAPtr));

		comp = struct.getComponent(3);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType().isEquivalent(structAPtr));

		DataType structB =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructB");
		assertEquals(struct, structB);
	}

	@Test
    public void testCreateNoFitData() throws Exception {

		long startOffset = UNDEFINED_AREA;

		int structLen = 4;
		Command cmd = new CreateStructureCmd(addr(startOffset), structLen);
		cmd.applyTo(program);

		cmd = new CreateDataInStructureBackgroundCmd(addr(startOffset), new int[] { 0 }, 4,
			new ByteDataType());
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructA");
		assertEquals(structLen, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		for (int i = 0; i < 4; i++) {
			DataTypeComponent comp = struct.getComponent(i);
			assertEquals(1, comp.getLength());
			assertTrue(comp.getDataType() instanceof ByteDataType);
		}

		cmd = new CreateDataInStructureBackgroundCmd(addr(startOffset), new int[] { 1 }, 3,
			new WordDataType());
		cmd.applyTo(program);

		assertEquals(structLen, struct.getLength());
		assertEquals(3, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct.getComponent(1);
		assertEquals(2, comp.getLength());
		assertTrue(comp.getDataType() instanceof WordDataType);

		comp = struct.getComponent(2);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() == DataType.DEFAULT);

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);

	}

}
