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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.app.cmd.data.*;
import ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin;
import ghidra.framework.cmd.Command;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests the {@link StructureFactory}.
 * 
 * 
 * @since Tracker Id 383
 */
public class StructureFactoryTest extends AbstractGhidraHeadedIntegrationTest {

	private static final long UNDEFINED_AREA = 0x01001398;

	private TestEnv env;
	private PluginTool tool;
	private Program program;

	/**
	 * Constructor for StructureFactoryTest.
	 * 
	 * @param testName
	 */
	public StructureFactoryTest() {
		super();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
		builder.disassemble("0x1001400", 10);
		return builder.getProgram();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		tool = env.getTool();
		tool.addPlugin(CodeBrowserPlugin.class.getName());

		program = buildProgram("notepad");
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		if (program != null) {
			env.release(program);
		}
		env.dispose();
	}

	/*
	 * Class under test for Structure 
	 * createStructureDataType(Program, Address, int, String, boolean)
	 */
	@Test
	public void testCreateStructureDataType() {

		// verify exceptions on:
		// data length <= 0
		long startOffset = UNDEFINED_AREA;
		long offset = startOffset;
		int structureLength = (int) (offset - startOffset);
		Address structureAddress = addr(startOffset);

		try {
			StructureFactory.createStructureDataType(program, structureAddress, 0);

			Assert.fail(
				"Did not receive an exception when passing an invalid " + "instruction length.");
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		try {
			StructureFactory.createStructureDataType(program, structureAddress, Integer.MIN_VALUE);

			Assert.fail(
				"Did not receive an exception when passing an invalid " + "instruction length.");
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		// bad end address
		try {
			Address endAddress = structureAddress.getAddressSpace().getMaxAddress();

			StructureFactory.createStructureDataType(program, endAddress, Integer.MAX_VALUE);

			Assert.fail("Did not receive an exception when passing an invalid " + "address range.");
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		// contains instructions
		try {
			Instruction instruction = program.getListing().getInstructionAfter(structureAddress);
			Address instructionAddress = instruction.getMaxAddress();

			StructureFactory.createStructureDataType(program, instructionAddress,
				instruction.getLength());

			Assert.fail("Did not receive an exception when passing an address that " +
				"contains instructions.");
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		// now build some structures without exception
		int transaction = program.startTransaction("TEST");

		DataType floatPtr = program.getDataTypeManager().getPointer(new FloatDataType());
		DataType stringPtr = program.getDataTypeManager().getPointer(new StringDataType());
		int defaultPtrLen = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();

		offset = createData(offset, new ByteDataType());
		offset = createData(offset, floatPtr);
		offset = createMultipleData(offset, 10, new StringDataType());
		offset = createArray(offset, 8, 4, stringPtr);

		structureLength = (int) (offset - startOffset);
		Structure structure =
			StructureFactory.createStructureDataType(program, structureAddress, structureLength);

		assertNotNull("The created structure is null.", structure);
		assertEquals(
			"The components at the structures were not added to " +
				"the new structure--the structure was not initialized.",
			4, structure.getNumComponents());

		DataTypeComponent comp = structure.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = structure.getComponent(1);
		assertEquals(defaultPtrLen, comp.getLength());
		assertTrue(floatPtr.isEquivalent(comp.getDataType()));

		comp = structure.getComponent(2);
		assertEquals(10, comp.getLength());
		assertTrue(comp.getDataType() instanceof StringDataType);

		comp = structure.getComponent(3);
		assertEquals(8 * defaultPtrLen, comp.getLength());
		assertTrue(comp.getDataType() instanceof Array);
		Array a = (Array) comp.getDataType();
		assertEquals(defaultPtrLen, a.getElementLength());
		assertEquals(8, a.getNumElements());
		assertTrue(a.getDataType().isEquivalent(stringPtr));

		// more expected exceptions
		// null name-not unique switch
		try {
			StructureFactory.createStructureDataType(program, structureAddress, structureLength,
				null, false);

			Assert.fail("Did not receive an exception when passing a null name.");
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		// null name-unique switch
		try {
			StructureFactory.createStructureDataType(program, structureAddress, structureLength,
				null, true);

			Assert.fail("Did not receive an exception when passing a dupicate name.");
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		program.endTransaction(transaction, false);
	}

	/*
	 * Class under test for Structure 
	 * createStructureDataTypeInStrucuture(Program, Address, int[], int[], String, boolean)
	 */
	@Test
	public void testCreateStructureDataTypeInStrucuture() {

		int transaction = program.startTransaction("TEST");

		long startOffset = UNDEFINED_AREA;
		long offset = startOffset;

		DataType floatPtr = program.getDataTypeManager().getPointer(new FloatDataType());
		DataType stringPtr = program.getDataTypeManager().getPointer(new StringDataType());

		offset = createData(offset, new ByteDataType());
		offset = createData(offset, floatPtr);
		offset = createMultipleData(offset, 10, new StringDataType());
		offset = createArray(offset, 8, 4, stringPtr);

		int structureLength = (int) (offset - startOffset);
		Address address = addr(startOffset);
		int[] fromPath = new int[] { 1 };
		int[] toPath = new int[] { 2 };

		// null structure name
		try {
			StructureFactory.createStructureDataTypeInStrucuture(program, address, fromPath, toPath,
				null, false);
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		// no parent structure
		try {
			StructureFactory.createStructureDataTypeInStrucuture(program, address, fromPath, toPath,
				"testChild", true);
		}
		catch (IllegalArgumentException iae) {
			// good, expected
		}

		// create a valid structure...
		int defaultPtrLen = program.getAddressFactory().getDefaultAddressSpace().getPointerSize();
		Command cmd = new CreateStructureCmd("TestStructA", addr(startOffset), structureLength);
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structureLength, d.getLength());

		Structure struct = (Structure) d.getDataType();
		assertEquals(structureLength, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		Structure childStructure = StructureFactory.createStructureDataTypeInStrucuture(program,
			address, fromPath, toPath, "TestStructB", true);

		assertEquals(2, childStructure.getNumComponents());
		assertEquals(defaultPtrLen + 10, childStructure.getLength());

		DataTypeComponent component = childStructure.getComponent(0);
		assertEquals(defaultPtrLen, component.getLength());
		assertTrue(component.getDataType().isEquivalent(floatPtr));

		component = childStructure.getComponent(1);
		assertEquals(10, component.getLength());
		assertTrue(component.getDataType() instanceof StringDataType);

		program.endTransaction(transaction, false);
	}

	private long createArray(long offset, int elementCnt, int elementLen, DataType dt) {
		if (elementLen < 0) {
			Assert.fail();
		}
		CreateArrayCmd cmd = new CreateArrayCmd(addr(offset), elementCnt, dt, elementLen);
		cmd.applyTo(program);
		return offset + (elementCnt * elementLen);
	}

	private long createMultipleData(long offset, int len, DataType dt) {
		if (len < 0) {
			Assert.fail();
		}
		AddressSet set = new AddressSet(addr(offset), addr(offset + len - 1));
		CreateDataBackgroundCmd cmd = new CreateDataBackgroundCmd(set, dt);
		cmd.applyTo(program);
		return offset + len;
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

	private Address addr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}
}
