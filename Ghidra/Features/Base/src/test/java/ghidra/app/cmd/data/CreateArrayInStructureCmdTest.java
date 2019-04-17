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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;

/**
 * 
 */
public class CreateArrayInStructureCmdTest extends AbstractGenericTest {

	private static final long UNDEFINED_AREA = 0x01001000;

//	private TestEnv env;
	private Program program;

	/**
	 * Constructor for CreateArrayInStructureCmdTest.
	 * @param arg0
	 */
	public CreateArrayInStructureCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
//		env = new TestEnv();
		program = buildProgram();
		program.startTransaction("TEST");
	}

	private Program buildProgram() throws Exception {
		ProgramBuilder builder = new ProgramBuilder("Test", ProgramBuilder._TOY);
		builder.createMemory("test1", "0x1001000", 0x2000);
		return builder.getProgram();
	}

	@After
	public void tearDown() {
//		env.release(program);
//		env.dispose();
	}

	private Address addr(long offset) {
		AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
		return space.getAddress(offset);
	}

	@Test
    public void testCreateArrayInStructureCmd() throws Exception {

		Address addr = addr(UNDEFINED_AREA);
		int structLen = 30;
		Command cmd = new CreateStructureCmd(addr, structLen);
		cmd.applyTo(program);

		DataType dt = new Pointer16DataType(new ByteDataType());
		cmd = new CreateArrayInStructureCmd(addr, 10, dt, new int[] { 0 });
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr);
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructA");
		assertEquals(structLen, struct.getLength());
		assertEquals(11, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(20, comp.getLength());
		assertTrue(comp.getDataType() instanceof Array);
		Array a = (Array) comp.getDataType();
		assertEquals(2, a.getElementLength());
		assertEquals(10, a.getNumElements());
		assertTrue(a.getDataType().isEquivalent(dt));

		for (int i = 1; i < 11; i++) {
			comp = struct.getComponent(i);
			assertEquals(1, comp.getLength());
			assertEquals(DataType.DEFAULT, comp.getDataType());
		}

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);
	}

	@Test
    public void testCreateArrayInNestedStructureCmd() throws Exception {

		long startOffset = UNDEFINED_AREA;

		Structure struct1 = new StructureDataType("IntStruct", 0);
		struct1.add(new ByteDataType());
		struct1.add(new WordDataType());
		struct1.add(new DWordDataType());
		struct1.add(new QWordDataType());

		Command cmd = new CreateDataCmd(addr(startOffset + 1), struct1);
		cmd.applyTo(program);
		Data dataAt = program.getListing().getDataAt(addr(startOffset + 1));
		struct1 = (Structure) dataAt.getDataType();

		int structLen = struct1.getLength() + 10;
		cmd = new CreateStructureCmd(addr(startOffset), structLen);
		cmd.applyTo(program);

		DataType dt = new Pointer16DataType(new ByteDataType());
		cmd = new CreateArrayInStructureCmd(addr(startOffset), 3, dt, new int[] { 1, 1 });
		cmd.applyTo(program);

		Data d = program.getListing().getDataAt(addr(startOffset));
		assertNotNull(d);
		assertTrue(d.isDefined());
		assertTrue(d.getDataType() instanceof Structure);
		assertEquals(structLen, d.getLength());

		Structure struct = (Structure) d.getDataType();
		struct.setName("TestStructA");
		assertEquals(structLen, struct.getLength());
		assertEquals(11, struct.getNumComponents());

		DataTypeComponent comp = struct.getComponent(0);
		assertEquals(1, comp.getLength());
		assertEquals(DataType.DEFAULT, comp.getDataType());

		comp = struct.getComponent(1);
		assertEquals(struct1.getLength(), comp.getLength());
		assertTrue(comp.getDataType() instanceof Structure);
		Structure s = (Structure) comp.getDataType();
		assertEquals(3, s.getNumComponents());
		assertEquals(s, struct1);

		comp = struct1.getComponent(0);
		assertEquals(1, comp.getLength());
		assertTrue(comp.getDataType() instanceof ByteDataType);

		comp = struct1.getComponent(1);
		assertEquals(6, comp.getLength());
		assertTrue(comp.getDataType() instanceof Array);
		Array a = (Array) comp.getDataType();
		assertEquals(2, a.getElementLength());
		assertEquals(3, a.getNumElements());
		assertTrue(a.getDataType().isEquivalent(dt));

		comp = struct1.getComponent(2);
		assertEquals(8, comp.getLength());
		assertTrue(comp.getDataType() instanceof QWordDataType);

		for (int i = 2; i < 11; i++) {
			comp = struct.getComponent(i);
			assertEquals(1, comp.getLength());
			assertEquals(DataType.DEFAULT, comp.getDataType());
		}

		DataType structA =
			program.getDataTypeManager().getDataType(CategoryPath.ROOT, "TestStructA");
		assertEquals(struct, structA);
	}

}
