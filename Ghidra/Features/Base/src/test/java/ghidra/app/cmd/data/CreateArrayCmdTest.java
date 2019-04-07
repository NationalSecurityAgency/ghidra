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
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

/**
 * 
 */
public class CreateArrayCmdTest extends AbstractGenericTest {

	private static final long UNDEFINED_AREA = 0x01001000;

//	private TestEnv env;
	private Program program;
	private Listing listing;

	/**
	 * Constructor for CreateDataCmdTest.
	 * @param arg0
	 */
	public CreateArrayCmdTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
//		env = new TestEnv();
		program = buildProgram();
		listing = program.getListing();
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

	private DataType createArray(DataType elementDataType, int elementLength) {

		Address addr = addr(UNDEFINED_AREA);
		CreateArrayCmd cmd = new CreateArrayCmd(addr, 10, elementDataType, elementLength);
		cmd.applyTo(program);

		Data data = program.getListing().getDataAt(addr);
		assertNotNull(data);
		assertTrue(data.isArray());
		DataType dt = data.getDataType();
		assertTrue(dt instanceof Array);
		Array a = (Array) dt;
		dt = a.getDataType();
		assertNotNull(dt);
		assertTrue(dt.isEquivalent(elementDataType));

		data = program.getListing().getDataAfter(addr);
		assertNotNull(data);
		assertTrue(!data.isDefined());
		assertEquals(addr(UNDEFINED_AREA + (10 * elementLength)), data.getMinAddress());

		return data.getDataType();
	}

	private DataType createStruct(Address addr) {

		CreateStructureCmd cmd = new CreateStructureCmd(addr, 10);
		cmd.applyTo(program);

		Data d = listing.getDataAt(addr);
		assertTrue(d.isStructure());
		DataType dt = d.getDataType();
		assertTrue(dt instanceof Structure);
		assertEquals(10, dt.getLength());
		return dt;
	}

	@Test
	public void testCreateUndefinedDataArray() {
		createArray(DataType.DEFAULT, 1);
	}

	@Test
	public void testCreateUndefinedPointerArray() {
		DataType pt = new Pointer32DataType(DataType.DEFAULT);
		int psize = addr(UNDEFINED_AREA).getPointerSize();
		createArray(pt, psize);
	}

	@Test
	public void testCreateDefinedDataArray() {
		createArray(new ByteDataType(), 1);
	}

	@Test
	public void testCreateDefinedPointerArray() {
		DataType pt = new Pointer32DataType(new ByteDataType());
		int psize = addr(UNDEFINED_AREA).getPointerSize();
		createArray(pt, psize);
	}

	@Test
	public void testCreateStringArray() {
		createArray(new StringDataType(), 8);
	}

	@Test
	public void testStringPointerArray() {
		DataType pt = new Pointer32DataType(new StringDataType());
		int psize = addr(UNDEFINED_AREA).getPointerSize();
		createArray(pt, psize);
	}

	@Test
	public void testCreateStructArray() {
		Address addr = addr(UNDEFINED_AREA);
		DataType sdt = createStruct(addr);
		createArray(sdt, sdt.getLength());
	}

	@Test
	public void testCreateArrayArray() {
		DataType adt = createArray(new ByteDataType(), 1);
		createArray(adt, adt.getLength());
	}

	@Test
	public void testCreateArrayPointerArray() {
		DataType adt = createArray(new ByteDataType(), 1);
		DataType pt = new Pointer32DataType(adt);
		int psize = addr(UNDEFINED_AREA).getPointerSize();
		createArray(pt, psize);
	}

	@Test
	public void testCreateStructPointerArray() {
		Address addr = addr(UNDEFINED_AREA);
		DataType sdt = createStruct(addr);
		DataType pt = new Pointer32DataType(sdt);
		int psize = addr.getPointerSize();
		createArray(pt, psize);
	}

}
