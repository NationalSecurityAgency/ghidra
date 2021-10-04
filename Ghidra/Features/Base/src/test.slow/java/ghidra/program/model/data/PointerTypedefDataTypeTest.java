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

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.data.PointerTypedefInspector;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for manipulating data types in the category/data type tree.
 */
public class PointerTypedefDataTypeTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private DataTypeManager dtm;
	private BuiltInDataTypeManager builtInDtm;

	public PointerTypedefDataTypeTest() {
		super();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
		return builder.getProgram();
	}

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram("notepad");
		dtm = program.getDataTypeManager();
		builtInDtm = BuiltInDataTypeManager.getDataTypeManager();
		
		program.startTransaction("TEST");
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testIBOBuiltIn() throws Exception {

		DataType dt = builtInDtm.getDataType(CategoryPath.ROOT, IBO32DataType.NAME);
		assertTrue(dt instanceof TypeDef);
		assertFalse(dt instanceof BuiltIn); // transforms from BuiltIn to DataTypeDB
		assertEquals(IBO32DataType.NAME, dt.getName());
		assertFalse(dt.hasLanguageDependantLength());
		assertTrue(dt.isEquivalent(dtm.resolve(dt, null)));

		dt = new IBO32DataType(CharDataType.dataType, dtm);
		assertTrue(dt instanceof TypeDef);
		assertTrue(dt instanceof BuiltIn);
		assertEquals("char *32 __attribute__((image-base-relative))", dt.getName());
		DataType dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertFalse(dbDt instanceof BuiltIn); // transforms from BuiltIn to DataTypeDB
		assertTrue(dt.isEquivalent(dbDt));

		dt = builtInDtm.getDataType(CategoryPath.ROOT, IBO64DataType.NAME);
		assertTrue(dt instanceof TypeDef);
		assertFalse(dt instanceof BuiltIn); // transforms from BuiltIn to DataTypeDB
		assertEquals(IBO64DataType.NAME, dt.getName());
		assertFalse(dt.hasLanguageDependantLength());
		assertTrue(dt.isEquivalent(dtm.resolve(dt, null)));

		dt = new IBO64DataType(CharDataType.dataType, dtm);
		assertTrue(dt instanceof TypeDef);
		assertTrue(dt instanceof BuiltIn);
		assertEquals("char *64 __attribute__((image-base-relative))", dt.getName());
		dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertFalse(dbDt instanceof BuiltIn); // transforms from BuiltIn to DataTypeDB
		assertTrue(dt.isEquivalent(dbDt));
	}

	@Test
	public void testPointerTypedef() throws Exception {

		DataType dt = new PointerTypedef(null, CharDataType.dataType, -1, dtm,
			program.getAddressFactory().getRegisterSpace());
		assertTrue(dt.hasLanguageDependantLength());
		assertEquals(4, dt.getLength());
		assertTrue(dt instanceof TypeDef);
		assertTrue(dt instanceof BuiltIn);
		assertEquals("char * __attribute__((space(register)))", dt.getName());
		DataType dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertFalse(dbDt instanceof BuiltIn); // transforms from BuiltIn to DataTypeDB
		assertTrue(dt.isEquivalent(dbDt));

		AddressSpace space = PointerTypedefInspector.getPointerAddressSpace((TypeDef) dbDt,
			program.getAddressFactory());
		assertTrue(program.getAddressFactory().getRegisterSpace().equals(space));

		dt = new PointerTypedef(null, CharDataType.dataType, -1, dtm,
			PointerType.RELATIVE);
		assertTrue(dt.hasLanguageDependantLength());
		assertEquals(4, dt.getLength());
		assertTrue(dt instanceof TypeDef);
		assertTrue(dt instanceof BuiltIn);
		assertEquals("char * __attribute__((relative))", dt.getName());
		dbDt = dtm.resolve(dt, null);
		assertTrue(dbDt instanceof TypeDef);
		assertFalse(dbDt instanceof BuiltIn); // transforms from BuiltIn to DataTypeDB
		assertTrue(dt.isEquivalent(dbDt));

		assertEquals(PointerType.RELATIVE, PointerTypedefInspector.getPointerType((TypeDef) dbDt));

	}


}
