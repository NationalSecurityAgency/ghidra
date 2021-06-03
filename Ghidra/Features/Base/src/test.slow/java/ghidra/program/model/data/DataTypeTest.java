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
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;

/**
 * Tests for manipulating data types in the category/data type tree.
 */
public class DataTypeTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private DataTypeManager dtm;

	public DataTypeTest() {
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
	}

	@After
	public void tearDown() throws Exception {
		env.release(program);
		env.dispose();
	}

	@Test
	public void testPointerEquivalence() throws Exception {

		Structure structA = new StructureDataType("structA", 0);
		structA.setCategoryPath(new CategoryPath("/catA"));
		structA.setPackingEnabled(true);

		Pointer p = new PointerDataType(structA);

		structA.add(p);
		structA.add(ByteDataType.dataType);
		structA.add(LongDataType.dataType);

		int txId = program.startTransaction("Add Struct");
		Structure structAp = (Structure) dtm.resolve(structA, null);
		program.endTransaction(txId, true);

		// Check structure equivalence

		assertTrue(structAp.isEquivalent(structA));

		assertTrue(structAp.isEquivalent(structAp.clone(null)));

		assertTrue(structAp.isEquivalent(structAp.copy(null)));

		// Check pointer equivalence

		Pointer p1 = dtm.getPointer(structAp);

		DataTypeComponent component = structAp.getComponent(0);
		assertNotNull(component);

		DataType dt = component.getDataType();
		assertTrue(dt instanceof Pointer);

		assertTrue(p1.isEquivalent(dt));

		DataType dt2 = p1.clone(null);

		assertTrue(p1.isEquivalent(dt2));

		assertTrue(dt2.isEquivalent(p1.clone(null)));
	}

	@Test
	public void testConflictRenameAndAdd() {
		int txId = program.startTransaction("Add Struct");

		Structure struct1 = createStruct("abc", new ByteDataType(), 10);
		Structure struct2 = createStruct("abc", new WordDataType(), 10);

		DataType resolvedStruct1 = dtm.resolve(struct1, null);
		DataType resolvedStruct2 = dtm.resolve(struct2, null);

		assertEquals("abc", struct1.getName());
		assertEquals("abc", struct2.getName());

		assertEquals("abc", resolvedStruct1.getName());
		assertEquals("abc.conflict", resolvedStruct2.getName());

		program.endTransaction(txId, true);

	}

	@Test
	public void testReplaceWithStructureContainingReplacedStructure() {
		int txId = program.startTransaction("Add Struct");

		Structure struct1 = createStruct("abc", new ByteDataType(), 10);
		DataType resolvedStruct1 = dtm.resolve(struct1, null);

		Structure struct2 = createStruct("abc", resolvedStruct1, 1);

		// Replacement type refers to existing type preventing existing type from being removed
		// Resolve reverts to default add behavior producing a conflict name
		// Uncertain if a dependency exception should be thrown instead

		DataType resolvedStruct2 = dtm.resolve(struct2, DataTypeConflictHandler.REPLACE_HANDLER);

		assertEquals("abc", struct1.getName());
		assertEquals("abc", struct2.getName());

		assertEquals("abc.conflict", resolvedStruct2.getName());

		assertTrue(
			resolvedStruct1.equals(((Structure) resolvedStruct2).getComponentAt(0).getDataType()));

		program.endTransaction(txId, true);

	}

	private StructureDataType createStruct(String name, DataType contentType, int count) {
		StructureDataType struct = new StructureDataType(name, 0, dtm);
		for (int i = 0; i < count; i++) {
			struct.add(contentType);
		}
		return struct;
	}
}
