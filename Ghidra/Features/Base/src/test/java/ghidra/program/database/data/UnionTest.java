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
package ghidra.program.database.data;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

/**
 * Test the database implementation of Union data type.
 *  
 * 
 */
public class UnionTest extends AbstractGenericTest {
	private Union union;
	private ProgramDB program;
	private DataTypeManagerDB dataMgr;
	private int transactionID;

	/**
	 * Constructor for UnionTest.
	 * @param name
	 */
	public UnionTest() {
		super();
	}

	private Structure createStructure(String name, int length) {
		return (Structure) dataMgr.resolve(new StructureDataType(name, length),
			DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private Union createUnion(String name) {
		return (Union) dataMgr.resolve(new UnionDataType(name),
			DataTypeConflictHandler.DEFAULT_HANDLER);
	}

	private TypeDef createTypeDef(DataType dataType) {
		return (TypeDef) dataMgr.resolve(
			new TypedefDataType(dataType.getName() + "TypeDef", dataType), null);
	}

	private Array createArray(DataType dataType, int numElements) {
		return (Array) dataMgr.resolve(
			new ArrayDataType(dataType, numElements, dataType.getLength()), null);
	}

	private Pointer createPointer(DataType dataType, int length) {
		return (Pointer) dataMgr.resolve(new Pointer32DataType(dataType), null);
	}

	@Before
	public void setUp() throws Exception {
		program =
			AbstractGhidraHeadlessIntegrationTest.createDefaultProgram("Test", ProgramBuilder._TOY, this);
		dataMgr = program.getDataManager();
		transactionID = program.startTransaction("Test");
		union = createUnion("Test");
		union.add(new ByteDataType(), "field1", "Comment1");
		union.add(new WordDataType(), null, "Comment2");
		union.add(new DWordDataType(), "field3", null);
		union.add(new ByteDataType(), "field4", "Comment4");
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);

	}

	@Test
	public void testAdd() throws Exception {
		assertEquals(4, union.getLength());
		assertEquals(4, union.getNumComponents());

		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(4, dtcs.length);
		DataTypeComponent dtc = union.getComponent(3);
		assertEquals("field4", dtc.getFieldName());
		assertEquals("byte", dtc.getDataType().getName());

		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);

		union.add(struct);
		assertEquals(struct.getLength(), union.getLength());
	}

	@Test
	public void testAdd2() {
		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);

		union.add(struct);

		union.delete(4);
		assertEquals(4, union.getNumComponents());
		assertEquals(4, union.getLength());
	}

	@Test
	public void testGetComponent() {
		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);
		DataTypeComponent newdtc = union.add(struct, "field5", "comments");
		DataTypeComponent dtc = union.getComponent(4);
		assertEquals(newdtc, dtc);
		assertEquals("field5", dtc.getFieldName());
		assertEquals("comments", dtc.getComment());

	}

	@Test
	public void testGetComponents() {
		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);
		union.add(struct, "field5", "comments");
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(5, dtcs.length);

		assertEquals(5, union.getNumComponents());
	}

	@Test
	public void testInsert() {
		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);

		DataTypeComponent dtc = union.getComponent(2);
		assertEquals("field3", dtc.getFieldName());

		union.insert(2, struct, struct.getLength(), "field5", "field5 comments");
		assertEquals(11, union.getLength());
		dtc = union.getComponent(2);
		assertEquals("field5", dtc.getFieldName());
	}

	@Test
	public void testGetName() {
		assertEquals("Test", union.getName());
	}

	@Test
	public void testClone() throws Exception {
		Union unionCopy = (Union) union.clone(null);
		assertNull(unionCopy.getDataTypeManager());
		assertEquals(4, union.getLength());
	}

	@Test
	public void testDelete() throws Exception {
		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);
		union.add(struct);
		assertEquals(11, union.getLength());

		union.delete(4);
		assertEquals(4, union.getLength());

		union.delete(2);
		assertEquals(2, union.getLength());
	}

	@Test
	public void testIsPartOf() {
		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		DataTypeComponent dtc = struct.add(new StringDataType(), 10);
		DataTypeComponent newdtc = union.add(struct);
		dtc = union.getComponent(4);
		DataType dt = dtc.getDataType();
		assertTrue(union.isPartOf(dt));

		Structure newstruct = (Structure) newdtc.getDataType();
		Structure s1 = (Structure) newstruct.add(new StructureDataType("s1", 1)).getDataType();
		dt = s1.add(new QWordDataType()).getDataType();

		assertTrue(union.isPartOf(dt));
	}

	@Test
	public void testReplaceWith() {
		Structure struct = new StructureDataType("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);
		Union newunion = new UnionDataType("newunion");
		newunion.add(struct);

		union.replaceWith(newunion);
		assertEquals(1, newunion.getNumComponents());
		DataType dt = dataMgr.getDataType("/struct_1");
		assertNotNull(dt);

		assertEquals(dt, union.getComponent(0).getDataType());
	}

	/**
	 * Test that a structure can't be added to itself.
	 */
	@Test
	public void testCyclicDependencyProblem1() {
		try {
			union.add(union);
			Assert.fail("Shouldn't be able to add a union to itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union to itself.
		}
		try {
			union.insert(0, union);
			Assert.fail("Shouldn't be able to insert a union into itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union to itself.
		}
	}

	/**
	 * Test that a structure array can't be added to the same structure.
	 */
	@Test
	public void testCyclicDependencyProblem2() {
		Array array = createArray(union, 3);
		try {
			union.add(array);
			Assert.fail("Shouldn't be able to add a union array to the same union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union to itself.
		}
		try {
			union.insert(0, array);
			Assert.fail("Shouldn't be able to insert a union array into the same union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union to itself.
		}
	}

	/**
	 * Test that a typedef of a union can't be added to the union.
	 */
	@Test
	public void testCyclicDependencyProblem3() {
		TypeDef typeDef = createTypeDef(union);
		try {
			union.add(typeDef);
			Assert.fail("Shouldn't be able to add a union typedef to the typedef's union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union to itself.
		}
		try {
			union.insert(0, typeDef);
			Assert.fail("Shouldn't be able to insert a union typedef into the typedef's union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union to itself.
		}
	}

	/**
	 * Test that a union can't contain another union that contains it.
	 */
	@Test
	public void testCyclicDependencyProblem4() {
		Union anotherUnion = createUnion("AnotherUnion");
		anotherUnion.add(union);
		try {
			union.add(anotherUnion);
			Assert.fail(
				"Shouldn't be able to add another union, which contains this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union to itself.
		}
		try {
			union.insert(0, anotherUnion);
			Assert.fail(
				"Shouldn't be able to insert another union, which contains this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union to itself.
		}
	}

	/**
	 * Test that a union can't contain another union that contains a typedef to it.
	 */
	@Test
	public void testCyclicDependencyProblem5() {
		Union anotherUnion = createUnion("AnotherUnion");
		TypeDef typeDef = createTypeDef(union);
		anotherUnion.add(typeDef);
		try {
			union.add(anotherUnion);
			Assert.fail(
				"Shouldn't be able to add another union, which contains a typedef of this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union to itself.
		}
		try {
			union.insert(0, anotherUnion);
			Assert.fail(
				"Shouldn't be able to insert another union, which contains a typedef of this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union to itself.
		}
	}

	/**
	 * Test that a union can't contain a structure that contains that union.
	 */
	@Test
	public void testCyclicDependencyProblem6() {
		Union structure = createUnion("TestStructure");
		structure.add(union);
		try {
			union.add(structure);
			Assert.fail(
				"Shouldn't be able to add a structure, which contains this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union to itself.
		}
		try {
			union.insert(0, structure);
			Assert.fail(
				"Shouldn't be able to insert a structure, which contains this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union to itself.
		}
	}

	/**
	 * Test that a structure can't contain a typedef of a union that contains that structure.
	 */
	@Test
	public void testCyclicDependencyProblem7() {
		Structure structure = createStructure("TestStructure", 0);
		structure.add(union);
		TypeDef typeDef = createTypeDef(structure);
		try {
			union.add(typeDef);
			Assert.fail(
				"Shouldn't be able to add a typedef of a strucutre, which contains this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the structure typedef to the union.
		}
		try {
			union.insert(0, typeDef);
			Assert.fail(
				"Shouldn't be able to insert a typedef of a structure, which contains this union, to this union.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the structure typedef to the union.
		}
	}

	/**
	 * Test that a structure can contain a pointer in it to the same structure.
	 */
	@Test
	public void testNoCyclicDependencyProblemForStructurePointer() {
		Pointer unionPointer = createPointer(union, 4);
		try {
			union.add(unionPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail("Should be able to add a union pointer to the pointer's union.");
		}
		try {
			union.insert(0, unionPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail("Should be able to insert a union pointer into the pointer's union.");
		}
	}

	/**
	 * Test that a union can contain a pointer in it to a typedef of the same union.
	 */
	@Test
	public void testNoCyclicDependencyProblemForTypedefPointer() {
		TypeDef typeDef = createTypeDef(union);
		Pointer typedefPointer = createPointer(typeDef, 4);
		try {
			union.add(typedefPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail("Should be able to add a union typedef pointer to the pointer's union.");
		}
		try {
			union.insert(0, typedefPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a union typedef pointer into the pointer's union.");
		}
	}

	/**
	 * Test that a union can contain a pointer in it to a typedef of the same union.
	 */
	@Test
	public void testNoCyclicDependencyProblemForArrayPointer() {
		TypeDef typeDef = createTypeDef(union);
		Array array = createArray(typeDef, 5);
		Pointer arrayPointer = createPointer(array, 4);
		try {
			union.add(arrayPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to add a union typedef array pointer to the pointer's union.");
		}
		try {
			union.insert(0, arrayPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a union typedef array pointer into the pointer's union.");
		}
	}

}
