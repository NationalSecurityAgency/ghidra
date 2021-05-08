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
/*
 *
 */
package ghidra.program.database.data;

import static org.junit.Assert.*;

import org.junit.*;

import com.google.common.collect.Sets;

import generic.test.AbstractGTest;
import ghidra.program.model.data.*;

/**
 *
 */
public class UnionDataTypeTest extends AbstractGTest {

	private Union union;

	@Before
	public void setUp() throws Exception {
		union = createUnion("TestUnion");
		union.add(new ByteDataType(), "field1", "Comment1");
		union.add(new WordDataType(), null, "Comment2");
		union.add(new DWordDataType(), "field3", null);
		union.add(new ByteDataType(), "field4", "Comment4");
	}

	private void transitionToBigEndian() {

		// transition default little-endian structure to big-endian
		DataTypeManager beDtm = new MyBigEndianDataTypeManager();
		union = (Union) union.clone(beDtm);
	}

	private Union createUnion(String name) {
		return new UnionDataType(name);
	}

	private Structure createStructure(String name, int size) {
		return new StructureDataType(name, size);
	}

	private TypeDef createTypeDef(DataType dataType) {
		return new TypedefDataType(dataType.getName() + "TypeDef", dataType);
	}

	private Array createArray(DataType dataType, int numElements) {
		return new ArrayDataType(dataType, numElements, dataType.getLength());
	}

	private Pointer createPointer(DataType dataType, int length) {
		return new PointerDataType(dataType, length);
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
		Structure struct = createStructure("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);

		union.add(struct);
		union.delete(4);
		assertEquals(4, union.getNumComponents());
		assertEquals(4, union.getLength());
	}

	@Test
	public void testGetComponent() {
		Structure struct = createStructure("struct_1", 0);
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
		Structure struct = createStructure("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);
		union.add(struct, "field5", "comments");
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(5, dtcs.length);

		assertEquals(5, union.getNumComponents());
	}

	@Test
	public void testInsert() {
		Structure struct = createStructure("struct_1", 0);
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
	public void testBitFieldUnion() throws Exception {

		int cnt = union.getNumComponents();
		for (int i = 0; i < cnt; i++) {
			union.delete(0);
		}
		// NOTE: bitOffset ignored for union
		union.insertBitField(0, IntegerDataType.dataType, 2, "bf1", "bf1Comment");
		union.insert(0, ShortDataType.dataType);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestUnion\n" + 
			"pack(disabled)\n" + 
			"Union TestUnion {\n" + 
			"   0   short   2   null   \"\"\n" + 
			"   0   int:2(0)   1   bf1   \"bf1Comment\"\n" + 
			"}\n" + 
			"Size = 2   Actual Alignment = 1", union);
		//@formatter:on
	}

	@Test
	public void testAlignedBitFieldUnion() throws Exception {

		int cnt = union.getNumComponents();
		for (int i = 0; i < cnt; i++) {
			union.delete(0);
		}
		union.insertBitField(0, IntegerDataType.dataType, 2, "bf1", "bf1Comment");
		union.insert(0, ShortDataType.dataType);
		union.setPackingEnabled(true);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestUnion\n" + 
			"pack()\n" + 
			"Union TestUnion {\n" + 
			"   0   short   2   null   \"\"\n" + 
			"   0   int:2(0)   1   bf1   \"bf1Comment\"\n" + 
			"}\n" + 
			"Size = 4   Actual Alignment = 4", union);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldLittleEndian() throws Exception {

		union.insertBitField(2, IntegerDataType.dataType, 4, "bf1", "bf1Comment");
		union.insertBitField(3, ByteDataType.dataType, 4, "bf2", "bf2Comment");

	//@formatter:off
	CompositeTestUtils.assertExpectedComposite(this, "/TestUnion\n" + 
		"pack(disabled)\n" + 
		"Union TestUnion {\n" + 
		"   0   byte   1   field1   \"Comment1\"\n" + 
		"   0   word   2   null   \"Comment2\"\n" + 
		"   0   int:4(0)   1   bf1   \"bf1Comment\"\n" + 
		"   0   byte:4(0)   1   bf2   \"bf2Comment\"\n" + 
		"   0   dword   4   field3   \"\"\n" + 
		"   0   byte   1   field4   \"Comment4\"\n" + 
		"}\n" + 
		"Size = 4   Actual Alignment = 1", union);
	//@formatter:on
	}

	@Test
	public void testInsertBitFieldBigEndian() throws Exception {

		transitionToBigEndian();

		union.insertBitField(2, IntegerDataType.dataType, 4, "bf1", "bf1Comment");
		union.insertBitField(3, ByteDataType.dataType, 4, "bf2", "bf2Comment");

	//@formatter:off
	CompositeTestUtils.assertExpectedComposite(this, "/TestUnion\n" + 
		"pack(disabled)\n" + 
		"Union TestUnion {\n" + 
		"   0   byte   1   field1   \"Comment1\"\n" + 
		"   0   word   2   null   \"Comment2\"\n" + 
		"   0   int:4(4)   1   bf1   \"bf1Comment\"\n" + 
		"   0   byte:4(4)   1   bf2   \"bf2Comment\"\n" + 
		"   0   dword   4   field3   \"\"\n" + 
		"   0   byte   1   field4   \"Comment4\"\n" + 
		"}\n" + 
		"Size = 4   Actual Alignment = 1", union);
	//@formatter:on
	}

	@Test
	public void testGetName() {
		assertEquals("TestUnion", union.getName());
	}

	@Test
	public void testCloneRetainIdentity() throws Exception {
		Union unionCopy = (Union) union.clone(null);
		assertNull(unionCopy.getDataTypeManager());
		assertEquals(4, union.getLength());
	}

	@Test
	public void testCopyDontRetain() throws Exception {
		Union unionCopy = (Union) union.copy(null);
		assertNull(unionCopy.getDataTypeManager());
		assertEquals(4, union.getLength());
	}

	@Test
	public void testDelete() throws Exception {
		Structure struct = createStructure("struct_1", 0);
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
	public void testDeleteMany() throws Exception {
		Structure struct = createStructure("struct_1", 0);
		struct.add(new ByteDataType());
		struct.add(new StringDataType(), 10);
		union.add(struct);
		assertEquals(11, union.getLength());

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestUnion\n" + 
			"pack(disabled)\n" + 
			"Union TestUnion {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   0   word   2   null   \"Comment2\"\n" + 
			"   0   dword   4   field3   \"\"\n" + 
			"   0   byte   1   field4   \"Comment4\"\n" + 
			"   0   struct_1   11   null   \"\"\n" + 
			"}\n" + 
			"Size = 11   Actual Alignment = 1", union);
		//@formatter:on

		union.delete(Sets.newHashSet(2, 4));

		assertEquals(2, union.getLength());
		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestUnion\n" + 
			"pack(disabled)\n" + 
			"Union TestUnion {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   0   word   2   null   \"Comment2\"\n" + 
			"   0   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 2   Actual Alignment = 1", union);
		//@formatter:on
	}

	@Test
	public void testIsPartOf() {
		Structure struct = createStructure("struct_1", 0);
		struct.add(new ByteDataType());
		DataTypeComponent dtc = struct.add(createStructure("mystring", 10));
		DataType dt = dtc.getDataType();
		DataTypeComponent newdtc = union.add(struct);
		assertTrue(union.isPartOf(dt));

		Structure newstruct = (Structure) newdtc.getDataType();
		Structure s1 = (Structure) newstruct.add(createStructure("s1", 1)).getDataType();
		dt = s1.add(new QWordDataType()).getDataType();

		assertTrue(union.isPartOf(dt));
	}

	@Test
	public void testReplaceWith() {
		assertEquals(4, union.getLength());
		assertEquals(4, union.getNumComponents());

		Union newUnion = createUnion("Replaced");
		newUnion.setDescription("testReplaceWith()");
		DataTypeComponent dtc2 = newUnion.insert(0, new DWordDataType(), 4, "field2", null);
		DataTypeComponent dtc1 = newUnion.insert(0, new WordDataType(), 2, null, "Comment2");
		DataTypeComponent dtc0 = newUnion.insert(0, new ByteDataType(), 1, "field0", "Comment1");

		union.replaceWith(newUnion);
		assertEquals(4, union.getLength());
		assertEquals(3, union.getNumComponents());
		DataTypeComponent[] dtcs = union.getComponents();
		assertEquals(3, dtcs.length);
		assertEquals(dtc0, dtcs[0]);
		assertEquals(dtc1, dtcs[1]);
		assertEquals(dtc2, dtcs[2]);
		assertEquals("TestUnion", union.getName());
		assertEquals("", union.getDescription()); // unchanged
	}

	@Test
	public void testCyclingProblem() {
		Union newUnion = createUnion("Test");
		newUnion.setDescription("testReplaceWith()");
		newUnion.add(new ByteDataType(), "field0", "Comment1");
		newUnion.add(union, "field1", null);
		newUnion.add(new WordDataType(), null, "Comment2");
		newUnion.add(new DWordDataType(), "field3", null);

		try {
			union.add(newUnion);
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
		try {
			union.insert(0, newUnion);
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
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

	protected class MyBigEndianDataTypeManager extends StandAloneDataTypeManager {
		MyBigEndianDataTypeManager() {
			super("BEdtm");
			DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
			dataOrg.setBigEndian(true);
			this.dataOrganization = dataOrg;
		}
	}
}
