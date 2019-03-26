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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGTest;

/**
 *
 */
public class StructureTest extends AbstractGTest {
	private Structure struct;

	/**
	 * @param arg0
	 */
	public StructureTest() {
		super();
	}

	private Structure createStructure(String name, int length) {
		return new StructureDataType(name, length);
	}

	private Union createUnion(String name) {
		return new UnionDataType(name);
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

	@Before
	public void setUp() throws Exception {
		struct = createStructure("TestStruct", 0);
		struct.add(new ByteDataType(), "field1", "Comment1");
		struct.add(new WordDataType(), null, "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");
	}

	@Test
	public void testAdd() throws Exception {
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertEquals("field_0x1", dtc.getDefaultFieldName());
		assertEquals(null, dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(3, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

	}

	@Test
	public void testAdd2() throws Exception {
		struct = createStructure("Test", 10);

		assertEquals(10, struct.getLength());
		assertEquals(10, struct.getNumComponents());

		struct.add(new ByteDataType(), "field1", "Comment1");
		struct.add(new WordDataType(), null, "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");

		assertEquals(18, struct.getLength());
		assertEquals(14, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field_0x0", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());
		assertNull(dtc.getComment());
		assertEquals(DataType.DEFAULT, dtc.getDataType());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertEquals("field_0x1", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());

		assertEquals(null, dtc.getComment());
		assertEquals(DataType.DEFAULT, dtc.getDataType());

		dtc = struct.getComponent(10);
		assertEquals(10, dtc.getOffset());
		assertEquals(10, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(11);
		assertEquals(11, dtc.getOffset());
		assertEquals(11, dtc.getOrdinal());
		assertEquals("field_0xb", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());

		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(12);
		assertEquals(13, dtc.getOffset());
		assertEquals(12, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());
	}

	@Test
	public void testInsert_beginning() {
		struct.insert(0, new FloatDataType());
		assertEquals(12, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field_0x0", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());
		assertNull(dtc.getComment());
		assertEquals(FloatDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(4, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(5, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertEquals("field_0x5", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(4);
		assertEquals(11, dtc.getOffset());
		assertEquals(4, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

	}

	@Test
	public void testInsert_end() {

		struct.insert(4, new FloatDataType());
		assertEquals(12, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertEquals("field_0x1", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(3, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(4);
		assertEquals(8, dtc.getOffset());
		assertEquals(4, dtc.getOrdinal());
		assertEquals("field_0x8", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(FloatDataType.class, dtc.getDataType().getClass());

	}

	@Test
	public void testInsert_middle() {

		struct.insert(2, new FloatDataType());
		assertEquals(12, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(0, dtc.getOffset());
		assertEquals(0, dtc.getOrdinal());
		assertEquals("field1", dtc.getFieldName());
		assertEquals("Comment1", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(1);
		assertEquals(1, dtc.getOffset());
		assertEquals(1, dtc.getOrdinal());
		assertEquals("field_0x1", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());
		assertEquals("Comment2", dtc.getComment());
		assertEquals(WordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(2);
		assertEquals(3, dtc.getOffset());
		assertEquals(2, dtc.getOrdinal());
		assertEquals("field_0x3", dtc.getDefaultFieldName());
		assertNull(dtc.getFieldName());
		assertNull(dtc.getComment());
		assertEquals(FloatDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(3);
		assertEquals(7, dtc.getOffset());
		assertEquals(3, dtc.getOrdinal());
		assertEquals("field3", dtc.getFieldName());
		assertEquals(null, dtc.getComment());
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());

		dtc = struct.getComponent(4);
		assertEquals(11, dtc.getOffset());
		assertEquals(4, dtc.getOrdinal());
		assertEquals("field4", dtc.getFieldName());
		assertEquals("Comment4", dtc.getComment());
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());

	}

	@Test
	public void testInsertWithEmptySpace() {
		struct = createStructure("Test", 100);
		struct.insert(40, new ByteDataType());
		struct.insert(20, new WordDataType());

		struct.insert(10, new FloatDataType());

		assertEquals(107, struct.getLength());
		assertEquals(103, struct.getNumComponents());

		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(3, comps.length);

		assertEquals(10, comps[0].getOffset());
		assertEquals(10, comps[0].getOrdinal());
		assertEquals(FloatDataType.class, comps[0].getDataType().getClass());

		assertEquals(24, comps[1].getOffset());
		assertEquals(21, comps[1].getOrdinal());
		assertEquals(WordDataType.class, comps[1].getDataType().getClass());

		assertEquals(46, comps[2].getOffset());
		assertEquals(42, comps[2].getOrdinal());
		assertEquals(ByteDataType.class, comps[2].getDataType().getClass());
	}

	// test inserting at offset 0
	@Test
	public void testInsertAtOffset() {
		struct.insertAtOffset(0, new FloatDataType(), 4);
		assertEquals(12, struct.getLength());
		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(FloatDataType.class, comps[0].getDataType().getClass());

		assertEquals(4, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertEquals(ByteDataType.class, comps[1].getDataType().getClass());

		assertEquals(5, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		assertEquals(7, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertEquals(DWordDataType.class, comps[3].getDataType().getClass());

	}

	// test inserting at offset 1
	@Test
	public void testInsertAtOffset1() {
		struct.insertAtOffset(1, new FloatDataType(), 4);
		assertEquals(12, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertEquals(FloatDataType.class, comps[1].getDataType().getClass());

		assertEquals(5, comps[2].getOffset());
		assertEquals(2, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		assertEquals(7, comps[3].getOffset());
		assertEquals(3, comps[3].getOrdinal());
		assertEquals(DWordDataType.class, comps[3].getDataType().getClass());

	}

	// test inserting at offset 1
	@Test
	public void testInsertAtOffset2() {
		struct.insertAtOffset(2, new FloatDataType(), 4);
		assertEquals(13, struct.getLength());

		DataTypeComponent[] comps = struct.getDefinedComponents();

		assertEquals(5, comps.length);

		assertEquals(0, comps[0].getOffset());
		assertEquals(0, comps[0].getOrdinal());
		assertEquals(ByteDataType.class, comps[0].getDataType().getClass());

		assertEquals(2, comps[1].getOffset());
		assertEquals(2, comps[1].getOrdinal());
		assertEquals(FloatDataType.class, comps[1].getDataType().getClass());

		assertEquals(6, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(WordDataType.class, comps[2].getDataType().getClass());

		assertEquals(8, comps[3].getOffset());
		assertEquals(4, comps[3].getOrdinal());
		assertEquals(DWordDataType.class, comps[3].getDataType().getClass());

	}

	@Test
	public void testInsertAtOffsetPastEnd() {
		struct.insertAtOffset(100, new FloatDataType(), 4);
		assertEquals(104, struct.getLength());
	}

	@Test
	public void testClearComponent() {
		struct.clearComponent(0);
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());
		DataTypeComponent dtc = struct.getComponent(0);
		assertEquals(DataType.DEFAULT, dtc.getDataType());
		dtc = struct.getComponent(1);
		assertEquals(WordDataType.class, dtc.getDataType().getClass());
	}

	@Test
	public void testClearComponent1() {
		struct.clearComponent(1);
		assertEquals(8, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent dtc = struct.getComponent(1);
		assertEquals(DataType.DEFAULT, dtc.getDataType());
		dtc = struct.getComponent(2);
		assertEquals(DataType.DEFAULT, dtc.getDataType());
		dtc = struct.getComponent(0);
		assertEquals(ByteDataType.class, dtc.getDataType().getClass());
		dtc = struct.getComponent(3);
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());
		assertEquals(3, dtc.getOrdinal());
		assertEquals(3, dtc.getOffset());
	}

	@Test
	public void testReplace() { // bigger, no space below
		try {
			struct.replace(0, new QWordDataType(), 8);
			Assert.fail();
		}
		catch (Exception e) {
		}
	}

	@Test
	public void testReplace1() { // bigger, space below
		struct.insert(1, new QWordDataType());
		struct.clearComponent(1);
		assertEquals(16, struct.getLength());
		assertEquals(12, struct.getNumComponents());

		struct.replace(0, new QWordDataType(), 8);
		assertEquals(16, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(9, comps[1].getOffset());
		assertEquals(2, comps[1].getOrdinal());
	}

	@Test
	public void testReplace2() { // same size
		struct.replace(0, new CharDataType(), 1);
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(CharDataType.class, comps[0].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
	}

	@Test
	public void testReplace3() { // smaller
		struct.replace(1, new CharDataType(), 1);
		assertEquals(8, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(CharDataType.class, comps[1].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
		assertEquals(1, comps[1].getOrdinal());
		assertEquals(3, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(DWordDataType.class, comps[2].getDataType().getClass());
	}

	@Test
	public void testDelete() {
		struct.delete(1);
		assertEquals(6, struct.getLength());
		assertEquals(3, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
	}

	@Test
	public void testDeleteAtOffset() {
		struct.deleteAtOffset(2);
		assertEquals(6, struct.getLength());
		assertEquals(3, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(1, comps[1].getOffset());
	}

	@Test
	public void testDeleteAll() {

		Structure s = new StructureDataType("test1", 0);
		s.add(new ByteDataType());
		s.add(new FloatDataType());

		struct.add(s);
		s.deleteAll();
		assertEquals(1, s.getLength());
		assertTrue(s.isNotYetDefined());
		assertEquals(0, s.getNumComponents());
	}

	@Test
	public void testGetComponents() {
		struct = createStructure("Test", 8);
		struct.insert(2, new ByteDataType(), 1, "field3", "Comment1");
		struct.insert(5, new WordDataType(), 2, null, "Comment2");
		struct.insert(7, new DWordDataType(), 4, "field8", null);
		assertEquals(15, struct.getLength());
		assertEquals(11, struct.getNumComponents());
		DataTypeComponent[] dtcs = struct.getComponents();
		assertEquals(11, dtcs.length);
		int offset = 0;
		for (int i = 0; i < 11; i++) {
			assertEquals(i, dtcs[i].getOrdinal());
			assertEquals(offset, dtcs[i].getOffset());
			offset += dtcs[i].getLength();
		}
		assertEquals(DataType.DEFAULT, dtcs[0].getDataType());
		assertEquals(DataType.DEFAULT, dtcs[1].getDataType());
		assertEquals(ByteDataType.class, dtcs[2].getDataType().getClass());
		assertEquals(DataType.DEFAULT, dtcs[3].getDataType());
		assertEquals(DataType.DEFAULT, dtcs[4].getDataType());
		assertEquals(WordDataType.class, dtcs[5].getDataType().getClass());
		assertEquals(DataType.DEFAULT, dtcs[6].getDataType());
		assertEquals(DWordDataType.class, dtcs[7].getDataType().getClass());
		assertEquals(DataType.DEFAULT, dtcs[8].getDataType());
		assertEquals(DataType.DEFAULT, dtcs[9].getDataType());
		assertEquals(DataType.DEFAULT, dtcs[10].getDataType());
	}

	@Test
	public void testGetDefinedComponents() {
		struct = createStructure("Test", 8);
		struct.insert(2, new ByteDataType(), 1, "field3", "Comment1");
		struct.insert(5, new WordDataType(), 2, null, "Comment2");
		struct.insert(7, new DWordDataType(), 4, "field8", null);
		assertEquals(15, struct.getLength());
		assertEquals(11, struct.getNumComponents());
		DataTypeComponent[] dtcs = struct.getDefinedComponents();
		assertEquals(3, dtcs.length);

		assertEquals(ByteDataType.class, dtcs[0].getDataType().getClass());
		assertEquals(2, dtcs[0].getOrdinal());
		assertEquals(2, dtcs[0].getOffset());

		assertEquals(WordDataType.class, dtcs[1].getDataType().getClass());
		assertEquals(5, dtcs[1].getOrdinal());
		assertEquals(5, dtcs[1].getOffset());

		assertEquals(DWordDataType.class, dtcs[2].getDataType().getClass());
		assertEquals(7, dtcs[2].getOrdinal());
		assertEquals(8, dtcs[2].getOffset());

	}

	@Test
	public void testGetComponentAt() {
		DataTypeComponent dtc = struct.getComponentAt(4);
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());
		assertEquals(2, dtc.getOrdinal());
		assertEquals(3, dtc.getOffset());
	}

	@Test
	public void testGetDataTypeAt() {
		Structure s1 = createStructure("Test1", 0);
		s1.add(new WordDataType());
		s1.add(struct);
		s1.add(new ByteDataType());

		DataTypeComponent dtc = s1.getComponentAt(7);
		assertEquals(struct, dtc.getDataType());
		dtc = s1.getDataTypeAt(7);
		assertEquals(DWordDataType.class, dtc.getDataType().getClass());
	}

	@Test
	public void testReplaceWith() {
		assertEquals(8, struct.getLength());
		assertEquals(4, struct.getNumComponents());

		Structure newStruct = createStructure("Replaced", 8);
		newStruct.setDescription("testReplaceWith()");
		DataTypeComponent dtc0 = newStruct.insert(2, new ByteDataType(), 1, "field3", "Comment1");
		DataTypeComponent dtc1 = newStruct.insert(5, new WordDataType(), 2, null, "Comment2");
		DataTypeComponent dtc2 = newStruct.insert(7, new DWordDataType(), 4, "field8", null);

		struct.replaceWith(newStruct);
		assertEquals(15, struct.getLength());
		assertEquals(11, struct.getNumComponents());
		DataTypeComponent[] dtcs = struct.getDefinedComponents();
		assertEquals(3, dtcs.length);
		assertEquals(dtc0, dtcs[0]);
		assertEquals(dtc1, dtcs[1]);
		assertEquals(dtc2, dtcs[2]);
		assertEquals("TestStruct", struct.getName());
		assertEquals("", struct.getDescription());
	}

	/**
	 * Test that a structure can't ... ???
	 */
	@Test
	public void testCyclingProblem() {
		Structure newStruct = createStructure("TestStruct", 80);
		newStruct.setDescription("testReplaceWith()");
		newStruct.add(new ByteDataType(), "field0", "Comment1");
		newStruct.add(struct, "field1", null);
		newStruct.add(new WordDataType(), null, "Comment2");
		newStruct.add(new DWordDataType(), "field3", null);

		try {
			struct.add(newStruct);
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
		try {
			struct.insert(0, newStruct);
			Assert.fail();
		}
		catch (IllegalArgumentException e) {
		}
		try {
			struct.replace(0, newStruct, newStruct.getLength());
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
			struct.add(struct);
			Assert.fail("Shouldn't be able to add a structure to itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, struct);
			Assert.fail("Shouldn't be able to insert a structure into itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, struct, struct.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with the structure itself.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure array can't be added to the same structure.
	 */
	@Test
	public void testCyclicDependencyProblem2() {
		Array array = createArray(struct, 3);
		try {
			struct.add(array);
			Assert.fail("Shouldn't be able to add a structure array to the same structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, array);
			Assert.fail("Shouldn't be able to insert a structure array into the same structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, array, array.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with an array of the same structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a typedef of a structure can't be added to the structure.
	 */
	@Test
	public void testCyclicDependencyProblem3() {
		TypeDef typeDef = createTypeDef(struct);
		try {
			struct.add(typeDef);
			Assert.fail("Shouldn't be able to add a structure typedef to the typedef's structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, typeDef);
			Assert.fail(
				"Shouldn't be able to insert a structure typedef into the typedef's structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, typeDef, typeDef.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with the structure's typedef.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain another structure that contains it.
	 */
	@Test
	public void testCyclicDependencyProblem4() {
		Structure anotherStruct = createStructure("AnotherStruct", 0);
		anotherStruct.add(struct);
		try {
			struct.add(anotherStruct);
			Assert.fail(
				"Shouldn't be able to add another structure, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, anotherStruct);
			Assert.fail(
				"Shouldn't be able to insert another structure, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, anotherStruct, anotherStruct.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with another structure which contains this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain another structure that contains a typedef to it.
	 */
	@Test
	public void testCyclicDependencyProblem5() {
		Structure anotherStruct = createStructure("AnotherStruct", 0);
		TypeDef typeDef = createTypeDef(struct);
		anotherStruct.add(typeDef);
		try {
			struct.add(anotherStruct);
			Assert.fail(
				"Shouldn't be able to add another structure, which contains a typedef of this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, anotherStruct);
			Assert.fail(
				"Shouldn't be able to insert another structure, which contains a typedef of this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, anotherStruct, anotherStruct.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with another structure which contains a typedef of this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain a union that contains that structure.
	 */
	@Test
	public void testCyclicDependencyProblem6() {
		Union union = createUnion("TestUnion");
		union.add(struct);
		try {
			struct.add(union);
			Assert.fail(
				"Shouldn't be able to add a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the struct to itself.
		}
		try {
			struct.insert(0, union);
			Assert.fail(
				"Shouldn't be able to insert a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the struct to itself.
		}
		try {
			struct.replace(0, union, union.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with a union, which contains this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct to itself.
		}
	}

	/**
	 * Test that a structure can't contain a typedef of a union that contains that structure.
	 */
	@Test
	public void testCyclicDependencyProblem7() {
		Union union = createUnion("TestUnion");
		union.add(struct);
		TypeDef typeDef = createTypeDef(union);
		try {
			struct.add(typeDef);
			Assert.fail(
				"Shouldn't be able to add a typedef of a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from adding the union typedef to the struct.
		}
		try {
			struct.insert(0, typeDef);
			Assert.fail(
				"Shouldn't be able to insert a typedef of a union, which contains this structure, to this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from inserting the union typedef to the struct.
		}
		try {
			struct.replace(0, typeDef, typeDef.getLength());
			Assert.fail(
				"Shouldn't be able to replace a structure component with a typedef of a union, which contains this structure.");
		}
		catch (IllegalArgumentException e) {
			// Should get an exception from replacing the struct component with the union typedef.
		}
	}

	/**
	 * Test that a structure can contain a pointer in it to the same structure.
	 */
	@Test
	public void testNoCyclicDependencyProblemForStructurePointer() {
		Pointer structurePointer = createPointer(struct, 4);
		try {
			struct.add(structurePointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail("Should be able to add a structure pointer to the pointer's structure.");
		}
		try {
			struct.insert(0, structurePointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a structure pointer into the pointer's structure.");
		}
		try {
			struct.replace(0, structurePointer, structurePointer.getLength());
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to replace a structure component with the structure's pointer.");
		}
	}

	/**
	 * Test that a structure can contain a pointer in it to a typedef of the same structure.
	 */
	@Test
	public void testNoCyclicDependencyProblemForTypedefPointer() {
		TypeDef typeDef = createTypeDef(struct);
		Pointer typedefPointer = createPointer(typeDef, 4);
		try {
			struct.add(typedefPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to add a structure typedef pointer to the pointer's structure.");
		}
		try {
			struct.insert(0, typedefPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a structure typedef pointer into the pointer's structure.");
		}
		try {
			struct.replace(0, typedefPointer, typedefPointer.getLength());
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to replace a structure component with the structure's typedef pointer.");
		}
	}

	/**
	 * Test that a structure can contain a pointer in it to a typedef of the same structure.
	 */
	@Test
	public void testNoCyclicDependencyProblemForArrayPointer() {
		TypeDef typeDef = createTypeDef(struct);
		Array array = createArray(typeDef, 5);
		Pointer arrayPointer = createPointer(array, 4);
		try {
			struct.add(arrayPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to add a structure typedef array pointer to the pointer's structure.");
		}
		try {
			struct.insert(0, arrayPointer);
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to insert a structure typedef arrayointer into the pointer's structure.");
		}
		try {
			struct.replace(0, arrayPointer, arrayPointer.getLength());
		}
		catch (IllegalArgumentException e) {
			Assert.fail(
				"Should be able to replace a structure component with the structure's typedef array pointer.");
		}
	}

}
