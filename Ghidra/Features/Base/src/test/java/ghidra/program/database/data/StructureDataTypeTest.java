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

import org.apache.commons.compress.utils.Sets;
import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.program.model.data.*;

/**
 *
 */
public class StructureDataTypeTest extends AbstractGTest {

	private Structure struct;

	@Before
	public void setUp() throws Exception {
		struct = createStructure("TestStruct", 0);
		struct.add(new ByteDataType(), "field1", "Comment1");
		struct.add(new WordDataType(), null, "Comment2");
		struct.add(new DWordDataType(), "field3", null);
		struct.add(new ByteDataType(), "field4", "Comment4");
	}

	private void transitionToBigEndian() {

		// transition default little-endian structure to big-endian
		DataTypeManager beDtm = new MyBigEndianDataTypeManager();
		struct = struct.clone(beDtm);
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
	public void testInsertBitFieldLittleEndianAppend() throws Exception {

		struct.insertBitField(4, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2   null   \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
			"   8   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   9   undefined   1   null   \"\"\n" + 
//			"   10   undefined   1   null   \"\"\n" + 
//			"   11   undefined   1   null   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 1", struct);
		//@formatter:on

		struct.insertBitField(4, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2   null   \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
			"   8   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   8   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
//			"   9   undefined   1   null   \"\"\n" + 
//			"   10   undefined   1   null   \"\"\n" + 
//			"   11   undefined   1   null   \"\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldAtLittleEndianAppend() throws Exception {

		struct.insertBitFieldAt(10, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2   null   \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1   null   \"\"\n" + 
//			"   9   undefined   1   null   \"\"\n" + 
			"   10   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   11   undefined   1   null   \"\"\n" + 
//			"   12   undefined   1   null   \"\"\n" + 
//			"   13   undefined   1   null   \"\"\n" + 
			"}\n" + 
			"Size = 14   Actual Alignment = 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(10, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2   null   \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1   null   \"\"\n" + 
//			"   9   undefined   1   null   \"\"\n" + 
			"   10   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   10   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
//			"   11   undefined   1   null   \"\"\n" + 
//			"   12   undefined   1   null   \"\"\n" + 
//			"   13   undefined   1   null   \"\"\n" + 
			"}\n" + 
			"Size = 14   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldAtLittleEndian() throws Exception {

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
//			"   4   undefined   1   null   \"\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
//			"   4   undefined   1   null   \"\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		try {
			struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 12, "bf4", "bf4Comment");
			fail(
				"expected - IllegalArgumentException: Bitfield does not fit within specified constraints");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertBitFieldAtBigEndian() throws Exception {

		transitionToBigEndian();

		try {
			struct.insertBitFieldAt(2, 4, 30, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
			fail(
				"expected - IllegalArgumentException: Bitfield does not fit within specified constraints");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		struct.insertBitFieldAt(2, 4, 29, IntegerDataType.dataType, 3, "bf1", "bf1Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
//			"   4   undefined   1   null   \"\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 26, IntegerDataType.dataType, 3, "bf2", "bf2Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(2)   1   bf2   \"bf2Comment\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
//			"   4   undefined   1   null   \"\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 11, IntegerDataType.dataType, 15, "bf3", "bf3Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(2)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(3)   3   bf3   \"bf3Comment\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(5)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(2)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(3)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(0)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on
	}

	@Test
	public void testInsertAtOffsetAfterBeforeBitField() throws Exception {

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");
		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");
		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		struct.insertAtOffset(2, FloatDataType.dataType, 4);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   float   4   null   \"\"\n" + 
			"   6   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   6   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   6   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   8   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   10   word   2   null   \"Comment2\"\n" + 
			"   12   dword   4   field3   \"\"\n" + 
			"   16   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 17   Actual Alignment = 1", struct);
		//@formatter:on

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
	public void testReplaceFailure() {// bigger, no space below
		DataTypeComponent dtc = null;
		try {
			dtc = struct.replace(0, new QWordDataType(), 8);
		}
		catch (IllegalArgumentException e) {
			// Not enough undefined bytes so should throw this.
		}
		assertNull(dtc);
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
	public void testDataTypeReplaced1() {// bigger, space below
		Structure struct2 = createStructure("struct2", 3);
		Structure struct2A = createStructure("struct2A", 5);
		struct.insert(0, DataType.DEFAULT);
		struct.insert(3, struct2);
		struct.clearComponent(4);
		assertEquals(12, struct.getLength());
		assertEquals(9, struct.getNumComponents());

		struct.dataTypeReplaced(struct2, struct2A);
		assertEquals(12, struct.getLength());
		assertEquals(7, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(4, comps[2].getOffset());
		assertEquals(3, comps[2].getOrdinal());
		assertEquals(5, comps[2].getLength());
		assertEquals(11, comps[3].getOffset());
		assertEquals(6, comps[3].getOrdinal());
	}

	@Test
	public void testDataTypeReplaced3() {// bigger, no space at end (structure grows)
		Structure struct2 = createStructure("struct2", 3);
		Structure struct2A = createStructure("struct2A", 5);
		struct.add(struct2);
		assertEquals(11, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		struct.dataTypeReplaced(struct2, struct2A);
		assertEquals(13, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(8, comps[4].getOffset());
		assertEquals(4, comps[4].getOrdinal());
		assertEquals(5, comps[4].getLength());
	}

	@Test
	public void testDataTypeSizeChanged() {
		Structure struct2 = createStructure("struct2", 3);
		struct.add(struct2);
		assertEquals(11, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		struct2.add(new WordDataType());
		assertEquals(13, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(8, comps[4].getOffset());
		assertEquals(4, comps[4].getOrdinal());
		assertEquals(5, comps[4].getLength());
	}

	@Test
	public void testDataTypeComponentReplaced() {// bigger, no space at end (structure grows)
		Structure struct2 = createStructure("struct2", 3);
		Structure struct2A = createStructure("struct2A", 5);
		struct.add(struct2);
		assertEquals(11, struct.getLength());
		assertEquals(5, struct.getNumComponents());

		struct.replace(4, struct2A, struct2A.getLength());
		assertEquals(13, struct.getLength());
		assertEquals(5, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(8, comps[4].getOffset());
		assertEquals(4, comps[4].getOrdinal());
		assertEquals(5, comps[4].getLength());
	}

	@Test
	public void testDataTypeReplaced2() {// smaller, create undefineds
		Structure struct2 = createStructure("struct2", 5);
		Structure struct2A = createStructure("struct2A", 3);
		struct.insert(0, DataType.DEFAULT);
		struct.insert(0, DataType.DEFAULT);
		struct.insert(4, struct2);
		assertEquals(15, struct.getLength());
		assertEquals(7, struct.getNumComponents());

		struct.dataTypeReplaced(struct2, struct2A);

		assertEquals(15, struct.getLength());
		assertEquals(9, struct.getNumComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(5, comps[2].getOffset());
		assertEquals(4, comps[2].getOrdinal());
		assertEquals(3, comps[2].getLength());
		assertEquals(10, comps[3].getOffset());
		assertEquals(7, comps[3].getOrdinal());
	}

	@Test
	public void testDeleteMany() {

		struct.growStructure(20);
		struct.insertAtOffset(12, WordDataType.dataType, -1, "A", null);
		struct.insertAtOffset(16, WordDataType.dataType, -1, "B", null);

		assertEquals(32, struct.getLength());
		assertEquals(26, struct.getNumComponents());
		assertEquals(6, struct.getNumDefinedComponents());

		struct.delete(Sets.newHashSet(1, 4, 5));

		assertEquals(28, struct.getLength());
		assertEquals(23, struct.getNumComponents());
		assertEquals(5, struct.getNumDefinedComponents());

		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(WordDataType.class, comps[3].getDataType().getClass());
		assertEquals(5, comps[3].getOrdinal());
		assertEquals(8, comps[3].getOffset());
	}

	@Test
	public void testDeleteManyBF() throws InvalidDataTypeException {

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");
		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");
		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//					"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		struct.delete(Sets.newHashSet(1, 2, 3, 4, 5, 6));

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//					"   1   undefined   1   null   \"\"\n" + 
//					"   2   undefined   1   null   \"\"\n" + 
//					"   3   undefined   1   null   \"\"\n" + 
//					"   4   undefined   1   null   \"\"\n" + 
			"   5   dword   4   field3   \"\"\n" + 
			"   9   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 10   Actual Alignment = 1", struct);
		//@formatter:on

		assertEquals(10, struct.getLength());
		assertEquals(7, struct.getNumComponents());
		assertEquals(3, struct.getNumDefinedComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(5, comps[1].getOffset());
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
	public void testDeleteBF() throws InvalidDataTypeException {

		struct.insertBitFieldAt(2, 4, 0, IntegerDataType.dataType, 3, "bf1", "bf1Comment");
		struct.insertBitFieldAt(2, 4, 3, IntegerDataType.dataType, 3, "bf2", "bf2Comment");
		struct.insertBitFieldAt(2, 4, 6, IntegerDataType.dataType, 15, "bf3", "bf3Comment");
		struct.insertBitFieldAt(2, 4, 21, IntegerDataType.dataType, 11, "bf4", "bf4Comment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   word   2   null   \"Comment2\"\n" + 
			"   8   dword   4   field3   \"\"\n" + 
			"   12   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 13   Actual Alignment = 1", struct);
		//@formatter:on

		struct.delete(6);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:3(3)   1   bf2   \"bf2Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 11   Actual Alignment = 1", struct);
		//@formatter:on

		struct.delete(3);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
			"   2   int:15(6)   3   bf3   \"bf3Comment\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 11   Actual Alignment = 1", struct);
		//@formatter:on

		struct.delete(3);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
			"   4   int:11(5)   2   bf4   \"bf4Comment\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 11   Actual Alignment = 1", struct);
		//@formatter:on

		struct.delete(4);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
			"   2   int:3(0)   1   bf1   \"bf1Comment\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
//			"   4   undefined   1   null   \"\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 11   Actual Alignment = 1", struct);
		//@formatter:on

		struct.delete(2);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
//			"   2   undefined   1   null   \"\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
//			"   4   undefined   1   null   \"\"\n" + 
//			"   5   undefined   1   null   \"\"\n" + 
			"   6   dword   4   field3   \"\"\n" + 
			"   10   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 11   Actual Alignment = 1", struct);
		//@formatter:on

		struct.delete(2);

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
//			"   1   undefined   1   null   \"\"\n" + 
//			"   2   undefined   1   null   \"\"\n" + 
//			"   3   undefined   1   null   \"\"\n" + 
//			"   4   undefined   1   null   \"\"\n" + 
			"   5   dword   4   field3   \"\"\n" + 
			"   9   byte   1   field4   \"Comment4\"\n" + 
			"}\n" + 
			"Size = 10   Actual Alignment = 1", struct);
		//@formatter:on

		assertEquals(10, struct.getLength());
		assertEquals(7, struct.getNumComponents());
		assertEquals(3, struct.getNumDefinedComponents());
		DataTypeComponent[] comps = struct.getDefinedComponents();
		assertEquals(DWordDataType.class, comps[1].getDataType().getClass());
		assertEquals(5, comps[1].getOffset());
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
	public void testDeleteComponent() {
		Structure s = new StructureDataType("test1", 0);
		s.add(new ByteDataType());
		s.add(new FloatDataType());

		struct.add(s);

		DataTypeComponent[] dtc = struct.getComponents();
		assertEquals(5, dtc.length);

		struct.dataTypeDeleted(s);

		dtc = struct.getComponents();
		assertEquals(9, dtc.length);

		assertEquals(9, struct.getNumComponents());
	}

	@Test
	public void testDeleteAll() {

		struct.setPackingEnabled(true); // enable packing for struct
		assertEquals(12, struct.getLength());

		Structure s = new StructureDataType("test1", 0);
		s.add(new ByteDataType());
		s.add(new FloatDataType());
		assertEquals(1, s.getAlignment());
		assertEquals(5, s.getLength());

		struct.add(s);
		assertEquals(16, struct.getLength());

		s.deleteAll();
		assertEquals(1, s.getLength());
		assertTrue(s.isNotYetDefined());
		assertTrue(s.isZeroLength());
		assertEquals(0, s.getNumComponents());

		assertEquals(12, struct.getLength());

	}

	@Test
	public void testAlignmentAndPacking() {

		struct.setPackingEnabled(true); // enable packing for struct
		assertEquals(12, struct.getLength());

		Structure s = new StructureDataType("test1", 0);
		s.add(new ByteDataType());
		s.add(new FloatDataType());
		assertEquals(1, s.getAlignment());
		assertEquals(5, s.getLength());

		struct.add(s);
		assertEquals(16, struct.getLength());

		s.setExplicitMinimumAlignment(8); // does not force packing (s length unaffected)

		assertEquals(5, s.getLength());
		assertFalse(s.isNotYetDefined());
		assertFalse(s.isZeroLength());
		assertEquals(2, s.getNumComponents());

		assertEquals(24, struct.getLength());
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
	public void testAddVarLengthDataTypes() {
		Structure s1 = createStructure("Test1", 0);
		s1.add(new StringDataType(), 5);
		s1.add(new StringDataType(), 10);
		s1.add(new StringDataType(), 15);

		DataTypeComponent dtc = s1.getComponentAt(5);
		DataType dt = dtc.getDataType();
		assertEquals(-1, dt.getLength());
		assertEquals(10, dtc.getLength());
		assertEquals("string", dt.getDisplayName());

	}

	@Test
	public void testReplaceVarLengthDataTypes() {
		Structure s1 = new StructureDataType("Test1", 25);

		s1.replaceAtOffset(0, new StringDataType(), 5, null, null);
		s1.replaceAtOffset(5, new StringDataType(), 10, null, null);
		s1.replaceAtOffset(15, new StringDataType(), 10, null, null);

		DataTypeComponent dtc = s1.getComponentAt(5);
		DataType dt = dtc.getDataType();
		assertEquals(-1, dt.getLength());
		assertEquals(10, dtc.getLength());
		assertEquals("string", dt.getDisplayName());
	}

	@Test
	public void testReplaceVarLengthDataTypes2() {

		Structure s1 = new StructureDataType("Test1", 0x60);
		s1.replaceAtOffset(0, new StringDataType(), 0xd, null, null);

		s1.replaceAtOffset(0xd, new StringDataType(), 0xd, null, null);
		s1.replaceAtOffset(0x19, new StringDataType(), 0xc, null, null);
		s1.replaceAtOffset(0x24, new StringDataType(), 0xb, null, null);
		s1.replaceAtOffset(0x31, new StringDataType(), 0xd, null, null);
		s1.replaceAtOffset(0x3e, new StringDataType(), 0xa, null, null);
		s1.replaceAtOffset(0x48, new StringDataType(), 0xb, null, null);
		s1.replaceAtOffset(0x53, new StringDataType(), 0xd, null, null);

		DataTypeComponent dtc = s1.getComponentAt(0);
		DataType dt = dtc.getDataType();
		assertEquals("string", dt.getDisplayName());
		assertEquals(0xd, dtc.getLength());

		dtc = s1.getComponentAt(0x31);
		dt = dtc.getDataType();
		assertEquals("string", dt.getDisplayName());
		assertEquals(0xd, dtc.getLength());
	}

	@Test
	public void testSetName() throws Exception {
		Structure s1 = new StructureDataType("Test1", 0);
		s1.add(new StringDataType(), 5);
		s1.add(new StringDataType(), 10);
		s1.add(new StringDataType(), 15);
		s1.add(new ByteDataType());

		s1.setName("NewName");

		assertEquals("NewName", s1.getName());
	}

	@Test
	public void testTypedefName() throws Exception {
		Structure s1 = new StructureDataType("Test1", 0);
		s1.add(new StringDataType(), 5);
		s1.add(new StringDataType(), 10);
		TypedefDataType typdef = new TypedefDataType("TypedefToTest1", s1);

		assertEquals("TypedefToTest1", typdef.getName());

		typdef.setName("NewTypedef");
		assertEquals("NewTypedef", typdef.getName());
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

	@Test
	public void testReplaceWith2() throws InvalidDataTypeException {

		// NOTE: pack(disabled) bitfields should remain unchanged when
		// transitioning endianess even though it makes little sense.
		// pack(disabled) structures are not intended to be portable! 

		TypeDef td = new TypedefDataType("Foo", IntegerDataType.dataType);

		struct.insertBitFieldAt(9, 1, 0, td, 4, "MyBit1", "bitComment1");
		struct.insertBitFieldAt(9, 1, 4, td, 3, "MyBit2", "bitComment2");
		struct.insertBitFieldAt(9, 2, 7, td, 2, "MyBit3", "bitComment3");
		struct.growStructure(1);

		struct.setFlexibleArrayComponent(td, "myFlex", "flexComment");

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/TestStruct\n" + 
			"pack(disabled)\n" + 
			"Structure TestStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2   null   \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1   null   \"\"\n" + 
			"   9   Foo:4(0)   1   MyBit1   \"bitComment1\"\n" + 
			"   9   Foo:3(4)   1   MyBit2   \"bitComment2\"\n" + 
			"   9   Foo:2(7)   2   MyBit3   \"bitComment3\"\n" + 
//			"   11   undefined   1   null   \"\"\n" + 
			"   Foo[0]   0   myFlex   \"flexComment\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 1", struct);
		//@formatter:on

		DataTypeManager beDtm = new MyBigEndianDataTypeManager();

		Structure newStruct = new StructureDataType("bigStruct", 0, beDtm);
		newStruct.replaceWith(struct);

		assertTrue(newStruct.getDataOrganization().isBigEndian());

		//@formatter:off
		CompositeTestUtils.assertExpectedComposite(this, "/bigStruct\n" + 
			"pack(disabled)\n" + 
			"Structure bigStruct {\n" + 
			"   0   byte   1   field1   \"Comment1\"\n" + 
			"   1   word   2   null   \"Comment2\"\n" + 
			"   3   dword   4   field3   \"\"\n" + 
			"   7   byte   1   field4   \"Comment4\"\n" + 
//			"   8   undefined   1   null   \"\"\n" + 
			"   9   Foo:4(0)   1   MyBit1   \"bitComment1\"\n" + 
			"   9   Foo:3(4)   1   MyBit2   \"bitComment2\"\n" + 
			"   9   Foo:2(7)   2   MyBit3   \"bitComment3\"\n" + 
//			"   11   undefined   1   null   \"\"\n" + 
			"   Foo[0]   0   myFlex   \"flexComment\"\n" + 
			"}\n" + 
			"Size = 12   Actual Alignment = 1", newStruct);
		//@formatter:on
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
		Pointer p = (Pointer) struct.getComponent(0).getDataType();
		TypedefDataType dataType = (TypedefDataType) p.getDataType();
		assertEquals(dataType, typeDef);
		assertEquals(dataType.getBaseDataType(), struct);
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

	protected class MyBigEndianDataTypeManager extends StandAloneDataTypeManager {
		MyBigEndianDataTypeManager() {
			super("BEdtm");
			DataOrganizationImpl dataOrg = DataOrganizationImpl.getDefaultOrganization(null);
			dataOrg.setBigEndian(true);
			this.dataOrganization = dataOrg;
		}
	}

}
