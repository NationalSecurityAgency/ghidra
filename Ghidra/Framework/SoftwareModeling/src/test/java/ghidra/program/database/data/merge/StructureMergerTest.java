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
package ghidra.program.database.data.merge;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.*;
import ghidra.util.UniversalIdGenerator;

public class StructureMergerTest extends AbstractGenericTest {
	private DataType wordDt;
	private DataType dwordDt;
	private IntegerDataType intDt;
	private DataType zeroArray;
	private StandAloneDataTypeManager dtm;
	private int txId;

	@Before
	public void setUp() throws Exception {
		UniversalIdGenerator.initialize();
		wordDt = new WordDataType();
		dwordDt = new DWordDataType();
		intDt = new IntegerDataType();
		zeroArray = new ArrayDataType(intDt, 0);
		dtm = new StandAloneDataTypeManager("Test");
		txId = dtm.startTransaction("Test");
	}

	@After
	public void tearDown() {
		dtm.endTransaction(txId, false);
	}

	@Test
	public void testSimpleMerge() throws Exception {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(4, wordDt, "bob")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "bob")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
	}

	@Test
	public void testSimpleMerge_NoDb() throws Exception {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.build();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(4, wordDt, "bob")
				.build();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "bob")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
	}

	@Test
	public void testNameCollision() {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(4, wordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(4, wordDt, "bob")
				.buildDb();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		try {
			merger.merge();
			fail("Expected error for name collision");
		}
		catch (DataTypeMergeException e) {
			assertEquals(
				"Components have conflicting field names at ordinal 4, offset 4. Names: joe vs bob",
				e.getMessage());
		}
	}

	@Test
	public void testMerge_DifferentSizes() throws Exception {
		Structure struct1 = new StructureBuilder(dtm, "A", 4)
				.add(0, wordDt, "joe")
				.build();

		Structure struct2 = new StructureBuilder(dtm, "B", 12)
				.add(4, wordDt, "bob")
				.build();

		Structure expected = new StructureBuilder(dtm, "A", 12)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "bob")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);

		Structure result = merger.merge();
		assertStructEquals(expected, result);

		// expected a warning
		List<String> warnings = merger.getWarnings();
		assertEquals(1, warnings.size());
		assertEquals("Structures are not the same size.", warnings.get(0));
	}

	@Test
	public void testOverlappingFields_otherInsertsIntoMiddleOfExisting() {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(3, wordDt, "bob")
				.buildDb();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		try {
			merger.merge();
			fail("Expected error for offcut collision");
		}
		catch (DataTypeMergeException e) {
			assertEquals("Conflict at offset 3. Existing component extends to this offset.",
				e.getMessage());
		}
	}

	@Test
	public void testOverlappingFields_NotEnoughRoom() {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(3, dwordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, dwordDt, "bob")
				.buildDb();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		try {
			merger.merge();
			fail("Expected error for offcut collision");
		}
		catch (DataTypeMergeException e) {
			assertEquals("Conflict at offset 0. Not enough undefined bytes to insert here.",
				e.getMessage());
		}
	}

	@Test
	public void testDefinedFieldNameOverridesDefaultFieldName() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, null)
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, dwordDt, "bob")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "bob")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();
		assertStructEquals(expected, result);
	}

	@Test
	public void testUpgradeFromUndefined4ToDWord() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, new Undefined4DataType(), "bob", "aaa")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, dwordDt, "bob", "aaa")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "bob", "aaa")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();
		assertStructEquals(expected, result);

		// expected a warning
		List<String> warnings = merger.getWarnings();
		assertEquals(1, warnings.size());
		assertEquals("Merging 'undefined4' and 'dword' at offset 0 to 'dword'.",
			warnings.get(0));
	}

	@Test
	public void testUpgradeFromUndefined4ToDWord_otherDirection() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "bob", "aaa")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, new Undefined4DataType(), "bob", "aaa")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "bob", "aaa")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();
		assertStructEquals(expected, result);

		// expected a warning
		List<String> warnings = merger.getWarnings();
		assertEquals(1, warnings.size());
		assertEquals("Merging 'dword' and 'undefined4' at offset 0 to 'dword'.",
			warnings.get(0));
	}

	@Test
	public void testUpgradeFromDWordToPointer() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "bob", "aaa")
				.buildDb();

		PointerDataType pointer = new PointerDataType(intDt);
		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, pointer, "bob", "aaa")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, pointer, "bob", "aaa")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();
		assertStructEquals(expected, result);
		// expected a warning
		List<String> warnings = merger.getWarnings();
		assertEquals(1, warnings.size());
		assertEquals("Merging 'dword' and 'int *' at offset 0 to 'int *'.", warnings.get(0));
	}

	@Test
	public void testUpgradePointers() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, new PointerDataType(new Undefined4DataType()), "bob", "aaa")
				.buildDb();

		PointerDataType pointer = new PointerDataType(intDt);
		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, new PointerDataType(new IntegerDataType()), "bob", "aaa")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, new PointerDataType(new IntegerDataType()), "bob", "aaa")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();
		assertStructEquals(expected, result);
		// expected a warning
		List<String> warnings = merger.getWarnings();
		assertEquals(1, warnings.size());
		assertEquals("Merging 'undefined4 *' and 'int *' at offset 0 to 'int *'.", warnings.get(0));
	}

	@Test
	public void testPackedStructureSameExceptFieldName() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, null)
				.pack()
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, dwordDt, "bob")
				.pack()
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "bob")
				.pack()
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();
		assertStructEquals(expected, result);
	}

	@Test
	public void testPackedStructureDifferentSize() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, null)
				.pack()
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, dwordDt, "bob")
				.add(4, dwordDt, "joe")
				.pack()
				.buildDb();

		StructureMerger merger = new StructureMerger(struct1, struct2);

		Structure result = merger.merge();
		assertFalse(result.isPackingEnabled());
	}

	@Test
	public void testMergingPackedIntoUnpacked() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(4, dwordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, dwordDt, "bob")
				.pack()
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, dwordDt, "bob")
				.add(4, dwordDt, "joe")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();
		assertStructEquals(expected, result);
	}

	@Test
	public void testMergeCyclic() throws Exception {
		Structure struct1 = new StructureBuilder(dtm, "A", 16)
				.add(0, wordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 16)
				.add(4, wordDt, "bob")
				.add(10, new PointerDataType(struct1), "ptr2")
				.buildDb();
		struct1.replaceAtOffset(6, new PointerDataType(struct2), 6, "ptr1", null);

		Structure expected = new StructureBuilder(dtm, "A", 16)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "bob")
				.build();
		expected.replaceAtOffset(6, new PointerDataType(expected), 4, "ptr1", null);
		expected.replaceAtOffset(10, new PointerDataType(expected), 4, "ptr2", null);

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();

		// we need to do the replace with to complete the cycle
		struct1.replaceWith(result);
		dtm.replaceDataType(struct2, struct1, false);
		assertStructEquals(expected, struct1);
	}

	@Test
	public void testMergeSameDescription() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 16)
				.add(0, wordDt, "joe")
				.description("Hi")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 16)
				.add(4, wordDt, "bob")
				.description("Hi")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 16)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "bob")
				.description("Hi")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
		assertEquals("Hi", expected.getDescription());
	}

	@Test
	public void testMergeDifferentDescription() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 16)
				.add(0, wordDt, "joe")
				.description("Hi")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 16)
				.add(4, wordDt, "bob")
				.description("There")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 16)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "bob")
				.description("Hi There")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
		assertEquals("Hi There", expected.getDescription());
	}

	@Test
	public void testDatatypeCollisionNonTerminate() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, intDt, "bob")
				.add(4, wordDt, "cal")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "cal")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2, false);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
	}

	@Test
	public void testDatatypeUpgradeNamesDifferNonTerminate() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, new Undefined4DataType(), "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, intDt, "bob")
				.add(4, wordDt, "cal")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, intDt, "joe")
				.add(4, wordDt, "cal")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2, false);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
	}

	@Test
	public void testNameCollisionNonTerminate() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, wordDt, "bob")
				.add(4, wordDt, "cal")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.add(4, wordDt, "cal")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2, false);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
	}

	@Test
	public void testZeroLengthArraysNoConflict() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(0, zeroArray, "bob")
				.add(0, zeroArray, "cal")
				.add(4, wordDt, "dave")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.add(0, zeroArray, "bob")
				.add(0, zeroArray, "cal")
				.add(0, wordDt, "joe")
				.add(4, wordDt, "dave")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2, false);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
	}

	@Test
	public void testZeroLengthArraysWithConflict() throws DataTypeMergeException {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.add(0, wordDt, "joe")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.add(1, zeroArray, "bob")
				.add(4, wordDt, "dave")
				.buildDb();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		try {
			merger.merge();
			fail("Expected error for offcut collision");
		}
		catch (DataTypeMergeException e) {
			assertEquals("Conflict at offset 1. Existing component extends to this offset.",
				e.getMessage());
		}
	}

	@Test
	public void testBiFieldsNoConflict() throws Exception {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.bitField(0, 1, 0, 2, "A")
				.bitField(0, 1, 6, 7, "B")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.bitField(0, 1, 3, 5, "C")
				.buildDb();

		Structure expected = new StructureBuilder(dtm, "A", 8)
				.bitField(0, 1, 0, 2, "A")
				.bitField(0, 1, 3, 5, "C")
				.bitField(0, 1, 6, 7, "B")
				.build();

		StructureMerger merger = new StructureMerger(struct1, struct2, false);
		Structure result = merger.merge();

		assertStructEquals(expected, result);
	}

	@Test
	public void testBiFieldsWithConflict() throws Exception {
		Structure struct1 = new StructureBuilder(dtm, "A", 8)
				.bitField(0, 1, 0, 2, "A")
				.bitField(0, 1, 6, 7, "B")
				.buildDb();

		Structure struct2 = new StructureBuilder(dtm, "B", 8)
				.bitField(0, 1, 1, 7, "C")
				.buildDb();

		StructureMerger merger = new StructureMerger(struct1, struct2);
		try {
			merger.merge();
			fail("Expected error for offcut collision");
		}
		catch (DataTypeMergeException e) {
			assertEquals("Conflict at offset 0. Conflicting bit field exists at this offset.",
				e.getMessage());
		}
	}

	private void assertStructEquals(Structure expected, Structure actual) {
		if (expected.equals(actual)) {
			return;
		}

		String es = expected.toString();
		String as = actual.toString();
		String msg = "\nExpected: \n%s\nActual: \n%s".formatted(es, as);
		fail(msg);
	}
}
