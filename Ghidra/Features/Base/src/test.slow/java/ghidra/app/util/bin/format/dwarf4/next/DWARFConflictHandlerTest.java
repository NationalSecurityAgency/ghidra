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
package ghidra.app.util.bin.format.dwarf4.next;

import static org.junit.Assert.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 * Tests for the {@link DataTypeConflictHandler conflict handler} stuff.
 *  
 * 
 */
public class DWARFConflictHandlerTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private DataTypeManager dataMgr;
	private int transactionID;

	private CategoryPath root = new CategoryPath(CategoryPath.ROOT, "conflict_test");

	public DWARFConflictHandlerTest() {
		super();
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		dataMgr = program.getDataTypeManager();
		startTransaction();
	}

	@After
	public void tearDown() throws Exception {
		endTransaction();
		program.release(this);
	}

	private StructureDataType createPopulated(DataTypeManager dtm) {
		StructureDataType struct = new StructureDataType(root, "struct1", 0, dtm);
		struct.add(new CharDataType(dataMgr), 1, "char1", null);
		struct.add(new CharDataType(dataMgr), 1, "char2", null);

		return struct;
	}

	private StructureDataType createPopulated2(DataTypeManager dtm) {
		StructureDataType struct = new StructureDataType(root, "struct1", 0, dtm);
		struct.add(new CharDataType(dataMgr), 1, "blah1", null);
		struct.add(new CharDataType(dataMgr), 1, "blah2", null);
		struct.add(new CharDataType(dataMgr), 1, "blah3", null);
		struct.add(new CharDataType(dataMgr), 1, "blah4", null);

		return struct;
	}

	private StructureDataType createPopulated2Partial(DataTypeManager dtm) {
		StructureDataType struct = createPopulated2(dtm);
		struct.clearComponent(2);
		struct.clearComponent(1);

		return struct;
	}

	private StructureDataType createStub(DataTypeManager dtm, int size) {
		return new StructureDataType(root, "struct1", size, dtm);
	}

	/**
	 * Assert a particular ConflictResult outcome when adding two structs to the DTM.
	 * <p>
	 * Create a copy of the "addingStruct" before adding it because the impl instance can be
	 * modified during the conflict resolution by the DTM when it tries to DataType.clone()
	 * it before renaming the clone().
	 * <p>
	 * @param existingStruct
	 * @param addingStruct
	 * @param expectedResult
	 */
	private void assertStruct(Composite existingStruct, Composite addingStruct,
			ConflictResult expectedResult) {
		DataType existingResult =
			dataMgr.addDataType(existingStruct, DWARFDataTypeConflictHandler.INSTANCE);
		DataType existingResult_copy = existingResult.copy(null);

		DataType addingCopy = addingStruct.copy(null);
		DataType addedResult =
			dataMgr.addDataType(addingStruct, DWARFDataTypeConflictHandler.INSTANCE);

		switch (expectedResult) {
			case USE_EXISTING:
				assertEquals("DataType name should match", existingResult.getName(),
					addedResult.getName());
				assertEquals("DataType CategoryPath should match", existingResult.getCategoryPath(),
					addedResult.getCategoryPath());
				assertEquals("DataType length should match", existingResult.getLength(),
					addedResult.getLength());
				assertTrue("Added DataType should be equiv to existing DataType",
					addedResult.isEquivalent(existingResult));
				break;
			case REPLACE_EXISTING:
				assertEquals("DataType name should match", addingCopy.getName(),
					addedResult.getName());
				assertEquals("DataType CategoryPath should match", addingCopy.getCategoryPath(),
					addedResult.getCategoryPath());
				assertEquals("DataType length should match", addingCopy.getLength(),
					addedResult.getLength());
				assertTrue("Added DataType should be equiv to its impl before it was added",
					addedResult.isEquivalent(addingCopy));
				assertFalse("Added DataType should not be equiv to existing DataType",
					addedResult.isEquivalent(existingResult_copy));
// NOTE: direct member replacement works in most cases
//				assertTrue("Overwritten DataType should have a deleted flag",
//					existingResult.isDeleted());
				break;
			case RENAME_AND_ADD:
				Assert.assertNotEquals("DataType name should have changed", addingCopy.getName(),
					addedResult.getName());
				assertEquals("DataType CategoryPath should not changed",
					addingCopy.getCategoryPath(), addedResult.getCategoryPath());
				assertEquals("DataType length should not change", addingCopy.getLength(),
					addedResult.getLength());
				break;
		}
	}

	/**
	 * Tests the {@link DWARFDataTypeConflictHandler#INSTANCE}
	 * conflict handler to ensure that adding a empty conflicting structure resolves to a previous
	 * populated structure.
	 */
	@Test
	public void testAddEmptyStructResolveToPopulatedStruct1() {
		assertStruct(createPopulated(dataMgr), createStub(dataMgr, 0), ConflictResult.USE_EXISTING);
	}

	@Test
	public void testAddEmptyStructResolveToPopulatedStruct2() {
		assertStruct(createPopulated(null), createStub(null, 0), ConflictResult.USE_EXISTING);
	}

	/**
	 * Tests the {@link DWARFDataTypeConflictHandler#INSTANCE}
	 * conflict handler to ensure that adding a populated structure replaces an existing
	 * 'empty' structure.  'Empty' means either 0 byte length or 1 byte length structs
	 * as previous versions of Ghidra did not allow truly empty structs.
	 */
	@Test
	public void testAddPopulatedStructOverwriteStub1() {
		assertStruct(createStub(dataMgr, 0), createPopulated(dataMgr),
			ConflictResult.REPLACE_EXISTING);
	}

	@Test
	public void testAddPopulatedStructOverwriteStub2() {
		assertStruct(createStub(null, 0), createPopulated(null), ConflictResult.REPLACE_EXISTING);
	}

	@Test
	public void testAddPopulatedStructOverwriteSameSizedStub() {
		StructureDataType populated = createPopulated(dataMgr);
		assertStruct(createStub(dataMgr, populated.getLength()), populated,
			ConflictResult.REPLACE_EXISTING);
	}

	@Test
	public void testAddStubStructUseSameSizedPopulated() {
		StructureDataType populated = createPopulated(dataMgr);
		assertStruct(populated, createStub(dataMgr, populated.getLength()),
			ConflictResult.USE_EXISTING);
	}

	@Test
	public void testAddStubStructCreateConflict() {
		StructureDataType populated = createPopulated(dataMgr);
		assertStruct(populated, createStub(dataMgr, populated.getLength() + 1),
			ConflictResult.RENAME_AND_ADD);
	}

	@Test
	public void testAddPartialStructResolveToPopulatedStruct() {
		assertStruct(createPopulated2(dataMgr), createPopulated2Partial(dataMgr),
			ConflictResult.USE_EXISTING);
	}

	@Test
	public void testAddPopulatedStructOverwritePartialStruct() {
		assertStruct(createPopulated2Partial(dataMgr), createPopulated2(dataMgr),
			ConflictResult.REPLACE_EXISTING);
	}

	@Test
	public void testAddStubUnionResolveToPopulated() {
		Union populated = new UnionDataType(root, "union1", dataMgr);
		populated.add(new CharDataType(dataMgr), 1, "blah1", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah2", null);

		Union stub = new UnionDataType(root, "union1", dataMgr);

		assertStruct(populated, stub, ConflictResult.USE_EXISTING);
	}

	@Test
	public void testAddPopulatedUnionOverwriteStub() {
		Union populated = new UnionDataType(root, "union1", dataMgr);
		populated.add(new CharDataType(dataMgr), 1, "blah1", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah2", null);

		Union stub = new UnionDataType(root, "union1", dataMgr);

		assertStruct(stub, populated, ConflictResult.REPLACE_EXISTING);
	}

	@Test
	public void testAddPopulatedUnionOverwritePartial() {
		Union populated = new UnionDataType(root, "union1", dataMgr);
		populated.add(new CharDataType(dataMgr), 1, "blah1", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah2", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah3", null);

		Union partial = new UnionDataType(root, "union1", dataMgr);
		partial.add(new CharDataType(dataMgr), 1, "blah1", null);

		assertStruct(partial, populated, ConflictResult.REPLACE_EXISTING);
	}

	@Test
	public void testAddConflictUnion() {
		Union populated = new UnionDataType(root, "union1", dataMgr);
		populated.add(new CharDataType(dataMgr), 1, "blah1", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah2", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah3", null);

		Union populated2 = new UnionDataType(root, "union1", dataMgr);
		populated2.add(new CharDataType(dataMgr), 1, "blahA", null);

		assertStruct(populated, populated2, ConflictResult.RENAME_AND_ADD);
	}

	@Test
	public void testAddPartialUnionWithStubStructResolveToExisting() {
		Structure s1a = createPopulated(dataMgr);
		Union populated = new UnionDataType(root, "union1", dataMgr);
		populated.add(new CharDataType(dataMgr), 1, "blah1", null);
		populated.add(s1a, s1a.getLength(), "blah2", null);
		populated.add(s1a, s1a.getLength(), null, null);

		Structure s1b = createStub(dataMgr, 0);
		Union partial = new UnionDataType(root, "union1", dataMgr);
		partial.add(s1b, s1b.getLength(), "blah2", null);

		assertStruct(populated, partial, ConflictResult.USE_EXISTING);
	}

	/**
	 * Tests the {@link DWARFDataTypeConflictHandler#INSTANCE}
	 * conflict handler to ensure that adding a conflicting typedef to a conflicting stub structure 
	 * (when there is already a typedef to a populated structure) correctly uses the 
	 * existing populated structure and existing typedef to the populated structure.
	 */
	@Test
	public void testTypedefToStubUseExistingTypedefToPopulatedStructure() {
		StructureDataType populatedStructure = createPopulated(dataMgr);
		int origPopStructLen = populatedStructure.getLength();
		TypeDef populatedTD = new TypedefDataType(root, "typedef1", populatedStructure, dataMgr);
		dataMgr.addDataType(populatedTD, null);

		StructureDataType stubStructure = createStub(dataMgr, 0);
		TypeDef stubTD = new TypedefDataType(root, "typedef1", stubStructure, dataMgr);
		DataType stubTDResult = dataMgr.addDataType(stubTD, DWARFDataTypeConflictHandler.INSTANCE);

		assertTrue(stubTDResult instanceof TypeDef);

		assertEquals(populatedTD.getPathName(), stubTDResult.getPathName());

		DataType stubTDResultRefdDT = ((TypeDef) stubTDResult).getDataType();
		assertEquals(stubTDResultRefdDT.getLength(), origPopStructLen);
	}

	/**
	 * Tests the {@link DWARFDataTypeConflictHandler#INSTANCE}
	 * conflict handler to ensure that adding truly conflicting structures and typedefs
	 * are treated as new data types and are renamed to a different name when added.
	 */
	@Test
	public void testTypedefConflictToConflictStruct() {
		StructureDataType struct1a = createPopulated(dataMgr);
		TypeDef td1a = new TypedefDataType(root, "typedef1", struct1a, dataMgr);
		DataType td1a_result = dataMgr.addDataType(td1a, null);
		String td1a_result_path = td1a_result.getPathName();

		DataType s1a_result = ((TypeDef) td1a_result).getDataType();
		String s1a_result_path = s1a_result.getPathName();

		StructureDataType struct1b = createPopulated2(dataMgr);
		TypeDef td1b = new TypedefDataType(root, "typedef1", struct1b, dataMgr);
		DataType td1b_result = dataMgr.addDataType(td1b, DWARFDataTypeConflictHandler.INSTANCE);
		String td1b_result_path = td1b_result.getPathName();

		DataType s1b_result = ((TypeDef) td1b_result).getDataType();
		String s1b_result_path = s1b_result.getPathName();

		Assert.assertNotEquals(td1a_result_path, td1b_result_path);
		Assert.assertNotEquals(s1a_result_path, s1b_result_path);
		assertFalse(td1a_result.isDeleted());
		assertFalse(s1a_result.isDeleted());
	}

	/**
	 * Tests the {@link DWARFDataTypeConflictHandler#INSTANCE}
	 * conflict handler when adding a conflicting typedef impl that is referred to multiple 
	 * times during a single addDataType() call.
	 * <p>
	 * Success is if the fields of struct2 are all the same datatype, probably named typedef1.conflict.
	 * <p>
	 * A failure would be if the fields of struct2 are different types, ie. field1 is typedef1.conflict,
	 * field2 is typedef1.conflict1, field3 is typedef1.conflict2.
	 * <p>
	 * This test is useful because the typedef impl that is referred to multiple times causes
	 * equiv checking and conflict resolution each time it is referred to, and if a precondition
	 * for those checks changes in some way and causes it to operate differently, this test will
	 * fail.
	 */
	@Test
	public void testTypedefConflictToConflictStructMultiRef() {
		StructureDataType struct1a = createPopulated(dataMgr);
		TypeDef td1a = new TypedefDataType(root, "typedef1", struct1a, dataMgr);
		DataType td1a_result = dataMgr.addDataType(td1a, DWARFDataTypeConflictHandler.INSTANCE);

		StructureDataType struct1b = createPopulated2(dataMgr);
		TypeDef td1b = new TypedefDataType(root, "typedef1", struct1b, dataMgr);

		// Struct2 is used to create multiple references to the same conflicting typedef impl.
		StructureDataType struct2 = new StructureDataType(root, "struct2", 0, dataMgr);
		struct2.add(td1b, "typedef1_instance1", "first");
		struct2.add(td1b, "typedef1_instance2", "second");
		struct2.add(td1b, "typedef1_instance3", "third");

		Structure struct2_result =
			(Structure) dataMgr.addDataType(struct2, DWARFDataTypeConflictHandler.INSTANCE);

		TypeDef td1b_result = (TypeDef) struct2_result.getComponent(0).getDataType();
		String td1b_conflict_name = td1b_result.getPathName();
		Assert.assertNotEquals(td1b_conflict_name, td1a_result.getPathName());

		for (DataTypeComponent dtc : struct2_result.getComponents()) {
			DataType dtcDT = dtc.getDataType();
			String dtcDTName = dtcDT.getPathName();
			assertEquals(dtcDTName, td1b_conflict_name);
		}
	}

	/**
	 * Tests the {@link DWARFDataTypeConflictHandler#INSTANCE}
	 * conflict handler  when adding a conflicting typedef impl (but equiv) that is referred to multiple 
	 * times during a single addDataType() call.
	 * <p>
	 * Success is if the fields of struct2 are all the original typedef1 type.
	 * <p>
	 * A failure would be if the fields of struct2 are different types.
	 */
	@Test
	public void testTypedefToStubUseExistingTypedefToPopulatedStructureMultiRef() {
		StructureDataType struct1a = createPopulated(dataMgr);
		TypeDef td1a = new TypedefDataType(root, "typedef1", struct1a, dataMgr);
		DataType td1a_result = dataMgr.addDataType(td1a, DWARFDataTypeConflictHandler.INSTANCE);
		String origtd1Name = td1a_result.getPathName();

		StructureDataType struct1b = createStub(dataMgr, 0);
		TypeDef td1b = new TypedefDataType(root, "typedef1", struct1b, dataMgr);
		PointerDataType ptd = new PointerDataType(td1b, program.getDefaultPointerSize(), dataMgr);

		// Struct2 is used to create multiple references to the same conflicting typedef impl.
		// Use a pointer to the typedef, otherwise struct2's size will be wrong when the
		// conflicting struct1 impl size changes from 0 to 10.
		StructureDataType struct2 = new StructureDataType(root, "struct2", 0, dataMgr);
		struct2.add(ptd, "typedef1_instance1", "first");
		struct2.add(ptd, "typedef1_instance2", "second");
		struct2.add(ptd, "typedef1_instance3", "third");

		Structure struct2_result =
			(Structure) dataMgr.addDataType(struct2, DWARFDataTypeConflictHandler.INSTANCE);

		for (DataTypeComponent dtc : struct2_result.getComponents()) {
			Pointer pr = (Pointer) dtc.getDataType();
			TypeDef tr = (TypeDef) pr.getDataType();
			String dtcDTName = tr.getPathName();
			assertEquals(origtd1Name, dtcDTName);
		}
	}

	/**
	 * Tests the {@link DWARFDataTypeConflictHandler#INSTANCE}
	 * conflict handler when adding a typedef to a populated when there is already a typedef
	 * to a stub structure.  
	 */
	@Test
	public void testAddTypedefToPopulatedStructReplaceTypedefToStubStructure() {
		StructureDataType struct1a = createStub(dataMgr, 0);
		TypeDef td1a = new TypedefDataType(root, "typedef1", struct1a, dataMgr);
		DataType td1a_result = dataMgr.addDataType(td1a, DWARFDataTypeConflictHandler.INSTANCE);
		String td1a_pathname = td1a_result.getPathName();
		String struct1a_pathname = ((TypeDef) td1a_result).getDataType().getPathName();

		StructureDataType struct1b = createPopulated(dataMgr);
		TypeDef td1b = new TypedefDataType(root, "typedef1", struct1b, dataMgr);

		DataType td1b_result = dataMgr.addDataType(td1b, DWARFDataTypeConflictHandler.INSTANCE);
		String td1b_pathname = td1b_result.getPathName();
		String struct1b_pathname = ((TypeDef) td1b_result).getDataType().getPathName();

		assertEquals("Typedef should have same name as previous typedef", td1a_pathname,
			td1b_pathname);
		assertEquals("Typedef target should have same name as previous typedef target",
			struct1a_pathname, struct1b_pathname);
	}

	@Test
	public void testResolveDataTypeStructConflict() throws Exception {
		DataTypeManager dtm = new StandAloneDataTypeManager("Test");
		int id = dtm.startTransaction("");
		Category otherRoot = dataMgr.getRootCategory();
		Category subc = otherRoot.createCategory("subc");

		Structure struct = new StructureDataType(subc.getCategoryPath(), "struct1", 10);

		DataType resolvedStruct = dtm.resolve(struct, DWARFDataTypeConflictHandler.INSTANCE);
		assertTrue(struct.isEquivalent(resolvedStruct));
		assertEquals("/subc/struct1", resolvedStruct.getPathName());

		struct.replace(0, dtm.resolve(new PointerDataType(resolvedStruct, 4, dtm),
			DWARFDataTypeConflictHandler.INSTANCE), 4);

		// NOTE: placing a DB dataType in an Impl datatype results in an invalid
		// Impl type if one of its children refer to a deleted datatype.  The
		// 'struct' instance is such a case.

		DataType resolvedStructA = dtm.resolve(struct, DWARFDataTypeConflictHandler.INSTANCE);

		// Update struct with the expected result (old empty struct was replaced)
		struct.replace(0, new PointerDataType(resolvedStructA, 4, dtm), 4);

		assertTrue(struct.isEquivalent(resolvedStructA));
		assertEquals("/subc/struct1", resolvedStructA.getPathName());

		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void testResolveDataTypeNonStructConflict() throws Exception {
		DataTypeManager dtm = new StandAloneDataTypeManager("Test");
		int id = dtm.startTransaction("");
		Category otherRoot = dataMgr.getRootCategory();
		Category subc = otherRoot.createCategory("subc");

		EnumDataType e = new EnumDataType(subc.getCategoryPath(), "Enum", 2);

		DataType resolvedEnum = dtm.resolve(e, DWARFDataTypeConflictHandler.INSTANCE);
		assertTrue(e.isEquivalent(resolvedEnum));
		assertEquals("/subc/Enum", resolvedEnum.getPathName());

		e.add("xyz", 1);

		resolvedEnum = dtm.resolve(e, DWARFDataTypeConflictHandler.INSTANCE);
		assertTrue(e.isEquivalent(resolvedEnum));
		assertEquals("/subc/Enum.conflict", resolvedEnum.getPathName());

		dtm.endTransaction(id, true);
		dtm.close();
	}
}
