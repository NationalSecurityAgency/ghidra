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
public class ConflictHandlerTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private DataTypeManagerDB dataMgr;
	private int transactionID;

	private CategoryPath root = new CategoryPath(CategoryPath.ROOT, "conflict_test");

	/**
	 * Constructor for DataManagerTest.
	 * @param arg0
	 */
	public ConflictHandlerTest() {
		super();
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		dataMgr = program.getDataTypeManager();
		startTransaction();
	}

	/*
	 * @see TestCase#tearDown()
	 */
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
		DataType existingResult = dataMgr.addDataType(existingStruct,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		DataType existingResult_copy = existingResult.copy(null);

		DataType addingCopy = addingStruct.copy(null);
		DataType addedResult = dataMgr.addDataType(addingStruct,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

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
	 * Tests the {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
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
	 * Tests the {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
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
	public void testAddStubStructCreateConflict() {
		StructureDataType populated = createPopulated(dataMgr);
		assertStruct(populated, createStub(dataMgr, populated.getLength() + 1),
			ConflictResult.RENAME_AND_ADD);
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
	public void testAddConflictUnion() {
		Union populated = new UnionDataType(root, "union1", dataMgr);
		populated.add(new CharDataType(dataMgr), 1, "blah1", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah2", null);
		populated.add(new IntegerDataType(dataMgr), 4, "blah3", null);

		Union populated2 = new UnionDataType(root, "union1", dataMgr);
		populated2.add(new CharDataType(dataMgr), 1, "blahA", null);

		assertStruct(populated, populated2, ConflictResult.RENAME_AND_ADD);
	}

	/**
	 * Tests the {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
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
		DataType stubTDResult = dataMgr.addDataType(stubTD,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

		assertTrue(stubTDResult instanceof TypeDef);

		assertEquals(populatedTD.getPathName(), stubTDResult.getPathName());

		DataType stubTDResultRefdDT = ((TypeDef) stubTDResult).getDataType();
		assertEquals(stubTDResultRefdDT.getLength(), origPopStructLen);
	}

	/**
	 * Tests the {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
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
		DataType td1b_result = dataMgr.addDataType(td1b,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		String td1b_result_path = td1b_result.getPathName();

		DataType s1b_result = ((TypeDef) td1b_result).getDataType();
		String s1b_result_path = s1b_result.getPathName();

		Assert.assertNotEquals(td1a_result_path, td1b_result_path);
		Assert.assertNotEquals(s1a_result_path, s1b_result_path);
		assertFalse(td1a_result.isDeleted());
		assertFalse(s1a_result.isDeleted());
	}

	/**
	 * Tests the {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
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
		DataType td1a_result = dataMgr.addDataType(td1a,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

		StructureDataType struct1b = createPopulated2(dataMgr);
		TypeDef td1b = new TypedefDataType(root, "typedef1", struct1b, dataMgr);

		// Struct2 is used to create multiple references to the same conflicting typedef impl.
		StructureDataType struct2 = new StructureDataType(root, "struct2", 0, dataMgr);
		struct2.add(td1b, "typedef1_instance1", "first");
		struct2.add(td1b, "typedef1_instance2", "second");
		struct2.add(td1b, "typedef1_instance3", "third");

		Structure struct2_result = (Structure) dataMgr.addDataType(struct2,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

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
	 * Tests the {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
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
		DataType td1a_result = dataMgr.addDataType(td1a,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
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

		Structure struct2_result = (Structure) dataMgr.addDataType(struct2,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);

		for (DataTypeComponent dtc : struct2_result.getComponents()) {
			Pointer pr = (Pointer) dtc.getDataType();
			TypeDef tr = (TypeDef) pr.getDataType();
			String dtcDTName = tr.getPathName();
			assertEquals(origtd1Name, dtcDTName);
		}
	}

	/**
	 * Tests the {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
	 * conflict handler when adding a typedef to a populated when there is already a typedef
	 * to a stub structure.  
	 */
	@Test
	public void testAddTypedefToPopulatedStructReplaceTypedefToStubStructure() {
		StructureDataType struct1a = createStub(dataMgr, 0);
		TypeDef td1a = new TypedefDataType(root, "typedef1", struct1a, dataMgr);
		DataType td1a_result = dataMgr.addDataType(td1a,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		String td1a_pathname = td1a_result.getPathName();
		String struct1a_pathname = ((TypeDef) td1a_result).getDataType().getPathName();

		StructureDataType struct1b = createPopulated(dataMgr);
		TypeDef td1b = new TypedefDataType(root, "typedef1", struct1b, dataMgr);

		DataType td1b_result = dataMgr.addDataType(td1b,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		String td1b_pathname = td1b_result.getPathName();
		String struct1b_pathname = ((TypeDef) td1b_result).getDataType().getPathName();

		assertEquals("Typedef should have same name as previous typedef", td1a_pathname,
			td1b_pathname);
		assertEquals("Typedef target should have same name as previous typedef target",
			struct1a_pathname, struct1b_pathname);
	}

	/**
	 * Tests the
	 * {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
	 * conflict handler to be sure that, if all else is the same, the packed version is chosen
	 * over the non-packed version.
	 * <p>
	 * Success is the packed version is chosen over the non-packed version.
	 */
	@Test
	public void testChooseNewPackedOverExistingNonPackedWhenAllElseIsEqualForEmptyStructures() {
		// NonPacked exists first.
		Structure empty1NonPacked = new StructureDataType(root, "empty1", 0, dataMgr);
		Composite empty1PackedToAdd = (Composite) empty1NonPacked.copy(dataMgr);
		empty1PackedToAdd.setPackingEnabled(true);

		String empty1NonPackedString = empty1NonPacked.toString();
		String empty1PackedToAddString = empty1PackedToAdd.toString();

		Structure empty1AddResult = (Structure) dataMgr.addDataType(empty1PackedToAdd,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		String empty1AddResultString = empty1AddResult.toString();
		assertEquals(empty1PackedToAddString, empty1AddResultString);
		assertNotEquals(empty1NonPackedString, empty1AddResultString);
	}

	/**
	 * Tests the
	 * {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
	 * conflict handler to be sure that, if all else is the same, the packed version is chosen
	 * over the non-packed version.
	 * <p>
	 * Success is the packed version is chosen over the non-packed version.
	 */
	@Test
	public void testChooseNewPackedOverExistingNonPackedWhenAllElseIsEqualForNonEmptyStructures() {
		// NonPacked exists first.
		StructureDataType struct1NonPacked = createPopulated(dataMgr);
		Composite struct1PackedToAdd = (Composite) struct1NonPacked.copy(dataMgr);
		struct1PackedToAdd.setPackingEnabled(true);

		String struct1NonPackedString = struct1NonPacked.toString();
		String struct1PackedToAddString = struct1PackedToAdd.toString();

		Structure struct1AddResult = (Structure) dataMgr.addDataType(struct1PackedToAdd,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		String struct1AddResultString = struct1AddResult.toString();
		assertEquals(struct1PackedToAddString, struct1AddResultString);
		assertNotEquals(struct1NonPackedString, struct1AddResultString);
	}

	/**
	 * Tests the
	 * {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
	 * conflict handler to be sure that, if all else is the same, the new non-packed version is
	 * chosen over the existing non-packed version.
	 * <p>
	 * Success is the new non-packed version is chosen over the existing packed version.
	 */
	// TODO: consider whether we want to change the logic of the conflict handler to favor
	//  packed over non-packed.
	@Test
	public void testChooseNewNonPackedOverExistingPackedWhenAllElseIsEqualForEmptyStructures() {

		// Packed exists first.
		Structure empty2Packed = new StructureDataType(root, "empty2", 0, dataMgr);
		Composite empty2NonPackedToAdd = (Composite) empty2Packed.copy(dataMgr);
		// aligning only after making non-packed copy.
		empty2Packed.setPackingEnabled(true);

		String empty2PackedString = empty2Packed.toString();
		String empty2NonPackedToAddString = empty2NonPackedToAdd.toString();

		Structure empty2AddResult = (Structure) dataMgr.addDataType(empty2NonPackedToAdd,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		String empty2AddResultString = empty2AddResult.toString();
		assertEquals(empty2NonPackedToAddString, empty2AddResultString);
		assertNotEquals(empty2PackedString, empty2AddResultString);
	}

	/**
	 * Tests the
	 * {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
	 * conflict handler to be sure that, if all else is the same, the new non-packed version is
	 * chosen over the existing packed version.
	 * <p>
	 * Success is the new non-packed version is chosen over the existing packed version.
	 */
	// TODO: consider whether we want to change the logic of the conflict handler to favor
	//  packed over non-packed.
	@Test
	public void testChooseNewNonPackedOverExistingPackedWhenAllElseIsEqualForNonEmptyStructures() {

		// Packed exists first.
		StructureDataType struct2Packed = createPopulated(dataMgr);
		Composite struct2NonPackedToAdd = (Composite) struct2Packed.copy(dataMgr);
		// aligning only after making non-packed copy.
		struct2Packed.setPackingEnabled(true);

		String struct2PackedString = struct2Packed.toString();
		String struct2NonPackedToAddString = struct2NonPackedToAdd.toString();

		Structure struct2AddResult = (Structure) dataMgr.addDataType(struct2NonPackedToAdd,
			DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		String struct2AddResultString = struct2AddResult.toString();
		assertEquals(struct2NonPackedToAddString, struct2AddResultString);
		assertNotEquals(struct2PackedString, struct2AddResultString);
	}

	/**
	 * Tests the
	 * {@link DataTypeConflictHandler#REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER RESORAAH}
	 * conflict handler to be sure that, if all else is the same, the packed version is chosen
	 * over the non-packed version.
	 * <p>
	 * Success is the packed version is chosen over the non-packed version.
	 */
	@Test
	public void testResolveDataTypeNonStructConflict() throws Exception {
		DataTypeManager dtm = new StandAloneDataTypeManager("Test");
		int id = dtm.startTransaction("");
		Category otherRoot = dataMgr.getRootCategory();
		Category subc = otherRoot.createCategory("subc");

		EnumDataType e = new EnumDataType(subc.getCategoryPath(), "Enum", 2);

		DataType resolvedEnum =
			dtm.resolve(e, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		assertTrue(e.isEquivalent(resolvedEnum));
		assertEquals("/subc/Enum", resolvedEnum.getPathName());

		e.add("xyz", 1);

		resolvedEnum =
			dtm.resolve(e, DataTypeConflictHandler.REPLACE_EMPTY_STRUCTS_OR_RENAME_AND_ADD_HANDLER);
		assertTrue(e.isEquivalent(resolvedEnum));
		assertEquals("/subc/Enum.conflict", resolvedEnum.getPathName());

		dtm.endTransaction(id, true);
		dtm.close();
	}
}
