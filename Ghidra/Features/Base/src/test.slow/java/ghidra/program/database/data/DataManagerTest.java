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

import java.util.ArrayList;
import java.util.Iterator;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class DataManagerTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private DataTypeManagerDB dataMgr;
	private int transactionID;

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

	@Test
	public void testSetName() throws InvalidNameException {
		String oldName = dataMgr.getName();
		String newName = "NewName";
		dataMgr.setName("NewName");

		assertEquals(newName, dataMgr.getName());
	}

	@Test
	public void testGetUniqueName() throws Exception {
		DataType bt = new EnumDataType("test", 2);
		dataMgr.resolve(bt, null);
		assertEquals("test_1", dataMgr.getUniqueName(CategoryPath.ROOT, "test"));
	}

	@Test
	public void testGetDataTypeByID() throws Exception {
		Category root = dataMgr.getRootCategory();

		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		StringDataType str = new StringDataType();
		str.setCategoryPath(s.getCategoryPath());
		DataType newdt = dataMgr.resolve(str, null);
		long ID = dataMgr.getResolvedID(newdt);

		assertNotNull(dataMgr.getDataType(ID));

		str = new StringDataType();
		str.setCategoryPath(s.getCategoryPath());
		newdt = dataMgr.resolve(newdt, null);
		long newID = dataMgr.getResolvedID(newdt);
		assertTrue(ID == newID);
	}

	@Test
	public void testFindDataTypes() throws Exception {
		Category root = dataMgr.getRootCategory();

		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		dataMgr.resolve(new EnumDataType("Enum", 2), null);

		Category s2 = s.createCategory("s2");
		dataMgr.resolve(new EnumDataType(s2.getCategoryPath(), "Enum", 2), null);

		Category s3 = s.createCategory("s3");
		dataMgr.resolve(new EnumDataType(s3.getCategoryPath(), "Enum", 2), null);
		dataMgr.resolve(new EnumDataType(s3.getCategoryPath(), "Enum", 2), null);

		ArrayList<DataType> list = new ArrayList<DataType>();
		dataMgr.findDataTypes("Enum", list);

		assertEquals(3, list.size());

		Category c1 = root.createCategory("c1");
		dataMgr.resolve(new EnumDataType(c1.getCategoryPath(), "Enum", 2), null);

		list.clear();
		dataMgr.findDataTypes("Enum", list);
		assertEquals(4, list.size());

		ArrayList<DataType> dataTypeList = new ArrayList<DataType>();
		dataMgr.findDataTypes("nu", dataTypeList, false, TaskMonitor.DUMMY);
		assertEquals(0, dataTypeList.size());

		dataTypeList.clear();
		dataMgr.findDataTypes("*num", dataTypeList, false, TaskMonitor.DUMMY);
		assertEquals(4, dataTypeList.size());

		dataTypeList.clear();
		dataMgr.findDataTypes("*num*", dataTypeList, false, TaskMonitor.DUMMY);
		assertEquals(4, dataTypeList.size());

		dataTypeList.clear();
		dataMgr.findDataTypes("num*", dataTypeList, false, TaskMonitor.DUMMY);
		assertEquals(0, dataTypeList.size());

		dataTypeList.clear();
		dataMgr.findDataTypes("*n*m*", dataTypeList, false, TaskMonitor.DUMMY);
		assertEquals(4, dataTypeList.size());

		dataTypeList.clear();
		dataMgr.findDataTypes("*n*u*", dataTypeList, false, TaskMonitor.DUMMY);
		assertEquals(4, dataTypeList.size());
	}

	@Test
	public void testFindDataTypesWildcard() throws Exception {
		Category root = dataMgr.getRootCategory();

		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		dataMgr.resolve(new EnumDataType("enum", 2), null);

		Category s2 = s.createCategory("s2");
		dataMgr.resolve(new EnumDataType(s2.getCategoryPath(), "MyEnum", 2), null);

		Category s3 = s.createCategory("s3");
		dataMgr.resolve(new EnumDataType(s3.getCategoryPath(), "AnotherEnum", 2), null);
		dataMgr.resolve(new EnumDataType(s3.getCategoryPath(), "Enum3", 2), null);

		ArrayList<DataType> list = new ArrayList<DataType>();
		dataMgr.findDataTypes("*Enum*", list, false, null);

		assertEquals(4, list.size());

		Category c1 = root.createCategory("c1");
		dataMgr.resolve(new EnumDataType(c1.getCategoryPath(), "enum2", 2), null);

		list.clear();
		dataMgr.findDataTypes("*Enum", list, true, null);
		assertEquals(2, list.size());

		dataMgr.resolve(new EnumDataType(c1.getCategoryPath(), "ABXXEnum", 2), null);
		list.clear();
		dataMgr.findDataTypes("An*Enum", list, true, null);
		assertEquals(1, list.size());
	}

	@Test
	public void testFindDataType() throws Exception {
		Category root = dataMgr.getRootCategory();
		Category subc = root.createCategory("subc");
		subc.createCategory("subc2");
		dataMgr.resolve(new EnumDataType(subc.getCategoryPath(), "Enum", 2), null);

		DataType dt = dataMgr.getDataType(subc.getCategoryPathName() + "/Enum");
		assertNotNull(dt);
		assertEquals("Enum", dt.getName());

	}

	@Test
	public void testCreateCategoryHierarchy() throws Exception {
		String fullName = "/cat1/cat2/cat3/cat4/cat5";
		CategoryPath cp = new CategoryPath(fullName);
		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));

		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));

		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));

		cp = new CategoryPath("/A/B/C/D/E/F/G/H");
		dataMgr.createCategory(cp);
		assertTrue(dataMgr.containsCategory(cp));
	}

	@Test
	public void testCreateArray() throws Exception {
		ArrayDataType adt = new ArrayDataType(new ByteDataType(), 3, 1);
		Array array = (Array) dataMgr.addDataType(adt, null);
		assertNotNull(array);
		assertEquals(3, array.getNumElements());
		DataType bdt = dataMgr.getDataType("/byte");
		assertNotNull(bdt);
		assertEquals(bdt, array.getDataType());
	}

	@Test
	public void testCreateTypedef() throws Exception {
		ArrayDataType adt = new ArrayDataType(new ByteDataType(), 3, 1);
		Array array = (Array) dataMgr.addDataType(adt, null);
		TypedefDataType tdt = new TypedefDataType("ArrayTypedef", array);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);
		assertNotNull(td);
		assertNotNull(td.getDataType());
	}

	@Test
	public void testCreatePointer() throws Exception {

		ArrayDataType adt = new ArrayDataType(new ByteDataType(), 5, 1);
		Array array = (Array) dataMgr.addDataType(adt, null);
		TypedefDataType tdt = new TypedefDataType("ArrayTypedef", array);
		TypeDef td = (TypeDef) dataMgr.addDataType(tdt, null);
		PointerDataType pdt = new Pointer32DataType(td);
		Pointer ptr = (Pointer) dataMgr.addDataType(pdt, null);

		assertNotNull(ptr);
		assertTrue(td.isEquivalent(ptr.getDataType()));
		assertEquals(4, ptr.getLength());

		assertNotNull(dataMgr.getDataType("/ArrayTypedef"));
	}

	@Test
	public void testCreatePointers() throws Exception {

		Array array = new ArrayDataType(new ByteDataType(), 5, 1);
		TypeDef td = new TypedefDataType("ByteTypedef", array);
		Pointer p = new Pointer32DataType(td);
		Pointer p2 = new Pointer32DataType(p);

		Pointer ptr = (Pointer) dataMgr.resolve(p2, null);
		assertNotNull(ptr);
		assertEquals("ByteTypedef * *", ptr.getMnemonic(null));

		p = new Pointer32DataType(null);
		ptr = (Pointer) dataMgr.resolve(p, null);
		assertNotNull(ptr);
		assertEquals("pointer32", ptr.getName());
		assertEquals("addr", ptr.getMnemonic(null));

	}

	@Test
	public void testRemoveDataType() throws Exception {
		Array array = new ArrayDataType(new ByteDataType(), 5, 1);
		TypeDef td = new TypedefDataType("ByteTypedef", array);
		Pointer p = new Pointer32DataType(td);
		Pointer p2 = new Pointer32DataType(p);

		Pointer ptr = (Pointer) dataMgr.resolve(p2, null);

		assertTrue(new ByteDataType().isEquivalent(dataMgr.getDataType("/byte")));
		assertTrue(array.isEquivalent(dataMgr.getDataType("/byte[5]")));
		assertTrue(td.isEquivalent(dataMgr.getDataType("/ByteTypedef")));
		assertTrue(p.isEquivalent(dataMgr.getDataType("/ByteTypedef *32")));
		assertTrue(ptr.isEquivalent(dataMgr.getDataType("/ByteTypedef *32 *32")));
		DataType bdt = dataMgr.getDataType("/byte");
		dataMgr.remove(bdt, new TaskMonitorAdapter());
		assertNull(dataMgr.getDataType("/byte"));
		assertNull(dataMgr.getDataType("/byte[5]"));
		assertNull(dataMgr.getDataType("/ByteTypedef"));
		assertNull(dataMgr.getDataType("/ByteTypedef *"));
		assertNull(dataMgr.getDataType("/ByteTypedef * *"));
	}

	@Test
	public void testRemoveDataType2() throws Exception {
		Array array = new ArrayDataType(new ByteDataType(), 5, 1);
		TypeDef td = new TypedefDataType("ByteTypedef", array);
		Pointer p = new Pointer32DataType(td);

		Pointer ptr = (Pointer) dataMgr.resolve(p, null);
		// delete the typedef
		td = (TypeDef) ptr.getDataType();
		DataType bdt = td.getDataType();
		long byteID = dataMgr.getResolvedID(bdt);

		dataMgr.remove(td, new TaskMonitorAdapter());
		assertNull(ptr.getDataType());
		assertNotNull(dataMgr.getDataType(byteID));
	}

//	public void testSave() throws Exception {
//		
//		Array array = new ArrayDataType(new ByteDataType(), 5);
//		TypeDef td = new TypedefDataType("ByteTypedef", array);
//		Pointer p = new PointerDataType(td, 4);
//		
//		Pointer ptr = dataMgr.createPointer(p, p.getLength());
//		File programFile = new File("c:\\");
//		program.saveAs(programFile, "testdb", null);
//
//				
//	}

// TODO: This should be addressed at some point
//	
//	@Test
//	public void testReplaceBuiltInDataType() throws Exception {
//		// Byte based types
//		TypeDef btd =
//			(TypeDef) dataMgr.resolve(new TypedefDataType("ByteTypedef", ByteDataType.dataType),
//				null);
//		Array barray =
//			(Array) dataMgr.resolve(new ArrayDataType(ByteDataType.dataType, 5, btd.getLength()),
//				null);
//		Array barray2 =
//			(Array) dataMgr.resolve(new ArrayDataType(barray, 2, barray.getLength()), null);
//		TypeDef btd1 = (TypeDef) dataMgr.resolve(new TypedefDataType("ByteTypedef1", barray), null);
//		Pointer bp = (Pointer) dataMgr.resolve(new PointerDataType(btd), null);
//		Pointer bp2 = (Pointer) dataMgr.resolve(new PointerDataType(bp), null);
//		TypeDef btd2 = (TypeDef) dataMgr.resolve(new TypedefDataType("ByteTypedef2", bp2), null);
//
//		// Int based types
//		TypeDef itd =
//			(TypeDef) dataMgr.resolve(new TypedefDataType("ByteTypedef", IntegerDataType.dataType),
//				null);
//		Array iarray =
//			(Array) dataMgr.resolve(new ArrayDataType(ByteDataType.dataType, 5, itd.getLength()),
//				null);
//		Array iarray2 =
//			(Array) dataMgr.resolve(new ArrayDataType(iarray, 2, iarray.getLength()), null);
//		TypeDef itd1 = (TypeDef) dataMgr.resolve(new TypedefDataType("ByteTypedef1", iarray), null);
//		Pointer ip = (Pointer) dataMgr.resolve(new PointerDataType(itd), null);
//		Pointer ip2 = (Pointer) dataMgr.resolve(new PointerDataType(ip), null);
//		TypeDef itd2 = (TypeDef) dataMgr.resolve(new TypedefDataType("ByteTypedef2", ip2), null);
//
//		dataMgr.replaceDataType(btd.getBaseDataType(), IntegerDataType.dataType, false);
//
//		assertTrue(btd.getBaseDataType().isEquivalent(IntegerDataType.dataType));
//
//		if (!barray.isDeleted()) {
//			Msg.debug(this, "barray: " + barray.getDisplayName());
//			fail("Expected barray to be replaced by iarray");
//		}
//
//		if (!barray2.isDeleted()) {
//			Msg.debug(this, "barray2: " + barray.getDisplayName());
//			fail("Expected barray2 to be replaced by iarray2");
//		}
//
//		if (!bp.isDeleted()) {
//			Msg.debug(this, "bp: " + bp.getDisplayName());
//			fail("Expected bp to be replaced by ip");
//		}
//
//		if (!bp2.isDeleted()) {
//			Msg.debug(this, "bp2: " + bp2.getDisplayName());
//			fail("Expected bp2 to be replaced by ip2");
//		}
//
//		assertTrue(itd.getBaseDataType() == btd.getBaseDataType());
//		assertTrue(itd2.getBaseDataType() == btd2.getBaseDataType());
//	}

	@Test
	public void testCreateStructure() {
		StructureDataType sdt = new StructureDataType("test", 0);
		Structure struct = (Structure) dataMgr.addDataType(sdt, null);
		assertNotNull(struct);

		long id = dataMgr.getResolvedID(struct);

		assertNotNull(dataMgr.getDataType(id));
	}

	@Test
	public void testCreateUnion() {
		UnionDataType udt = new UnionDataType("test");
		Union union = (Union) dataMgr.addDataType(udt, null);
		assertNotNull(union);
		long id = dataMgr.getResolvedID(union);
		assertNotNull(dataMgr.getDataType(id));
	}

	@Test
	public void testCreateFunctionDef() {
		FunctionDefinitionDataType fdt =
			new FunctionDefinitionDataType(new FunctionDefinitionDataType("test"));
		FunctionDefinition funcDef = (FunctionDefinition) dataMgr.addDataType(fdt, null);
		assertNotNull(funcDef);
		long id = dataMgr.getResolvedID(funcDef);
		assertNotNull(dataMgr.getDataType(id));
	}

	@Test
	public void testGetAllStructures() {
		StructureDataType sdt1 = new StructureDataType("test1", 0);
		Structure struct1 = (Structure) dataMgr.addDataType(sdt1, null);
		StructureDataType sdt2 = new StructureDataType("test2", 0);
		Structure struct2 = (Structure) dataMgr.addDataType(sdt2, null);
		Iterator<Structure> it = dataMgr.getAllStructures();
		assertTrue(it.hasNext());
		assertEquals(it.next(), struct1);
		assertTrue(it.hasNext());
		assertEquals(it.next(), struct2);
		assertTrue(!it.hasNext());
	}

	@Test
	public void testDataTypeSizeChanged() {

		Structure dt = new StructureDataType("MyStruct", 100);
		dt.insert(0, new ByteDataType());
		dt.insert(1, new WordDataType());
		dt.insert(2, new ByteDataType());

		Structure newDt = (Structure) dataMgr.resolve(dt, null);
		newDt.add(new StringDataType(), 20);
		newDt.add(new ByteDataType());

		Structure struct2 = new StructureDataType("InnerStruct", 0);
		struct2.add(new StringDataType(), 30);
		struct2.add(new ByteDataType());

		struct2 = (Structure) newDt.insert(3, struct2).getDataType();
		int length = struct2.getLength();
		// increase size of struct2
		struct2.add(new QWordDataType());
		int newlen = struct2.getLength();
		assertTrue(newlen > length);
		assertEquals(length + 8, newlen);
	}

	@Test
	public void testResolveDataType() {

		DataTypeManager dtm = new StandAloneDataTypeManager("Test");
		int id = dtm.startTransaction("");
		try {
			DataType byteDT = dtm.resolve(new ByteDataType(), null);

			DataType myByteDT = dataMgr.resolve(byteDT, null);
			assertTrue(myByteDT == dataMgr.getDataType("/byte"));
			assertNotNull(myByteDT);
			assertEquals(myByteDT.getCategoryPath(), CategoryPath.ROOT);
		}
		finally {
			dtm.endTransaction(id, true);
		}
	}

	@Test
	public void testResolveDataType2() throws Exception {
		DataTypeManager dtm = new StandAloneDataTypeManager("Test");
		int id = dtm.startTransaction("");
		Category otherRoot = dataMgr.getRootCategory();
		Category subc = otherRoot.createCategory("subc");
		DataType byteDT = dtm.resolve(new EnumDataType(subc.getCategoryPath(), "Enum", 2), null);

		DataType myByteDT = dataMgr.resolve(byteDT, null);
		assertNotNull(myByteDT);
		assertEquals(myByteDT.getCategoryPath().getName(), "subc");
		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void testResolveDataType3() throws Exception {
		DataTypeManager dtm = new StandAloneDataTypeManager("Test");
		int id = dtm.startTransaction("");
		Category otherRoot = dataMgr.getRootCategory();
		Category subc = otherRoot.createCategory("subc");
		DataType byteDT = dtm.resolve(new EnumDataType(subc.getCategoryPath(), "Enum", 2), null);

		DataType myByteDT = dataMgr.resolve(byteDT, null);
		assertNotNull(myByteDT);

		DataType b2Copy = myByteDT.copy(null);
		dtm.resolve(b2Copy, null);

		DataType bb = dataMgr.resolve(byteDT, null);
		assertNotNull(bb);
		dtm.endTransaction(id, true);
		dtm.close();
	}

	@Test
	public void testDoubleReplace() throws Exception {
		Structure struct = new StructureDataType("test", 0);
		struct.add(new ByteDataType());
		struct.add(new WordDataType());
		struct = (Structure) dataMgr.addDataType(struct, null);
		Array array = new ArrayDataType(struct, 10, struct.getLength());
		dataMgr.addDataType(array, null);

		Structure struct2 = new StructureDataType("test1", 0);
		struct2.add(new WordDataType());
		struct2.add(new ByteDataType());
		struct2 = (Structure) dataMgr.addDataType(struct2, null);

		dataMgr.replaceDataType(struct, struct2, false);

		dataMgr.getDataType(CategoryPath.ROOT, struct2.getName());
		assertNull(dataMgr.getDataType(CategoryPath.ROOT, "test[10]"));
		assertNotNull(dataMgr.getDataType(CategoryPath.ROOT, "test1[10]"));

		Structure struct3 = new StructureDataType("test2", 0);
		struct3.add(new FloatDataType());
		struct3.add(new ByteDataType());
		struct3 = (Structure) dataMgr.addDataType(struct3, null);

		dataMgr.replaceDataType(struct2, struct3, false);

		dataMgr.invalidateCache();
		dataMgr.getDataType(CategoryPath.ROOT, struct3.getName());

		assertNull(dataMgr.getDataType(CategoryPath.ROOT, "test[10]"));
		assertNull(dataMgr.getDataType(CategoryPath.ROOT, "test1[10]"));
		assertNotNull(dataMgr.getDataType(CategoryPath.ROOT, "test2[10]"));

	}

//	public void testAddCustomFormat() {
//	
//		Structure struct = new StructureDataType("test", 0);
//		struct.add(new ByteDataType());
//		struct.add(new WordDataType());
//		
//		DataType dt = dataMgr.resolve(struct);
//		dataMgr.addCustomFormat(dt, new byte[] {(byte)0, (byte)1, (byte)2});
//		
//		CustomFormat[] fmts = dataMgr.getAllCustomFormats();
//		assertEquals(1, fmts.length);	
//	}
//	
//	public void testRemoveCustomFormat() {
//		Structure struct = new StructureDataType("test", 0);
//		struct.add(new ByteDataType());
//		struct.add(new WordDataType());
//		
//		DataType dt = dataMgr.resolve(struct);
//		dataMgr.addCustomFormat(dt, new byte[] {(byte)0, (byte)1, (byte)2});
//		
//		assertTrue(dataMgr.removeCustomFormat(dt));
//	}
//	
//	public void testGetAllCustomFormats() {
//
//		Structure struct = new StructureDataType("test", 0);
//		struct.add(new ByteDataType());
//		struct.add(new WordDataType());
//		
//		DataType dt = dataMgr.resolve(struct);
//		dataMgr.addCustomFormat(dt, new byte[] {(byte)0, (byte)1, (byte)2});
//
//		struct = new StructureDataType("test-two", 0);		
//		struct.add(new ByteDataType());
//		struct.add(new WordDataType());
//		
//		DataType dt2 = dataMgr.resolve(struct);
//		dataMgr.addCustomFormat(dt2, new byte[] {(byte)4, (byte)5, (byte)6, (byte)7});
//		
//		
//		CustomFormat[] fmts = dataMgr.getAllCustomFormats();
//		assertEquals(2, fmts.length);	
//		
//		assertEquals(dt, fmts[0].getDataType());
//		assertEquals(dt2, fmts[1].getDataType());
//		
//	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}
}
