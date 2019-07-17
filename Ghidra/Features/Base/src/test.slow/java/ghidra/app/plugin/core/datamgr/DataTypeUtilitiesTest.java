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
package ghidra.app.plugin.core.datamgr;

import static org.junit.Assert.*;

import org.junit.*;

import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.data.DataTypeUtilities;
import ghidra.program.model.data.*;

/**
 * Class for testing the DataType.equalsIgnoreConflict(String name1, String name2).
 * Previously names for pointer data types were not being handled correctly if they were
 * built on a data type with a conflict name.
 */
public class DataTypeUtilitiesTest extends AbstractGenericTest {

	private ProgramBuilder builder;
	private ProgramDB program;
	private DataTypeManager dataTypeManager;
	private int txID;

	public DataTypeUtilitiesTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		builder = new ProgramBuilder("nameTest", ProgramBuilder._TOY, this);

		assertNotNull(builder);
		program = builder.getProgram();
		assertNotNull(program);
		dataTypeManager = program.getDataTypeManager();
		assertNotNull(dataTypeManager);
		txID = program.startTransaction("NamingUtilities test");
	}

	@After
	public void tearDown() throws Exception {
		if (txID != 0) {
			program.endTransaction(txID, false);
		}
		if (builder != null) {
			builder.dispose();
		}
	}

	@Test
	public void testEqualsIgnoreConflictviaManagedDataTypes() throws Exception {

		DataType byteDt = new ByteDataType();
		DataType asciiDt = new CharDataType();
		DataType wordDt = new WordDataType();
		DataType floatDt = new FloatDataType();

		CategoryPath cat1 = new CategoryPath("/cat1");
		dataTypeManager.createCategory(cat1);

		Structure struct1 = new StructureDataType("simpleStruct", 0);
		struct1.add(wordDt);
		struct1.add(byteDt);
		struct1.setCategoryPath(cat1);

		Structure struct2 = new StructureDataType("simpleStruct", 0);
		struct2.add(wordDt);
		struct2.add(asciiDt);
		struct2.setCategoryPath(cat1);

		Structure struct3 = new StructureDataType("simpleStruct", 0);
		struct3.add(floatDt);
		struct3.setCategoryPath(cat1);

		DataType dt1 =
			dataTypeManager.addDataType(struct1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dt2 =
			dataTypeManager.addDataType(struct2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dt3 =
			dataTypeManager.addDataType(struct3, DataTypeConflictHandler.DEFAULT_HANDLER);

		//=================

		PointerDataType p1 = new Pointer64DataType(dt1);
		Pointer ptrptr1 = new Pointer64DataType(p1);
		PointerDataType p2 = new Pointer64DataType(dt2);
		Pointer ptrptr2 = new Pointer64DataType(p2);
		PointerDataType p3 = new Pointer64DataType(dt3);
		Pointer ptrptr3 = new Pointer64DataType(p3);

		DataType dtPP1 =
			dataTypeManager.addDataType(ptrptr1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtPP2 =
			dataTypeManager.addDataType(ptrptr2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtPP3 =
			dataTypeManager.addDataType(ptrptr3, DataTypeConflictHandler.DEFAULT_HANDLER);

		String pathNamePP1 = dtPP1.getPathName();
		String pathNamePP2 = dtPP2.getPathName();
		String pathNamePP3 = dtPP3.getPathName();
		assertEquals("/cat1/simpleStruct *64 *64", pathNamePP1);
		assertEquals("/cat1/simpleStruct.conflict *64 *64", pathNamePP2);
		assertEquals("/cat1/simpleStruct.conflict1 *64 *64", pathNamePP3);
		same(pathNamePP1, pathNamePP2);
		same(pathNamePP1, pathNamePP3);
		same(pathNamePP2, pathNamePP3);

		//=================

		TypeDef typedef1 = new TypedefDataType("simpleTypedef", dt1);
		TypeDef typedef2 = new TypedefDataType("simpleTypedef", dt2);
		TypeDef typedef3 = new TypedefDataType("simpleTypedef", dt3);

		DataType t1 =
			dataTypeManager.addDataType(typedef1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType t2 =
			dataTypeManager.addDataType(typedef2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType t3 =
			dataTypeManager.addDataType(typedef3, DataTypeConflictHandler.DEFAULT_HANDLER);

		String pathNameT1 = t1.getPathName();
		String pathNameT2 = t2.getPathName();
		String pathNameT3 = t3.getPathName();
		assertEquals("/simpleTypedef", pathNameT1);
		assertEquals("/simpleTypedef.conflict", pathNameT2);
		assertEquals("/simpleTypedef.conflict1", pathNameT3);
		same(pathNameT1, pathNameT2);
		same(pathNameT1, pathNameT3);
		same(pathNameT2, pathNameT3);

		//=================

		Pointer ptrTypedef1 = new Pointer32DataType(t1);
		Pointer ptrTypedef2 = new Pointer32DataType(t2);
		Pointer ptrTypedef3 = new Pointer32DataType(t3);

		DataType ptrT1 =
			dataTypeManager.addDataType(ptrTypedef1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType ptrT2 =
			dataTypeManager.addDataType(ptrTypedef2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType ptrT3 =
			dataTypeManager.addDataType(ptrTypedef3, DataTypeConflictHandler.DEFAULT_HANDLER);

		String pathNamePtrT1 = ptrT1.getPathName();
		String pathNamePtrT2 = ptrT2.getPathName();
		String pathNamePtrT3 = ptrT3.getPathName();
		assertEquals("/simpleTypedef *32", pathNamePtrT1);
		assertEquals("/simpleTypedef.conflict *32", pathNamePtrT2);
		assertEquals("/simpleTypedef.conflict1 *32", pathNamePtrT3);
		same(pathNamePtrT1, pathNamePtrT2);
		same(pathNamePtrT1, pathNamePtrT3);
		same(pathNamePtrT2, pathNamePtrT3);

	}

	@Test
	public void testEqualsIgnoreConflictPointerToArray() throws Exception {

		DataType byteDt = new ByteDataType();
		DataType asciiDt = new CharDataType();
		DataType wordDt = new WordDataType();
		DataType floatDt = new FloatDataType();

		CategoryPath cat1 = new CategoryPath("/cat1");
		dataTypeManager.createCategory(cat1);

		Structure struct1 = new StructureDataType("simpleStruct", 0);
		struct1.add(wordDt);
		struct1.add(byteDt);
		struct1.setCategoryPath(cat1);

		Structure struct2 = new StructureDataType("simpleStruct", 0);
		struct2.add(wordDt);
		struct2.add(asciiDt);
		struct2.setCategoryPath(cat1);

		Structure struct3 = new StructureDataType("simpleStruct", 0);
		struct3.add(floatDt);
		struct3.setCategoryPath(cat1);

		DataType dt1 =
			dataTypeManager.addDataType(struct1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dt2 =
			dataTypeManager.addDataType(struct2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dt3 =
			dataTypeManager.addDataType(struct3, DataTypeConflictHandler.DEFAULT_HANDLER);

		//=================

		ArrayDataType ar1 = new ArrayDataType(dt1, 5, dt1.getLength());
		ArrayDataType ar2 = new ArrayDataType(dt2, 5, dt2.getLength());
		ArrayDataType ar3 = new ArrayDataType(dt3, 5, dt3.getLength());

		DataType dtAr1 = dataTypeManager.addDataType(ar1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtAr2 = dataTypeManager.addDataType(ar2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtAr3 = dataTypeManager.addDataType(ar3, DataTypeConflictHandler.DEFAULT_HANDLER);

		PointerDataType p1 = new Pointer64DataType(dtAr1);
		PointerDataType p2 = new Pointer64DataType(dtAr2);
		PointerDataType p3 = new Pointer64DataType(dtAr3);

		DataType dtP1 = dataTypeManager.addDataType(p1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtP2 = dataTypeManager.addDataType(p2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtP3 = dataTypeManager.addDataType(p3, DataTypeConflictHandler.DEFAULT_HANDLER);

		String pathNameP1 = dtP1.getPathName();
		String pathNameP2 = dtP2.getPathName();
		String pathNameP3 = dtP3.getPathName();
		assertEquals("/cat1/simpleStruct[5] *64", pathNameP1);
		assertEquals("/cat1/simpleStruct.conflict[5] *64", pathNameP2);
		assertEquals("/cat1/simpleStruct.conflict1[5] *64", pathNameP3);
		same(pathNameP1, pathNameP2);
		same(pathNameP1, pathNameP3);
		same(pathNameP2, pathNameP3);

		//=================

		Pointer ptrptr1 = new Pointer64DataType(p1);
		Pointer ptrptr2 = new Pointer64DataType(p2);
		Pointer ptrptr3 = new Pointer64DataType(p3);

		DataType dtPP1 =
			dataTypeManager.addDataType(ptrptr1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtPP2 =
			dataTypeManager.addDataType(ptrptr2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtPP3 =
			dataTypeManager.addDataType(ptrptr3, DataTypeConflictHandler.DEFAULT_HANDLER);

		String pathNamePP1 = dtPP1.getPathName();
		String pathNamePP2 = dtPP2.getPathName();
		String pathNamePP3 = dtPP3.getPathName();
		assertEquals("/cat1/simpleStruct[5] *64 *64", pathNamePP1);
		assertEquals("/cat1/simpleStruct.conflict[5] *64 *64", pathNamePP2);
		assertEquals("/cat1/simpleStruct.conflict1[5] *64 *64", pathNamePP3);
		same(pathNamePP1, pathNamePP2);
		same(pathNamePP1, pathNamePP3);
		same(pathNamePP2, pathNamePP3);
	}

	@Test
	public void testEqualsIgnoreConflictArrayOfPointers() throws Exception {

		DataType byteDt = new ByteDataType();
		DataType asciiDt = new CharDataType();
		DataType wordDt = new WordDataType();
		DataType floatDt = new FloatDataType();

		CategoryPath cat1 = new CategoryPath("/cat1");
		dataTypeManager.createCategory(cat1);

		Structure struct1 = new StructureDataType("simpleStruct", 0);
		struct1.add(wordDt);
		struct1.add(byteDt);
		struct1.setCategoryPath(cat1);

		Structure struct2 = new StructureDataType("simpleStruct", 0);
		struct2.add(wordDt);
		struct2.add(asciiDt);
		struct2.setCategoryPath(cat1);

		Structure struct3 = new StructureDataType("simpleStruct", 0);
		struct3.add(floatDt);
		struct3.setCategoryPath(cat1);

		DataType dt1 =
			dataTypeManager.addDataType(struct1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dt2 =
			dataTypeManager.addDataType(struct2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dt3 =
			dataTypeManager.addDataType(struct3, DataTypeConflictHandler.DEFAULT_HANDLER);

		//=================

		PointerDataType p1 = new Pointer64DataType(dt1);
		PointerDataType p2 = new Pointer64DataType(dt2);
		PointerDataType p3 = new Pointer64DataType(dt3);

		DataType dtP1 = dataTypeManager.addDataType(p1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtP2 = dataTypeManager.addDataType(p2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtP3 = dataTypeManager.addDataType(p3, DataTypeConflictHandler.DEFAULT_HANDLER);

		ArrayDataType ar1 = new ArrayDataType(dtP1, 5, dtP1.getLength());
		ArrayDataType ar2 = new ArrayDataType(dtP2, 5, dtP2.getLength());
		ArrayDataType ar3 = new ArrayDataType(dtP3, 5, dtP3.getLength());

		DataType dtAr1 = dataTypeManager.addDataType(ar1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtAr2 = dataTypeManager.addDataType(ar2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtAr3 = dataTypeManager.addDataType(ar3, DataTypeConflictHandler.DEFAULT_HANDLER);

		String pathNameP1 = dtAr1.getPathName();
		String pathNameP2 = dtAr2.getPathName();
		String pathNameP3 = dtAr3.getPathName();
		assertEquals("/cat1/simpleStruct *64[5]", pathNameP1);
		assertEquals("/cat1/simpleStruct.conflict *64[5]", pathNameP2);
		assertEquals("/cat1/simpleStruct.conflict1 *64[5]", pathNameP3);
		same(pathNameP1, pathNameP2);
		same(pathNameP1, pathNameP3);
		same(pathNameP2, pathNameP3);

		//=================

		Pointer ptrptr1 = new Pointer64DataType(dtAr1);
		Pointer ptrptr2 = new Pointer64DataType(dtAr2);
		Pointer ptrptr3 = new Pointer64DataType(dtAr3);

		DataType dtPAP1 =
			dataTypeManager.addDataType(ptrptr1, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtPAP2 =
			dataTypeManager.addDataType(ptrptr2, DataTypeConflictHandler.DEFAULT_HANDLER);
		DataType dtPAP3 =
			dataTypeManager.addDataType(ptrptr3, DataTypeConflictHandler.DEFAULT_HANDLER);

		String pathNamePAP1 = dtPAP1.getPathName();
		String pathNamePAP2 = dtPAP2.getPathName();
		String pathNamePAP3 = dtPAP3.getPathName();
		assertEquals("/cat1/simpleStruct *64[5] *64", pathNamePAP1);
		assertEquals("/cat1/simpleStruct.conflict *64[5] *64", pathNamePAP2);
		assertEquals("/cat1/simpleStruct.conflict1 *64[5] *64", pathNamePAP3);
		same(pathNamePAP1, pathNamePAP2);
		same(pathNamePAP1, pathNamePAP3);
		same(pathNamePAP2, pathNamePAP3);
	}

	@Test
	public void testEqualConflictNames() throws Exception {
		same("/cat1/simpleStruct.conflict1 *64 *64", "/cat1/simpleStruct.conflict1 *64 *64");

		same("/cat1/simpleStruct.conflict1 *32 *64", "/cat1/simpleStruct.conflict1 *32 *64");

		same("/cat1/simpleStruct *64 *64", "/cat1/simpleStruct.conflict1 *64 *64");

		same("/cat1/simpleStruct.conflict1 *32 *64", "/cat1/simpleStruct *32 *64");

		same("/cat1/simpleStruct.conflict_1234 *64", "/cat1.conflict5/simpleStruct *64");

		same("/cat1/simpleStruct", "/cat1/simpleStruct.conflict1");

		same("/cat1/simpleStruct.conflict_1234.conflict", "/cat1/simpleStruct");

		same("/cat1/simpleStruct.conflict_1234", "/cat1/simpleStruct.conflict3");

		same("simpleStruct.conflict_1234_abc", "simpleStruct.conflict4_abc");

		same("simpleStruct.conflict12", "simpleStruct.conflict34");

		same("/cat1/simpleStruct[5]", "/cat1/simpleStruct.conflict1[5]");

		same("/cat1/simpleStruct.conflict1[5][2]", "/cat1/simpleStruct[5][2]");

		same("/cat1/simpleStruct[3] *64 *64", "/cat1/simpleStruct.conflict1[3] *64 *64");

		same("/cat1/simpleStruct *64[4] *64", "/cat1/simpleStruct.conflict1 *64[4] *64");

		same("/cat1/simpleStruct *64 *64[7]", "/cat1/simpleStruct.conflict1 *64 *64[7]");

		same("/cat1/simpleStruct[11] *32", "/cat1/simpleStruct.conflict1[11] *32");

		same("/cat1/simpleStruct *64[9]", "/cat1/simpleStruct.conflict1 *64[9]");

		same("/cat1/simpleStruct.conflict1[3][3] *64 *64", "/cat1/simpleStruct[3][3] *64 *64");

		same("/cat1/simpleStruct *64[4][3] *64", "/cat1/simpleStruct.conflict1 *64[4][3] *64");

		same("/cat1/simpleStruct *64 *64[7][3]", "/cat1/simpleStruct.conflict1 *64 *64[7][3]");

		same("/cat1/simpleStruct[11][3] *32", "/cat1/simpleStruct.conflict1[11][3] *32");

		same("/cat1/simpleStruct *64[9]", "/cat1/simpleStruct.conflict1 *64[9]");

		same("/cat1/simpleStruct.conflict1[11] *32[2]", "/cat1/simpleStruct[11] *32[2]");

		same("/cat1/simpleStruct[6] *64[9]", "/cat1/simpleStruct.conflict1[6] *64[9]");
	}

	@Test
	public void testUnequalConflictNames() throws Exception {
		different("/cat1/simpleStruct.conflict1 *64 *32", "/cat1/simpleStruct.conflict1 *64 *64");

		different("/cat1/simpleStruct.conflict1 *64 *32", "/cat1/simpleStruct.conflict1 *32 *64");

		different("/cat1/simpleStruct.conflict1 *64", "/cat1/simpleStruct.conflict1 *32");

		different("/cat1/simpleStruct *64 *32", "/cat1/simpleStruct.conflict1 *64 *64");

		different("/cat1/simpleStruct *64 *32", "/cat1/simpleStruct.conflict1 *32 *64");

		different("/cat1/simpleStruct *64", "/cat1/simpleStruct.conflict1 *32");

		different("/cat1.conflict3/simpleStruct.conflict_1234 *64", "/cat1/simpleStruct *32");

		different("/cat1/simpleStruct", "/cat1/simpleStruct.conflict1 *32");

		different("/cat1/simpleStruct.conflict_1234_abc", "/cat1/simpleStruct *32");

		different("/simpleStruct", "/cat1/simpleStruct");

		different("/simpleStruct", "/cat1/simpleStruct.conflict1");

		different("/cat1/simpleStruct", "/cat1/simpleStruct1.conflict1 *32");

		different("/cat1/simpleStruct[5]", "/cat1/simpleStruct.conflict1[4]");

		different("/cat1/simpleStruct.conflict1[5][2]", "/cat1/simpleStruct[4][2]");

		different("/cat1/simpleStruct[5][4]", "/cat1/simpleStruct.conflict1[5][2]");

		different("/cat1/simpleStruct[2] *64 *64", "/cat1/simpleStruct.conflict1[3] *64 *64");

		different("/cat1/simpleStruct[3] *64 *32", "/cat1/simpleStruct.conflict1[3] *64 *64");

		different("/cat1/simpleStruct *64[4] *64", "/cat1/simpleStruct.conflict1 *64[5] *64");

		different("/cat1/simpleStruct *64 *32[7]", "/cat1/simpleStruct.conflict1 *64 *64[7]");

		different("/cat1/simpleStruct[11] *32", "/cat1/simpleStruct.conflict1[11] *32 [5]");

		different("/cat1/simpleStruct [9]", "/cat1/simpleStruct.conflict1 *64[9]");

		different("/cat1/simpleStruct *32[9]", "/cat1/simpleStruct.conflict1 *64[9]");

		different("/cat1/simpleStruct *64[5]", "/cat1/simpleStruct.conflict1 *64[9]");

		different("/cat1/simpleStruct[3][5] *64 *64", "/cat1/simpleStruct.conflict1[3][3] *64 *64");

		different("/cat1/simpleStruct *64[4][6] *64", "/cat1/simpleStruct.conflict1 *64[4][3] *64");

		different("/cat1/simpleStruct *64 *64[7][2]", "/cat1/simpleStruct.conflict1 *64 *64[7][3]");

		different("/cat1/simpleStruct.conflict1[11][3] *32", "/cat1/simpleStruct[11][8] *32");

		different("/cat1/simpleStruct *64[9]", "/cat1/simpleStruct.conflict1 *64[7]");

		different("/cat1/simpleStruct[11] *32[3]", "/cat1/simpleStruct.conflict1[11] *32[2]");

		different("/cat1/simpleStruct[6] *64[9]", "/cat1/simpleStruct.conflict1[6] *64[4]");

		different("/cat1/simpleStruct.conflict1[5]", "/cat1/simpleStruct");

		different("/cat1/simpleStruct[5][2]", "/cat1/simpleStruct.conflict1[5][2][1]");

		different("/cat1/simpleStruct[3] *64", "/cat1/simpleStruct.conflict1[3] *64 *64");

		different("/cat1/simpleStruct", "/cat1/simpleStruct.conflict1 *64[4] *64");

		different("/cat1/simpleStruct.conflict1 *64 *64[7]", "/cat1/simpleStruct *64 [7]");

		different("/cat1/simpleStruct[11] *32", "/cat1/simpleStruct.conflict1 *32");

		different("/cat1/simpleStruct[11] *32", "/cat1/simpleStruct.conflict1[11]");

		different("/cat1/simpleStruct *64", "/cat1/simpleStruct.conflict1 *64[9]");

		different("/cat1/simpleStruct[3][3] *64", "/cat1/simpleStruct.conflict1[3][3] *64 *64");

		different("/cat1/simpleStruct.conflict1 *64[3] *64", "/cat1/simpleStruct *64[4][3] *64");

		different("/cat1/simpleStruct *64 [7][3]", "/cat1/simpleStruct.conflict1 *64 *64[7][3]");

		different("/cat1/simpleStruct[11][3] *32", "/cat1/simpleStruct.conflict1[11][5] *32");

		different("/cat1/simpleStruct.conflict1 *64[9]", "/cat1/simpleStruct");

		different("/cat1/simpleStruct[11] *32[2]", "/cat1/simpleStruct.conflict1[11] *8[2]");

		different("/cat1/simpleStruct[6] *16[9]", "/cat1/simpleStruct.conflict1[6] *64[9]");
	}

	private void same(String name1, String name2) {
		assertTrue(name1 + " isn't equivalent to " + name2 + " when it should be.",
			DataTypeUtilities.equalsIgnoreConflict(name1, name2));
	}

	private void different(String name1, String name2) {
		assertFalse(name1 + " is equivalent to " + name2 + " when it shouldn't be.",
			DataTypeUtilities.equalsIgnoreConflict(name1, name2));
	}
}
