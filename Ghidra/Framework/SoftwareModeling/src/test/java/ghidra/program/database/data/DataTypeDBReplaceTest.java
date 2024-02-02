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

import java.util.Iterator;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;
import ghidra.program.model.data.*;

public class DataTypeDBReplaceTest extends AbstractGenericTest {

	private DataTypeManagerDB dataMgr;

	@Before
	public void setUp() throws Exception {
		dataMgr = new StandAloneDataTypeManager("dummyDTM");
		dataMgr.startTransaction("Test");
	}

	@Test
	public void testReplaceHandlingPointers() throws Exception {

		Structure s1 = new StructureDataType(new CategoryPath("/P1"), "MyStruct1", 0, dataMgr);
		s1.add(ByteDataType.dataType);
		Structure sDb1 = (Structure) dataMgr.resolve(s1, null);

		Structure s2 = new StructureDataType(new CategoryPath("/P2"), "MyStruct2", 0, dataMgr);
		s2.add(new PointerDataType(s1)); // MyStruct1*
		Structure sDb2 = (Structure) dataMgr.resolve(s2, null);
		DataType ptrDb1 = sDb2.getComponent(0).getDataType(); // MyStruct1*

		Structure s3 = new StructureDataType(new CategoryPath("/P3"), "MyStruct3", 0, dataMgr);
		s3.add(new PointerDataType(new PointerDataType(s2))); // MyStruct2**
		Structure sDb3 = (Structure) dataMgr.resolve(s3, null);
		Pointer ptrDb2a = (Pointer) sDb3.getComponent(0).getDataType(); // MyStruct2**
		Pointer ptrDb2b = (Pointer) ptrDb2a.getDataType(); // MyStruct2*

		assertTrue(sDb3.isEquivalent(s3));

		assertEquals(8, getDataTypeCount()); // include "undefined" type used during resolve

		dataMgr.replaceDataType(sDb2, sDb1, false);

		System.out.println("---");

		assertTrue("Expected MyStruct2* to be replaced by MyStruct1*", ptrDb2b.isDeleted());
		assertFalse("Expected /P2/MyStruct2** to be moved/transformed to /P1/MyStruct1**",
			ptrDb2a.isDeleted());

		// Pointer instance should have changed category as well as using MyStruct1*
		Pointer ptrPtr = (Pointer) sDb3.getComponent(0).getDataType(); // MyStruct1**
		assertTrue(ptrDb2a == ptrPtr);
		assertEquals("/P1/MyStruct1 * *", ptrPtr.getPathName());

		// Existing MyStruct1* pointer instance should be used and MyStruct2* removed
		Pointer ptr = (Pointer) ptrPtr.getDataType(); // MyStruct1*
		assertTrue(ptrDb1 == ptr);
		assertEquals("/P1/MyStruct1 *", ptr.getPathName());

		assertEquals(6, getDataTypeCount()); // include "undefined" type used during resolve

	}

	@Test
	public void testReplaceHandlingArrays() throws Exception {

		Structure s1 = new StructureDataType(new CategoryPath("/P1"), "MyStruct1", 0, dataMgr);
		s1.add(ByteDataType.dataType);
		Structure sDb1 = (Structure) dataMgr.resolve(s1, null);

		Structure s2 = new StructureDataType(new CategoryPath("/P2"), "MyStruct2", 0, dataMgr);
		s2.add(WordDataType.dataType);
		Structure sDb2 = (Structure) dataMgr.resolve(s2, null);

		Structure s3 = new StructureDataType(new CategoryPath("/P3"), "MyStruct3", 0, dataMgr);
		s3.add(new ArrayDataType(s1, 3, -1)); // MyStruct1[3]
		s3.add(new ArrayDataType(s2, 2, -1)); // MyStruct2[2]
		s3.add(new ArrayDataType(new ArrayDataType(s2, 3, -1), 2, -1)); // MyStruct2[2][3]

		Structure sDb3 = (Structure) dataMgr.resolve(s3, null);
		Array aDb1_3 = (Array) sDb3.getComponent(0).getDataType(); // 0: MyStruct1[3]
		Array aDb2_2 = (Array) sDb3.getComponent(1).getDataType(); // 1: MyStruct2[2]
		Array aDb2_3_2 = (Array) sDb3.getComponent(2).getDataType(); // 2: MyStruct2[2][3]
		Array aDb2_3 = (Array) aDb2_3_2.getDataType(); // MyStruct2[3]

		//@formatter:off
		assertEquals("/P3/MyStruct3\n" + 
			"pack(disabled)\n" + 
			"Structure MyStruct3 {\n" + 
			"   0   MyStruct1[3]   3      \"\"\n" + 
			"   3   MyStruct2[2]   4      \"\"\n" + 
			"   7   MyStruct2[2][3]   12      \"\"\n" + 
			"}\n" + 
			"Length: 19 Alignment: 1\n", sDb3.toString());
		//@formatter:on

		assertTrue(sDb3.isEquivalent(s3));

		assertEquals(9, getDataTypeCount()); // include "undefined" type used during resolve

		dataMgr.replaceDataType(sDb2, sDb1, false);

		System.out.println("---");

		assertFalse("Expected no change", aDb1_3.isDeleted());
		assertFalse("Expected MyStruct2[2] to be moved/transformed to MyStruct1[2]",
			aDb2_2.isDeleted());
		assertFalse("Expected MyStruct2[3][2] to be moved/transformed to MyStruct1[3][2]",
			aDb2_3_2.isDeleted());
		assertTrue("Expected MyStruct2[3] to be replaced by MyStruct1[3]", aDb2_3.isDeleted());

		DataTypeComponent[] definedComponents = sDb3.getDefinedComponents();
		assertEquals(3, definedComponents.length);

		// Array instance should have changed category as well as using MyStruct1
		Array a1 = (Array) definedComponents[1].getDataType(); // MyStruct1[2]
		assertTrue(aDb2_2 == a1);
		assertEquals("/P1/MyStruct1[2]", a1.getPathName());

		// Array instance should have changed category as well as using MyStruct1[3]
		Array a1a = (Array) definedComponents[2].getDataType(); // MyStruct1[3][2]
		assertTrue(aDb2_3_2 == a1a);
		assertEquals("/P1/MyStruct1[2][3]", a1a.getPathName());

		// Existing MyStruct1[3] array instance should be used and MyStruct2[3] removed
		Array a1b = (Array) a1a.getDataType(); // MyStruct1[3]
		assertTrue(aDb1_3 == a1b);
		assertEquals("/P1/MyStruct1[3]", a1b.getPathName());

		// Component placements should not change but sizes will
		//@formatter:off
		assertEquals("/P3/MyStruct3\n" + 
			"pack(disabled)\n" + 
			"Structure MyStruct3 {\n" + 
			"   0   MyStruct1[3]   3      \"\"\n" + 
			"   3   MyStruct1[2]   2      \"\"\n" + 
			"   7   MyStruct1[2][3]   6      \"\"\n" + 
			"}\n" + 
			"Length: 19 Alignment: 1\n", sDb3.toString());
		//@formatter:on

		assertEquals(7, getDataTypeCount()); // include "undefined" type used during resolve

	}

	@Test
	public void testReplaceHandlingArraysPacked() throws Exception {

		Structure s1 = new StructureDataType(new CategoryPath("/P1"), "MyStruct1", 0, dataMgr);
		s1.setPackingEnabled(true);
		s1.add(ByteDataType.dataType);
		Structure sDb1 = (Structure) dataMgr.resolve(s1, null);

		Structure s2 = new StructureDataType(new CategoryPath("/P2"), "MyStruct2", 0, dataMgr);
		s2.setPackingEnabled(true);
		s2.add(WordDataType.dataType);
		Structure sDb2 = (Structure) dataMgr.resolve(s2, null);

		Structure s3 = new StructureDataType(new CategoryPath("/P3"), "MyStruct3", 0, dataMgr);
		s3.setPackingEnabled(true);
		s3.add(new ArrayDataType(s1, 3, -1)); // MyStruct1[3]
		s3.add(new ArrayDataType(s2, 2, -1)); // MyStruct2[2]
		s3.add(new ArrayDataType(new ArrayDataType(s2, 3, -1), 2, -1)); // MyStruct2[2][3]

		Structure sDb3 = (Structure) dataMgr.resolve(s3, null);
		Array aDb1_3 = (Array) sDb3.getComponent(0).getDataType(); // 0: MyStruct1[3]
		Array aDb2_2 = (Array) sDb3.getComponent(1).getDataType(); // 1: MyStruct2[2]
		Array aDb2_3_2 = (Array) sDb3.getComponent(2).getDataType(); // 2: MyStruct2[2][3]
		Array aDb2_3 = (Array) aDb2_3_2.getDataType(); // MyStruct2[3]

		//@formatter:off
		assertEquals("/P3/MyStruct3\n" + 
			"pack()\n" + 
			"Structure MyStruct3 {\n" + 
			"   0   MyStruct1[3]   3      \"\"\n" + 
			"   4   MyStruct2[2]   4      \"\"\n" + 
			"   8   MyStruct2[2][3]   12      \"\"\n" + 
			"}\n" + 
			"Length: 20 Alignment: 2\n", sDb3.toString());
		//@formatter:on

		assertTrue(sDb3.isEquivalent(s3));

		assertEquals(9, getDataTypeCount()); // include "undefined" type used during resolve

		dataMgr.replaceDataType(sDb2, sDb1, false);

		assertFalse("Expected no change", aDb1_3.isDeleted());
		assertFalse("Expected MyStruct2[2] to be moved/transformed to MyStruct1[2]",
			aDb2_2.isDeleted());
		assertFalse("Expected MyStruct2[3][2] to be moved/transformed to MyStruct1[3][2]",
			aDb2_3_2.isDeleted());
		assertTrue("Expected MyStruct2[3] to be replaced by MyStruct1[3]", aDb2_3.isDeleted());

		DataTypeComponent[] definedComponents = sDb3.getDefinedComponents();
		assertEquals(3, definedComponents.length);

		// Array instance should have changed category as well as using MyStruct1
		Array a1 = (Array) definedComponents[1].getDataType(); // MyStruct1[2]
		assertTrue(aDb2_2 == a1);
		assertEquals("/P1/MyStruct1[2]", a1.getPathName());

		// Array instance should have changed category as well as using MyStruct1[3]
		Array a1a = (Array) definedComponents[2].getDataType(); // MyStruct1[3][2]
		assertTrue(aDb2_3_2 == a1a);
		assertEquals("/P1/MyStruct1[2][3]", a1a.getPathName());

		// Existing MyStruct1[3] array instance should be used and MyStruct2[3] removed
		Array a1b = (Array) a1a.getDataType(); // MyStruct1[3]
		assertTrue(aDb1_3 == a1b);
		assertEquals("/P1/MyStruct1[3]", a1b.getPathName());

		// Structure should get repacked
		//@formatter:off
		assertEquals("/P3/MyStruct3\n" + 
			"pack()\n" + 
			"Structure MyStruct3 {\n" + 
			"   0   MyStruct1[3]   3      \"\"\n" + 
			"   3   MyStruct1[2]   2      \"\"\n" + 
			"   5   MyStruct1[2][3]   6      \"\"\n" + 
			"}\n" + 
			"Length: 11 Alignment: 1\n", sDb3.toString());
		//@formatter:on

		assertEquals(7, getDataTypeCount()); // include "undefined" type used during resolve

	}

	private int getDataTypeCount() {
		// NOTE: the DataTypeManager.getAllDataTypes() method will not properly detect duplicate
		// datatypes if they occur due to the category-based collection which use named-based
		// maps.
		int cnt = 0;
		Iterator<DataType> allDataTypes = dataMgr.getAllDataTypes();
		while (allDataTypes.hasNext()) {
			allDataTypes.next();
			++cnt;
		}

		// Compare count with actual record count to ensure both proper maps updates and
		// potential datatype duplication not reflected in count above.
		assertEquals("Incomplete datatype manager update", cnt, dataMgr.getDataTypeRecordCount());

		return cnt;
	}

}
