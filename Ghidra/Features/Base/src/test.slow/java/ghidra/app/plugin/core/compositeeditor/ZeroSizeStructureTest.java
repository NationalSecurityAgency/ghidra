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
package ghidra.app.plugin.core.compositeeditor;

import static org.junit.Assert.*;

import org.junit.Test;

import ghidra.program.model.data.*;

public class ZeroSizeStructureTest extends AbstractStructureEditorTest {

	@Test
    public void testCreateEmptyStructure() throws Exception {
		init(emptyStructure, pgmRootCat, false);

		assertNull(pgmRootCat.getDataType(emptyStructure.getName()));

		assertEquals(0, model.getNumComponents());// no components
		assertEquals(1, model.getRowCount());// blank row
		assertEquals(0, model.getLength());// size is 0
		assertTrue(model.hasChanges());// new empty structure
		assertTrue(model.isValidName());// name should be valid
		assertEquals(emptyStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(emptyStructure.getName(), model.getCompositeName());
		assertEquals(pgmRootCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		DataType dt = pgmRootCat.getDataType(emptyStructure.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(emptyStructure.getName(), model.getCompositeName());
		assertEquals(pgmRootCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");
	}

	@Test
    public void testCanZeroDataTypeIfComponent() throws Exception {
		init(simpleStructure, pgmBbCat, false);

		DataType dt = pgmBbCat.getDataType(simpleStructure.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(8, model.getNumComponents());
		assertEquals(9, model.getRowCount());
		assertEquals(29, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(simpleStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 8 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(29);
		assertEquals(simpleStructure.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty structure
		assertTrue(model.isValidName());// name should be valid
		assertEquals(simpleStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(simpleStructure.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		assertTrue(simpleStructure.isEquivalent(model.viewComposite));
		assertTrue(simpleStructure.isZeroLength());

		dt = pgmBbCat.getDataType(simpleStructure.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(simpleStructure.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
	}

	@Test
    public void testCanZeroDataTypeIfPointerComponent() throws Exception {

		Structure innerStructureImpl = new StructureDataType("innerStructure", 0);
		innerStructureImpl.add(DataType.DEFAULT);// component 0
		innerStructureImpl =
			(Structure) CommonTestData.category.addDataType(innerStructureImpl, null);

		Structure outerStructureImpl = new StructureDataType("outerStructure", 0);
		outerStructureImpl.add(DataType.DEFAULT);// component 0
		outerStructureImpl.add(new ByteDataType());// component 1
		outerStructureImpl.add(new PointerDataType(innerStructureImpl));// component 2
		outerStructureImpl.add(new DWordDataType());// component 3
		outerStructureImpl.add(new QWordDataType());// component 4
		outerStructureImpl =
			(Structure) CommonTestData.category.addDataType(outerStructureImpl, null);

		Structure innerStructure = null;
		Structure outerStructure = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerStructure = (Structure) programDTM.resolve(innerStructureImpl, null);
			outerStructure = (Structure) programDTM.resolve(outerStructureImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerStructure);
		assertNotNull(outerStructure);

		init(innerStructure, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(1, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(1);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty structure
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");
	}

	@Test
    public void testCanZeroDataTypeIfNonPointerComponent() throws Exception {

		Structure innerStructureImpl = new StructureDataType("innerStructure", 0);
		innerStructureImpl.add(DataType.DEFAULT);// component 0
		innerStructureImpl =
			(Structure) CommonTestData.category.addDataType(innerStructureImpl, null);

		Structure outerStructureImpl = new StructureDataType("outerStructure", 0);
		outerStructureImpl.add(DataType.DEFAULT);// component 0
		outerStructureImpl.add(new ByteDataType());// component 1
		outerStructureImpl.add(innerStructureImpl);// component 2
		outerStructureImpl.add(new DWordDataType());// component 3
		outerStructureImpl.add(new QWordDataType());// component 4
		outerStructureImpl =
			(Structure) CommonTestData.category.addDataType(outerStructureImpl, null);

		Structure innerStructure = null;
		Structure outerStructure = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerStructure = (Structure) programDTM.resolve(innerStructureImpl, null);
			outerStructure = (Structure) programDTM.resolve(outerStructureImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerStructure);
		assertNotNull(outerStructure);

		init(innerStructure, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(1, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(1);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty structure
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertTrue(innerStructure.isEquivalent(model.viewComposite));
		assertTrue(innerStructure.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
//		assertStatus("/testCat/innerStructure is contained in /testCat/outerStructure and can't be changed to a zero size data type.");
	}

	@Test
    public void testCanZeroDataTypeIfInTypedef() throws Exception {

		Structure innerStructureImpl = new StructureDataType("innerStructure", 0);
		innerStructureImpl.add(DataType.DEFAULT);// component 0
		innerStructureImpl =
			(Structure) CommonTestData.category.addDataType(innerStructureImpl, null);

		TypeDef innerTypedefImpl = new TypedefDataType("innerStructureTypedef", innerStructureImpl);
		innerTypedefImpl = (TypeDef) CommonTestData.category.addDataType(innerTypedefImpl, null);

		Structure innerStructure = null;
		TypeDef innerTypedef = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerStructure = (Structure) programDTM.resolve(innerStructureImpl, null);
			innerTypedef = (TypeDef) programDTM.resolve(innerTypedefImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerStructure);
		assertNotNull(innerTypedef);
		assertTrue(!innerTypedef.isZeroLength());

		init(innerStructure, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(1, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(1);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty structure
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertTrue(innerStructure.isEquivalent(model.viewComposite));
		assertTrue(innerStructure.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
//		assertStatus("/testCat/innerStructure is contained in /testCat/innerStructureTypedef and can't be changed to a zero size data type.");

		assertTrue(innerTypedef.isZeroLength());
		assertEquals(1, innerTypedef.getLength());
	}

	@Test
    public void testCanZeroDataTypeIfInArray() throws Exception {

		Structure innerStructureImpl = new StructureDataType("innerStructure", 0);
		innerStructureImpl.add(WordDataType.dataType);// component 0
		innerStructureImpl =
			(Structure) CommonTestData.category.addDataType(innerStructureImpl, null);

		Array innerArrayImpl = new ArrayDataType(innerStructureImpl, 5, 2);
		innerArrayImpl = (Array) CommonTestData.category.addDataType(innerArrayImpl, null);

		Structure innerStructure = null;
		Array innerArray = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerStructure = (Structure) programDTM.resolve(innerStructureImpl, null);
			innerArray = (Array) programDTM.resolve(innerArrayImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerStructure);
		assertNotNull(innerArray);
		assertEquals(10, innerArray.getLength());

		init(innerStructure, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(2, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(2);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty structure
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerStructure.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerStructure.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertTrue(innerStructure.isEquivalent(model.viewComposite));
		assertTrue(innerStructure.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerStructure.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Structure");
		assertEquals(false, applyAction.isEnabled());
//		assertStatus("/testCat/innerStructure is contained in /testCat/innerStructure[5] and can't be changed to a zero size data type.");

		assertEquals(5, innerArray.getLength());
	}

	private void deleteAllComponents() {
		while (model.getLength() > 0) {
			model.setSelection(new int[] { 0 });
			invoke(deleteAction);
		}
	}
}
