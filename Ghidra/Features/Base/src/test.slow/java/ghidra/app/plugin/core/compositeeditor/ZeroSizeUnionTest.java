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

public class ZeroSizeUnionTest extends AbstractUnionEditorTest {

	@Test
	public void testCreateEmptyUnion() throws Exception {
		init(emptyUnion, pgmRootCat, false);

		assertNull(pgmRootCat.getDataType(emptyUnion.getName()));

		assertEquals(0, model.getNumComponents());// no components
		assertEquals(1, model.getRowCount());// blank row
		assertEquals(0, model.getLength());// size is 0
		assertTrue(model.hasChanges());// new empty union
		assertTrue(model.isValidName());// name should be valid
		assertEquals(emptyUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(emptyUnion.getName(), model.getCompositeName());
		assertEquals(pgmRootCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		DataType dt = pgmRootCat.getDataType(emptyUnion.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(emptyUnion.getName(), model.getCompositeName());
		assertEquals(pgmRootCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");
	}

	@Test
	public void testCanZeroDataTypeIfComponent() throws Exception {
		init(simpleUnion, pgmBbCat, false);

		DataType dt = pgmBbCat.getDataType(simpleUnion.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(7, model.getNumComponents());
		assertEquals(8, model.getRowCount());
		assertEquals(8, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(simpleUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 7 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(8);
		assertEquals(simpleUnion.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty union
		assertTrue(model.isValidName());// name should be valid
		assertEquals(simpleUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(simpleUnion.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		assertTrue(simpleUnion.isEquivalent(model.viewComposite));
		assertTrue(simpleUnion.isZeroLength());

		dt = pgmBbCat.getDataType(simpleUnion.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertTrue(simpleUnion.isEquivalent(model.viewComposite));

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(simpleUnion.getName(), model.getCompositeName());
		assertEquals(pgmBbCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
	}

	@Test
	public void testCanZeroDataTypeIfPointerComponent() throws Exception {

		Union innerUnionImpl = new UnionDataType("innerUnion");
		innerUnionImpl.add(DataType.DEFAULT);// component 0
		innerUnionImpl = (Union) CommonTestData.category.addDataType(innerUnionImpl, null);

		Union outerUnionImpl = new UnionDataType("outerUnion");
		outerUnionImpl.add(DataType.DEFAULT);// component 0
		outerUnionImpl.add(new ByteDataType());// component 1
		outerUnionImpl.add(new PointerDataType(innerUnionImpl));// component 2
		outerUnionImpl.add(new DWordDataType());// component 3
		outerUnionImpl.add(new QWordDataType());// component 4
		outerUnionImpl = (Union) CommonTestData.category.addDataType(outerUnionImpl, null);

		Union innerUnion = null;
		Union outerUnion = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerUnion = (Union) programDTM.resolve(innerUnionImpl, null);
			outerUnion = (Union) programDTM.resolve(outerUnionImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerUnion);
		assertNotNull(outerUnion);

		init(innerUnion, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(1, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(1);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty union
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");
	}

	@Test
	public void testCannotZeroDataTypeIfNonPointerComponent() throws Exception {

		Union innerUnionImpl = new UnionDataType("innerUnion");
		innerUnionImpl.add(DataType.DEFAULT);// component 0
		innerUnionImpl = (Union) CommonTestData.category.addDataType(innerUnionImpl, null);

		Union outerUnionImpl = new UnionDataType("outerUnion");
		outerUnionImpl.add(DataType.DEFAULT);// component 0
		outerUnionImpl.add(new ByteDataType());// component 1
		outerUnionImpl.add(innerUnionImpl);// component 2
		outerUnionImpl.add(new DWordDataType());// component 3
		outerUnionImpl.add(new QWordDataType());// component 4
		outerUnionImpl = (Union) CommonTestData.category.addDataType(outerUnionImpl, null);

		Union innerUnion = null;
		Union outerUnion = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerUnion = (Union) programDTM.resolve(innerUnionImpl, null);
			outerUnion = (Union) programDTM.resolve(outerUnionImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerUnion);
		assertNotNull(outerUnion);

		init(innerUnion, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(1, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(1);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty union
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertTrue(innerUnion.isEquivalent(model.viewComposite));
		assertTrue(innerUnion.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
	}

	@Test
	public void testCannotZeroDataTypeIfInTypedef() throws Exception {

		Union innerUnionImpl = new UnionDataType("innerUnion");
		innerUnionImpl.add(DataType.DEFAULT);// component 0
		innerUnionImpl = (Union) CommonTestData.category.addDataType(innerUnionImpl, null);

		TypeDef innerTypedefImpl = new TypedefDataType("innerUnionTypedef", innerUnionImpl);
		innerTypedefImpl = (TypeDef) CommonTestData.category.addDataType(innerTypedefImpl, null);

		Union innerUnion = null;
		TypeDef innerTypedef = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerUnion = (Union) programDTM.resolve(innerUnionImpl, null);
			innerTypedef = (TypeDef) programDTM.resolve(innerTypedefImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerUnion);
		assertNotNull(innerTypedef);

		init(innerUnion, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(1, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(1);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty union
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertTrue(innerUnion.isEquivalent(model.viewComposite));
		assertTrue(innerUnion.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
	}

	@Test
	public void testCannotZeroDataTypeIfInArray() throws Exception {

		Union innerUnionImpl = new UnionDataType("innerUnion");
		innerUnionImpl.add(DataType.DEFAULT);// component 0
		innerUnionImpl = (Union) CommonTestData.category.addDataType(innerUnionImpl, null);

		Array innerArrayImpl = new ArrayDataType(innerUnionImpl, 5, 5);
		innerArrayImpl = (Array) CommonTestData.category.addDataType(innerArrayImpl, null);

		Union innerUnion = null;
		Array innerArray = null;

		try {
			txId = program.startTransaction("Change DataType");

			innerUnion = (Union) programDTM.resolve(innerUnionImpl, null);
			innerArray = (Array) programDTM.resolve(innerArrayImpl, null);
		}
		finally {
			program.endTransaction(txId, true);
		}
		assertNotNull(innerUnion);
		assertNotNull(innerArray);

		init(innerUnion, pgmTestCat, false);

		DataType dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertFalse(dt.isZeroLength());

		assertEquals(1, model.getNumComponents());
		assertEquals(2, model.getRowCount());
		assertEquals(1, model.getLength());
		assertFalse(model.hasChanges());
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 1 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(1);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
		assertStatus("");

		deleteAllComponents();

		assertEquals(0, model.getNumComponents());
		assertEquals(1, model.getRowCount());
		assertEquals(0, model.getLength());
		assertTrue(model.hasChanges());// new empty union
		assertTrue(model.isValidName());// name should be valid
		assertEquals(innerUnion.getDescription(), model.getDescription());
		assertEquals(0, model.getNumSelectedComponentRows());
		assertEquals(1, model.getNumSelectedRows());
		checkSelection(new int[] { 0 });
		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(true, applyAction.isEnabled());
		assertStatus("");

		invoke(applyAction);

		dt = pgmTestCat.getDataType(innerUnion.getName());
		assertNotNull(dt);
		assertTrue(dt.isZeroLength());

		assertTrue(innerUnion.isEquivalent(model.viewComposite));
		assertTrue(innerUnion.isZeroLength());

		assertIsPackingEnabled(false);
		assertIsDefaultAligned();
		assertActualAlignment(1);
		assertLength(0);
		assertEquals(innerUnion.getName(), model.getCompositeName());
		assertEquals(pgmTestCat.getCategoryPathName(), model.getOriginalCategoryPath().getPath());
		assertEquals(model.getTypeName(), "Union");
		assertEquals(false, applyAction.isEnabled());
	}

	private void deleteAllComponents() {
		while (model.getLength() > 0) {
			model.setSelection(new int[] { 0 });
			invoke(deleteAction);
			waitForTasks();
		}
	}
}
