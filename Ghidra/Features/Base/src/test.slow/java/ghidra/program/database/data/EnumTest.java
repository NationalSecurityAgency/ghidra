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

import java.util.NoSuchElementException;

import org.junit.*;

import ghidra.framework.model.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.util.ChangeManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.task.TaskMonitor;

/**
 * Tests for Enum data types.
 */
public class EnumTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private DataTypeManagerDB dataMgr;
	private int transactionID;

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);

		dataMgr = program.getDataTypeManager();
		transactionID = program.startTransaction("Test");
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, false);
		program.release(this);
	}

	@Test
	public void testCreateEnum() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 1);
		enumm.add("Blue", 2);

		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());
		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		assertNotNull(enummDT);

		assertEquals("Color", enummDT.getName());
		assertEquals(0, enummDT.getValue("Red"));
		assertEquals(1, enummDT.getValue("Green"));
		assertEquals(2, enummDT.getValue("Blue"));

		assertEquals(1, enummDT.getLength());
		assertEquals(3, enummDT.getCount());

		assertTrue(enumm.isEquivalent(enummDT));
		assertTrue(enummDT.isEquivalent(enumm));

		assertEquals(c.getCategoryPath(), enummDT.getCategoryPath());

		assertNotNull(c.getDataType("Color"));
	}

	@Test
	public void testRemoveValue() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 1);
		enumm.add("Blue", 2);
		enumm.add("blue", 2);

		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());
		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		assertArrayEquals(new long[] { 0, 1, 2 }, enumm.getValues());
		assertEquals(4, enumm.getCount());

		enummDT.remove("Green");
		enummDT.remove("blue");

		assertEquals(2, enummDT.getCount());
		assertArrayEquals(new long[] { 0, 2 }, enummDT.getValues());

		assertEquals(2, enummDT.getValue("Blue"));
		try {
			enummDT.getValue("blue");
			fail("expected NoSuchElementException");
		}
		catch (NoSuchElementException e) {
			// expected
		}
	}

	@Test
	public void testAddValue() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 1);
		enumm.add("Blue", 2);
		enumm.add("blue", 2);

		assertArrayEquals(new long[] { 0, 1, 2 }, enumm.getValues());
		assertEquals(4, enumm.getCount());

		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());

		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		enummDT.add("Purple", 7);
		assertEquals(5, enummDT.getCount());
		assertEquals(7, enummDT.getValue("Purple"));
		assertEquals(2, enummDT.getValue("Blue"));
		assertEquals(2, enummDT.getValue("blue"));
		assertArrayEquals(new long[] { 0, 1, 2, 7 }, enummDT.getValues());
	}

	@Test
	public void testEditValue() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());

		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);
		DomainObjListener listener = new DomainObjListener();
		program.addListener(listener);
		enummDT.remove("Blue");
		assertEquals(2, enummDT.getCount());
		waitForListenerCount(listener, 1);
		assertEquals(1, listener.getCount());
		enummDT.add("Blue", 30);
		assertEquals(30, enummDT.getValue("Blue"));
		assertEquals("Blue", enummDT.getName(30));
		assertNull(enummDT.getName(20));
		waitForListenerCount(listener, 2);
		assertEquals(2, listener.getCount());
	}

	@Test
	public void testCloneRetainIdentity() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());
		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		Enum copyDT = (Enum) enummDT.clone(null);
		assertNotNull(copyDT);

		copyDT.setCategoryPath(c.getCategoryPath());
		Enum c2 = (Enum) dataMgr.resolve(copyDT, null);
		assertNotNull(c2);
		assertTrue(copyDT.isEquivalent(c2));
	}

	@Test
	public void testCopyNoRetainIdentity() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());
		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		Enum copyDT = (Enum) enummDT.copy(null);
		assertNotNull(copyDT);

		copyDT.setCategoryPath(c.getCategoryPath());
		Enum c2 = (Enum) dataMgr.resolve(copyDT, null);
		assertNotNull(c2);
		assertTrue(copyDT.isEquivalent(c2));
	}

	@Test
	public void testRemoveEnum() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());

		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);
		assertNotNull(enummDT);

		c.remove(enummDT, TaskMonitor.DUMMY);
		assertNull(c.getDataType("Color"));

		assertTrue(enummDT.isDeleted());

	}

	@Test
	public void testMoveEnum() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());
		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		root.moveDataType(enummDT, null);
		assertNotNull(root.getDataType(enumm.getName()));
		assertNull(c.getDataType(enumm.getName()));
	}

	@Test
	public void testResolve() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);

		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);
		assertNotNull(enummDT);

		long id = dataMgr.getResolvedID(enummDT);

		assertEquals(enummDT, dataMgr.getDataType(id));
	}

	@Test
	public void testReplace() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());
		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		Enum myEnum = new EnumDataType("my enumm", 1);
		myEnum.add("My red", 0);
		myEnum.add("My Green", 5);
		myEnum.add("My Blue", 25);
		myEnum.add("Purple", 10);

		enummDT.replaceWith(myEnum);

		assertEquals(4, enummDT.getCount());
		long[] values = enummDT.getValues();
		assertEquals(4, values.length);

		assertEquals(0, values[0]);
		assertEquals(5, values[1]);
		assertEquals(10, values[2]);
		assertEquals(25, values[3]);

		try {
			enummDT.getValue("Red");
			Assert.fail("Should have gotten no such element exception!");
		}
		catch (NoSuchElementException e) {
			// expected
		}
	}

	@Test
	public void testIsEquivalent() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		enumm.setCategoryPath(c.getCategoryPath());

		Enum enummDT = (Enum) dataMgr.resolve(enumm, null);

		Enum myEnum = new EnumDataType("Color", 1);
		myEnum.add("Red", 1);
		myEnum.add("Green", 5);
		myEnum.add("Blue", 10);

		assertTrue(!enummDT.isEquivalent(myEnum));

		myEnum = new EnumDataType("Color", 1);
		myEnum.add("Red", 10);
		myEnum.add("Green", 15);
		myEnum.add("Blue", 20);
		myEnum.add("Gold", 1);

		assertTrue(!enumm.isEquivalent(myEnum));

		myEnum = new EnumDataType("MyColors", 1);
		myEnum.add("Red", 10);
		myEnum.add("Green", 15);
		myEnum.add("Blue", 20);
		assertTrue(!enummDT.isEquivalent(myEnum));

		myEnum = new EnumDataType("Color", 1);
		myEnum.add("Red", 10);
		myEnum.add("Green", 15);
		myEnum.add("Blue", 20);
		assertTrue(enummDT.isEquivalent(myEnum));
	}

	@Test
	public void testNameSort() {

		Enum myEnum = new EnumDataType("Color", 1);
		myEnum.add("Red", 1);
		myEnum.add("Green", 5);
		myEnum.add("Blue", 10);

		String[] names = myEnum.getNames();
		assertEquals("Red", names[0]);
		assertEquals("Green", names[1]);
		assertEquals("Blue", names[2]);

		myEnum = new EnumDataType("Color", 1);
		myEnum.add("Red", 20);
		myEnum.add("Green", 1);
		myEnum.add("Blue", 3);

		names = myEnum.getNames();
		assertEquals("Green", names[0]);
		assertEquals("Blue", names[1]);
		assertEquals("Red", names[2]);

		// multiple names per value, requires sub-sorting
		myEnum = new EnumDataType("Color", 1);
		myEnum.add("Red", 20);
		myEnum.add("Pink", 20);
		myEnum.add("Salmon", 20);
		myEnum.add("Green", 1);
		myEnum.add("AnotherGreen", 1);
		myEnum.add("Blue", 3);

		names = myEnum.getNames();
		assertEquals("AnotherGreen", names[0]);
		assertEquals("Green", names[1]);
		assertEquals("Blue", names[2]);
		assertEquals("Pink", names[3]);
		assertEquals("Red", names[4]);
		assertEquals("Salmon", names[5]);
	}

	private void waitForListenerCount(DomainObjListener listener, int count) {
		waitForCondition(() -> listener.getCount() == count);
	}

	private class DomainObjListener implements DomainObjectListener {
		private int count;

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord rec = ev.getChangeRecord(i);
				if (rec.getEventType() == ChangeManager.DOCR_DATA_TYPE_CHANGED) {
					++count;
				}
			}
		}

		int getCount() {
			return count;
		}
	}
}
