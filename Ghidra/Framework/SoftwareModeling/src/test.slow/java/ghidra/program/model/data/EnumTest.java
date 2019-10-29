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
package ghidra.program.model.data;

import static org.junit.Assert.*;

import java.util.NoSuchElementException;

import org.junit.*;

import generic.test.AbstractGTest;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Tests for Enum data types.
 */
public class EnumTest extends AbstractGTest {

	private DataTypeManager dataMgr;

	@Before
	public void setUp() throws Exception {
		dataMgr = new StandAloneDataTypeManager("Test");
		dataMgr.startTransaction("");
	}

	@Test
	public void testCreateEnum() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 1);
		enumm.add("Blue", 2);

		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");

		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);

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

		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");

		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		assertEquals(3, enummDT.getCount());
		enummDT.remove("Green");
		assertEquals(2, enummDT.getCount());

	}

	@Test
	public void testAddValue() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 0);
		enumm.add("Green", 1);
		enumm.add("Blue", 2);

		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");

		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);

		enummDT.add("Purple", 7);
		assertEquals(4, enummDT.getCount());
		assertEquals(7, enummDT.getValue("Purple"));
	}

	@Test
	public void testEditValue() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");

		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		enummDT.remove("Blue");
		assertEquals(2, enummDT.getCount());
		enummDT.add("Blue", 30);
		assertEquals(30, enummDT.getValue("Blue"));
		assertEquals("Blue", enummDT.getName(30));
		assertNull(enummDT.getName(20));
	}

	@Test
	public void testCloneRetain() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);

		Enum copyDT = (Enum) enummDT.clone(null);
		assertNotNull(copyDT);

		Enum c2 = (Enum) root.addDataType(copyDT, DataTypeConflictHandler.DEFAULT_HANDLER);
		assertNotNull(c2);
		assertTrue(copyDT.isEquivalent(c2));
	}

	@Test
	public void testCopyDontRetain() throws Exception {
		Enum enumm = new EnumDataType("Color", 1);
		enumm.add("Red", 10);
		enumm.add("Green", 15);
		enumm.add("Blue", 20);
		Category root = dataMgr.getRootCategory();
		Category c = root.createCategory("enumms");
		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);

		Enum copyDT = (Enum) enummDT.copy(null);
		assertNotNull(copyDT);

		Enum c2 = (Enum) root.addDataType(copyDT, DataTypeConflictHandler.DEFAULT_HANDLER);
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
		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		assertNotNull(enummDT);

		c.remove(enummDT, TaskMonitorAdapter.DUMMY_MONITOR);
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
		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);

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
		Enum enummDT = (Enum) c.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);

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
		}
	}

}
