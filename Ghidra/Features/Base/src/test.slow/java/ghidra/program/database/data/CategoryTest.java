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

import java.util.*;

import org.junit.*;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.data.*;
import ghidra.program.model.data.Enum;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.InvalidNameException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 * Test the database Category implementation.
 * 
 * 
 */
public class CategoryTest extends AbstractGhidraHeadedIntegrationTest {
	private ProgramDB program;
	private int transactionID;
	private DataTypeManagerDB dataMgr;
	private Category root;

	private List<Event> events = Collections.synchronizedList(new ArrayList<Event>());

	private int getEventCount() {
		waitForPostedSwingRunnables();
		return events.size();
	}

	private Event getEvent(int index) {
		waitForPostedSwingRunnables();
		return events.get(index);
	}

	private void clearEvents() {
		waitForPostedSwingRunnables();
		events.clear();
	}

	private TaskMonitor monitor;
	private CategoryTestListener eventRecordingListener;

	public CategoryTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		dataMgr = program.getDataTypeManager();
		eventRecordingListener = new CategoryTestListener();
		dataMgr.addDataTypeManagerListener(eventRecordingListener);
		root = dataMgr.getRootCategory();
		monitor = new TaskMonitorAdapter();
		startTransaction();
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		waitForPostedSwingRunnables();// wait for leftover datatype events

		endTransaction();
		program.release(this);
	}

	private void startTransaction() {
		transactionID = program.startTransaction("Test");
	}

	private void endTransaction() {
		program.endTransaction(transactionID, true);
	}

	@Test
	public void testCreateCategory() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		assertNotNull(sub1);
		assertEquals("SubCat-A", sub1.getName());

		Category sub2 = root.createCategory("SubCat-B");
		assertNotNull(sub2);
		assertEquals("SubCat-B", sub2.getName());
	}

	@Test(expected = InvalidNameException.class)
	public void testCreateCategoryBadName() throws Exception {
		root.createCategory("");
		Assert.fail("Should not create category with empty name");
	}

	@Test
	public void testCreateSubCategories() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category parent = sub1;
		for (int i = 0; i < 10; i++) {
			parent = parent.createCategory("sub" + i);
			assertNotNull(parent);
		}
		parent = sub1;
		for (int i = 0; i < 10; i++) {
			parent = parent.getCategory("sub" + i);
			assertNotNull(parent);
		}
	}

	@Test
	public void testGetCategory() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		s.createCategory("new category");

		sub1.createCategory("Sub-cat2");
		Category c = sub1.getCategory("Sub-cat");
		assertNotNull(c);
		assertEquals("Sub-cat", c.getName());
		assertEquals(1, c.getCategories().length);
	}

	@Test
	public void testSetName() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		assertEquals("/SubCat-A", sub1.getCategoryPath().getPath());

		sub1.setName("MyCategory");
		assertEquals("/MyCategory", sub1.getCategoryPath().getPath());

		assertNotNull(root.getCategory("MyCategory"));
		Category sub2 = root.createCategory("NewCategory");
		sub2.setName("new name");

		assertNotNull(root.getCategory("new name"));
	}

	@Test(expected = InvalidNameException.class)
	public void testSetBadName() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");
		sub1.setName(null);
		Assert.fail("Should not have set name to null");
	}

	@Test
	public void testGetCategories() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		s.createCategory("new category");
		for (int i = 0; i < 10; i++) {
			s.createCategory("sub-" + i);
		}
		Category[] cats = s.getCategories();
		Arrays.sort(cats);
		assertEquals(11, cats.length);
		assertEquals("sub-9", cats[10].getName());
	}

	@Test
	public void testRemoveCategory() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		s.createCategory("new category");
		for (int i = 0; i < 10; i++) {
			s.createCategory("sub-" + i);
		}
		Category c = s.getCategory("sub-5");
		assertTrue(s.removeCategory(c.getName(), monitor));
		assertNull(s.getCategory("sub-5"));
		assertNotNull(s.getCategory("sub-6"));

		String name = s.getName();
		assertTrue(sub1.removeCategory(name, monitor));
		assertNull(sub1.getCategory(name));
	}

	@Test
	public void testMoveCategory2() throws Exception {
		Category cat1 = root.createCategory("c1");
		Category cat2 = cat1.createCategory("c2");
		Category cat4 = cat2.createCategory("c4");
		Category cat5 = cat2.createCategory("c5");

		cat2.createCategory("c3");

		Structure s1 = new StructureDataType("s1", 0);
		s1.add(new ByteDataType());

		cat4.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

		Structure s2 = new StructureDataType("s2", 0);
		s2.add(new ByteDataType());
		cat5.addDataType(s2, DataTypeConflictHandler.DEFAULT_HANDLER);

		// move c4 to c5
		cat5.moveCategory(cat4, TaskMonitorAdapter.DUMMY_MONITOR);
		waitForPostedSwingRunnables();

		assertEquals(new CategoryPath("/c1/c2/c5/c4"), cat4.getCategoryPath());
		assertTrue(dataMgr.containsCategory(new CategoryPath("/c1/c2/c5/c4")));
		assertNotNull(cat4.getDataType("s1"));
		assertEquals(1, cat5.getCategories().length);
	}

	@Test
	public void testMoveCategory3() throws Exception {
		Category myCat = root.createCategory("my category");
		Category cat1 = myCat.createCategory("category 1");
		Enum enumm = new EnumDataType("Colors", 1);
		enumm.add("Red", 0);

		Structure s1 = new StructureDataType("struct_1", 0);
		s1.add(new ByteDataType());

		cat1.addDataType(enumm, DataTypeConflictHandler.DEFAULT_HANDLER);
		cat1.addDataType(s1, DataTypeConflictHandler.DEFAULT_HANDLER);

		Category c1 = root.createCategory("c1");
		Category c2 = c1.createCategory("c2");

		c2.moveCategory(myCat, TaskMonitorAdapter.DUMMY_MONITOR);

		Category[] cats = c2.getCategories();
		assertEquals(1, cats.length);
		assertEquals(new CategoryPath("/c1/c2/my category"), cats[0].getCategoryPath());

		cats = cats[0].getCategories();
		assertEquals(1, cats.length);
		assertEquals(new CategoryPath("/c1/c2/my category/category 1"), cats[0].getCategoryPath());

	}

	@Test
	public void testMoveCategory() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		s.createCategory("new category");
		for (int i = 0; i < 10; i++) {
			s.createCategory("sub-" + i);
		}

		Category sub2 = root.createCategory("SubCat-B");
		sub2.moveCategory(s, monitor);
		assertEquals(sub2, s.getParent());

		assertNotNull(sub1.createCategory("Sub-cat"));
	}

	@Test
	public void testCategoryPathUpdateAfterMoveParent() throws Exception {
		Category catA = root.createCategory("A");
		Category catB = catA.createCategory("B");
		Category catC = catB.createCategory("C");
		assertEquals("/A/B/C", catC.getCategoryPath().getPath());

		root.moveCategory(catB, monitor);

		assertEquals("/B/C", catC.getCategoryPath().getPath());
	}

	@Test
	public void testMoveParentCategory() throws Exception {
		Category catA = root.createCategory("A");
		Category catB = catA.createCategory("B");
		Category catC = catB.createCategory("C");
		catC.createCategory("D");
		long idB = catB.getID();
		long idC = catC.getID();
		assertEquals("/A/B/C", catC.getCategoryPath().getPath());

		root.moveCategory(catB, monitor);

		assertTrue(dataMgr.containsCategory(new CategoryPath("/B/C")));
		assertTrue(!dataMgr.containsCategory(new CategoryPath("/A/B/C")));
		assertEquals("/B/C", catC.getCategoryPath().getPath());

		Category newB = dataMgr.getCategory(idB);
		Category newC = dataMgr.getCategory(idC);
		assertEquals("/B", newB.getCategoryPath().getPath());
		assertEquals("/B/C", newC.getCategoryPath().getPath());

	}

	@Test
	public void testMoveCategoryAncestor() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		s.createCategory("new category");
		for (int i = 0; i < 10; i++) {
			s.createCategory("sub-" + i);
		}
		try {
			Category c = s.getCategory("sub-5");
			c.moveCategory(s, monitor);
			Assert.fail("Should not be able to move an ancestor to its child");
		}
		catch (IllegalArgumentException e) {
		}

		try {
			Category c = s.getCategory("sub-5");
			c.moveCategory(sub1, monitor);
			Assert.fail("Should not be able to move an ancestor to any descendant");
		}
		catch (IllegalArgumentException e) {
		}
	}

	@Test
	public void testCopyCategory() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		s.createCategory("new category");
		for (int i = 0; i < 10; i++) {
			s.createCategory("sub-" + i);
		}
		Category sub2 = sub1.createCategory("my category");
		sub2.copyCategory(s, null, monitor);
		Category c = sub2.getCategory("Sub-cat");
		assertNotNull(c);
		assertNotNull(c.getCategory("new category"));
		assertEquals(11, c.getCategories().length);

		assertNotNull(sub1.getCategory("Sub-cat"));
	}

	@Test
	public void testGetParent() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		assertNull(root.getParent());
		assertEquals(sub1, s.getParent());
		assertEquals(root, sub1.getParent());

		s.createCategory("new category");
		assertEquals(s, s.getCategory("new category").getParent());
	}

	@Test
	public void testgetCategoryPathName() throws Exception {
		assertEquals("/", root.getCategoryPathName());
		Category sub1 = root.createCategory("SubCat-A");
		assertEquals("/SubCat-A", sub1.getCategoryPathName());
		Category s = sub1.createCategory("Sub-cat");
		assertEquals(sub1.getCategoryPathName() + "/Sub-cat", s.getCategoryPathName());
	}

	@Test
	public void testAddBuiltInDataType() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		ByteDataType b = new ByteDataType();
		DataType bdt = s.addDataType(b, null);

		DataType dt = s.getDataType("byte");
		assertNull(dt);
		dt = root.getDataType("byte");
		assertTrue(b.isEquivalent(dt));
		assertTrue(bdt == dt);

	}

	@Test
	public void testGetDataTypes() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		DataType[] dts = new DataType[10];
		DataType[] newdts = new DataType[dts.length];
		for (int i = 0; i < 10; i++) {
			dts[i] = new EnumDataType("Enum_" + i, 2);
			newdts[i] = s.addDataType(dts[i], null);
		}

		for (int i = 0; i < dts.length; i++) {
			assertTrue(dts[i].isEquivalent(newdts[i]));
		}
		DataType[] d = s.getDataTypes();
		Arrays.sort(d, new Comparator<DataType>() {
			@Override
			public int compare(DataType o1, DataType o2) {
				return o1.getName().compareTo(o2.getName());
			}
		});
		assertEquals(dts.length, d.length);
		assertTrue(newdts[0] == d[0]);
	}

	@Test
	public void testAddVariableLengthDataType() throws Exception {

		StringDataType str = new StringDataType();
		String name = str.getName();
		DataType newdt = root.addDataType(str, null);
		assertTrue(str.isEquivalent(newdt));

		DataType dt = root.getDataType(name);
		assertNotNull(dt);
		assertTrue(newdt == dt);

		str = new StringDataType();
		newdt = root.addDataType(str, null);
		assertTrue(str.isEquivalent(newdt));
		assertNotNull(root.getDataType(newdt.getName()));
		assertEquals(1, root.getDataTypes().length);

	}

	@Test
	public void testFindDataTypes() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		DataType str = new EnumDataType("Enum", 2);
		String name = str.getName();
		s.addDataType(str, null);

		str = new EnumDataType("Enum", 2);
		root.addDataType(str, null);

		str = new EnumDataType("Enum", 2);
		Category sub2 = sub1.createCategory("sub2");
		sub2.addDataType(str, null);

		ArrayList<DataType> list = new ArrayList<>();
		dataMgr.findDataTypes(name, list);
		assertEquals(3, list.size());

	}

	@Test
	public void testGetDataType() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		StringDataType str = new StringDataType();
		s.addDataType(str, null);
		ByteDataType b = new ByteDataType();
		DataType newb = s.addDataType(b, null);

		assertEquals(newb, root.getDataType("byte"));
	}

	@Test
	public void testGetDataTypeFullName() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		DataType dt = s.addDataType(new EnumDataType("Enum", 2), null);
		assertEquals("/SubCat-A/Sub-cat/" + dt.getName(), dt.getPathName());
	}

	@Test
	public void testMoveDataType() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s2 = sub1.createCategory("Sub-cat");
		Category s = root.createCategory("Sub-Cat-B");

		StringDataType str = new StringDataType();
		DataType newdt = s2.addDataType(str, null);
		assertEquals(root.getCategoryPath(), newdt.getCategoryPath());

		s.moveDataType(newdt, null);
		assertEquals(root.getCategoryPath(), newdt.getCategoryPath());

	}

	@Test
	public void testRemove() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		StringDataType str = new StringDataType();
		DataType newdt = s.addDataType(str, null);

		DataType[] dts = new DataType[10];
		DataType[] newdts = new DataType[dts.length];
		for (int i = 0; i < 10; i++) {

			dts[i] = new EnumDataType("Enum" + i, 2);
			newdts[i] = s.addDataType(dts[i], null);
		}

		assertTrue(root.remove(newdt, monitor));
		assertNull(root.getDataType(str.getName()));

		for (int i = 0; i < 10; i++) {
			assertTrue(s.remove(newdts[i], monitor));
			assertNull(s.getDataType("Enum_" + i));
		}
	}

	@Test
	public void testAddStructureDataType() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		StructureDataType dt = new StructureDataType("MyStruct", 0);
		dt.add(new ByteDataType());
		dt.add(new WordDataType());
		dt.add(new ByteDataType());

		DataType newDt = s.addDataType(dt, null);
		assertTrue(newDt == s.getDataType("MyStruct"));
	}

	@Test
	public void testDataTypeSizeChanged() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		Structure dt = new StructureDataType("MyStruct", 100);
		dt.insert(0, new ByteDataType());
		dt.insert(1, new WordDataType());
		dt.insert(2, new ByteDataType());

		Structure newDt = (Structure) s.addDataType(dt, null);
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
	public void testDataTypeDeleted() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");

		Structure dt = new StructureDataType("MyStruct", 100);
		dt.insert(0, new ByteDataType());
		dt.insert(1, new WordDataType());
		dt.insert(2, new ByteDataType());
		Structure newDt = (Structure) s.addDataType(dt, null);

		Structure struct2 = new StructureDataType("InnerStruct", 0);
		struct2.add(new StringDataType(), 30);
		struct2.add(new ByteDataType());

		struct2 = (Structure) newDt.insert(3, struct2).getDataType();

		DataTypeComponent[] comps = newDt.getDefinedComponents();

		DataType cdt = root.getDataType("InnerStruct");
		assertNotNull(cdt);

		root.remove(cdt, monitor);

		assertEquals(comps.length - 1, newDt.getDefinedComponents().length);
	}

	@Test
	public void testDataTypeConflictHandling() throws Exception {
		Category sub1 = root.createCategory("Cat1");
		DataType dt1 = new StructureDataType("DT", 1);
		DataType dt2 = new StructureDataType("DT", 2);
		DataType added1 = sub1.addDataType(dt1, null);
		DataType added2 = sub1.addDataType(dt2, null);
		assertEquals("DT", added1.getName());
		assertEquals("DT.conflict", added2.getName());

		List<DataType> list = sub1.getDataTypesByBaseName("DT");
		assertEquals(2, list.size());
		assertEquals(added1, list.get(0));
		assertEquals(added2, list.get(1));

		list = sub1.getDataTypesByBaseName("DT.conflict");
		assertEquals(2, list.size());
		assertEquals(added1, list.get(0));
		assertEquals(added2, list.get(1));

		sub1.remove(added2, TaskMonitor.DUMMY);
		list = sub1.getDataTypesByBaseName("DT");
		assertEquals(1, list.size());
		assertEquals(added1, list.get(0));

		list = sub1.getDataTypesByBaseName("DT.conflict");
		assertEquals(1, list.size());
		assertEquals(added1, list.get(0));

	}

	@Test
	public void testGetDataTypeManager() throws Exception {
		Category sub1 = root.createCategory("SubCat-A");
		Category s = sub1.createCategory("Sub-cat");
		DataTypeManager dtm = s.getDataTypeManager();
		assertNotNull(dtm);
		assertEquals(dataMgr, dtm);
	}

	@Test
	public void testListenerCategoryAdded() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");
		assertEquals(1, getEventCount());
		Event ev = getEvent(0);
		assertEquals("Cat Added", ev.evName);
		assertEquals(root.getCategoryPath(), ev.parent);
		assertEquals(sub1.getCategoryPath(), ev.cat);
	}

	@Test
	public void testListenerCategoryRemoved() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");
		Category sub2 = sub1.createCategory("sub2");

		sub1.removeCategory(sub2.getName(), monitor);
		assertEquals(3, getEventCount());

		Event ev = getEvent(2);
		assertEquals(sub1.getCategoryPath(), ev.parent);
		assertEquals("sub2", ev.name);
	}

	@Test
	public void testListenerCategoryRenamed() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");
		Category sub2 = sub1.createCategory("sub2");

		sub2.setName("my_sub2");
		assertEquals(3, getEventCount());
		Event ev = getEvent(2);

		assertEquals("sub2", ev.name);
		assertEquals(sub2.getCategoryPath(), ev.cat);
	}

	@Test
	public void testListenerCategoryMoved() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");
		Category sub2 = sub1.createCategory("sub2");
		Category sub3 = root.createCategory("sub3");
		sub2.moveCategory(sub3, monitor);
		assertEquals(4, getEventCount());
		Event ev = getEvent(3);

		assertEquals(sub3.getCategoryPath(), ev.cat);
		assertEquals(root.getCategoryPath(), ev.parent);
	}

	@Test
	public void testListenerDataTypeAdded() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");

		Structure dt = new StructureDataType("MyStruct", 0);
		dt.add(new ByteDataType());
		dt.add(new WordDataType());
		dt.add(new ByteDataType());

		sub1.addDataType(dt, null);
		DataType byteDt = root.getDataType("byte");
		DataType wordDt = root.getDataType("word");

		Event ev = getEvent(0);
		assertEquals("Cat Added", ev.evName);
		assertEquals(null, ev.dt);
		assertEquals(root.getCategoryPath(), ev.parent);

		ev = getEvent(1);
		assertEquals("DT Added", ev.evName);
		assertEquals(byteDt, ev.dt);
		assertEquals(root.getCategoryPath(), ev.parent);

		ev = getEvent(2);
		assertEquals("DT Added", ev.evName);
		assertEquals(wordDt, ev.dt);
		assertEquals(root.getCategoryPath(), ev.parent);

		ev = getEvent(3);
		assertEquals("DT Changed", ev.evName);
		assertTrue(dt.isEquivalent(ev.dt));
		assertEquals(null, ev.parent);

//		ev = getEvent(4);  // eliminated size change event during creation
//		assertEquals("DT Changed", ev.evName);
//		assertTrue(dt.isEquivalent(ev.dt));
//		assertEquals(null, ev.parent);

		ev = getEvent(4);
		assertEquals("DT Added", ev.evName);
		assertTrue(dt.isEquivalent(ev.dt));
		assertEquals(sub1.getCategoryPath(), ev.parent);

		assertEquals(5, getEventCount());

	}

	@Test
	public void testListenerDataTypeRemoved() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");

		Structure dt = new StructureDataType("MyStruct", 0);
		dt.add(new ByteDataType());
		dt.add(new WordDataType());
		dt.add(new ByteDataType());

		DataType newDt = sub1.addDataType(dt, null);

		clearEvents();

		sub1.remove(newDt, monitor);

		assertEquals(1, getEventCount());
		Event ev = getEvent(0);
		assertEquals(sub1.getCategoryPath(), ev.parent);
		assertEquals(newDt.getName(), ev.name);
	}

	@Test
	public void testListenerDataTypeRenamed() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");

		Structure dt = new StructureDataType("MyStruct", 0);
		dt.add(new ByteDataType());
		dt.add(new WordDataType());
		dt.add(new ByteDataType());

		DataType newDt = sub1.addDataType(dt, null);
		clearEvents();

		newDt.setName("MyNewStructName");
		assertEquals(1, getEventCount());
		Event ev = getEvent(0);

		assertEquals(newDt, ev.dt);
		assertEquals("MyStruct", ev.name);

	}

	@Test
	public void testListenerDataTypeMoved() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");
		Category sub2 = sub1.createCategory("sub2");

		Structure dt = new StructureDataType("MyStruct", 0);
		dt.add(new ByteDataType());
		dt.add(new WordDataType());
		dt.add(new EnumDataType("Enum", 2));

		sub1.addDataType(dt, null);
		root.getDataType("byte");

		clearEvents();
		DataType byteAdded = root.getDataType("Enum");
		sub2.moveDataType(byteAdded, null);
		waitForPostedSwingRunnables();

		assertEquals(1, getEventCount());
		Event ev = getEvent(0);
		assertEquals(root.getCategoryPath(), ev.cat);
		assertEquals(sub2.getCategoryPath(), ev.parent);
		assertEquals(byteAdded, ev.dt);
	}

	@Test
	public void testListenerDataTypeChanged() throws Exception {

		Category sub1 = root.createCategory("SubCat-A");

		Structure dt = new StructureDataType("MyStruct", 0);
		dt.add(new ByteDataType());
		dt.add(new WordDataType());
		dt.add(new ByteDataType());
		Structure newDt = (Structure) sub1.addDataType(dt, null);

		Structure struct2 = new StructureDataType("InnerStruct", 0);
		struct2.add(new StringDataType(), 30);
		struct2.add(new ByteDataType());
		clearEvents();

		struct2 = (Structure) newDt.insert(3, struct2).getDataType();

		assertEquals(4, getEventCount());
		Event ev = getEvent(3);
		assertEquals("DT Changed", ev.evName);
		assertEquals(newDt, ev.dt);
	}

	private class Event {
		String evName;
		CategoryPath parent;
		CategoryPath cat;
		String name;
		DataType dt;

		Event(String evName, CategoryPath parent, CategoryPath cat, String name, DataType dt) {
			this.evName = evName;
			this.parent = parent;
			this.cat = cat;
			this.name = name;
			this.dt = dt;
		}
	}

	private class CategoryTestListener implements DataTypeManagerChangeListener {

		@Override
		public void categoryAdded(DataTypeManager dtm, CategoryPath path) {
			events.add(new Event("Cat Added", path.getParent(), path, null, null));
		}

		@Override
		public void categoryMoved(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			events.add(new Event("Cat Moved", oldPath.getParent(), newPath, null, null));
		}

		@Override
		public void categoryRemoved(DataTypeManager dtm, CategoryPath path) {
			events.add(new Event("Cat Removed", path.getParent(), null, path.getName(), null));
		}

		@Override
		public void categoryRenamed(DataTypeManager dtm, CategoryPath oldPath, CategoryPath newPath) {
			events.add(new Event("Cat Renamed", null, newPath, oldPath.getName(), null));
		}

		@Override
		public void dataTypeAdded(DataTypeManager dtm, DataTypePath path) {
			DataType dataType = dtm.getDataType(path);
			events.add(new Event("DT Added", path.getCategoryPath(), null, null, dataType));
		}

		@Override
		public void dataTypeChanged(DataTypeManager dtm, DataTypePath path) {
			DataType dataType = dtm.getDataType(path);
			events.add(new Event("DT Changed", null, null, null, dataType));
		}

		@Override
		public void dataTypeMoved(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			DataType dataType = dtm.getDataType(newPath);
			events.add(new Event("DT Moved", newPath.getCategoryPath(), oldPath.getCategoryPath(),
				null, dataType));
		}

		@Override
		public void dataTypeRemoved(DataTypeManager dtm, DataTypePath path) {
			events.add(new Event("DT Removed", path.getCategoryPath(), null,
				path.getDataTypeName(), null));
		}

		@Override
		public void dataTypeRenamed(DataTypeManager dtm, DataTypePath oldPath, DataTypePath newPath) {
			DataType dataType = dtm.getDataType(newPath);
			events.add(new Event("DT Renamed", null, null, oldPath.getDataTypeName(), dataType));
		}

		@Override
		public void dataTypeReplaced(DataTypeManager dtm, DataTypePath oldPath,
				DataTypePath newPath, DataType newDataType) {
			// don't care
		}

		@Override
		public void favoritesChanged(DataTypeManager dtm, DataTypePath path, boolean isFavorite) {
			// don't care
		}

		@Override
		public void sourceArchiveAdded(DataTypeManager dtm, SourceArchive dataTypeSource) {
			// don't care
		}

		@Override
		public void sourceArchiveChanged(DataTypeManager dataTypeManager,
				SourceArchive dataTypeSource) {
			// don't care
		}
	}
}
