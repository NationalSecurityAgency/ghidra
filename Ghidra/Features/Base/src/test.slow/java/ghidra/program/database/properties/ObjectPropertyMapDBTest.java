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
package ghidra.program.database.properties;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.Random;

import org.junit.*;

import db.*;
import db.util.ErrorHandler;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Saveable;
import ghidra.util.prop.PropertyVisitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 *
 */
public class ObjectPropertyMapDBTest extends AbstractGhidraHeadedIntegrationTest implements ErrorHandler {

	private DBHandle db;
	private ProgramDB program;
	private AddressSpace addrSpace;
	private MemoryMapDB memMap;
	private AddressMap addrMap;
	private ObjectPropertyMapDB propertyMap;
	private Random random;
	private int transactionID;

	/**
	 * Constructor for ObjectPropertyMapDBTest.
	 * @param arg0
	 */
	public ObjectPropertyMapDBTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		db = program.getDBHandle();
		addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		memMap = (MemoryMapDB) program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memMap);
		transactionID = program.startTransaction("Test");

		memMap.createUninitializedBlock("Block1", addr(0), 0x3fffffffL, false);

		random = new Random(1);
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);

	}

	private Address addr(long offset) {
		return addrSpace.getAddress(offset);
	}

	private void createPropertyMap(String name) throws Exception {
		propertyMap = new ObjectPropertyMapDB(db, DBConstants.CREATE, this, null, addrMap, name,
			TestSaveable.class, TaskMonitorAdapter.DUMMY_MONITOR, true);
		propertyMap.setCacheSize(2);
	}

	@Test
	public void testObjectPropertyMapDB() throws Exception {
		createPropertyMap("TEST");
		assertNull(db.getTable(propertyMap.getTableName())); // Table created when first value added
	}

	@Test
	public void testGetName() throws Exception {
		createPropertyMap("TEST");
		assertEquals("TEST", propertyMap.getName());
	}

	@Test
	public void testAdd() throws Exception {
		createPropertyMap("TEST");
		Table propertyTable = null;

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
			if (i == 0) {
				propertyTable = db.getTable(propertyMap.getTableName());
				assertNotNull(propertyTable);
			}
		}
		propertyTable = db.getTable(propertyMap.getTableName());
		assertEquals(propertyTable.getRecordCount(), 20);
	}

	@Test
	public void testGetObject() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		for (int i = 0; i < 20; i++) {
			TestSaveable obj = (TestSaveable) propertyMap.getObject(addr(i * 100));
			assertEquals(obj, objs[i]);
		}

		assertNull(propertyMap.getObject(addr(150)));
	}

	@Test
	public void testGetSize() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		assertEquals(propertyMap.getSize(), 20);
	}

	@Test
	public void testApplyValue() throws Exception {
		MyObjectVisitor visitor = new MyObjectVisitor();
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		for (int i = 0; i < 20; i++) {
			propertyMap.applyValue(visitor, addr(i * 100));
			assertEquals(visitor.value, objs[i]);
		}

	}

	@Test
	public void testDelete() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		propertyMap.delete();
		assertNull(db.getTable(propertyMap.getTableName()));
	}

	@Test
	public void testIntersects() throws Exception {
		createPropertyMap("TEST");
		assertTrue(!propertyMap.intersects(addr(50), addr(120)));

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}

		assertTrue(!propertyMap.intersects(addr(50), addr(90)));
		assertTrue(propertyMap.intersects(addr(50), addr(100)));
		assertTrue(propertyMap.intersects(addr(50), addr(120)));
		assertTrue(!propertyMap.intersects(addr(150), addr(170)));
		assertTrue(propertyMap.intersects(addr(50), addr(2100)));
		assertTrue(propertyMap.intersects(addr(150), addr(250)));
		assertTrue(propertyMap.intersects(addr(1850), addr(1900)));
		assertTrue(propertyMap.intersects(addr(1900), addr(1950)));
		assertTrue(!propertyMap.intersects(addr(1901), addr(2000)));

	}

	@Test
	public void testRemoveRange() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		assertEquals(propertyMap.getSize(), 20);
		propertyMap.removeRange(addr(1), addr(99));
		assertEquals(propertyMap.getSize(), 20);
		propertyMap.removeRange(addr(50), addr(250));
		assertEquals(propertyMap.getSize(), 18);
		assertNull(propertyMap.getObject(addr(200)));
		propertyMap.removeRange(addr(1900), addr(2050));
		assertEquals(propertyMap.getSize(), 17);
		assertNull(propertyMap.getObject(addr(1900)));

	}

	@Test
	public void testRemove() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		assertEquals(propertyMap.getSize(), 20);
		propertyMap.remove(addr(99));
		assertEquals(propertyMap.getSize(), 20);
		propertyMap.remove(addr(200));
		assertEquals(propertyMap.getSize(), 19);
		assertNull(propertyMap.getObject(addr(200)));
		propertyMap.remove(addr(1900));
		assertEquals(propertyMap.getSize(), 18);
		assertNull(propertyMap.getObject(addr(1900)));
	}

	@Test
	public void testHasProperty() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		for (int i = 0; i < 20; i++) {
			assertTrue(propertyMap.hasProperty(addr(i * 100)));
			assertTrue(!propertyMap.hasProperty(addr((i * 100) + 50)));
		}
	}

	@Test
	public void testGetNextPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		assertEquals(propertyMap.getNextPropertyAddress(addr(0)), addr(100));
		assertEquals(propertyMap.getNextPropertyAddress(addr(50)), addr(100));
		assertEquals(propertyMap.getNextPropertyAddress(addr(550)), addr(600));
		assertNull(propertyMap.getNextPropertyAddress(addr(1900)));
		assertNull(propertyMap.getNextPropertyAddress(addr(1950)));
	}

	@Test
	public void testGetPreviousPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		assertEquals(propertyMap.getPreviousPropertyAddress(addr(2050)), addr(1900));
		assertEquals(propertyMap.getPreviousPropertyAddress(addr(200)), addr(100));
		assertEquals(propertyMap.getPreviousPropertyAddress(addr(50)), addr(0));
		assertNull(propertyMap.getPreviousPropertyAddress(addr(0)));
	}

	@Test
	public void testGetFirstPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 1; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		assertEquals(propertyMap.getFirstPropertyAddress(), addr(100));
	}

	@Test
	public void testGetLastPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 1; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		assertEquals(propertyMap.getLastPropertyAddress(), addr(1900));
	}

	/*
	 * Test for AddressIterator getPropertyIterator(Address, Address)
	 */
	@Test
	public void testGetPropertyRangeIterator() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		AddressIterator iter = propertyMap.getPropertyIterator(addr(50), addr(1600));
		long addr = 100;
		while (iter.hasNext()) {
			assertEquals(iter.next(), addr(addr));
			addr += 100;
		}
		assertEquals(addr, 1700);
	}

	/*
	 * Test for AddressIterator getPropertyIterator(Address, Address, boolean)
	 */
	@Test
	public void testGetPropertyRangeIterator2() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}

		AddressIterator iter = propertyMap.getPropertyIterator(addr(50), addr(1600), true);
		long addr = 100;
		while (iter.hasNext()) {
			assertEquals(iter.next(), addr(addr));
			addr += 100;
		}
		assertEquals(addr, 1700);

		iter = propertyMap.getPropertyIterator(addr(50), addr(1600), false);
		addr = 1600;
		while (iter.hasNext()) {
			assertEquals(iter.next(), addr(addr));
			addr -= 100;
		}
		assertEquals(addr, 0);
	}

	/*
	 * Test for AddressIterator getPropertyIterator(Address)
	 */
	@Test
	public void testGetPropertyIterator3() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 1; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		AddressIterator iter = propertyMap.getPropertyIterator(addr(450), true);
		long addr = 500;
		while (iter.hasNext()) {
			assertEquals(iter.next(), addr(addr));
			addr += 100;
		}
		assertEquals(addr, 2000);

		iter = propertyMap.getPropertyIterator(addr(450), false);
		addr = 400;
		while (iter.hasNext()) {
			assertEquals(iter.next(), addr(addr));
			addr -= 100;
		}
		assertEquals(addr, 0);
	}

	/*
	 * Test for AddressIterator getPropertyIterator()
	 */
	@Test
	public void testGetPropertyIterator() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}
		AddressIterator iter = propertyMap.getPropertyIterator();
		long addr = 0;
		while (iter.hasNext()) {
			assertEquals(iter.next(), addr(addr));
			addr += 100;
		}
		assertEquals(addr, 2000);
	}

	/*
	 * Test for AddressIterator getPropertyIterator(AddressSetView)
	 */
	@Test
	public void testGetPropertyIteratorAddressSetView() throws Exception {
		createPropertyMap("TEST");

		TestSaveable[] objs = new TestSaveable[20];
		for (int i = 0; i < 20; i++) {
			objs[i] = createSaveableObject();
			propertyMap.add(addr(i * 100), objs[i]);
		}

		AddressSet set = new AddressSet();
		set.addRange(addr(50), addr(150));
		set.addRange(addr(600), addr(800));
		AddressIterator iter = propertyMap.getPropertyIterator(set);
		assertEquals(iter.next(), addr(100));
		assertEquals(iter.next(), addr(600));
		assertEquals(iter.next(), addr(700));
		assertEquals(iter.next(), addr(800));
		assertNull(iter.next());
	}

	/**
	 * @see ghidra.program.db.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		throw new RuntimeException(e.getMessage());
	}

	private TestSaveable createSaveableObject() throws Exception {
		TestSaveable obj = new TestSaveable();
		obj.booleanValue = random.nextBoolean();
		obj.byteValue = (byte) random.nextInt();
		obj.shortValue = (short) random.nextInt();
		obj.intValue = random.nextInt();
		obj.longValue = random.nextLong();
		obj.floatValue = random.nextFloat();
		obj.doubleValue = random.nextDouble();
		obj.strValue = "STR" + obj.byteValue;

		int cnt = random.nextInt(9) - 1;
		if (cnt >= 0) {
			obj.byteValues = new byte[cnt];
			for (int i = 0; i < cnt; i++) {
				obj.byteValues[i] = (byte) random.nextInt();
			}
		}

		cnt = random.nextInt(9) - 1;
		if (cnt >= 0) {
			obj.shortValues = new short[cnt];
			for (int i = 0; i < cnt; i++) {
				obj.shortValues[i] = (short) random.nextInt();
			}
		}

		cnt = random.nextInt(9) - 1;
		if (cnt >= 0) {
			obj.intValues = new int[cnt];
			for (int i = 0; i < cnt; i++) {
				obj.intValues[i] = random.nextInt();
			}
		}

		cnt = random.nextInt(9) - 1;
		if (cnt >= 0) {
			obj.longValues = new long[cnt];
			for (int i = 0; i < cnt; i++) {
				obj.longValues[i] = random.nextLong();
			}
		}

		cnt = random.nextInt(9) - 1;
		if (cnt >= 0) {
			obj.floatValues = new float[cnt];
			for (int i = 0; i < cnt; i++) {
				obj.floatValues[i] = random.nextFloat();
			}
		}

		cnt = random.nextInt(9) - 1;
		if (cnt >= 0) {
			obj.doubleValues = new double[cnt];
			for (int i = 0; i < cnt; i++) {
				obj.doubleValues[i] = random.nextDouble();
			}
		}

		cnt = random.nextInt(9) - 1;
		if (cnt >= 0) {
			obj.strValues = new String[cnt];
			for (int i = 0; i < cnt; i++) {
				obj.strValues[i] = "STR" + ((byte) random.nextInt());
			}
		}

		return obj;
	}

}

class MyObjectVisitor implements PropertyVisitor {

	Saveable value;

	/** Handle the case of a void property type. */
	@Override
	public void visit() {
		throw new RuntimeException();
	}

	/** Handle the case of a String property type. */
	@Override
	public void visit(String value1) {
		throw new RuntimeException();
	}

	/** Handle the case of an Object property type. */
	@Override
	public void visit(Object value1) {
		throw new RuntimeException();
	}

	/** Handle the case of a Saveable property type*/
	@Override
	public void visit(Saveable value1) {
		this.value = value1;
	}

	/** Handle the case of an int property type. */
	@Override
	public void visit(int value1) {
		throw new RuntimeException();
	}
}
