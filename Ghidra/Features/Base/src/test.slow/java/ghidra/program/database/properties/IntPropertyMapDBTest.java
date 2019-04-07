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
import ghidra.util.exception.NoValueException;
import ghidra.util.prop.PropertyVisitor;
import ghidra.util.task.TaskMonitorAdapter;

/**
 *
 */
public class IntPropertyMapDBTest extends AbstractGhidraHeadedIntegrationTest implements ErrorHandler {

	private DBHandle db;
	private ProgramDB program;
	private AddressSpace addrSpace;
	private MemoryMapDB memMap;
	private AddressMap addrMap;
	private IntPropertyMapDB propertyMap;
	private Random random;
	private int transactionID;

	/**
	 * Constructor for IntPropertyMapDBTest.
	 * @param arg0
	 */
	public IntPropertyMapDBTest() {
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
		propertyMap = new IntPropertyMapDB(db, DBConstants.CREATE, this, null, addrMap, name,
			TaskMonitorAdapter.DUMMY_MONITOR);
		propertyMap.setCacheSize(2);
	}

	@Test
	public void testIntPropertyMapDB() throws Exception {
		createPropertyMap("TEST");
		Table propertyTable = db.getTable(propertyMap.getTableName());
		assertNull(propertyTable); // Table created when first value added
	}

	@Test
	public void testGetName() throws Exception {
		createPropertyMap("TEST");
		assertEquals("TEST", propertyMap.getName());
	}

	@Test
	public void testAdd() throws Exception {
		createPropertyMap("TEST");
		propertyMap.add(addr(100), 100);
		Table propertyTable = db.getTable(propertyMap.getTableName());
		assertNotNull(propertyTable);
		propertyMap.add(addr(200), 200);
		propertyMap.add(addr(300), 300);
		propertyMap.add(addr(400), 400);
		propertyMap.add(addr(500), 500);
		assertEquals(5, propertyTable.getRecordCount());
	}

	@Test
	public void testGetInt() throws Exception {
		createPropertyMap("TEST");
		propertyMap.add(addr(100), 100);
		propertyMap.add(addr(200), 200);
		propertyMap.add(addr(300), 300);
		propertyMap.add(addr(400), 400);
		propertyMap.add(addr(500), 500);
		assertEquals(100, propertyMap.getInt(addr(100)));
		assertEquals(200, propertyMap.getInt(addr(200)));
		assertEquals(300, propertyMap.getInt(addr(300)));
		assertEquals(400, propertyMap.getInt(addr(400)));
		assertEquals(500, propertyMap.getInt(addr(500)));
		try {
			propertyMap.getInt(addr(150));
			Assert.fail();
		}
		catch (NoValueException e) {
		}
	}

	@Test
	public void testGetSize() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		assertEquals(20, propertyMap.getSize());
	}

	@Test
	public void testApplyValue() throws Exception {
		MyIntVisitor visitor = new MyIntVisitor();
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		for (int i = 0; i < 20; i++) {
			propertyMap.applyValue(visitor, addr(i * 100));
			assertEquals(values[i], visitor.value);
		}

	}

	@Test
	public void testDelete() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		propertyMap.delete();
		assertNull(db.getTable(propertyMap.getTableName()));
	}

	@Test
	public void testIntersects() throws Exception {
		createPropertyMap("TEST");
		assertTrue(!propertyMap.intersects(addr(50), addr(120)));

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
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

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		assertEquals(20, propertyMap.getSize());
		propertyMap.removeRange(addr(1), addr(99));
		assertEquals(20, propertyMap.getSize());
		propertyMap.removeRange(addr(50), addr(250));
		assertEquals(18, propertyMap.getSize());
		try {
			propertyMap.getInt(addr(200));
			Assert.fail();
		}
		catch (NoValueException e) {
		}
		propertyMap.removeRange(addr(1900), addr(2050));
		assertEquals(17, propertyMap.getSize());
		try {
			propertyMap.getInt(addr(1900));
			Assert.fail();
		}
		catch (NoValueException e) {
		}
	}

	@Test
	public void testRemove() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		assertEquals(20, propertyMap.getSize());
		propertyMap.remove(addr(99));
		assertEquals(20, propertyMap.getSize());
		propertyMap.remove(addr(200));
		assertEquals(19, propertyMap.getSize());
		try {
			propertyMap.getInt(addr(200));
			Assert.fail();
		}
		catch (NoValueException e) {
		}
		propertyMap.remove(addr(1900));
		assertEquals(18, propertyMap.getSize());
		try {
			propertyMap.getInt(addr(1900));
			Assert.fail();
		}
		catch (NoValueException e) {
		}
	}

	@Test
	public void testHasProperty() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		for (int i = 0; i < 20; i++) {
			assertTrue(propertyMap.hasProperty(addr(i * 100)));
			assertTrue(!propertyMap.hasProperty(addr((i * 100) + 50)));
		}
	}

	@Test
	public void testGetNextPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		assertEquals(addr(100), propertyMap.getNextPropertyAddress(addr(0)));
		assertEquals(addr(100), propertyMap.getNextPropertyAddress(addr(50)));
		assertEquals(addr(600), propertyMap.getNextPropertyAddress(addr(550)));
		assertNull(propertyMap.getNextPropertyAddress(addr(1900)));
		assertNull(propertyMap.getNextPropertyAddress(addr(1950)));
	}

	@Test
	public void testGetPreviousPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		assertEquals(addr(1900), propertyMap.getPreviousPropertyAddress(addr(2050)));
		assertEquals(addr(100), propertyMap.getPreviousPropertyAddress(addr(200)));
		assertEquals(addr(0), propertyMap.getPreviousPropertyAddress(addr(50)));
		assertNull(propertyMap.getPreviousPropertyAddress(addr(0)));
	}

	@Test
	public void testGetFirstPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 1; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		assertEquals(addr(100), propertyMap.getFirstPropertyAddress());
	}

	@Test
	public void testGetLastPropertyAddress() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 1; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		assertEquals(addr(1900), propertyMap.getLastPropertyAddress());
	}

	/*
	 * Test for AddressIterator getPropertyIterator(Address, Address)
	 */
	@Test
	public void testGetPropertyRangeIterator() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		AddressIterator iter = propertyMap.getPropertyIterator(addr(50), addr(1600));
		long addr = 100;
		while (iter.hasNext()) {
			assertEquals(addr(addr), iter.next());
			addr += 100;
		}
		assertEquals(1700, addr);
	}

	/*
	 * Test for AddressIterator getPropertyIterator(Address, Address, boolean)
	 */
	@Test
	public void testGetPropertyRangeIterator2() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}

		AddressIterator iter = propertyMap.getPropertyIterator(addr(50), addr(1600), true);
		long addr = 100;
		while (iter.hasNext()) {
			assertEquals(addr(addr), iter.next());
			addr += 100;
		}
		assertEquals(1700, addr);

		iter = propertyMap.getPropertyIterator(addr(50), addr(1600), false);
		addr = 1600;
		while (iter.hasNext()) {
			assertEquals(addr(addr), iter.next());
			addr -= 100;
		}
		assertEquals(0, addr);
	}

	/*
	 * Test for AddressIterator getPropertyIterator(Address)
	 */
	@Test
	public void testGetPropertyIterator3() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 1; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		AddressIterator iter = propertyMap.getPropertyIterator(addr(450), true);
		long addr = 500;
		while (iter.hasNext()) {
			assertEquals(addr(addr), iter.next());
			addr += 100;
		}
		assertEquals(2000, addr);

		iter = propertyMap.getPropertyIterator(addr(450), false);
		addr = 400;
		while (iter.hasNext()) {
			assertEquals(addr(addr), iter.next());
			addr -= 100;
		}
		assertEquals(0, addr);
	}

	/*
	 * Test for AddressIterator getPropertyIterator()
	 */
	@Test
	public void testGetPropertyIterator() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}
		AddressIterator iter = propertyMap.getPropertyIterator();
		long addr = 0;
		while (iter.hasNext()) {
			assertEquals(addr(addr), iter.next());
			addr += 100;
		}
		assertEquals(2000, addr);
	}

	/*
	 * Test for AddressIterator getPropertyIterator(AddressSetView)
	 */
	@Test
	public void testGetPropertyIteratorAddressSetView() throws Exception {
		createPropertyMap("TEST");

		int[] values = new int[20];
		for (int i = 0; i < 20; i++) {
			values[i] = random.nextInt();
			propertyMap.add(addr(i * 100), values[i]);
		}

		AddressSet set = new AddressSet();
		set.addRange(addr(50), addr(150));
		set.addRange(addr(600), addr(800));
		AddressIterator iter = propertyMap.getPropertyIterator(set);
		assertEquals(addr(100), iter.next());
		assertEquals(addr(600), iter.next());
		assertEquals(addr(700), iter.next());
		assertEquals(addr(800), iter.next());
		assertNull(iter.next());
	}

	/**
	 * @see ghidra.program.db.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		throw new RuntimeException(e.getMessage());
	}

}

class MyIntVisitor implements PropertyVisitor {

	int value;

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
		throw new RuntimeException();
	}

	/** Handle the case of an int property type. */
	@Override
	public void visit(int value1) {
		this.value = value1;
	}
}
