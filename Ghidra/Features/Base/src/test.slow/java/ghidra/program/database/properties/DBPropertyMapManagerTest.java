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

import java.io.File;
import java.io.IOException;
import java.util.Iterator;

import org.junit.*;

import db.*;
import db.util.ErrorHandler;
import generic.test.AbstractGenericTest;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.util.*;
import ghidra.program.util.ChangeManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Lock;
import ghidra.util.task.TaskMonitorAdapter;

/**
 *
 */
public class DBPropertyMapManagerTest extends AbstractGhidraHeadedIntegrationTest
		implements ChangeManager, ErrorHandler {

	private static final File testDir = new File(AbstractGenericTest.getTestDirectoryPath());
	private static File dbFile = new File(testDir, "test.dbf");

	private DBHandle dbh;
	private ProgramDB program;
	private AddressSpace addrSpace;
	private MemoryMapDB memMap;
	private AddressMap addrMap;
	private DBPropertyMapManager mgr;
	private int transactionID;

	/**
	 * Constructor for DBPropertyMapManagerTest.
	 * @param arg0
	 */
	public DBPropertyMapManagerTest() {
		super();
	}

	/*
	 * @see TestCase#setUp()
	 */
	@Before
	public void setUp() throws Exception {

		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		dbh = program.getDBHandle();
		addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		memMap = (MemoryMapDB) program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memMap);
		mgr = (DBPropertyMapManager) program.getUsrPropertyManager();

		transactionID = program.startTransaction("Test");

		memMap.createUninitializedBlock("Block1", addr(0), 0x3fffffffL, false);

		dbFile.delete();
	}

	/*
	 * @see TestCase#tearDown()
	 */
	@After
	public void tearDown() throws Exception {
		if (program != null) {
			if (program.getCurrentTransaction() != null) {
				program.endTransaction(transactionID, true);
			}
			program.release(this);
		}
		dbh.close();

	}

	private Address addr(long offset) {
		return addrSpace.getAddress(offset);
	}

	@Test
	public void testDBPropertyMapManager() throws Exception {
		program.endTransaction(transactionID, true);
		Table propertyTable = dbh.getTable(DBPropertyMapManager.PROPERTIES_TABLE_NAME);
		assertNotNull(propertyTable);
	}

	@Test
	public void testCreateIntPropertyMap() throws Exception {
		IntPropertyMap map = mgr.createIntPropertyMap("TEST");
		map.add(addr(100), 100);
		program.endTransaction(transactionID, true);
		assertEquals(map.getSize(), 1);
	}

	@Test
	public void testCreateLongPropertyMap() throws Exception {
		LongPropertyMap map = mgr.createLongPropertyMap("TEST");
		map.add(addr(100), 100);
		program.endTransaction(transactionID, true);
		assertEquals(map.getSize(), 1);
	}

	@Test
	public void testCreateStringPropertyMap() throws Exception {
		StringPropertyMap map = mgr.createStringPropertyMap("TEST");
		map.add(addr(100), "STR100");
		program.endTransaction(transactionID, true);
		assertEquals(map.getSize(), 1);
	}

	@Test
	public void testCreateObjectPropertyMap() throws Exception {
		ObjectPropertyMap map = mgr.createObjectPropertyMap("TEST", TestSaveable.class);
		map.add(addr(100), new TestSaveable());
		program.endTransaction(transactionID, true);
		assertEquals(map.getSize(), 1);
	}

	@Test
	public void testCreateVoidPropertyMap() throws Exception {
		VoidPropertyMap map = mgr.createVoidPropertyMap("TEST");
		map.add(addr(100));
		program.endTransaction(transactionID, true);
		assertEquals(map.getSize(), 1);
	}

	@Test
	public void testGetPropertyMap() throws Exception {
		IntPropertyMap map = mgr.createIntPropertyMap("TEST");
		map.add(addr(100), 100);
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);
		PropertyMap pmap = mgr.getPropertyMap("TEST");
		assertEquals(1, pmap.getSize());
	}

	@Test
	public void testGetIntPropertyMap() throws Exception {
		IntPropertyMap map = mgr.createIntPropertyMap("TEST");
		map.add(addr(100), 100);
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);
		PropertyMap pmap = mgr.getPropertyMap("TEST");
		assertEquals(1, pmap.getSize());
	}

	@Test
	public void testGetLongPropertyMap() throws Exception {
		LongPropertyMap map = mgr.createLongPropertyMap("TEST");
		map.add(addr(100), 100);
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);
		PropertyMap pmap = mgr.getPropertyMap("TEST");
		assertEquals(1, pmap.getSize());
	}

	@Test
	public void testGetStringPropertyMap() throws Exception {
		StringPropertyMap map = mgr.createStringPropertyMap("TEST");
		map.add(addr(100), "STR100");
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);
		PropertyMap pmap = mgr.getPropertyMap("TEST");
		assertEquals(1, pmap.getSize());
	}

	@Test
	public void testGetObjectPropertyMap() throws Exception {
		ObjectPropertyMap map = mgr.createObjectPropertyMap("TEST", TestSaveable.class);
		map.add(addr(100), new TestSaveable());
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);
		PropertyMap pmap = mgr.getPropertyMap("TEST");
		assertEquals(1, pmap.getSize());
	}

	@Test
	public void testGetVoidPropertyMap() throws Exception {
		VoidPropertyMap map = mgr.createVoidPropertyMap("TEST");
		map.add(addr(100));
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);
		PropertyMap pmap = mgr.getPropertyMap("TEST");
		assertEquals(1, pmap.getSize());
	}

	@Test
	public void testRemovePropertyMap() throws Exception {
		IntPropertyMap map = mgr.createIntPropertyMap("TEST");
		map.add(addr(100), 100);
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		dbh.startTransaction();
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);
		mgr.removePropertyMap("TEST");

		assertNull(mgr.getIntPropertyMap("TEST"));
	}

	@Test
	public void testPropertyManagers() throws Exception {
		mgr.createIntPropertyMap("TEST1");
		mgr.createLongPropertyMap("TEST2");
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr = new DBPropertyMapManager(dbh, this, addrMap, DBConstants.UPDATE, new Lock("TEST"),
			TaskMonitorAdapter.DUMMY_MONITOR);

		int cnt = 0;
		Iterator<String> iter = mgr.propertyManagers();
		while (iter.hasNext()) {
			String name = iter.next();
			assertEquals(name.indexOf("TEST"), 0);
			++cnt;
		}
		assertEquals(cnt, 2);
	}

	/*
	 * Test for void removeAll(Address)
	 */
	@Test
	public void testRemoveAll() {
	}

	/*
	 * Test for void removeAll(Address, Address)
	 */
	@Test
	public void testRemoveAllRange() {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setChanged(int, ghidra.program.model.address.Address, ghidra.program.model.address.Address, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setChanged(int type, Address start, Address end, Object oldValue, Object newValue) {

	}

	/**
	 * @see ghidra.program.util.ChangeManager#setChanged(int, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setChanged(int type, Object oldValue, Object newValue) {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setObjChanged(int, ghidra.program.model.address.Address, java.lang.Object, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setObjChanged(int type, Address addr, Object affectedObj, Object oldValue,
			Object newValue) {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setObjChanged(int, int, ghidra.program.model.address.Address, java.lang.Object, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setObjChanged(int type, int subType, Address addr, Object affectedObj,
			Object oldValue, Object newValue) {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setObjChanged(int, ghidra.program.model.address.AddressSetView, java.lang.Object, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setObjChanged(int type, AddressSetView addrSet, Object affectedObj, Object oldValue,
			Object newValue) {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setObjChanged(int, java.lang.Object, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setObjChanged(int type, Object affectedObj, Object oldValue, Object newValue) {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setObjChanged(int, int, java.lang.Object, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setObjChanged(int type, int subType, Object affectedObj, Object oldValue,
			Object newValue) {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setPropertyChanged(java.lang.String, ghidra.program.model.address.Address, java.lang.Object, java.lang.Object)
	 */
	@Override
	public void setPropertyChanged(String propertyName, Address codeUnitAddr, Object oldValue,
			Object newValue) {
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setPropertyRangeRemoved(java.lang.String, ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public void setPropertyRangeRemoved(String propertyName, Address start, Address end) {
	}

	/*
	 * @see ghidra.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		e.printStackTrace();
	}

	/**
	 * @see ghidra.program.util.ChangeManager#setDataTypeChanged(int, java.lang.Object, java.lang.Object)
	 */
	public void setDataTypeChanged(int type, Object obj1, Object obj2) {
		// TODO Auto-generated method stub

	}

	/**
	 * @see ghidra.program.util.ChangeManager#setRegisterValuesChanged(ghidra.program.model.lang.Register, ghidra.program.model.address.Address, ghidra.program.model.address.Address)
	 */
	@Override
	public void setRegisterValuesChanged(Register register, Address start, Address end) {
		// TODO Auto-generated method stub

	}

}
