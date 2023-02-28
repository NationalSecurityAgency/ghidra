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
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.util.*;
import ghidra.program.util.ChangeManager;
import ghidra.program.util.ChangeManagerAdapter;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Lock;
import ghidra.util.task.TaskMonitor;

public class DBPropertyMapManagerTest extends AbstractGhidraHeadedIntegrationTest
		implements ErrorHandler {

	private static final File testDir = new File(getTestDirectoryPath());
	private static File dbFile = new File(testDir, "test.dbf");

	private DBHandle dbh;
	private ProgramDB program;
	private AddressSpace addrSpace;
	private MemoryMapDB memMap;
	private AddressMap addrMap;
	private DBPropertyMapManager mgr;
	private int transactionID;

	private final ChangeManager changeMgr = new ChangeManagerAdapter();

	/**
	 * Constructor for DBPropertyMapManagerTest.
	 */
	public DBPropertyMapManagerTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {

		program = createDefaultProgram("Test", ProgramBuilder._TOY, this);
		dbh = program.getDBHandle();
		addrSpace = program.getAddressFactory().getDefaultAddressSpace();
		memMap = program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memMap);
		mgr = (DBPropertyMapManager) program.getUsrPropertyManager();

		transactionID = program.startTransaction("Test");

		memMap.createUninitializedBlock("Block1", addr(0), 0x3fffffffL, false);

		dbFile.delete();
	}

	@After
	public void tearDown() throws Exception {
		if (program != null) {
			if (program.getCurrentTransactionInfo() != null) {
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
		ObjectPropertyMap<TestSaveable> map =
			mgr.createObjectPropertyMap("TEST", TestSaveable.class);
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
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);
		PropertyMap<?> pmap = mgr.getPropertyMap("TEST");
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
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);
		PropertyMap<?> pmap = mgr.getPropertyMap("TEST");
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
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);
		PropertyMap<?> pmap = mgr.getPropertyMap("TEST");
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
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);
		PropertyMap<?> pmap = mgr.getPropertyMap("TEST");
		assertEquals(1, pmap.getSize());
	}

	@Test
	public void testGetObjectPropertyMap() throws Exception {
		ObjectPropertyMap<TestSaveable> map =
			mgr.createObjectPropertyMap("TEST", TestSaveable.class);
		map.add(addr(100), new TestSaveable());
		program.endTransaction(transactionID, true);

		dbh.saveAs(dbFile, true, null);
		program.release(this);
		program = null;

		dbh = new DBHandle(dbFile);
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);
		PropertyMap<?> pmap = mgr.getPropertyMap("TEST");
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
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);
		PropertyMap<?> pmap = mgr.getPropertyMap("TEST");
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
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);
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
		mgr =
			new DBPropertyMapManager(dbh, changeMgr, addrMap, DBConstants.UPDATE, new Lock("TEST"),
				TaskMonitor.DUMMY);

		int cnt = 0;
		Iterator<String> iter = mgr.propertyManagers();
		while (iter.hasNext()) {
			String name = iter.next();
			assertEquals(name.indexOf("TEST"), 0);
			++cnt;
		}
		assertEquals(cnt, 2);
	}

	@Override
	public void dbError(IOException e) {
		e.printStackTrace();
	}

}
