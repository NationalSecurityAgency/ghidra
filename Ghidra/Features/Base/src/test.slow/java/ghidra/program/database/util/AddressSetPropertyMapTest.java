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
package ghidra.program.database.util;

import static org.junit.Assert.*;

import java.util.ConcurrentModificationException;

import org.junit.*;

import ghidra.framework.model.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.util.ChangeManager;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

public class AddressSetPropertyMapTest extends AbstractGhidraHeadedIntegrationTest {

	private TestEnv env;
	private Program program;
	private AddressFactory addrFactory;
	private int transactionID;
	private int eventType;
	private String mapName;

	public AddressSetPropertyMapTest() {
		super();
	}

	private Program buildProgram(String programName) throws Exception {
		ProgramBuilder builder = new ProgramBuilder(programName, ProgramBuilder._TOY);
		builder.createMemory("test1", Long.toHexString(0x1001000), 0x2000);
		return builder.getProgram();
	}

    @Before
    public void setUp() throws Exception {
		env = new TestEnv();
		program = buildProgram("notepad");
		addrFactory = program.getAddressFactory();
		transactionID = program.startTransaction("test");
	}

    @After
    public void tearDown() throws Exception {
		if (transactionID >= 0) {
			program.endTransaction(transactionID, true);
		}
		env.dispose();
	}

@Test
    public void testGetNonExistentMap() throws Exception {
		AddressSetPropertyMap pm = program.getAddressSetPropertyMap("MyMap");
		assertNull(pm);
	}

@Test
    public void testCreateAddressSetMap() throws Exception {
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		assertNotNull(pm);
	}

@Test
    public void testDuplicateName() throws Exception {
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(getAddr(0x100), getAddr(0x200));
		try {
			program.createAddressSetPropertyMap("MyMap");
			Assert.fail("Should have gotten DuplicateNameException!");
		}
		catch (DuplicateNameException e) {
		}
	}

@Test
    public void testAddRange() throws Exception {
		Address start = getAddr(0x1001000);
		Address end = getAddr(0x1001005);
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(start, end);

		AddressSet set = pm.getAddressSet();
		assertTrue(!set.isEmpty());
		assertTrue(set.contains(start, end));
		set.delete(new AddressRangeImpl(start, end));
		assertTrue(set.isEmpty());
	}

@Test
    public void testAddSet() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x100), getAddr(0x200));
		set.addRange(getAddr(0x400), getAddr(0x500));
		set.addRange(getAddr(0x1000), getAddr(0x1001));

		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		AddressSet pset = pm.getAddressSet();

		assertEquals(set, pset);
	}

@Test
    public void testRemoveRange() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x100), getAddr(0x200));
		set.addRange(getAddr(0x400), getAddr(0x500));
		set.addRange(getAddr(0x1000), getAddr(0x1001));

		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		pm.remove(getAddr(0x101), getAddr(0x105));
		AddressSet pset = pm.getAddressSet();
		assertTrue(!pset.contains(getAddr(0x101), getAddr(0x105)));

		AddressSet s = set.subtract(new AddressSet(getAddr(0x101), getAddr(0x105)));
		assertEquals(s, pset);
	}

@Test
    public void testRemoveSet() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x200));
		set.addRange(getAddr(0x205), getAddr(0x1000));
		set.addRange(getAddr(0x5000), getAddr(0x6001));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		AddressSet s = new AddressSet();
		s.addRange(getAddr(5), getAddr(0x6000));

		pm.remove(s);

		s = set.subtract(new AddressSet(getAddr(5), getAddr(0x6000)));
		AddressSet pset = pm.getAddressSet();
		assertEquals(s, pset);

	}

@Test
    public void testContainsAddress() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x200));
		set.addRange(getAddr(0x205), getAddr(0x1000));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		AddressSet pset = pm.getAddressSet();
		assertTrue(pset.contains(getAddr(0x210)));

		assertTrue(!pset.contains(getAddr(0x202)));

	}

@Test
    public void testClear() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x200));
		set.addRange(getAddr(0x205), getAddr(0x1000));
		set.addRange(getAddr(0x5000), getAddr(0x6001));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		pm.clear();
		assertTrue(pm.getAddressSet().isEmpty());
	}

@Test
    public void testAddressRangeIterator() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x200));
		set.addRange(getAddr(0x205), getAddr(0x1000));
		set.addRange(getAddr(0x5000), getAddr(0x6001));
		set.addRange(getAddr(0x01001000), getAddr(0x01005000));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		AddressRangeIterator iter = pm.getAddressRanges();
		assertTrue(iter.hasNext());
		int count = 0;
		while (iter.hasNext()) {
			AddressRange range = iter.next();
			switch (count) {
				case 0:
					assertEquals(new AddressRangeImpl(getAddr(0), getAddr(0x200)), range);
					break;
				case 1:
					assertEquals(new AddressRangeImpl(getAddr(0x205), getAddr(0x1000)), range);
					break;
				case 2:
					assertEquals(new AddressRangeImpl(getAddr(0x5000), getAddr(0x6001)), range);
					break;
				case 3:
					assertEquals(new AddressRangeImpl(getAddr(0x01001000), getAddr(0x01005000)),
						range);
					break;
			}
			++count;
		}
		assertEquals(4, count);
	}

@Test
    public void testAddressIterator() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(20), getAddr(0x25));
		set.addRange(getAddr(26), getAddr(0x30));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);
		AddressIterator iter = pm.getAddresses();
		AddressSet iterSet = new AddressSet();
		while (iter.hasNext()) {
			Address addr = iter.next();
			iterSet.addRange(addr, addr);
		}
		assertEquals(set, iterSet);
		assertNull(iter.next());
	}

@Test
    public void testRemoveAddressSetMap() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(20), getAddr(0x25));
		set.addRange(getAddr(26), getAddr(0x30));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		program.deleteAddressSetPropertyMap("MyMap");

		assertNull(program.getAddressSetPropertyMap("MyMap"));

		try {
			pm.add(getAddr(0), getAddr(5));
			Assert.fail("Map should have been deleted!");
		}
		catch (ConcurrentModificationException e) {
		}

	}

@Test
    public void testSaveProgram() throws Exception {
		Project project = env.getProject();
		DomainFolder rootFolder = project.getProjectData().getRootFolder();
		program.endTransaction(transactionID, true);
		transactionID = -1;

		DomainFile df =
			rootFolder.createFile("mynotepad", program, TaskMonitorAdapter.DUMMY_MONITOR);
		env.release(program);

		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(20), getAddr(0x25));
		set.addRange(getAddr(26), getAddr(0x30));

		Program p =
			(Program) df.getDomainObject(this, true, false, TaskMonitorAdapter.DUMMY_MONITOR);
		int txID = p.startTransaction("test");
		try {
			AddressSetPropertyMap pm = p.createAddressSetPropertyMap("MyMap");
			pm.add(set);
			AddressSetPropertyMap pm2 = p.createAddressSetPropertyMap("MyMap_Two");
			pm2.add(getAddr(0x10), getAddr(0x20));
		}
		finally {
			p.endTransaction(txID, true);
		}
		df.save(TaskMonitorAdapter.DUMMY_MONITOR);
		p.release(this);

		df = rootFolder.getFile("mynotepad");
		assertNotNull(df);

		p = (Program) df.getDomainObject(this, true, false, TaskMonitorAdapter.DUMMY_MONITOR);
		AddressSetPropertyMap pm = p.getAddressSetPropertyMap("MyMap");
		assertNotNull(pm);
		assertEquals(set, pm.getAddressSet());

		AddressSetPropertyMap pm2 = p.getAddressSetPropertyMap("MyMap_Two");
		assertNotNull(pm2);
		assertEquals(new AddressSet(getAddr(0x10), getAddr(0x20)), pm2.getAddressSet());

		p.release(this);
	}

@Test
    public void testEvents() throws Exception {
		MyDomainObjectListener dol = new MyDomainObjectListener();
		program.addListener(dol);
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_ADDED, eventType);
		assertEquals("MyMap", mapName);

		// map changed
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(0x20), getAddr(0x25));
		set.addRange(getAddr(0x26), getAddr(0x30));
		pm.add(set);
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		pm.remove(getAddr(0), getAddr(0x15));
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		set = new AddressSet();
		set.addRange(getAddr(20), getAddr(0x23));
		pm.remove(set);
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		pm.clear();
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		// map removed
		program.deleteAddressSetPropertyMap("MyMap");
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED, eventType);
		assertEquals("MyMap", mapName);
	}

@Test
    public void testMoveRange() throws Exception {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.createInitializedBlock(".test", getAddr(0), 0x23, (byte) 0xa,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(0x20), getAddr(0x25));
		set.addRange(getAddr(0x26), getAddr(0x30));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);

		assertEquals(set, pm.getAddressSet());

		// move .test block to 0x1000
		memory.moveBlock(block, getAddr(0x1000), TaskMonitorAdapter.DUMMY_MONITOR);

		// [0,10], [20, 22] should be moved
		// [23,30] should not be moved

		AddressSet s = new AddressSet();
		s.addRange(getAddr(0), getAddr(0x10));
		s.addRange(getAddr(0x20), getAddr(0x22));
		AddressSet pmSet = pm.getAddressSet();
		assertTrue(!pmSet.contains(s));
		assertTrue(pmSet.contains(getAddr(0x23), getAddr(0x30)));

		s.clear();
		s.addRange(getAddr(0x1000), getAddr(0x1010));
		s.addRange(getAddr(0x1020), getAddr(0x1022));
		s.addRange(getAddr(0x23), getAddr(0x30));
		assertEquals(s, pmSet);
	}

@Test
    public void testDeleteBlockRange() throws Exception {
		Memory memory = program.getMemory();
		MemoryBlock block = memory.createInitializedBlock(".test", getAddr(5), 0x20, (byte) 0xa,
			TaskMonitorAdapter.DUMMY_MONITOR, false);

		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(0x20), getAddr(0x25));
		set.addRange(getAddr(0x26), getAddr(0x30));
		AddressSetPropertyMap pm = program.createAddressSetPropertyMap("MyMap");
		pm.add(set);
		// remove the block
		memory.removeBlock(block, TaskMonitorAdapter.DUMMY_MONITOR);

		// [0,4], [25,30] should still exist
		// [5,24] should have been removed
		AddressSet s = new AddressSet();
		s.addRange(getAddr(0), getAddr(0x4));
		s.addRange(getAddr(0x25), getAddr(0x30));
		AddressSet pmSet = pm.getAddressSet();
		assertEquals(s, pmSet);
	}

	private Address getAddr(int offset) {
		return program.getMinAddress().getNewAddress(offset);
	}

	private class MyDomainObjectListener implements DomainObjectListener {
		@Override
		public void domainObjectChanged(DomainObjectChangedEvent ev) {
			for (int i = 0; i < ev.numRecords(); i++) {
				DomainObjectChangeRecord rec = ev.getChangeRecord(i);
				eventType = rec.getEventType();
				mapName = (String) rec.getNewValue();
			}
		}
	}
}
