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
import ghidra.program.database.IntRangeMap;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.ChangeManager;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitorAdapter;

public class IntRangeMapTest extends AbstractGhidraHeadlessIntegrationTest {

	private TestEnv env;
	private Program program;
	private AddressFactory addrFactory;
	private int transactionID;
	private int eventType;
	private String mapName;

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
		IntRangeMap map = program.getIntRangeMap("MyMap");
		assertNull(map);
	}

	@Test
    public void testCreateAddressSetMap() throws Exception {
		IntRangeMap map = program.createIntRangeMap("MyMap");
		assertNotNull(map);
	}

	@Test
    public void testDuplicateName() throws Exception {
		IntRangeMap map = program.createIntRangeMap("MyMap");
		map.setValue(getAddr(0x100), getAddr(0x200), 0x11223344);
		try {
			program.createIntRangeMap("MyMap");
			Assert.fail("Should have gotten DuplicateNameException!");
		}
		catch (DuplicateNameException e) {
			// good!
		}
	}

	@Test
    public void testSetValueOverRange() throws Exception {
		Address start = getAddr(0x1001000);
		Address end = getAddr(0x1001005);
		IntRangeMap map = program.createIntRangeMap("MyMap");

		int value = 0x11223344;
		map.setValue(start, end, value);

		AddressSet set = map.getAddressSet();
		assertTrue(!set.isEmpty());
		assertTrue(set.contains(start, end));
		assertEquals(value, (int) map.getValue(start.add(1)));
		set.delete(new AddressRangeImpl(start, end));
		assertTrue(set.isEmpty());
	}

	@Test
    public void testSetValueOverAddressSet() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x100), getAddr(0x200));
		set.addRange(getAddr(0x400), getAddr(0x500));
		set.addRange(getAddr(0x1000), getAddr(0x1001));

		IntRangeMap map = program.createIntRangeMap("MyMap");
		int value = 0x11223344;
		map.setValue(set, value);

		AddressSet resultSet = map.getAddressSet();
		assertEquals(set, resultSet);

		resultSet = map.getAddressSet(value);
		assertEquals(set, resultSet);
	}

	@Test
    public void testRemoveRange() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0x100), getAddr(0x200));
		set.addRange(getAddr(0x400), getAddr(0x500));
		set.addRange(getAddr(0x1000), getAddr(0x1001));

		IntRangeMap map = program.createIntRangeMap("MyMap");
		int value = 0x11223344;
		map.setValue(set, value);

		map.clearValue(getAddr(0x101), getAddr(0x105));
		AddressSet resultSet = map.getAddressSet();
		assertTrue(!resultSet.contains(getAddr(0x101), getAddr(0x105)));

		AddressSet s = set.subtract(new AddressSet(getAddr(0x101), getAddr(0x105)));
		assertEquals(s, resultSet);
	}

	@Test
    public void testRemoveSet() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x200));
		set.addRange(getAddr(0x205), getAddr(0x1000));
		set.addRange(getAddr(0x5000), getAddr(0x6001));

		IntRangeMap map = program.createIntRangeMap("MyMap");
		int value = 0x11223344;
		map.setValue(set, value);

		AddressSet s = new AddressSet();
		s.addRange(getAddr(5), getAddr(0x6000));

		map.clearValue(s);

		s = set.subtract(new AddressSet(getAddr(5), getAddr(0x6000)));
		AddressSet resultSet = map.getAddressSet();
		assertEquals(s, resultSet);
	}

	@Test
    public void testClearAll() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x200));
		set.addRange(getAddr(0x205), getAddr(0x1000));
		set.addRange(getAddr(0x5000), getAddr(0x6001));

		IntRangeMap map = program.createIntRangeMap("MyMap");
		int value = 0x11223344;
		map.setValue(set, value);

		map.clearAll();
		assertTrue(map.getAddressSet().isEmpty());
	}

	@Test
    public void testRemoveAddressSetMap() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(20), getAddr(0x25));
		set.addRange(getAddr(26), getAddr(0x30));
		IntRangeMap map = program.createIntRangeMap("MyMap");
		int value = 0x11223344;
		map.setValue(set, value);

		program.deleteIntRangeMap("MyMap");

		assertNull(program.getIntRangeMap("MyMap"));

		try {
			map.setValue(getAddr(0), getAddr(5), value);
			Assert.fail("Map should have been deleted!");
		}
		catch (ConcurrentModificationException e) {
			// good!
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
		set.addRange(getAddr(0), getAddr(0x40));

		Program p =
			(Program) df.getDomainObject(this, true, false, TaskMonitorAdapter.DUMMY_MONITOR);
		int txID = p.startTransaction("test");
		int value = 0x11223344;
		int otherValue = 0x44332211;
		try {
			IntRangeMap map = p.createIntRangeMap("MyMap");
			map.setValue(set, value);
			map.setValue(getAddr(0x30), getAddr(0x40), otherValue);
		}
		finally {
			p.endTransaction(txID, true);
		}

		df.save(TaskMonitorAdapter.DUMMY_MONITOR);
		p.release(this);

		df = rootFolder.getFile("mynotepad");
		assertNotNull(df);

		p = (Program) df.getDomainObject(this, true, false, TaskMonitorAdapter.DUMMY_MONITOR);
		IntRangeMap map = p.getIntRangeMap("MyMap");
		assertNotNull(map);
		assertEquals(set, map.getAddressSet());

		assertEquals(new AddressSet(getAddr(0x0), getAddr(0x2f)), map.getAddressSet(value));
		assertEquals(new AddressSet(getAddr(0x30), getAddr(0x40)), map.getAddressSet(otherValue));

		p.release(this);
	}

	@Test
    public void testEvents() throws Exception {
		MyDomainObjectListener dol = new MyDomainObjectListener();
		program.addListener(dol);
		IntRangeMap map = program.createIntRangeMap("MyMap");
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED, eventType);
		assertEquals("MyMap", mapName);
		int value = 0x11223344;

		// map changed
		AddressSet set = new AddressSet();
		set.addRange(getAddr(0), getAddr(0x10));
		set.addRange(getAddr(0x20), getAddr(0x25));
		set.addRange(getAddr(0x26), getAddr(0x30));
		map.setValue(set, value);
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		map.clearValue(getAddr(0), getAddr(0x15));
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		set = new AddressSet();
		set.addRange(getAddr(20), getAddr(0x23));
		map.clearValue(set);
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		map.clearAll();
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED, eventType);
		assertEquals("MyMap", mapName);

		// map removed
		program.deleteIntRangeMap("MyMap");
		program.flushEvents();
		waitForPostedSwingRunnables();
		assertEquals(ChangeManager.DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED, eventType);
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
		IntRangeMap map = program.createIntRangeMap("MyMap");

		int value = 0x11223344;
		map.setValue(set, value);
		assertEquals(set, map.getAddressSet());

		// move .test block to 0x1000
		memory.moveBlock(block, getAddr(0x1000), TaskMonitorAdapter.DUMMY_MONITOR);

		// [0,10], [20, 22] should be moved
		// [23,30] should not be moved

		AddressSet s = new AddressSet();
		s.addRange(getAddr(0), getAddr(0x10));
		s.addRange(getAddr(0x20), getAddr(0x22));
		AddressSet mapSet = map.getAddressSet();
		assertTrue(!mapSet.contains(s));
		assertTrue(mapSet.contains(getAddr(0x23), getAddr(0x30)));

		s.clear();
		s.addRange(getAddr(0x1000), getAddr(0x1010));
		s.addRange(getAddr(0x1020), getAddr(0x1022));
		s.addRange(getAddr(0x23), getAddr(0x30));
		assertEquals(s, mapSet);
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
		IntRangeMap map = program.createIntRangeMap("MyMap");
		int value = 0x11223344;
		map.setValue(set, value);
		// remove the block
		memory.removeBlock(block, TaskMonitorAdapter.DUMMY_MONITOR);

		// [0,4], [25,30] should still exist
		// [5,24] should have been removed
		AddressSet s = new AddressSet();
		s.addRange(getAddr(0), getAddr(0x4));
		s.addRange(getAddr(0x25), getAddr(0x30));
		AddressSet mapSet = map.getAddressSet();
		assertEquals(s, mapSet);
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
