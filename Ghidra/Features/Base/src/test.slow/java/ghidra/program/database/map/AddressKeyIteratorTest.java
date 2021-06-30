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
package ghidra.program.database.map;

import static org.junit.Assert.*;

import java.util.NoSuchElementException;

import org.junit.*;

import db.*;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.datastruct.LongArray;

public class AddressKeyIteratorTest extends AbstractGhidraHeadedIntegrationTest {

	private static Schema SCHEMA =
		new Schema(0, "addr", new Field[] { StringField.INSTANCE }, new String[] { "str" });

	private ProgramDB program;
	private AddressSpace space;
	private AddressMap addrMap;
	private Memory memMap;
	private int transactionID;
	private Table myTable;
	private LongArray keys;

	/**
	 * Constructor for AddressKeyIteratorTest.
	 * @param arg0
	 */
	public AddressKeyIteratorTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		program = createDefaultProgram(testName.getMethodName(), ProgramBuilder._TOY, this);
		space = program.getAddressFactory().getDefaultAddressSpace();
		memMap = program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memMap);
		transactionID = program.startTransaction("Test");

		// Set image base
		program.setImageBase(addr(0x1000), true);

		// Create fragmented memory
		memMap.createInitializedBlock("Block1", addr(0x8000), 0x10, (byte) 0, null, false);// startKey: 0x0
		memMap.createUninitializedBlock("Block2", addr(0x5000), 0x10, false);// startKey: 0x10000
		memMap.createBitMappedBlock("Block3", addr(0x9000), addr(0x5000), 0x10, false);// startKey: 0x20000
		memMap.createUninitializedBlock("Block4", addr(0x3000), 0x10, false);// startKey: 0x30000

		// Create table keyed on address

		DBHandle handle = program.getDBHandle();
		myTable = handle.createTable("MyTable", SCHEMA);

		assertTrue(memMap.contains(addr(0x3000)));
		assertTrue(memMap.contains(addr(0x5000)));
		assertTrue(memMap.contains(addr(0x8000)));
		assertTrue(memMap.contains(addr(0x9000)));
		assertTrue(!memMap.contains(addr(0x100)));

		int cnt = 0;
		keys = new LongArray();
		AddressRangeIterator ranges = memMap.getAddressRanges();
		while (ranges.hasNext()) {
			AddressRange r = ranges.next();
			Address a = r.getMinAddress();
			Address maxAddr = r.getMaxAddress();
			while (a.compareTo(maxAddr) <= 0) {
				long k = addRecord(a);
				keys.put(cnt++, k);
				a = a.add(1);
			}
		}
		assertEquals(0x40, cnt);
		assertEquals(0x40, myTable.getRecordCount());
	}

	private long addRecord(Address a) throws Exception {
		long key = addrMap.getKey(a, true);
		DBRecord rec = SCHEMA.createRecord(key);
		rec.setString(0, a.toString());
		myTable.putRecord(rec);
		return key;
	}

	@After
	public void tearDown() throws Exception {
		program.endTransaction(transactionID, true);
		program.release(this);
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	@Test
	public void testIterator0() throws Exception {
		AddressKeyIterator it = AddressKeyIterator.EMPTY_ITERATOR;
		assertTrue(!it.hasNext());
		assertTrue(!it.hasPrevious());
		try {
			it.next();
			Assert.fail();
		}
		catch (NoSuchElementException e) {
			// expected
		}
		try {
			it.previous();
			Assert.fail();
		}
		catch (NoSuchElementException e) {
			// expected
		}
	}

	@Test
	public void testIterator1() throws Exception {
		int index = 0;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, true);
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator2() throws Exception {
		int index = 0x10;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, addr(0x4000), true);
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator3() throws Exception {
		int index = 0x11;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, addr(0x5000), false);
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator4() throws Exception {
		int index = 0x10;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, addr(0x5000), true);
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator5() throws Exception {
		int index = 0x0f;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, addr(0x5000), true);
		while (it.hasPrevious()) {
			long k = it.previous();
			assertEquals(keys.get(index--), k);
		}
		assertEquals(-1, index);
	}

	@Test
	public void testIterator6() throws Exception {
		int index = 0x10;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, addr(0x5000), false);
		while (it.hasPrevious()) {
			long k = it.previous();
			assertEquals(keys.get(index--), k);
		}
		assertEquals(-1, index);
	}

	@Test
	public void testIterator7() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x3008), addr(0x5008));
		set.addRange(addr(0x9008), addr(0x10000));
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, set, addr(0x2000), true);
		int index = 0x08;
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
			if (index == 0x19) {
				index = 0x38;
			}
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator8() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x3008), addr(0x5008));
		set.addRange(addr(0x9008), addr(0x10000));
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, set, addr(0x5001), true);
		int index = 0x11;
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
			if (index == 0x19) {
				index = 0x38;
			}
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator9() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x3008), addr(0x5008));
		set.addRange(addr(0x9008), addr(0x10000));
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, set, addr(0x5008), false);
		int index = 0x38;
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator10() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x3008), addr(0x5008));
		set.addRange(addr(0x9008), addr(0x10000));
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, set, addr(0x5000), true);
		int index = 0x10;
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
			if (index == 0x19) {
				index = 0x38;
			}
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIterator11() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x3008), addr(0x5008));
		set.addRange(addr(0x9008), addr(0x10000));
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, set, addr(0x9008), true);
		int index = 0x18;
		while (it.hasPrevious()) {
			long k = it.previous();
//System.out.println("At " + Long.toHexString(k) + " - " + memMap.getAddress(k));
			assertEquals(keys.get(index--), k);
		}
		assertEquals(0x07, index);
	}

	@Test
	public void testIterator12() throws Exception {
		int index = 0x3f;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, null, false);
		while (it.hasPrevious()) {
			long k = it.previous();
			assertEquals(keys.get(index--), k);
		}
		assertEquals(-1, index);
	}

	@Test
	public void testIterator13() throws Exception {
		AddressSet set = new AddressSet();
		set.addRange(addr(0x3008), addr(0x5008));
		set.addRange(addr(0x9008), addr(0x10000));
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, set, addr(0x8000), true);
		int index = 0x38;
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIteratorCheckWrap1() throws Exception {

		addRecord(addr(0x0));
		addRecord(addr(0x0100));
		addRecord(addr(0x0fff));

		int index = 0x11;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, addr(0x5000), false);
		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(0x40, index);
	}

	@Test
	public void testIteratorCheckWrap2() throws Exception {

		addRecord(addr(0x0));
		addRecord(addr(0x0100));
		addRecord(addr(0x0fff));

		int index = 0;
		AddressKeyIterator it = new AddressKeyIterator(myTable, addrMap, addr(0x0), true);

		assertEquals(addrMap.getKey(addr(0x0), false), it.next());
		assertEquals(addrMap.getKey(addr(0x0100), false), it.next());
		assertEquals(addrMap.getKey(addr(0x0fff), false), it.next());

		while (it.hasNext()) {
			long k = it.next();
			assertEquals(Long.toHexString(keys.get(index++)), Long.toHexString(k));
		}
		assertEquals(keys.getLastNonEmptyIndex() + 1, index);
	}
}
