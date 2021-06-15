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

import org.junit.*;

import db.*;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageService;
import ghidra.program.model.mem.Memory;
import ghidra.test.*;

public class AddressIndexPrimaryKeyIteratorTest extends AbstractGhidraHeadedIntegrationTest {

	private ProgramDB program;
	private AddressSpace space;
	private AddressMap addrMap;
	private Memory memMap;
	private int transactionID;
	private Table myTable;

	/**
	 * Constructor for AddressIndexPrimaryKeyIteratorTest.
	 * @param arg0
	 */
	public AddressIndexPrimaryKeyIteratorTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		TestEnv env = new TestEnv();
		LanguageService ls = getLanguageService();
		Language language = ls.getDefaultLanguage(TestProcessorConstants.PROCESSOR_SPARC);
		program = new ProgramDB("TestProgram", language, language.getDefaultCompilerSpec(), this);
		env.dispose();

//		program = new ProgramDB("TestProgram", new SparcV8Language(),this); 
		space = program.getAddressFactory().getDefaultAddressSpace();
		memMap = program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memMap);
		transactionID = program.startTransaction("Test");

		// Create fragmented memory
		memMap.createInitializedBlock("Block1", addr(0x8000), 0x10, (byte) 0, null, false);// startKey: 0x0
		memMap.createUninitializedBlock("Block2", addr(0x5000), 0x10, false);// startKey: 0x10000
		memMap.createBitMappedBlock("Block3", addr(0x9000), addr(0x5000), 0x10, false);// startKey: 0x20000
		memMap.createUninitializedBlock("Block4", addr(0x3000), 0x10, false);// startKey: 0x30000

		// Create table with indexed address column
		Schema schema =
			new Schema(0, "id", new Field[] { LongField.INSTANCE }, new String[] { "addr" });
		DBHandle handle = program.getDBHandle();
		myTable = handle.createTable("MyTable", schema, new int[] { 0 });

		assertTrue(memMap.contains(addr(0x3000)));
		assertTrue(memMap.contains(addr(0x5000)));
		assertTrue(memMap.contains(addr(0x8000)));
		assertTrue(memMap.contains(addr(0x9000)));
		assertTrue(!memMap.contains(addr(0x100)));

		int cnt = 0;
		AddressRangeIterator ranges = memMap.getAddressRanges();
		while (ranges.hasNext()) {
			AddressRange r = ranges.next();
			Address a = r.getMinAddress();
			Address maxAddr = r.getMaxAddress();
			while (a.compareTo(maxAddr) <= 0) {
				long addrKey = addrMap.getKey(a, true);
				DBRecord rec = schema.createRecord(myTable.getKey());
				rec.setLongValue(0, addrKey);
				myTable.putRecord(rec);
				a = a.add(1);
				++cnt;
			}
		}
		assertEquals(0x40, cnt);
		assertEquals(0x40, myTable.getRecordCount());
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
	public void testIterator1() throws Exception {
		AddressIndexPrimaryKeyIterator iter =
			new AddressIndexPrimaryKeyIterator(myTable, 0, addrMap, true);
		long key = 0;
		while (iter.hasNext()) {
			assertEquals(key++, iter.next().getLongValue());
		}
		assertEquals(0x40, key);
	}

	@Test
	public void testIterator2() throws Exception {
		Address minAddr = addr(0x5002);
		Address maxAddr = addr(0x8004);
		AddressIndexPrimaryKeyIterator iter =
			new AddressIndexPrimaryKeyIterator(myTable, 0, addrMap, minAddr, maxAddr, true);
		long key = 18;
		while (iter.hasNext()) {
			assertEquals(key++, iter.next().getLongValue());
		}
		assertEquals(37, key);

		iter = new AddressIndexPrimaryKeyIterator(myTable, 0, addrMap, minAddr, maxAddr, false);
		key = 36;
		while (iter.hasPrevious()) {
			assertEquals(key--, iter.previous().getLongValue());
		}
		assertEquals(17, key);
	}

	@Test
	public void testIterator3() throws Exception {
		Address a = addr(0x5002);
		AddressIndexPrimaryKeyIterator iter =
			new AddressIndexPrimaryKeyIterator(myTable, 0, addrMap, a, true);
		long key = 18;
		while (iter.hasNext()) {
			assertEquals(key++, iter.next().getLongValue());
		}
		assertEquals(0x40, key);

		iter = new AddressIndexPrimaryKeyIterator(myTable, 0, addrMap, a, false);
		key = 18;
		while (iter.hasPrevious()) {
			assertEquals(key--, iter.previous().getLongValue());
		}
		assertEquals(-1, key);
	}

	@Test
	public void testIterator4() throws Exception {
		AddressSet set = new AddressSet(addr(0x5002), addr(0x8004));
		set.addRange(addr(0x3002), addr(0x3004));
		AddressIndexPrimaryKeyIterator iter =
			new AddressIndexPrimaryKeyIterator(myTable, 0, addrMap, set, true);
		assertEquals(2, iter.next().getLongValue());
		assertEquals(3, iter.next().getLongValue());
		assertEquals(4, iter.next().getLongValue());
		long key = 18;
		while (iter.hasNext()) {
			assertEquals(key++, iter.next().getLongValue());
		}
		assertEquals(37, key);

		iter = new AddressIndexPrimaryKeyIterator(myTable, 0, addrMap, set, false);
		key = 36;
		while (iter.hasPrevious()) {
			assertEquals(key--, iter.previous().getLongValue());
			if (key == 17) {
				break;
			}
		}
		assertEquals(4, iter.previous().getLongValue());
		assertEquals(3, iter.previous().getLongValue());
		assertEquals(2, iter.previous().getLongValue());
	}
}
