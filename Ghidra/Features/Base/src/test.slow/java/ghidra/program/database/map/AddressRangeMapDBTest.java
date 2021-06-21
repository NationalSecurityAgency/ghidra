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

import java.io.IOException;

import org.junit.*;

import db.LongField;
import db.NoTransactionException;
import db.util.ErrorHandler;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.database.util.AddressRangeMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.test.TestEnv;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;

public class AddressRangeMapDBTest extends AbstractGhidraHeadedIntegrationTest
		implements ErrorHandler {

	private TestEnv env; // needed to discover languages
	private ProgramDB program;
	private AddressMap addrMap;
	private AddressSpace space;

	private static LongField ONE = new LongField(1);
	private static LongField TWO = new LongField(2);
	private static LongField THREE = new LongField(3);

	@Before
	public void setUp() throws Exception {
		env = new TestEnv();
		LanguageService service = getLanguageService();
		Language language = service.getLanguage(new LanguageID("sparc:BE:64:default"));
		program = new ProgramDB("test", language, language.getDefaultCompilerSpec(), this);

		MemoryMapDB memory = (MemoryMapDB) program.getMemory();
		addrMap = (AddressMap) getInstanceField("addrMap", memory);
		space = program.getAddressFactory().getDefaultAddressSpace();
	}

	@After
	public void tearDown() {
		if (program != null) {
			program.release(this);
		}
		addrMap = null;
		env.dispose();
	}

	private Address addr(long offset) {
		return space.getAddress(offset);
	}

	/**
	 * @see db.util.ErrorHandler#dbError(java.io.IOException)
	 */
	@Override
	public void dbError(IOException e) {
		throw new RuntimeException(e.getMessage());
	}

	@Test
	public void testTransaction() {

		AddressRangeMapDB map = new AddressRangeMapDB(program.getDBHandle(), addrMap,
			new Lock("Test"), "TEST", this, LongField.INSTANCE, true);

		try {
			map.paintRange(addr(0), addr(0x1000), ONE);
			Assert.fail("expected no-transaction exception");
		}
		catch (NoTransactionException e) {
			// expected
		}

		int id = program.startTransaction("TEST");
		try {
			map.paintRange(addr(0), addr(0x1000), ONE);
		}
		finally {
			program.endTransaction(id, true);
		}

		try {
			map.paintRange(addr(800), addr(0x1000), TWO);
			Assert.fail("expected no-transaction exception");
		}
		catch (NoTransactionException e) {
			// expected
		}
	}

	@Test
	public void testPaint() {

		AddressRangeMapDB map = new AddressRangeMapDB(program.getDBHandle(), addrMap,
			new Lock("Test"), "TEST", this, LongField.INSTANCE, true);

		int id = program.startTransaction("TEST");
		try {
			assertNull(map.getValue(addr(0x01000000000L)));

			map.paintRange(addr(0x0000001000L), addr(0x0200001000L), ONE);
			assertNull(map.getValue(addr(0x0000000000L)));
			assertEquals(ONE, map.getValue(addr(0x00000001000L)));
			assertEquals(ONE, map.getValue(addr(0x0100001000L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
			assertNull(map.getValue(addr(0x0200001001L)));

			map.paintRange(addr(0x0100000000L), addr(0x0100001000L), TWO);
			assertNull(map.getValue(addr(0x0000000000L)));
			assertEquals(ONE, map.getValue(addr(0x0000001000L)));
			assertEquals(TWO, map.getValue(addr(0x0100000fffL)));
			assertEquals(TWO, map.getValue(addr(0x0100001000L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
			assertNull(map.getValue(addr(0x0200001001L)));

			map.paintRange(addr(0x0080000000L), addr(0x0100000fffL), THREE);
			assertNull(map.getValue(addr(0x0000000000L)));
			assertEquals(ONE, map.getValue(addr(0x0000001000L)));
			assertEquals(THREE, map.getValue(addr(0x0100000fffL)));
			assertEquals(TWO, map.getValue(addr(0x0100001000L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
			assertNull(map.getValue(addr(0x0200001001L)));
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	@Test
	public void testClear() {

		AddressRangeMapDB map = new AddressRangeMapDB(program.getDBHandle(), addrMap,
			new Lock("Test"), "TEST", this, LongField.INSTANCE, true);

		int id = program.startTransaction("TEST");
		try {
			assertNull(map.getValue(addr(0x01000000000L)));

			map.paintRange(addr(0x0000001000L), addr(0x0200001000L), ONE);
			map.paintRange(addr(0x0100000000L), addr(0x0100001000L), TWO);
			map.paintRange(addr(0x0080000000L), addr(0x0100000fffL), THREE);

			map.clearRange(addr(0x0100000000L), addr(0x0100000010L));
			map.clearRange(addr(0x01fffffff0L), addr(0x0200000010L));

			assertNull(map.getValue(addr(0x0000000000L)));
			assertEquals(ONE, map.getValue(addr(0x0000001000L)));
			assertNull(map.getValue(addr(0x0100000000L)));
			assertNull(map.getValue(addr(0x0100000010L)));
			assertEquals(THREE, map.getValue(addr(0x0100000011L)));
			assertEquals(TWO, map.getValue(addr(0x0100001000L)));
			assertNull(map.getValue(addr(0x01fffffff0L)));
			assertNull(map.getValue(addr(0x0200000010L)));
			assertEquals(ONE, map.getValue(addr(0x0200000011L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
			assertNull(map.getValue(addr(0x0200001001L)));
		}
		finally {
			program.endTransaction(id, true);
		}
	}

	@Test
	public void testAddressRangeIterator() {

		AddressRangeMapDB map = new AddressRangeMapDB(program.getDBHandle(), addrMap,
			new Lock("Test"), "TEST", this, LongField.INSTANCE, true);

		int id = program.startTransaction("TEST");
		try {
			assertNull(map.getValue(addr(0x01000000000L)));

			map.paintRange(addr(0x0000001000L), addr(0x0200001000L), ONE);
			map.paintRange(addr(0x0100000000L), addr(0x0100001000L), TWO);
			map.paintRange(addr(0x0080000000L), addr(0x0100000fffL), THREE);

			map.clearRange(addr(0x0100000000L), addr(0x0100000010L));
			map.clearRange(addr(0x01fffffff0L), addr(0x0200000010L));
		}
		finally {
			program.endTransaction(id, true);
		}

		// All address
		AddressRangeIterator iter = map.getAddressRanges();
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0000001000L), addr(0x007fffffffL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0080000000L), addr(0x00ffffffffL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100000011L), addr(0x0100000fffL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100001000L), addr(0x0100001000L)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100001001L), addr(0x01ffffffefL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0200000011L), addr(0x0200001000L)), iter.next());
		assertTrue(!iter.hasNext());

		// Limited range of addresses starting at 0x0100000100
		iter = map.getAddressRanges(addr(0x0100000100L));
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100000100L), addr(0x0100000fffL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100001000L), addr(0x0100001000L)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100001001L), addr(0x01ffffffefL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0200000011L), addr(0x0200001000L)), iter.next());
		assertTrue(!iter.hasNext());

		// Limited range of addresses from 0x0100000100 to 0x0200000100L
		iter = map.getAddressRanges(addr(0x0100000100L), addr(0x0200000100L));
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100000100L), addr(0x0100000fffL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100001000L), addr(0x0100001000L)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0100001001L), addr(0x01ffffffefL)), iter.next());
		assertTrue(iter.hasNext());
		assertEquals(new AddressRangeImpl(addr(0x0200000011L), addr(0x0200000100L)), iter.next());
		assertTrue(!iter.hasNext());
	}

	@Test
	public void testMove() {

		AddressRangeMapDB map = new AddressRangeMapDB(program.getDBHandle(), addrMap,
			new Lock("Test"), "TEST", this, LongField.INSTANCE, true);

		int id = program.startTransaction("TEST");
		try {
			assertNull(map.getValue(addr(0x01000000000L)));

			map.paintRange(addr(0x0000001000L), addr(0x0200001000L), ONE);
			assertNull(map.getValue(addr(0x0000000000L)));
			assertEquals(ONE, map.getValue(addr(0x00000001000L)));
			assertEquals(ONE, map.getValue(addr(0x0100001000L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
			assertNull(map.getValue(addr(0x0200001001L)));

			map.paintRange(addr(0x0100000000L), addr(0x0100001000L), TWO);
			assertNull(map.getValue(addr(0x0000000000L)));
			assertEquals(ONE, map.getValue(addr(0x0000001000L)));
			assertEquals(TWO, map.getValue(addr(0x0100000fffL)));
			assertEquals(TWO, map.getValue(addr(0x0100001000L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
			assertNull(map.getValue(addr(0x0200001001L)));

			map.paintRange(addr(0x0080000000L), addr(0x0100000fffL), THREE);
			assertNull(map.getValue(addr(0x0000000000L)));
			assertEquals(ONE, map.getValue(addr(0x0000001000L)));
			assertEquals(THREE, map.getValue(addr(0x0100000fffL)));
			assertEquals(TWO, map.getValue(addr(0x0100001000L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
			assertNull(map.getValue(addr(0x0200001001L)));

			try {
				map.moveAddressRange(addr(0x0100000000L), addr(0x0100001000L), 0x1000,
					TaskMonitorAdapter.DUMMY_MONITOR);
			}
			catch (CancelledException e) {
				Assert.fail();
			}

			assertNull(map.getValue(addr(0x01000000000L)));
			assertNull(map.getValue(addr(0x01000000fffL)));
			assertEquals(THREE, map.getValue(addr(0x0100001000L)));
			assertEquals(THREE, map.getValue(addr(0x0100001fffL)));
			assertEquals(ONE, map.getValue(addr(0x0100002000L)));
			assertEquals(ONE, map.getValue(addr(0x0200001000L)));
		}
		finally {
			program.endTransaction(id, true);
		}
	}

}
