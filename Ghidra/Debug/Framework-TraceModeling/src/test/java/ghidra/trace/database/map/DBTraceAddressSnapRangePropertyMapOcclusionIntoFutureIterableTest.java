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
package ghidra.trace.database.map;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.*;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;

public class DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterableTest
		extends AbstractGhidraHeadlessIntegrationTest {
	protected static class MyObject extends DBCachedDomainObjectAdapter {
		protected MyObject(Object consumer) throws IOException {
			super(new DBHandle(), DBOpenMode.CREATE, new ConsoleTaskMonitor(), "Testing", 500, 1000,
				consumer);
		}

		@Override
		public boolean isChangeable() {
			return true;
		}

		@Override
		public String getDescription() {
			return "Testing";
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static class MyEntry extends AbstractDBTraceAddressSnapRangePropertyMapData<String> {

		public static final String VALUE_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(VALUE_COLUMN_NAME)
		static DBObjectColumn VALUE_COLUMN;

		@DBAnnotatedField(column = VALUE_COLUMN_NAME)
		String value;

		public MyEntry(DBTraceAddressSnapRangePropertyMapTree<String, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(String value) {
			this.value = value;
			update(VALUE_COLUMN);
		}

		@Override
		protected String getRecordValue() {
			return value;
		}
	}

	protected MyObject obj;
	protected DBCachedObjectStoreFactory factory;
	protected Language toy;
	protected DBTraceAddressSnapRangePropertyMapSpace<String, MyEntry> space;

	protected Address addr(long offset) {
		return toy.getDefaultSpace().getAddress(offset);
	}

	protected AddressRange rng(long min, long max) {
		return new AddressRangeImpl(addr(min), addr(max));
	}

	protected AddressSetView set(AddressRange... ranges) {
		AddressSet result = new AddressSet();
		for (AddressRange r : ranges) {
			result.add(r);
		}
		return result;
	}

	protected TraceAddressSnapRange tasr(long minOff, long maxOff, long minSnap, long maxSnap) {
		return new ImmutableTraceAddressSnapRange(addr(minOff), addr(maxOff), minSnap, maxSnap);
	}

	protected <T> Entry<TraceAddressSnapRange, T> ent(long minOff, long maxOff, long minSnap,
			long maxSnap, T value) {
		return new ImmutablePair<>(tasr(minOff, maxOff, minSnap, maxSnap), value);
	}

	protected <T> List<T> list(Iterator<T> it) {
		List<T> result = new ArrayList<>();
		while (it.hasNext()) {
			result.add(it.next());
		}
		return result;
	}

	protected <T> List<T> list(Iterable<T> col) {
		List<T> result = new ArrayList<>();
		for (T t : col) {
			result.add(t);
		}
		return result;
	}

	@SafeVarargs
	protected static <T> List<T> list(T... args) {
		return Arrays.asList(args);
	}

	protected List<Address> addrs(long... offsets) {
		List<Address> result = new ArrayList<>(offsets.length);
		for (long off : offsets) {
			result.add(addr(off));
		}
		return result;
	}

	protected DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable<String> makeOcclusionIterable(
			TraceAddressSnapRange tasr) {
		return new DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable<>(space, tasr);
	}

	@Before
	public void setUp() throws IOException, VersionException {
		toy = DefaultLanguageService.getLanguageService()
				.getLanguage(
					new LanguageID("Toy:BE:64:default"));
		obj = new MyObject(this);
		factory = new DBCachedObjectStoreFactory(obj);
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "CreateTable", true)) {
			space = new DBTraceAddressSnapRangePropertyMapSpace<>("Entries", factory,
				obj.getReadWriteLock(), toy.getDefaultSpace(), MyEntry.class, MyEntry::new);
		}
	}

	@After
	public void tearDown() {
		obj.release(this);
	}

	@Test
	public void testEmpty() {
		DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable<String> it =
			makeOcclusionIterable(tasr(0x0000, 0xffff, 0, 100));

		assertFalse(it.iterator().hasNext());
		// This specification is a bit odd, but no one should peek or next in this situation. 
		try {
			it.iterator().peek();
			fail();
		}
		catch (NoSuchElementException e) {
			// pass
		}
		assertNull(it.iterator().next());
	}

	@Test
	public void testOutOfWindow() {
		DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable<String> it;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 5, 10), "A");
		}

		it = makeOcclusionIterable(tasr(0x0000, 0x0fff, 0, 100));
		assertFalse(it.iterator().hasNext());

		it = makeOcclusionIterable(tasr(0x2000, 0x2fff, 0, 100));
		assertFalse(it.iterator().hasNext());

		it = makeOcclusionIterable(tasr(0x0000, 0x2fff, 94, 100));
		assertFalse(it.iterator().hasNext());

		it = makeOcclusionIterable(tasr(0x0000, 0x2fff, 85, 89));
		assertFalse(it.iterator().hasNext());
	}

	@Test
	public void testSingleEntry() {
		DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable<String> it;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 90, 95), "A");
		}

		it = makeOcclusionIterable(tasr(0x0000, 0x2fff, 0, 100));
		assertEquals(list(ent(0x1000, 0x1fff, 90, 95, "A")), list(it));
		assertEquals(ent(0x1000, 0x1fff, 90, 95, "A"), it.iterator().peek());

		it = makeOcclusionIterable(tasr(0x0000, 0x17ff, 0, 100));
		assertEquals(list(ent(0x1000, 0x17ff, 90, 95, "A")), list(it));

		it = makeOcclusionIterable(tasr(0x1800, 0x2fff, 0, 100));
		assertEquals(list(ent(0x1800, 0x1fff, 90, 95, "A")), list(it));

		it = makeOcclusionIterable(tasr(0x0000, 0x2fff, 93, 100));
		assertEquals(list(ent(0x1000, 0x1fff, 93, 95, "A")), list(it));

		it = makeOcclusionIterable(tasr(0x0000, 0x2fff, 0, 93));
		assertEquals(list(ent(0x1000, 0x1fff, 90, 93, "A")), list(it));
	}

	@Test
	public void testEntriesAtExtremes() {
		DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable<String> it;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x0000, 0x0fff, 5, 10), "W");
			space.put(tasr(-0x1000, -0x0001, 5, 10), "E");
			space.put(tasr(0x1000, 0x1fff, Long.MIN_VALUE, Long.MIN_VALUE + 10), "S");
			space.put(tasr(0x2000, 0x2fff, Long.MAX_VALUE - 10, Long.MAX_VALUE), "N");
		}

		it = makeOcclusionIterable(tasr(0x0000, -0x0001, Long.MIN_VALUE, Long.MAX_VALUE));
		assertEquals(list( //
			ent(0x0000, 0x0fff, 5, 10, "W"), //
			ent(0x1000, 0x1fff, Long.MIN_VALUE, Long.MIN_VALUE + 10, "S"), //
			ent(0x2000, 0x2fff, Long.MAX_VALUE - 10, Long.MAX_VALUE, "N"), //
			ent(-0x1000, -0x0001, 5, 10, "E") //
		), list(it));
	}

	@Test
	public void testOcclusion() {
		DBTraceAddressSnapRangePropertyMapOcclusionIntoFutureIterable<String> it;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 90, 95), "A");
			space.put(tasr(0x1800, 0x27ff, 89, 95), "B");

			space.put(tasr(0x3000, 0x3fff, 89, 95), "C");
			space.put(tasr(0x3800, 0x47ff, 90, 95), "D");

			space.put(tasr(0x5000, 0x7fff, 90, 95), "E");
			space.put(tasr(0x6000, 0x6fff, 89, 95), "F");

			space.put(tasr(0xa000, 0xafff, 90, 95), "G");
			space.put(tasr(0x9000, 0xbfff, 89, 95), "H");
		}

		it = makeOcclusionIterable(tasr(0x0000, -0x0001, Long.MIN_VALUE, Long.MAX_VALUE));
		assertEquals(list( //
			ent(0x1000, 0x17ff, 90, 95, "A"), //
			ent(0x1800, 0x27ff, 89, 95, "B"), //

			ent(0x3000, 0x3fff, 89, 95, "C"), //
			ent(0x4000, 0x47ff, 90, 95, "D"), //

			ent(0x5000, 0x5fff, 90, 95, "E"), //
			ent(0x6000, 0x6fff, 89, 95, "F"), //
			ent(0x7000, 0x7fff, 90, 95, "E"), //

			ent(0x9000, 0xbfff, 89, 95, "H") //
		), list(it));
	}
}
