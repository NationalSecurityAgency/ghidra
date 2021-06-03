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
import java.util.function.Predicate;

import org.junit.*;

import db.DBHandle;
import db.DBRecord;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.UnionAddressSetView;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;

public class DBTraceAddressSnapRangePropertyMapAddressSetViewTest
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

	protected <T> List<T> list(Iterator<T> it) {
		List<T> result = new ArrayList<>();
		while (it.hasNext()) {
			result.add(it.next());
		}
		return result;
	}

	protected <T> List<T> list(Collection<T> col) {
		return new ArrayList<>(col);
	}

	protected List<Address> addrs(long... offsets) {
		List<Address> result = new ArrayList<>(offsets.length);
		for (long off : offsets) {
			result.add(addr(off));
		}
		return result;
	}

	protected AddressSetView makeIntersectingView(TraceAddressSnapRange tasr,
			Predicate<String> predicate) {
		return new DBTraceAddressSnapRangePropertyMapAddressSetView<>(toy.getDefaultSpace(),
			obj.getReadWriteLock(), space.reduce(TraceAddressSnapRangeQuery.intersecting(tasr)),
			predicate);
	}

	@Before
	public void setUp() throws IOException, VersionException {
		toy = DefaultLanguageService.getLanguageService()
				.getLanguage(new LanguageID("Toy:BE:64:default"));
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
	public void testContainsAddr() {
		AddressSetView view;

		view = makeIntersectingView(tasr(0x0100, 0x2fff, 0, 0), s -> true);
		assertFalse(view.contains(addr(0x1800)));

		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 9), "A");
		}

		view = makeIntersectingView(tasr(0x0000, 0x2fff, 0, 0), s -> true);
		assertFalse(view.contains(addr(0x0800)));
		assertTrue(view.contains(addr(0x1800)));
		assertFalse(view.contains(addr(0x2800)));

		view = makeIntersectingView(tasr(0x1400, 0x1bff, 0, 0), s -> true);
		assertFalse(view.contains(addr(0x0800)));
		assertTrue(view.contains(addr(0x1800)));
		assertFalse(view.contains(addr(0x2800)));

		view = makeIntersectingView(tasr(0x1000, 0x1fff, 10, 1000), s -> true);
		assertFalse(view.contains(addr(0x0800)));
		assertFalse(view.contains(addr(0x1800)));
		assertFalse(view.contains(addr(0x2800)));

		view = makeIntersectingView(tasr(0x1000, 0x1fff, 0, 0), s -> false);
		assertFalse(view.contains(addr(0x0800)));
		assertFalse(view.contains(addr(0x1800)));
		assertFalse(view.contains(addr(0x2800)));
	}

	@Test
	public void testContainsRange() {
		AddressSetView view;

		view = makeIntersectingView(tasr(0x0100, 0x2fff, 0, 0), s -> true);
		assertFalse(view.contains(addr(0x1000), addr(0x1fff)));

		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x3fff, 1, 1), "B");
		}

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> true);
		assertFalse(view.contains(addr(0x0000), addr(0x4fff)));
		assertTrue(view.contains(addr(0x1800), addr(0x37ff)));
		assertTrue(view.contains(addr(0x1800), addr(0x27ff)));
		assertTrue(view.contains(addr(0x2800), addr(0x3fff)));

		view = makeIntersectingView(tasr(0x0000, 0x1800, 0, 1), s -> true);
		assertFalse(view.contains(addr(0x0000), addr(0x4fff)));
		assertFalse(view.contains(addr(0x1800), addr(0x37ff)));
		assertTrue(view.contains(addr(0x1800), addr(0x27ff)));
		assertFalse(view.contains(addr(0x2800), addr(0x3fff)));

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 0), s -> true);
		assertFalse(view.contains(addr(0x0000), addr(0x4fff)));
		assertFalse(view.contains(addr(0x1800), addr(0x37ff)));
		assertTrue(view.contains(addr(0x1800), addr(0x27ff)));
		assertFalse(view.contains(addr(0x2800), addr(0x3fff)));

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> "A".equals(s));
		assertFalse(view.contains(addr(0x0000), addr(0x4fff)));
		assertFalse(view.contains(addr(0x1800), addr(0x37ff)));
		assertTrue(view.contains(addr(0x1800), addr(0x27ff)));
		assertFalse(view.contains(addr(0x2800), addr(0x3fff)));
	}

	@Test
	public void testContainsRangeSet() {
		AddressSetView view;

		view = makeIntersectingView(tasr(0x0100, 0x2fff, 0, 0), s -> true);
		assertFalse(view.contains(set(rng(0x1000, 0x1fff))));

		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x3fff, 1, 1), "B");
		}

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> true);
		assertFalse(view.contains(set(rng(0x0000, 0x4fff))));
		assertTrue(view.contains(set(rng(0x1800, 0x37ff))));
		assertTrue(view.contains(set(rng(0x1800, 0x27ff))));
		assertTrue(view.contains(set(rng(0x2800, 0x3fff))));

		view = makeIntersectingView(tasr(0x0000, 0x1800, 0, 1), s -> true);
		assertFalse(view.contains(set(rng(0x0000, 0x4fff))));
		assertFalse(view.contains(set(rng(0x1800, 0x37ff))));
		assertTrue(view.contains(set(rng(0x1800, 0x27ff))));
		assertFalse(view.contains(set(rng(0x2800, 0x3fff))));

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 0), s -> true);
		assertFalse(view.contains(set(rng(0x0000, 0x4fff))));
		assertFalse(view.contains(set(rng(0x1800, 0x37ff))));
		assertTrue(view.contains(set(rng(0x1800, 0x27ff))));
		assertFalse(view.contains(set(rng(0x2800, 0x3fff))));

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> "A".equals(s));
		assertFalse(view.contains(set(rng(0x0000, 0x4fff))));
		assertFalse(view.contains(set(rng(0x1800, 0x37ff))));
		assertTrue(view.contains(set(rng(0x1800, 0x27ff))));
		assertFalse(view.contains(set(rng(0x2800, 0x3fff))));
	}

	@Test
	public void testCounts() {
		AddressSetView view;

		view = makeIntersectingView(tasr(0x0100, 0x2fff, 0, 0), s -> true);
		assertTrue(view.isEmpty());
		assertEquals(0, view.getNumAddressRanges());
		assertEquals(0, view.getNumAddresses());

		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> true);
		assertFalse(view.isEmpty());
		assertEquals(1, view.getNumAddressRanges());
		assertEquals(0x3000, view.getNumAddresses());

		view = makeIntersectingView(tasr(0x0000, 0x1800, 0, 1), s -> true);
		assertFalse(view.isEmpty());
		assertEquals(1, view.getNumAddressRanges());
		assertEquals(0x1000, view.getNumAddresses());

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 0), s -> true);
		assertFalse(view.isEmpty());
		assertEquals(1, view.getNumAddressRanges());
		assertEquals(0x2000, view.getNumAddresses());

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> "B".equals(s));
		assertFalse(view.isEmpty());
		assertEquals(1, view.getNumAddressRanges());
		assertEquals(0x2000, view.getNumAddresses());
	}

	@Test
	public void testEndpoints() {
		AddressSetView view;

		view = makeIntersectingView(tasr(0x0100, 0x2fff, 0, 0), s -> true);
		assertNull(view.getMinAddress());
		assertNull(view.getMaxAddress());

		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x3fff, 1, 1), "B");
		}

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> true);
		assertEquals(addr(0x1000), view.getMinAddress());
		assertEquals(addr(0x3fff), view.getMaxAddress());

		view = makeIntersectingView(tasr(0x0000, 0x1800, 0, 1), s -> true);
		assertEquals(addr(0x1000), view.getMinAddress());
		assertEquals(addr(0x2fff), view.getMaxAddress());

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 0), s -> true);
		assertEquals(addr(0x1000), view.getMinAddress());
		assertEquals(addr(0x2fff), view.getMaxAddress());

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> "A".equals(s));
		assertEquals(addr(0x1000), view.getMinAddress());
		assertEquals(addr(0x2fff), view.getMaxAddress());
	}

	@Test
	public void testGetAddressRanges() {
		AddressSetView view;

		// TODO: Rewinding to coalesce the overlapping, connected entries may be desired
		view = makeIntersectingView(tasr(0x0100, 0x2fff, 0, 0), s -> true);
		assertEquals(List.of(), list(view.iterator()));

		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> true);
		assertEquals(List.of(rng(0x1000, 0x3fff)), list(view.iterator()));
		assertEquals(List.of(rng(0x1000, 0x3fff)), list(view.iterator(false)));
		assertEquals(List.of(rng(0x2000, 0x3fff)), list(view.iterator(addr(0x2800), true)));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator(addr(0x2800), false)));

		view = makeIntersectingView(tasr(0x0000, 0x2800, 0, 1), s -> true);
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator()));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator(false)));
		assertEquals(List.of(rng(0x2000, 0x2fff)), list(view.iterator(addr(0x2800), true)));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator(addr(0x2800), false)));

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 0), s -> true);
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator()));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator(false)));
		assertEquals(List.of(rng(0x2000, 0x2fff)), list(view.iterator(addr(0x2800), true)));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator(addr(0x2800), false)));

		view = makeIntersectingView(tasr(0x0000, 0x4fff, 0, 1), s -> "A".equals(s));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator()));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator(false)));
		assertEquals(List.of(rng(0x2000, 0x2fff)), list(view.iterator(addr(0x2800), true)));
		assertEquals(List.of(rng(0x1000, 0x2fff)), list(view.iterator(addr(0x2800), false)));
	}

	@Test
	public void testGetAddresses() {
		AddressSetView view;

		view = makeIntersectingView(tasr(0x0100, 0x2fff, 0, 0), s -> true);
		assertEquals(List.of(), list(view.getAddresses(true)));

		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(1, 5, 0, 0), "A");
		}

		view = makeIntersectingView(tasr(0, 9, 0, 0), s -> true);
		assertEquals(addrs(1, 2, 3, 4, 5), list(view.getAddresses(true)));
		assertEquals(addrs(5, 4, 3, 2, 1), list(view.getAddresses(false)));
		assertEquals(addrs(3, 4, 5), list(view.getAddresses(addr(3), true)));
		assertEquals(addrs(3, 2, 1), list(view.getAddresses(addr(3), false)));
		assertEquals(List.of(), list(view.getAddresses(addr(6), true)));

		view = makeIntersectingView(tasr(0, 9, 1, 1), s -> true);
		assertEquals(List.of(), list(view.getAddresses(true)));

		view = makeIntersectingView(tasr(0, 9, 0, 0), s -> false);
		assertEquals(List.of(), list(view.getAddresses(true)));
	}

	@Test
	public void testIntersects() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		assertTrue(view.intersects(addr(0x0000), addr(0x17ff)));
		assertEquals(set(rng(0x1000, 0x17ff)), view.intersectRange(addr(0x0000), addr(0x17ff)));
		assertFalse(view.intersects(addr(0x3800), addr(0x4fff)));
		assertEquals(set(), view.intersectRange(addr(0x3800), addr(0x4fff)));

		assertTrue(view.intersects(set(rng(0x0000, 0x0100), rng(0x1800, 0x1bff))));
		assertEquals(set(rng(0x1800, 0x1bff)),
			view.intersect(set(rng(0x0000, 0x0100), rng(0x1800, 0x1bff))));
		assertFalse(view.intersects(set(rng(0x3800, 0x3bff))));
		assertEquals(set(), view.intersect(set(rng(0x3800, 0x3bff))));
	}

	@Test
	public void testUnion() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		assertEquals(set(rng(0x0100, 0x2fff)), view.union(set(rng(0x0100, 0x0fff))));
	}

	@Test
	public void testSubtract() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		assertEquals(set(rng(0x1000, 0x17ff), rng(0x2800, 0x2fff)),
			view.subtract(set(rng(0x1800, 0x27ff))));
	}

	@Test
	public void testXor() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		assertEquals(set(rng(0x0800, 0x0fff), rng(0x1800, 0x2fff)),
			view.xor(set(rng(0x0800, 0x17ff))));
	}

	@Test
	public void testHasSameAddresses() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		assertTrue(view.hasSameAddresses(set(rng(0x1000, 0x2fff))));
		assertFalse(view.hasSameAddresses(set(rng(0x1000, 0x1fff))));
		assertFalse(view.hasSameAddresses(set()));
		assertFalse(view.hasSameAddresses(set(rng(0x1000, 0x2fff), rng(0x4000, 0x4fff))));
	}

	@Test
	public void testGetFirstLastRanges() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x27ff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "A");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		assertEquals(rng(0x1000, 0x27ff), view.getFirstRange());
		assertEquals(rng(0x3000, 0x3fff), view.getLastRange());
	}

	@Test
	public void testGetRangeContaining() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		// Note: underlying implementation uses a forward iterator.
		assertEquals(rng(0x1000, 0x2fff), view.getRangeContaining(addr(0x1800)));
		assertEquals(rng(0x2000, 0x2fff), view.getRangeContaining(addr(0x2800)));

		// Test this "quick fix" use case for coalescing connected, overlapping entries
		AddressSetView union = new UnionAddressSetView(view);
		assertEquals(rng(0x1000, 0x2fff), union.getRangeContaining(addr(0x1800)));
		assertEquals(rng(0x1000, 0x2fff), union.getRangeContaining(addr(0x2800)));
	}

	@Test
	public void testFindFirstAddressInCommon() {
		try (UndoableTransaction trans = UndoableTransaction.start(obj, "Create Entries", true)) {
			space.put(tasr(0x1000, 0x1fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 0, 0), "A");
			space.put(tasr(0x2000, 0x2fff, 1, 1), "B");
			space.put(tasr(0x3000, 0x3fff, 1, 1), "B");
		}
		AddressSetView view = makeIntersectingView(tasr(0x1000, 0x3fff, 0, 1), s -> "A".equals(s));

		assertEquals(addr(0x1000), view.findFirstAddressInCommon(set(rng(0x0000, 0x17ff))));
		assertEquals(addr(0x1800), view.findFirstAddressInCommon(set(rng(0x1800, 0x1fff))));
	}
}
