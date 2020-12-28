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
package ghidra.util.database;

import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.commons.collections4.IterableUtils;
import org.apache.commons.collections4.IteratorUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.*;

import com.google.common.collect.Range;

import db.*;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.database.DirectedIterator.Direction;
import ghidra.util.database.annot.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class DBCachedObjectStoreTest {
	static {
		UniversalIdGenerator.initialize();
	}

	private static final int MYOBJECT_VERSION = 0;
	private static final String OBJECTS_TABLE_NAME = "Objects";
	private static final String COL1_NAME = "Col1";
	private static final String COL2_NAME = "Col2";

	protected static <T, R> Function<T, R> nullable(Function<T, R> f) {
		return t -> {
			if (t == null) {
				return null;
			}
			return f.apply(t);
		};
	}

	public class MyDomainObject extends DBCachedDomainObjectAdapter {
		protected final DBCachedObjectStoreFactory storeFactory;
		@SuppressWarnings("hiding")
		protected final DBCachedObjectStore<MyObject> store;

		protected MyDomainObject(String name, int timeInterval, int bufSize, Object consumer)
				throws VersionException, IOException {
			super(new DBHandle(), DBOpenMode.CREATE, new ConsoleTaskMonitor(), name, timeInterval,
				bufSize, consumer);
			this.storeFactory = new DBCachedObjectStoreFactory(this);
			try (DBTransaction tid = DBTransaction.start(dbh, true)) {
				this.store = storeFactory.getOrCreateCachedStore(OBJECTS_TABLE_NAME, MyObject.class,
					MyObject::new, false);
			}
		}

		protected MyDomainObject(DBHandle handle, DBOpenMode openMode, TaskMonitor monitor,
				int timeInterval, int bufSize, Object consumer)
				throws VersionException, IOException {
			super(handle, openMode, monitor, null, timeInterval, bufSize, consumer);
			this.storeFactory = new DBCachedObjectStoreFactory(this);
			try (DBTransaction tid = DBTransaction.start(handle, true)) {
				this.store = storeFactory.getOrCreateCachedStore(OBJECTS_TABLE_NAME, MyObject.class,
					MyObject::new, false);
			}
		}

		@Override
		public boolean isChangeable() {
			return true;
		}

		@Override
		public String getDescription() {
			return "Dummy for testing";
		}
	}

	@DBAnnotatedObjectInfo(version = MYOBJECT_VERSION)
	static class MyObject extends DBAnnotatedObject {
		@DBAnnotatedColumn(COL1_NAME)
		private static DBObjectColumn COL1;
		@DBAnnotatedColumn(COL2_NAME)
		private static DBObjectColumn COL2;

		public MyObject(DBCachedObjectStore<MyObject> store, DBRecord record) {
			super(store, record);
		}

		@DBAnnotatedField(column = COL1_NAME)
		private long f1;
		@DBAnnotatedField(column = COL2_NAME, indexed = true)
		private int f2;

		public void setF1(long f1) {
			if (this.f1 != f1) {
				this.f1 = f1;
				write(COL1);
			}
		}

		public void setF2(int f2) {
			if (this.f2 != f2) {
				this.f2 = f2;
				write(COL2);
			}
		}
	}

	DBHandle handle;
	MyDomainObject myDomainObject;
	DBCachedObjectStore<MyObject> store;

	DBCachedObjectStoreMap<MyObject> map;
	DBCachedObjectStoreMap<MyObject> rMap;
	DBCachedObjectStoreKeySet keySet;
	DBCachedObjectStoreKeySet rKeySet;
	DBCachedObjectStoreValueCollection<MyObject> values;
	DBCachedObjectStoreValueCollection<MyObject> rValues;
	DBCachedObjectStoreEntrySet<MyObject> entrySet;
	DBCachedObjectStoreEntrySet<MyObject> rEntrySet;

	protected UndoableTransaction trans() {
		return UndoableTransaction.start(myDomainObject, "Test", true);
	}

	protected void populateStore(long... keys) {
		try (UndoableTransaction tid = trans()) {
			for (long k : keys) {
				store.create(k);
			}
		}
	}

	@Before
	public void setUp() throws IOException, VersionException {
		myDomainObject = new MyDomainObject("Testing", 500, 1000, this);
		handle = myDomainObject.getDBHandle();
		store = myDomainObject.store;

		map = store.asMap();
		rMap = map.descendingMap();
		keySet = map.keySet();
		rKeySet = keySet.descendingSet();
		values = map.values();
		rValues = rMap.values();
		entrySet = map.entrySet();
		rEntrySet = rMap.entrySet();
	}

	@After
	public void tearDown() {
		myDomainObject.release(this);
	}

	/**
	 * This exists to verify behavior in {@link #testAsValuesSubIterator()}
	 */
	@Test
	public void testTailOfReversedJavaCollections() {
		// NOTE: Verify the expected API
		NavigableSet<Integer> set = new TreeSet<>(List.of(-3, -1, 1, 3));
		List<Integer> rList = new ArrayList<>(set.descendingSet().tailSet(0, true));
		assertEquals(List.of(-1, -3), rList);
	}

	@Test
	public void testTableCreated() {
		Table table = handle.getTable(OBJECTS_TABLE_NAME);
		Schema schema = table.getSchema();
		assertEquals(0, schema.getVersion());
		assertArrayEquals(new String[] { COL1_NAME, COL2_NAME }, schema.getFieldNames());
		assertArrayEquals(new Class<?>[] { LongField.class, IntField.class },
			Stream.of(schema.getFields()).map(Object::getClass).toArray());
		assertEquals("Key", schema.getKeyName());
		assertEquals(LongField.class, schema.getKeyFieldType().getClass());
	}

	@Test
	public void testCreate() throws IOException {
		try (UndoableTransaction tid = trans()) {
			assertFalse(store.isCached(0));
			MyObject obj = store.create();
			assertEquals(0, obj.getKey());
			assertTrue(store.isCached(0));
			Table table = handle.getTable(OBJECTS_TABLE_NAME);
			DBRecord record = table.getRecord(obj.getKey());
			assertNotNull(record);
		}
	}

	@Test
	public void testCreateWithKey() throws IOException {
		try (UndoableTransaction tid = trans()) {
			assertFalse(store.isCached(0));
			MyObject obj = store.create(0x80);
			assertEquals(0x80, obj.getKey());
			assertTrue(store.isCached(0x80));
			Table table = handle.getTable(OBJECTS_TABLE_NAME);
			DBRecord record = table.getRecord(obj.getKey());
			assertNotNull(record);
		}
	}

	@Test
	public void testContains() {
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create();
			assertTrue(store.contains(obj));
		}
	}

	@Test
	public void testGetRecordCount() {
		assertEquals(0, store.getRecordCount());
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create();
			assertTrue(store.contains(obj));
		}
		assertEquals(1, store.getRecordCount());
	}

	@Test
	public void testGetMaxKey() {
		assertNull(store.getMaxKey());
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create();
			assertTrue(store.contains(obj));
		}
		assertEquals(0, store.getMaxKey().longValue());
	}

	@Test
	public void testContainsKey() {
		try (UndoableTransaction tid = trans()) {
			assertFalse(store.containsKey(0));
			@SuppressWarnings("unused")
			MyObject obj = store.create();
			assertTrue(store.containsKey(0));
		}
	}

	@Test
	public void testSave() throws IOException {
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create();
			obj.setF1(0x801);
			obj.setF2(0x802);
			obj.updated();
			Table table = handle.getTable(OBJECTS_TABLE_NAME);
			DBRecord record = table.getRecord(obj.getKey());
			assertEquals(0x801, record.getLongValue(0));
			assertEquals(0x802, record.getIntValue(1));
		}
	}

	@Test
	public void testGetObjectAt() throws IOException, VersionException {
		try (UndoableTransaction tid = trans()) {
			Table table = myDomainObject.storeFactory.getOrCreateTable(OBJECTS_TABLE_NAME,
				MyObject.class, false);
			assertEquals(0, table.getRecordCount());
			DBRecord record = table.getSchema().createRecord(0x1234);
			record.setLongValue(0, 0x811);
			record.setIntValue(1, 0x812);
			table.putRecord(record);

			MyObject obj = store.getObjectAt(0x1234);
			assertEquals(0x811, obj.f1);
			assertEquals(0x812, obj.f2);
		}
	}

	@Test
	public void testSaveAndLoad() throws IOException, VersionException, CancelledException {
		try (UndoableTransaction tid = trans()) {
			Table table = myDomainObject.storeFactory.getOrCreateTable(OBJECTS_TABLE_NAME,
				MyObject.class, false);
			assertEquals(0, table.getRecordCount());
			DBRecord record = table.getSchema().createRecord(0x1234);
			record.setLongValue(0, 0x811);
			record.setIntValue(1, 0x812);
			table.putRecord(record);
		}

		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		handle.saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());
		DBHandle opened = new DBHandle(tmp.toFile());
		MyDomainObject restored = null;
		try {
			restored = new MyDomainObject(opened, DBOpenMode.READ_ONLY, new ConsoleTaskMonitor(),
				500, 1000, this);
			MyObject rObj = restored.store.getObjectAt(0x1234);
			assertEquals(0x811, rObj.f1);
			assertEquals(0x812, rObj.f2);
		}
		finally {
			if (restored != null) {
				restored.release(this);
			}
		}
	}

	@Test
	public void testDelete() {
		try (UndoableTransaction tid = trans()) {
			assertNull(store.deleteKey(0));
			MyObject obj = store.create();
			assertTrue(store.isCached(0));
			assertTrue(store.delete(obj));
			assertFalse(store.isCached(0));
			assertFalse(store.contains(obj));
			assertFalse(store.delete(obj));
		}
	}

	@Test
	public void testDeleteKey() {
		try (UndoableTransaction tid = trans()) {
			assertNull(store.deleteKey(0));
			MyObject obj = store.create();
			assertTrue(store.isCached(0));
			assertNotNull(store.deleteKey(0));
			assertFalse(store.isCached(0));
			assertFalse(store.contains(obj));
			assertNull(store.deleteKey(0));
		}
	}

	@Test
	public void testDeleteAll() {
		try (UndoableTransaction tid = trans()) {
			assertEquals(0, store.getRecordCount());
			MyObject obj = store.create();
			assertEquals(1, store.getRecordCount());
			store.deleteAll();
			assertEquals(0, store.getRecordCount());
			assertFalse(store.isCached(0));
			assertFalse(store.contains(obj));
			assertNull(store.getObjectAt(0));
		}
	}

	@Test
	public void testAsMapSize() {
		assertTrue(map.isEmpty());
		assertEquals(0, map.size());
		try (UndoableTransaction tid = trans()) {
			store.create();
		}
		assertFalse(map.isEmpty());
		assertEquals(1, map.size());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapContainsKey() {
		assertFalse(map.containsKey(null));
		assertFalse(map.containsKey("Wrong type"));
		assertFalse(map.containsKey(0L));
		try (UndoableTransaction tid = trans()) {
			store.create();
		}
		assertTrue(map.containsKey(0L));
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapContainsValue() {
		try (UndoableTransaction tid = trans()) {
			assertFalse(map.containsValue(null));
			assertFalse(map.containsValue("Wrong type"));
			MyObject obj1 = store.create(0);
			assertTrue(map.containsValue(obj1));
			MyObject obj2 = store.create(0);
			assertFalse(map.containsValue(obj1));
			assertTrue(map.containsKey(0L));
			assertTrue(map.containsValue(obj2));
		}
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapGet() {
		try (UndoableTransaction tid = trans()) {
			assertNull(map.get(0L));
			assertNull(map.get("Wrong type"));
			MyObject obj = store.create(0);
			assertEquals(obj, map.get(0L));
		}
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapRemove() {
		try (UndoableTransaction tid = trans()) {
			assertNull(map.remove(null));
			assertNull(map.remove(0L));
			assertNull(map.remove("Wrong type"));
			MyObject obj = store.create();
			assertEquals(obj, map.remove(0L));
			assertEquals(0, store.getRecordCount());
			assertNull(map.remove(0L));
		}
	}

	@Test
	public void testAsMapClear() {
		try (UndoableTransaction tid = trans()) {
			store.create();
			assertEquals(1, map.size());
			map.clear();
			assertEquals(0, store.getRecordCount());
		}
	}

	@Test
	public void testAsMapComparator() {
		assertTrue(map.comparator().compare(0L, 1L) < 0);
		assertTrue(rMap.comparator().compare(0L, 1L) > 0);
	}

	@Test
	public void testAsMapNavigable() {
		assertNull(map.firstEntry());
		assertNull(map.firstKey());
		assertNull(map.lastEntry());
		assertNull(map.lastKey());
		assertNull(rMap.firstEntry());
		assertNull(rMap.firstKey());
		assertNull(rMap.lastEntry());
		assertNull(rMap.lastKey());

		populateStore(-3, -1, 1, 3);

		assertEquals(-3, map.firstEntry().getKey().longValue());
		assertEquals(map.firstEntry(), rMap.lastEntry());
		assertEquals(-3, map.firstKey().longValue());
		assertEquals(map.firstKey(), rMap.lastKey());
		assertEquals(3, map.lastEntry().getKey().longValue());
		assertEquals(map.lastEntry(), rMap.firstEntry());
		assertEquals(3, map.lastKey().longValue());
		assertEquals(map.lastKey(), rMap.firstKey());

		assertEquals(-1, map.lowerEntry(0L).getKey().longValue());
		assertEquals(map.lowerEntry(0L), rMap.higherEntry(0L));
		assertEquals(-1, map.lowerEntry(1L).getKey().longValue());
		assertEquals(map.lowerEntry(1L), rMap.higherEntry(1L));
		assertEquals(-1, map.lowerKey(0L).longValue());
		assertEquals(map.lowerKey(0L), rMap.higherKey(0L));
		assertEquals(-1, map.lowerKey(1L).longValue());
		assertEquals(map.lowerKey(1L), rMap.higherKey(1L));

		assertEquals(-1, map.floorEntry(0L).getKey().longValue());
		assertEquals(map.floorEntry(0L), rMap.ceilingEntry(0L));
		assertEquals(1, map.floorEntry(1L).getKey().longValue());
		assertEquals(map.floorEntry(1L), rMap.ceilingEntry(1L));
		assertEquals(-1, map.floorKey(0L).longValue());
		assertEquals(map.floorKey(0L), rMap.ceilingKey(0L));
		assertEquals(1, map.floorKey(1L).longValue());
		assertEquals(map.floorKey(1L), rMap.ceilingKey(1L));

		assertEquals(1, map.ceilingEntry(0L).getKey().longValue());
		assertEquals(map.ceilingEntry(0L), rMap.floorEntry(0L));
		assertEquals(1, map.ceilingEntry(1L).getKey().longValue());
		assertEquals(map.floorEntry(1L), rMap.ceilingEntry(1L));
		assertEquals(1, map.ceilingKey(0L).longValue());
		assertEquals(map.ceilingKey(0L), rMap.floorKey(0L));
		assertEquals(1, map.ceilingKey(1L).longValue());
		assertEquals(map.ceilingKey(1L), rMap.floorKey(1L));

		assertEquals(1, map.higherEntry(0L).getKey().longValue());
		assertEquals(map.higherEntry(0L), rMap.lowerEntry(0L));
		assertEquals(3, map.higherEntry(1L).getKey().longValue());
		assertEquals(map.higherEntry(1L), rMap.lowerEntry(1L));
		assertEquals(1, map.higherKey(0L).longValue());
		assertEquals(map.higherKey(0L), rMap.lowerKey(0L));
		assertEquals(3, map.higherKey(1L).longValue());
		assertEquals(map.higherKey(1L), rMap.lowerKey(1L));
	}

	@Test
	public void testAsMapDescendingMap() {
		assertEquals(Direction.BACKWARD, map.descendingMap().direction);
		assertEquals(Direction.FORWARD, map.descendingMap().descendingMap().direction);
	}

	@Test
	public void testAsMapSubSize() {
		populateStore(-3, -1, 1, 3);

		assertEquals(0, map.subMap(0L, true, 0L, false).size());
		assertTrue(map.subMap(0L, true, 0L, false).isEmpty());

		assertEquals(0, map.subMap(-1L, false, 1L, false).size());
		assertTrue(map.subMap(-1L, false, 1L, false).isEmpty());

		assertEquals(0, map.headMap(-4L, false).size());
		assertTrue(map.headMap(-4L, false).isEmpty());

		assertEquals(0, map.tailMap(4L, false).size());
		assertTrue(map.tailMap(4L, false).isEmpty());

		assertEquals(2, map.subMap(-2L, true, 2L, true).size());
		assertFalse(map.subMap(-2L, true, 2L, true).isEmpty());

		assertEquals(2, map.headMap(0L, true).size());
		assertFalse(map.headMap(0L, true).isEmpty());

		assertEquals(2, map.tailMap(0L, true).size());
		assertFalse(map.tailMap(0L, true).isEmpty());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapSubContainsKey() {
		populateStore(-3, -1, 1, 3);
		DBCachedObjectStoreSubMap<MyObject> subMap = map.subMap(-2L, true, 2L, true);

		assertFalse(subMap.containsKey(null));
		assertFalse(subMap.containsKey("Wrong type"));
		assertFalse(subMap.containsKey(0L));
		assertFalse(subMap.containsKey(-3L));
		assertTrue(subMap.containsKey(1L));
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapSubContainsValue() {
		populateStore(-3, -1, 1, 3);
		DBCachedObjectStoreSubMap<MyObject> subMap = map.subMap(-2L, true, 2L, true);

		assertFalse(subMap.containsValue(null));
		assertFalse(subMap.containsValue("Wrong type"));
		assertFalse(subMap.containsValue(store.getObjectAt(-3)));
		assertTrue(subMap.containsValue(store.getObjectAt(1)));
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapSubGet() {
		populateStore(-3, -1, 1, 3);
		DBCachedObjectStoreSubMap<MyObject> subMap = map.subMap(-2L, true, 2L, true);

		assertNull(subMap.get(null));
		assertNull(subMap.get("Wrong type"));
		assertNull(subMap.get(-3L));
		assertNotNull(subMap.get(1L));
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsMapSubRemove() {
		DBCachedObjectStoreSubMap<MyObject> tailMap = map.tailMap(0L);
		try (UndoableTransaction tid = trans()) {
			MyObject objN3 = store.create(-3);
			MyObject objP3 = store.create(3);

			assertNull(tailMap.remove(null));
			assertNull(tailMap.remove("Wrong type"));
			assertNull(tailMap.remove(-3L));
			assertEquals(objP3, tailMap.remove(3L));
			assertNull(tailMap.remove(3L));

			assertEquals(1, store.getRecordCount());
			assertFalse(store.contains(objP3));
			assertTrue(store.contains(objN3));
		}
	}

	@Test
	public void testAsMapSubClear() {
		populateStore(-3, -1, 1, 3);

		try (UndoableTransaction tid = trans()) {
			map.subMap(0L, 0L).clear(); // NOP
			assertEquals(4, store.getRecordCount());
			map.tailMap(0L, true).clear();
		}

		assertEquals(2, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
	}

	protected Long doTestMap(NavigableMap<Long, MyObject> m,
			Function<NavigableMap<Long, MyObject>, Long> fK,
			Function<NavigableMap<Long, MyObject>, Entry<Long, MyObject>> fE) {
		Long k = fK.apply(m);
		Entry<Long, MyObject> ent = fE.apply(m);
		if (k == null) {
			assertNull(ent);
		}
		else {
			assertEquals(k, ent.getKey());
		}
		return k;
	}

	protected Long doTestMap(NavigableMap<Long, MyObject> m,
			BiFunction<NavigableMap<Long, MyObject>, Long, Long> fK,
			BiFunction<NavigableMap<Long, MyObject>, Long, Entry<Long, MyObject>> fE, Long bound) {
		Long k = fK.apply(m, bound);
		Entry<Long, MyObject> ent = fE.apply(m, bound);
		if (k == null) {
			assertNull(ent);
		}
		else {
			assertEquals(k, ent.getKey());
		}
		return k;
	}

	@Test
	public void testAsMapSubFirst() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1, doTestMap(map.subMap(-2L, true, 2L, true), NavigableMap::firstKey,
			NavigableMap::firstEntry).longValue());
		assertEquals(-1, doTestMap(map.subMap(-1L, true, 2L, true), NavigableMap::firstKey,
			NavigableMap::firstEntry).longValue());
		assertEquals(1, doTestMap(map.subMap(-1L, false, 2L, true), NavigableMap::firstKey,
			NavigableMap::firstEntry).longValue());
		assertNull(doTestMap(map.subMap(-1L, false, 1L, false), NavigableMap::firstKey,
			NavigableMap::firstEntry));

		assertEquals(1, doTestMap(rMap.subMap(2L, true, -2L, true), NavigableMap::firstKey,
			NavigableMap::firstEntry).longValue());
		assertEquals(1, doTestMap(rMap.subMap(1L, true, -2L, true), NavigableMap::firstKey,
			NavigableMap::firstEntry).longValue());
		assertEquals(-1, doTestMap(rMap.subMap(1L, false, -2L, true), NavigableMap::firstKey,
			NavigableMap::firstEntry).longValue());
		assertNull(doTestMap(rMap.subMap(1L, false, -1L, false), NavigableMap::firstKey,
			NavigableMap::firstEntry));
	}

	@Test
	public void testAsMapSubLast() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1, doTestMap(map.subMap(-2L, true, 2L, true), NavigableMap::lastKey,
			NavigableMap::lastEntry).longValue());
		assertEquals(1, doTestMap(map.subMap(-2L, true, 1L, true), NavigableMap::lastKey,
			NavigableMap::lastEntry).longValue());
		assertEquals(-1, doTestMap(map.subMap(-2L, true, 1L, false), NavigableMap::lastKey,
			NavigableMap::lastEntry).longValue());
		assertNull(doTestMap(map.subMap(-1L, false, 1L, false), NavigableMap::lastKey,
			NavigableMap::lastEntry));

		assertEquals(-1, doTestMap(rMap.subMap(2L, true, -2L, true), NavigableMap::lastKey,
			NavigableMap::lastEntry).longValue());
		assertEquals(-1, doTestMap(rMap.subMap(2L, true, -1L, true), NavigableMap::lastKey,
			NavigableMap::lastEntry).longValue());
		assertEquals(1, doTestMap(rMap.subMap(2L, true, -1L, false), NavigableMap::lastKey,
			NavigableMap::lastEntry).longValue());
		assertNull(doTestMap(rMap.subMap(1L, false, -1L, false), NavigableMap::lastKey,
			NavigableMap::lastEntry));
	}

	@Test
	public void testAsMapSubLower() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1, doTestMap(map.subMap(-2L, true, 2L, true), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, 1L).longValue());
		assertEquals(-1, doTestMap(map.subMap(-2L, true, 1L, true), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, 1L).longValue());
		assertEquals(-1, doTestMap(map.subMap(-2L, true, 1L, false), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, 1L).longValue());
		assertNull(doTestMap(map.subMap(-2L, true, -1L, false), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, 1L));

		assertEquals(1, doTestMap(rMap.subMap(2L, true, -2L, true), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, -1L).longValue());
		assertEquals(1, doTestMap(rMap.subMap(2L, true, -1L, true), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, -1L).longValue());
		assertEquals(1, doTestMap(rMap.subMap(2L, true, -1L, false), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, -1L).longValue());
		assertNull(doTestMap(rMap.subMap(2L, true, 1L, false), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, -1L));
	}

	@Test
	public void testAsMapSubFloor() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1, doTestMap(map.subMap(-2L, true, 2L, true), NavigableMap::floorKey,
			NavigableMap::floorEntry, 1L).longValue());
		assertEquals(1, doTestMap(map.subMap(-2L, true, 1L, true), NavigableMap::floorKey,
			NavigableMap::floorEntry, 1L).longValue());
		assertEquals(-1, doTestMap(map.subMap(-2L, true, 1L, false), NavigableMap::floorKey,
			NavigableMap::floorEntry, 1L).longValue());
		assertNull(doTestMap(map.subMap(-2L, true, -1L, false), NavigableMap::floorKey,
			NavigableMap::floorEntry, 1L));

		assertEquals(-1, doTestMap(rMap.subMap(2L, true, -2L, true), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L).longValue());
		assertEquals(-1, doTestMap(rMap.subMap(2L, true, -1L, true), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L).longValue());
		assertEquals(1, doTestMap(rMap.subMap(2L, true, -1L, false), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L).longValue());
		assertNull(doTestMap(rMap.subMap(2L, true, 1L, false), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L));
	}

	@Test
	public void testAsMapSubCeiling() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1, doTestMap(map.subMap(-2L, true, 2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L).longValue());
		assertEquals(-1, doTestMap(map.subMap(-1L, true, 2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L).longValue());
		assertEquals(1, doTestMap(map.subMap(-1L, false, 2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L).longValue());
		assertNull(doTestMap(map.subMap(1L, false, 2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L));

		assertEquals(1, doTestMap(rMap.subMap(2L, true, -2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L).longValue());
		assertEquals(1, doTestMap(rMap.subMap(1L, true, -2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L).longValue());
		assertEquals(-1, doTestMap(rMap.subMap(1L, false, -2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L).longValue());
		assertNull(doTestMap(rMap.subMap(-1L, false, -2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L));
	}

	@Test
	public void testAsMapSubHigher() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1, doTestMap(map.subMap(-2L, true, 2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L).longValue());
		assertEquals(1, doTestMap(map.subMap(-1L, true, 2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L).longValue());
		assertEquals(1, doTestMap(map.subMap(-1L, false, 2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L).longValue());
		assertNull(doTestMap(map.subMap(1L, false, 2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L));

		assertEquals(-1, doTestMap(rMap.subMap(2L, true, -2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, 1L).longValue());
		assertEquals(-1, doTestMap(rMap.subMap(1L, true, -2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, 1L).longValue());
		assertEquals(-1, doTestMap(rMap.subMap(1L, false, -2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, 1L).longValue());
		assertNull(doTestMap(rMap.subMap(-1L, false, -2L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, 1L));
	}

	@Test
	public void testAsMapHeadFirst() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-3, doTestMap(map.headMap(-2L, true), NavigableMap::firstKey, //
			NavigableMap::firstEntry).longValue());
		assertEquals(-3, doTestMap(map.headMap(-3L, true), NavigableMap::firstKey, //
			NavigableMap::firstEntry).longValue());
		assertNull(doTestMap(map.headMap(-3L, false), NavigableMap::firstKey, //
			NavigableMap::firstEntry));
		assertNull(doTestMap(map.headMap(-4L, true), NavigableMap::firstKey, //
			NavigableMap::firstEntry));

		assertEquals(3, doTestMap(rMap.headMap(2L, true), NavigableMap::firstKey, //
			NavigableMap::firstEntry).longValue());
		assertEquals(3, doTestMap(rMap.headMap(3L, true), NavigableMap::firstKey, //
			NavigableMap::firstEntry).longValue());
		assertNull(doTestMap(rMap.headMap(3L, false), NavigableMap::firstKey, //
			NavigableMap::firstEntry));
		assertNull(doTestMap(rMap.headMap(4L, true), NavigableMap::firstKey, //
			NavigableMap::firstEntry));
	}

	@Test
	public void testAsMapHeadLast() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1, doTestMap(map.headMap(0L, true), NavigableMap::lastKey, //
			NavigableMap::lastEntry).longValue());
		assertEquals(-1, doTestMap(map.headMap(-1L, true), NavigableMap::lastKey, //
			NavigableMap::lastEntry).longValue());
		assertEquals(-3, doTestMap(map.headMap(-1L, false), NavigableMap::lastKey, //
			NavigableMap::lastEntry).longValue());
		assertNull(doTestMap(map.headMap(-4L, true), NavigableMap::lastKey, //
			NavigableMap::lastEntry));

		assertEquals(1, doTestMap(rMap.headMap(0L, true), NavigableMap::lastKey, //
			NavigableMap::lastEntry).longValue());
		assertEquals(1, doTestMap(rMap.headMap(1L, true), NavigableMap::lastKey, //
			NavigableMap::lastEntry).longValue());
		assertEquals(3, doTestMap(rMap.headMap(1L, false), NavigableMap::lastKey, //
			NavigableMap::lastEntry).longValue());
		assertNull(doTestMap(rMap.headMap(4L, true), NavigableMap::lastKey, //
			NavigableMap::lastEntry));
	}

	@Test
	public void testAsMapHeadLower() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1, doTestMap(map.headMap(2L, true), NavigableMap::lowerKey, //
			NavigableMap::lowerEntry, 1L).longValue());
		assertEquals(-1, doTestMap(map.headMap(1L, true), NavigableMap::lowerKey, //
			NavigableMap::lowerEntry, 1L).longValue());
		assertEquals(-1, doTestMap(map.headMap(1L, false), NavigableMap::lowerKey, //
			NavigableMap::lowerEntry, 1L).longValue());
		assertEquals(-1, doTestMap(map.headMap(-1L, true), NavigableMap::lowerKey, //
			NavigableMap::lowerEntry, 1L).longValue());
		assertEquals(-3, doTestMap(map.headMap(-1L, false), NavigableMap::lowerKey, //
			NavigableMap::lowerEntry, 1L).longValue());

		assertEquals(1, doTestMap(rMap.headMap(-2L, true), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, -1L).longValue());
		assertEquals(1, doTestMap(rMap.headMap(-1L, true), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, -1L).longValue());
		assertEquals(1, doTestMap(rMap.headMap(-1L, false), NavigableMap::lowerKey,
			NavigableMap::lowerEntry, -1L).longValue());
		assertEquals(1, doTestMap(rMap.headMap(1L, true), NavigableMap::lowerKey, // 
			NavigableMap::lowerEntry, -1L).longValue());
		assertEquals(3, doTestMap(rMap.headMap(1L, false), NavigableMap::lowerKey, // 
			NavigableMap::lowerEntry, -1L).longValue());
	}

	@Test
	public void testAsMapHeadFloor() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1, doTestMap(map.headMap(2L, true), NavigableMap::floorKey, //
			NavigableMap::floorEntry, 1L).longValue());
		assertEquals(1, doTestMap(map.headMap(1L, true), NavigableMap::floorKey, //
			NavigableMap::floorEntry, 1L).longValue());
		assertEquals(-1, doTestMap(map.headMap(1L, false), NavigableMap::floorKey, //
			NavigableMap::floorEntry, 1L).longValue());
		assertEquals(-3, doTestMap(map.headMap(-1L, false), NavigableMap::floorKey, //
			NavigableMap::floorEntry, 1L).longValue());

		assertEquals(-1, doTestMap(rMap.headMap(-2L, true), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L).longValue());
		assertEquals(-1, doTestMap(rMap.headMap(-1L, true), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L).longValue());
		assertEquals(1, doTestMap(rMap.headMap(-1L, false), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L).longValue());
		assertEquals(3, doTestMap(rMap.headMap(1L, false), NavigableMap::floorKey,
			NavigableMap::floorEntry, -1L).longValue());
	}

	@Test
	public void testAsMapHeadCeiling() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1, doTestMap(map.headMap(2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L).longValue());
		assertEquals(1, doTestMap(map.headMap(1L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L).longValue());
		assertNull(doTestMap(map.headMap(1L, false), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L));
		assertNull(doTestMap(map.headMap(-1L, false), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, 1L));

		assertEquals(-1, doTestMap(rMap.headMap(-2L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L).longValue());
		assertEquals(-1, doTestMap(rMap.headMap(-1L, true), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L).longValue());
		assertNull(doTestMap(rMap.headMap(-1L, false), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L));
		assertNull(doTestMap(rMap.headMap(1L, false), NavigableMap::ceilingKey,
			NavigableMap::ceilingEntry, -1L));
	}

	@Test
	public void testAsMapHeadHigher() {
		populateStore(-3, -1, 1, 3);

		assertEquals(3, doTestMap(map.headMap(3L, true), NavigableMap::higherKey, //
			NavigableMap::higherEntry, 1L).longValue());
		assertNull(doTestMap(map.headMap(1L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, 1L));
		assertNull(doTestMap(map.headMap(1L, false), NavigableMap::higherKey,
			NavigableMap::higherEntry, 1L));
		assertNull(doTestMap(map.headMap(-1L, false), NavigableMap::higherKey,
			NavigableMap::higherEntry, 1L));

		assertEquals(-3, doTestMap(rMap.headMap(-3L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L).longValue());
		assertNull(doTestMap(rMap.headMap(-1L, true), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L));
		assertNull(doTestMap(rMap.headMap(-1L, false), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L));
		assertNull(doTestMap(rMap.headMap(1L, false), NavigableMap::higherKey,
			NavigableMap::higherEntry, -1L));
	}

	@Test
	public void testAsMapSubEntrySet() {
		populateStore(-3, -1, 1, 3);

		List<Long> list = new ArrayList<>(map.subMap(-2L, true, 2L, true)
				.entrySet()
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(-1L, 1L), list);

		List<Long> rList = new ArrayList<>(rMap.subMap(2L, true, -2L, true)
				.entrySet()
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(1L, -1L), rList);
	}

	@Test
	public void testAsMapSubDescendingMap() {
		populateStore(-3, -1, 1, 3);

		List<Long> list = new ArrayList<>(map.subMap(-2L, true, 2L, true).descendingMap().keySet());
		assertEquals(List.of(1L, -1L), list);

		List<Long> rList =
			new ArrayList<>(rMap.subMap(2L, true, -2L, true).descendingMap().keySet());
		assertEquals(List.of(-1L, 1L), rList);
	}

	@Test
	public void testAsMapSubDescendingKeySet() {
		populateStore(-3, -1, 1, 3);

		List<Long> list = new ArrayList<>(map.subMap(-2L, true, 2L, true).descendingKeySet());
		assertEquals(List.of(1L, -1L), list);

		List<Long> rList = new ArrayList<>(rMap.subMap(2L, true, -2L, true).descendingKeySet());
		assertEquals(List.of(-1L, 1L), rList);
	}

	@Test
	public void testAsMapSubSubMap() {
		assertEquals(Range.closed(-2L, 2L),
			map.subMap(-2L, true, 4L, false).subMap(-4L, true, 2L, true).keyRange);
		assertEquals(Range.openClosed(-2L, 2L),
			rMap.subMap(4L, true, -2L, false).subMap(2L, true, -4L, true).keyRange);
	}

	@Test
	public void testAsMapSubHeadMap() {
		assertEquals(Range.closed(-2L, 2L),
			map.subMap(-2L, true, 4L, false).headMap(2L, true).keyRange);
		assertEquals(Range.closed(-2L, 2L),
			rMap.subMap(2L, true, -4L, false).headMap(-2L, true).keyRange);
	}

	@Test
	public void testAsMapSubTailMap() {
		assertEquals(Range.closedOpen(-2L, 2L),
			map.subMap(-4L, true, 2L, false).tailMap(-2L, true).keyRange);
		assertEquals(Range.openClosed(-2L, 2L),
			rMap.subMap(4L, true, -2L, false).tailMap(2L, true).keyRange);
	}

	@Test
	public void testDescendingKeysThreeWays() {
		DBCachedObjectStoreKeySet d1 = map.descendingKeySet();
		DBCachedObjectStoreKeySet d2 = map.descendingMap().keySet();
		DBCachedObjectStoreKeySet d3 = map.keySet().descendingSet();

		assertEquals(store, d1.store);
		assertEquals(store, d2.store);
		assertEquals(store, d3.store);

		assertEquals(Direction.BACKWARD, d1.direction);
		assertEquals(Direction.BACKWARD, d2.direction);
		assertEquals(Direction.BACKWARD, d3.direction);

		assertEquals(Direction.FORWARD, d1.descendingSet().direction);
	}

	@Test
	public void testAsKeySetSize() {
		assertTrue(keySet.isEmpty());
		assertEquals(0, keySet.size());
		try (UndoableTransaction tid = trans()) {
			store.create();
		}
		assertFalse(keySet.isEmpty());
		assertEquals(1, keySet.size());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsKeySetContains() {
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create(0);
			assertFalse(keySet.contains(null));
			assertFalse(keySet.contains("Wrong type"));
			assertTrue(keySet.contains(0L));
			store.delete(obj);
			assertFalse(values.contains(0L));
		}
	}

	@Test
	public void testAsKeySetIterator() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = IteratorUtils.toList(keySet.iterator());
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);

		List<Long> rList = IteratorUtils.toList(rKeySet.iterator());
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
	}

	@Test
	public void testAsKeySetToArray() {
		populateStore(-3, 3, 1, -1);

		List<Object> list = Arrays.asList(keySet.toArray());
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);

		List<Object> rList = Arrays.asList(rKeySet.toArray());
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
	}

	@Test
	public void testAsKeySetToTypedArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = Arrays.asList(keySet.toArray(new Long[0]));
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);
		list = Arrays.asList(keySet.toArray(new Long[4]));
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);
		list = Arrays.asList(keySet.toArray(new Long[5]));
		assertEquals(Arrays.asList(new Long[] { -3L, -1L, 1L, 3L, null }), list);

		List<Long> rList = Arrays.asList(rKeySet.toArray(new Long[0]));
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
		rList = Arrays.asList(rKeySet.toArray(new Long[4]));
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
		rList = Arrays.asList(rKeySet.toArray(new Long[5]));
		assertEquals(Arrays.asList(new Long[] { 3L, 1L, -1L, -3L, null }), rList);
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsKeySetRemove() {
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create(0);
			assertEquals(1, store.getRecordCount());

			assertFalse(keySet.remove(null));
			assertFalse(keySet.remove("Wrong type"));
			assertTrue(keySet.contains(0L));
			assertTrue(keySet.remove(0L));
			assertFalse(store.contains(obj));
			assertEquals(0, store.getRecordCount());
		}
	}

	@Test
	public void testAsKeySetContainsAll() {
		assertTrue(keySet.containsAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create(0);
			store.create(1);
			assertFalse(keySet.containsAll(List.of(0L, 1L, "Wrong type")));
			assertTrue(keySet.containsAll(List.of(0L, 1L)));
			store.delete(obj);
			assertFalse(keySet.containsAll(List.of(0L, 1L)));
			assertTrue(keySet.containsAll(List.of(1L)));
		}
	}

	@Test
	public void testAsKeySetRemoveAll() {
		assertFalse(keySet.removeAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			MyObject obj0 = store.create(0);
			MyObject obj1 = store.create(1);
			assertFalse(keySet.removeAll(List.of()));
			assertTrue(keySet.removeAll(List.of(1L)));
			assertTrue(store.contains(obj0));
			assertFalse(store.contains(obj1));
			assertFalse(keySet.removeAll(List.of(1L)));
		}
	}

	@Test
	public void testAsKeySetRetainAll() {
		assertFalse(keySet.retainAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			MyObject obj0 = store.create(0);
			MyObject obj1 = store.create(1);
			assertFalse(keySet.retainAll(List.of(0L, 1L)));
			assertTrue(keySet.retainAll(List.of(0L)));
			assertTrue(store.contains(obj0));
			assertFalse(store.contains(obj1));
			assertFalse(keySet.retainAll(List.of(0L)));
		}
	}

	@Test
	public void testAsKeySetClear() {
		try (UndoableTransaction tid = trans()) {
			store.create();
			store.create();
			assertEquals(2, store.getRecordCount());
			keySet.clear();
			assertEquals(0, store.getRecordCount());
		}
	}

	@Test
	public void testAsKeySetComparator() {
		assertTrue(keySet.comparator().compare(0L, 1L) < 0);
		assertTrue(rKeySet.comparator().compare(0L, 1L) > 0);
	}

	@Test
	public void testAsKeySetNavigable() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-3, keySet.first().longValue());
		assertEquals(keySet.first(), rKeySet.last());
		assertEquals(3, keySet.last().longValue());
		assertEquals(keySet.last(), rKeySet.first());

		assertEquals(-1, keySet.lower(0L).longValue());
		assertEquals(keySet.lower(0L), rKeySet.higher(0L));
		assertEquals(-1, keySet.lower(1L).longValue());
		assertEquals(keySet.lower(1L), rKeySet.higher(1L));

		assertEquals(-1, keySet.floor(0L).longValue());
		assertEquals(keySet.floor(0L), rKeySet.ceiling(0L));
		assertEquals(1, keySet.floor(1L).longValue());
		assertEquals(keySet.floor(1L), rKeySet.ceiling(1L));

		assertEquals(1, keySet.ceiling(0L).longValue());
		assertEquals(keySet.ceiling(0L), rKeySet.floor(0L));
		assertEquals(1, keySet.ceiling(1L).longValue());
		assertEquals(keySet.ceiling(1L), rKeySet.floor(1L));

		assertEquals(1, keySet.higher(0L).longValue());
		assertEquals(keySet.higher(0L), rKeySet.lower(0L));
		assertEquals(3, keySet.higher(1L).longValue());
		assertEquals(keySet.higher(1L), rKeySet.lower(1L));
	}

	@Test
	public void testAsKeySetDescendingSet() {
		assertEquals(Direction.BACKWARD, keySet.descendingSet().direction);
		assertEquals(Direction.FORWARD, keySet.descendingSet().descendingSet().direction);
	}

	@Test
	public void testAsKeySetDescendingIterator() {
		populateStore(-3, -1, 1, 3);

		assertEquals(List.of(3L, 1L, -1L, -3L), IteratorUtils.toList(keySet.descendingIterator()));
		assertEquals(List.of(-3L, -1L, 1L, 3L), IteratorUtils.toList(rKeySet.descendingIterator()));
	}

	@Test
	public void testAsKeySetSubSet() {
		assertEquals(map.subMap(1L, 2L).keySet().keyRange, keySet.subSet(1L, 2L).keyRange);
		assertEquals(rMap.subMap(2L, 1L).keySet().keyRange, rKeySet.subSet(2L, 1L).keyRange);
		assertEquals(map.subMap(1L, 2L).keySet().direction, keySet.subSet(1L, 2L).direction);
		assertEquals(rMap.subMap(2L, 1L).keySet().direction, rKeySet.subSet(2L, 1L).direction);

		populateStore(-5, -3, -1, 1, 3, 5);

		assertEquals(List.of(-1L, 1L), new ArrayList<>(keySet.subSet(-3L, false, 3L, false)));
		assertEquals(List.of(1L, -1L), new ArrayList<>(rKeySet.subSet(3L, false, -3L, false)));

		assertEquals(List.of(-3L, -1L, 1L), new ArrayList<>(keySet.subSet(-3L, true, 3L, false)));
		assertEquals(List.of(1L, -1L, -3L), new ArrayList<>(rKeySet.subSet(3L, false, -3L, true)));
		assertEquals(List.of(-3L, -1L, 1L), new ArrayList<>(keySet.subSet(-3L, 3L)));

		assertEquals(List.of(-1L, 1L, 3L), new ArrayList<>(keySet.subSet(-3L, false, 3L, true)));
		assertEquals(List.of(3L, 1L, -1L), new ArrayList<>(rKeySet.subSet(3L, true, -3L, false)));
		assertEquals(List.of(3L, 1L, -1L), new ArrayList<>(rKeySet.subSet(3L, -3L)));

		assertEquals(List.of(-3L, -1L, 1L, 3L),
			new ArrayList<>(keySet.subSet(-3L, true, 3L, true)));
		assertEquals(List.of(3L, 1L, -1L, -3L),
			new ArrayList<>(rKeySet.subSet(3L, true, -3L, true)));
	}

	@Test
	public void testAsKeySetHeadSet() {
		assertEquals(map.headMap(1L).keySet().keyRange, keySet.headSet(1L).keyRange);
		assertEquals(rMap.headMap(1L).keySet().keyRange, rKeySet.headSet(1L).keyRange);
		assertEquals(map.headMap(1L).keySet().direction, keySet.headSet(1L).direction);
		assertEquals(rMap.headMap(1L).keySet().direction, rKeySet.headSet(1L).direction);

		populateStore(-5, -3, -1, 1, 3, 5);

		assertEquals(List.of(-5L, -3L), new ArrayList<>(keySet.headSet(-1L, false)));
		assertEquals(List.of(5L, 3L), new ArrayList<>(rKeySet.headSet(1L, false)));

		assertEquals(List.of(-5L, -3L, -1L), new ArrayList<>(keySet.headSet(-1L, true)));
		assertEquals(List.of(5L, 3L, 1L), new ArrayList<>(rKeySet.headSet(1L, true)));

		assertEquals(List.of(-5L, -3L), new ArrayList<>(keySet.headSet(-1L)));
		assertEquals(List.of(5L, 3L), new ArrayList<>(rKeySet.headSet(1L)));
	}

	@Test
	public void testAsKeySetTailSet() {
		assertEquals(map.tailMap(1L).keySet().keyRange, keySet.tailSet(1L).keyRange);
		assertEquals(rMap.tailMap(1L).keySet().keyRange, rKeySet.tailSet(1L).keyRange);
		assertEquals(map.tailMap(1L).keySet().direction, keySet.tailSet(1L).direction);
		assertEquals(rMap.tailMap(1L).keySet().direction, rKeySet.tailSet(1L).direction);

		populateStore(-5, -3, -1, 1, 3, 5);

		assertEquals(List.of(3L, 5L), new ArrayList<>(keySet.tailSet(1L, false)));
		assertEquals(List.of(-3L, -5L), new ArrayList<>(rKeySet.tailSet(-1L, false)));

		assertEquals(List.of(1L, 3L, 5L), new ArrayList<>(keySet.tailSet(1L, true)));
		assertEquals(List.of(-1L, -3L, -5L), new ArrayList<>(rKeySet.tailSet(-1L, true)));

		assertEquals(List.of(1L, 3L, 5L), new ArrayList<>(keySet.tailSet(1L)));
		assertEquals(List.of(-1L, -3L, -5L), new ArrayList<>(rKeySet.tailSet(-1L)));
	}

	@Test
	public void testAsKeySetSubFirst() {
		DBCachedObjectStoreKeySubSet subSet = keySet.subSet(-2L, true, 2L, true);
		assertNull(subSet.first());
		populateStore(-3, -1, 1, 3);
		assertEquals(-1, subSet.first().longValue());
	}

	@Test
	public void testAsKeySetSubLast() {
		DBCachedObjectStoreKeySubSet subSet = keySet.subSet(-2L, true, 2L, true);
		assertNull(subSet.last());
		populateStore(-3, -1, 1, 3);
		assertEquals(1, subSet.last().longValue());
	}

	@Test
	public void testAsKeySetSubSize() {
		populateStore(-3, -1, 1, 3);
		assertEquals(0, keySet.subSet(-2L, true, -2L, false).size());
		assertTrue(keySet.subSet(-2L, true, -2L, false).isEmpty());
		assertEquals(2, keySet.subSet(-2L, true, 2L, true).size());
		assertFalse(keySet.subSet(-2L, true, 2L, true).isEmpty());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsKeySetSubContains() {
		populateStore(-3, -1, 1, 3);
		Set<Long> subSet = keySet.subSet(-2L, true, 2L, true);

		assertFalse(subSet.contains(null));
		assertFalse(subSet.contains("Wrong type"));
		assertFalse(subSet.contains(0L));
		assertFalse(subSet.contains(-3L));
		assertTrue(subSet.contains(1L));
	}

	@Test
	public void testAsKeySetSubToArray() {
		populateStore(-3, 3, 1, -1);

		List<Object> list = Arrays.asList(keySet.subSet(-2L, true, 2L, true).toArray());
		assertEquals(List.of(-1L, 1L), list);

		List<Object> rList = Arrays.asList(rKeySet.subSet(2L, true, -2L, true).toArray());
		assertEquals(List.of(1L, -1L), rList);
	}

	@Test
	public void testAsKeySetSubToTypedArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = Arrays.asList(keySet.subSet(-2L, true, 2L, true).toArray(new Long[0]));
		assertEquals(List.of(-1L, 1L), list);
		list = Arrays.asList(keySet.subSet(-2L, true, 2L, true).toArray(new Long[2]));
		assertEquals(List.of(-1L, 1L), list);
		list = Arrays.asList(keySet.subSet(-2L, true, 2L, true).toArray(new Long[3]));
		assertEquals(Arrays.asList(new Long[] { -1L, 1L, null }), list);

		List<Long> rList = Arrays.asList(rKeySet.subSet(2L, true, -2L, true).toArray(new Long[0]));
		assertEquals(List.of(1L, -1L), rList);
		rList = Arrays.asList(rKeySet.subSet(2L, true, -2L, true).toArray(new Long[2]));
		assertEquals(List.of(1L, -1L), rList);
		rList = Arrays.asList(rKeySet.subSet(2L, true, -2L, true).toArray(new Long[3]));
		assertEquals(Arrays.asList(new Long[] { 1L, -1L, null }), rList);
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsKeySetSubRemove() {
		DBCachedObjectStoreKeySubSet tailSet = keySet.tailSet(0L);
		try (UndoableTransaction tid = trans()) {
			MyObject objN3 = store.create(-3);
			MyObject objP3 = store.create(3);

			assertFalse(tailSet.remove(null));
			assertFalse(tailSet.remove("Wrong type"));
			assertFalse(tailSet.remove(-3L));
			assertTrue(tailSet.remove(3L));
			assertFalse(tailSet.remove(3L));

			assertEquals(1, store.getRecordCount());
			assertFalse(store.contains(objP3));
			assertTrue(store.contains(objN3));
		}
	}

	@Test
	public void testAsKeySetSubContainsAll() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreKeySubSet headSet = keySet.headSet(0L, true);
		assertFalse(headSet.containsAll(List.of(-3L, -1L, "Wrong type")));
		assertTrue(headSet.containsAll(List.of(-3L, -1L)));
		assertFalse(headSet.containsAll(List.of(-3L, -1L, 3L)));
	}

	@Test
	public void testAsKeySetSubRetainAll() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreKeySubSet tailSet = keySet.tailSet(0L, true);

		try (UndoableTransaction tid = trans()) {
			assertFalse(keySet.subSet(0L, 0L).retainAll(List.of()));
			assertFalse(tailSet.retainAll(List.of("Wrong type", 3L, 1L)));
			assertTrue(tailSet.retainAll(List.of("Wrong type", 1L)));
			assertFalse(tailSet.retainAll(List.of("Wrong type", 1L)));
		}

		assertEquals(3, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
		assertTrue(store.containsKey(1));
		assertFalse(store.containsKey(3));
	}

	@Test
	public void testAsKeySetSubRemoveAll() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreKeySubSet tailSet = keySet.tailSet(0L, true);

		try (UndoableTransaction tid = trans()) {
			assertFalse(tailSet.removeAll(List.of("Wrong type", -3L, -1L)));
			assertTrue(tailSet.removeAll(List.of("Wrong type", 3L)));
			assertFalse(tailSet.removeAll(List.of("Wrong type", 3L)));
		}

		assertEquals(3, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
		assertTrue(store.containsKey(1));
		assertFalse(store.containsKey(3));
	}

	@Test
	public void testAsKeySetSubClear() {
		populateStore(-3, -1, 1, 3);

		try (UndoableTransaction tid = trans()) {
			keySet.subSet(0L, 0L).clear(); // NOP
			assertEquals(4, store.getRecordCount());
			keySet.tailSet(0L, true).clear();
		}

		assertEquals(2, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
	}

	@Test
	public void testAsKeySetSubLower() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1, keySet.subSet(-2L, true, 2L, true).lower(1L).longValue());
		assertEquals(-1, keySet.subSet(-2L, true, 1L, true).lower(1L).longValue());
		assertEquals(-1, keySet.subSet(-2L, true, 1L, false).lower(1L).longValue());
		assertNull(keySet.subSet(-2L, true, -1L, false).lower(1L));

		assertEquals(1, rKeySet.subSet(2L, true, -2L, true).lower(-1L).longValue());
		assertEquals(1, rKeySet.subSet(2L, true, -1L, true).lower(-1L).longValue());
		assertEquals(1, rKeySet.subSet(2L, true, -1L, false).lower(-1L).longValue());
		assertNull(rKeySet.subSet(2L, true, 1L, false).lower(-1L));
	}

	@Test
	public void testAsKeySetSubFloor() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1, keySet.subSet(-2L, true, 2L, true).floor(1L).longValue());
		assertEquals(1, keySet.subSet(-2L, true, 1L, true).floor(1L).longValue());
		assertEquals(-1, keySet.subSet(-2L, true, 1L, false).floor(1L).longValue());
		assertNull(keySet.subSet(-2L, true, -1L, false).floor(1L));

		assertEquals(-1, rKeySet.subSet(2L, true, -2L, true).floor(-1L).longValue());
		assertEquals(-1, rKeySet.subSet(2L, true, -1L, true).floor(-1L).longValue());
		assertEquals(1, rKeySet.subSet(2L, true, -1L, false).floor(-1L).longValue());
		assertNull(rKeySet.subSet(2L, true, 1L, false).floor(-1L));
	}

	@Test
	public void testAsKeySetSubCeiling() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1, keySet.subSet(-2L, true, 2L, true).ceiling(-1L).longValue());
		assertEquals(-1, keySet.subSet(-1L, true, 2L, true).ceiling(-1L).longValue());
		assertEquals(1, keySet.subSet(-1L, false, 2L, true).ceiling(-1L).longValue());
		assertNull(keySet.subSet(1L, false, 2L, true).ceiling(-1L));

		assertEquals(1, rKeySet.subSet(2L, true, -2L, true).ceiling(1L).longValue());
		assertEquals(1, rKeySet.subSet(1L, true, -2L, true).ceiling(1L).longValue());
		assertEquals(-1, rKeySet.subSet(1L, false, -2L, true).ceiling(1L).longValue());
		assertNull(rKeySet.subSet(-1L, false, -2L, true).ceiling(1L));
	}

	@Test
	public void testAsKeySetSubHigher() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1, keySet.subSet(-2L, true, 2L, true).higher(-1L).longValue());
		assertEquals(1, keySet.subSet(-1L, true, 2L, true).higher(-1L).longValue());
		assertEquals(1, keySet.subSet(-1L, false, 2L, true).higher(-1L).longValue());
		assertNull(keySet.subSet(1L, false, 2L, true).higher(-1L));

		assertEquals(-1, rKeySet.subSet(2L, true, -2L, true).higher(1L).longValue());
		assertEquals(-1, rKeySet.subSet(1L, true, -2L, true).higher(1L).longValue());
		assertEquals(-1, rKeySet.subSet(1L, false, -2L, true).higher(1L).longValue());
		assertNull(rKeySet.subSet(-1L, false, -2L, true).higher(1L));
	}

	@Test
	public void testAsKeySetSubIterator() {
		populateStore(-3, -1, 1, 3);

		assertTrue(IteratorUtils.toList(keySet.subSet(0L, true, 0L, false).iterator()).isEmpty());

		List<Long> list = IteratorUtils.toList(keySet.tailSet(0L, true).iterator());
		assertEquals(List.of(1L, 3L), list);

		List<Long> rList = IteratorUtils.toList(rKeySet.tailSet(0L, true).iterator());
		assertEquals(List.of(-1L, -3L), rList);
	}

	@Test
	public void testAsKeySetSubDescendingSet() {
		populateStore(-3, -1, 1, 3);

		List<Long> list = new ArrayList<>(keySet.subSet(-2L, true, 2L, true).descendingSet());
		assertEquals(List.of(1L, -1L), list);

		List<Long> rList = new ArrayList<>(rKeySet.subSet(2L, true, -2L, true).descendingSet());
		assertEquals(List.of(-1L, 1L), rList);
	}

	@Test
	public void testAsKeySetSubDescendingIterator() {
		populateStore(-3, -1, 1, 3);

		assertEquals(List.of(1L, -1L),
			IteratorUtils.toList(keySet.subSet(-2L, true, 2L, true).descendingIterator()));
		assertEquals(List.of(-1L, 1L),
			IteratorUtils.toList(rKeySet.subSet(2L, true, -2L, true).descendingIterator()));
	}

	@Test
	public void testAsKeySetSubSubSet() {
		assertEquals(Range.closed(-2L, 2L),
			keySet.subSet(-2L, true, 4L, false).subSet(-4L, true, 2L, true).keyRange);
		assertEquals(Range.openClosed(-2L, 2L),
			rKeySet.subSet(4L, true, -2L, false).subSet(2L, true, -4L, true).keyRange);
	}

	@Test
	public void testAsKeySetSubHeadSet() {
		assertEquals(Range.closed(-2L, 2L),
			keySet.subSet(-2L, true, 4L, false).headSet(2L, true).keyRange);
		assertEquals(Range.closed(-2L, 2L),
			rKeySet.subSet(2L, true, -4L, false).headSet(-2L, true).keyRange);
	}

	@Test
	public void testAsKeySetSubTailSet() {
		assertEquals(Range.closedOpen(-2L, 2L),
			keySet.subSet(-4L, true, 2L, false).tailSet(-2L, true).keyRange);
		assertEquals(Range.openClosed(-2L, 2L),
			rKeySet.subSet(4L, true, -2L, false).tailSet(2L, true).keyRange);
	}

	@Test
	public void testAsValuesSize() {
		assertTrue(values.isEmpty());
		assertEquals(0, values.size());
		try (UndoableTransaction tid = trans()) {
			store.create();
		}
		assertFalse(values.isEmpty());
		assertEquals(1, values.size());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsValuesContains() {
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create();
			assertFalse(values.contains(null));
			assertFalse(values.contains("Wrong type"));
			assertTrue(values.contains(obj));
			store.delete(obj);
			assertFalse(values.contains(obj));
		}
	}

	@Test
	public void testAsValuesIterator() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = IteratorUtils
				.toList(IteratorUtils.transformedIterator(values.iterator(), MyObject::getKey));
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);

		List<Long> rList = IteratorUtils
				.toList(IteratorUtils.transformedIterator(rValues.iterator(), MyObject::getKey));
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
	}

	@Test
	public void testAsValuesToArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = new ArrayList<>(store.getRecordCount());
		for (Object o : values.toArray()) {
			list.add(((MyObject) o).getKey());
		}
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);

		List<Long> rList = new ArrayList<>(store.getRecordCount());
		for (Object o : rValues.toArray()) {
			rList.add(((MyObject) o).getKey());
		}
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
	}

	@Test
	public void testAsValuesToTypedArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = Arrays.asList(values.toArray(new MyObject[0]))
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);
		list = Arrays.asList(values.toArray(new MyObject[4]))
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);
		list = Arrays.asList(values.toArray(new MyObject[5]))
				.stream()
				.map(nullable(MyObject::getKey))
				.collect(Collectors.toList());
		assertEquals(Arrays.asList(new Long[] { -3L, -1L, 1L, 3L, null }), list);

		List<Long> rList = Arrays.asList(rValues.toArray(new MyObject[0]))
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
		rList = Arrays.asList(rValues.toArray(new MyObject[4]))
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
		rList = Arrays.asList(rValues.toArray(new MyObject[5]))
				.stream()
				.map(nullable(MyObject::getKey))
				.collect(Collectors.toList());
		assertEquals(Arrays.asList(new Long[] { 3L, 1L, -1L, -3L, null }), rList);
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsValuesRemove() {
		try (UndoableTransaction tid = trans()) {
			MyObject obj = store.create();
			assertEquals(1, store.getRecordCount());

			assertFalse(values.remove(null));
			assertFalse(values.remove("Wrong type"));
			assertTrue(store.contains(obj));
			assertTrue(values.remove(obj));
			assertFalse(store.contains(obj));
			assertEquals(0, store.getRecordCount());
		}
	}

	@Test
	public void testAsValuesContainsAll() {
		assertTrue(values.containsAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			MyObject obj1 = store.create();
			MyObject obj2 = store.create();
			assertFalse(values.containsAll(List.of(obj1, obj2, "Wrong type")));
			assertTrue(values.containsAll(List.of(obj1, obj2)));
			store.delete(obj1);
			assertFalse(values.containsAll(List.of(obj1, obj2)));
			assertTrue(values.containsAll(List.of(obj2)));
		}
	}

	@Test
	public void testAsValuesRemoveAll() {
		assertFalse(values.removeAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			MyObject obj1 = store.create();
			MyObject obj2 = store.create();
			assertFalse(values.removeAll(List.of()));
			assertTrue(values.removeAll(List.of(obj2)));
			assertTrue(store.contains(obj1));
			assertFalse(store.contains(obj2));
			assertFalse(values.removeAll(List.of(obj2)));
		}
	}

	@Test
	public void testAsValuesRetainAll() {
		assertFalse(values.retainAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			MyObject obj1 = store.create();
			MyObject obj2 = store.create();
			assertFalse(values.retainAll(List.of(obj1, obj2)));
			assertTrue(values.retainAll(List.of(obj1)));
			assertTrue(store.contains(obj1));
			assertFalse(store.contains(obj2));
			assertFalse(values.retainAll(List.of(obj1)));
		}
	}

	@Test
	public void testAsValuesClear() {
		try (UndoableTransaction tid = trans()) {
			store.create();
			store.create();
			assertEquals(2, store.getRecordCount());
			values.clear();
			assertEquals(0, store.getRecordCount());
		}
	}

	@Test
	public void testAsValuesSubSize() {
		populateStore(-3, -1, 1, 3);

		assertEquals(0, map.subMap(0L, true, 0L, false).values().size());
		assertTrue(map.subMap(0L, true, 0L, false).values().isEmpty());

		assertEquals(0, map.subMap(-1L, false, 1L, false).values().size());
		assertTrue(map.subMap(-1L, false, 1L, false).values().isEmpty());

		assertEquals(0, map.headMap(-4L, false).values().size());
		assertTrue(map.headMap(-4L, false).values().isEmpty());

		assertEquals(0, map.tailMap(4L, false).values().size());
		assertTrue(map.tailMap(4L, false).values().isEmpty());

		assertEquals(2, map.subMap(-2L, true, 2L, true).values().size());
		assertFalse(map.subMap(-2L, true, 2L, true).values().isEmpty());

		assertEquals(2, map.headMap(0L, true).values().size());
		assertFalse(map.headMap(0L, true).values().isEmpty());

		assertEquals(2, map.tailMap(0L, true).values().size());
		assertFalse(map.tailMap(0L, true).values().isEmpty());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsValuesSubContains() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreValueSubCollection<MyObject> headValues = map.headMap(0L, true).values();
		assertFalse(headValues.contains(null));
		assertFalse(headValues.contains("Wrong type"));
		MyObject objN3 = store.getObjectAt(-3);
		MyObject objP3 = store.getObjectAt(3);
		assertTrue(headValues.contains(objN3));
		assertFalse(headValues.contains(objP3));
	}

	@Test
	public void testAsValuesSubIterator() {
		populateStore(-3, -1, 1, 3);

		assertTrue(
			IteratorUtils.toList(map.subMap(0L, true, 0L, false).values().iterator()).isEmpty());

		List<Long> list = IteratorUtils.toList(map.tailMap(0L, true).values().iterator())
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(1L, 3L), list);

		List<Long> rList = IteratorUtils.toList(rMap.tailMap(0L, true).values().iterator())
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(-1L, -3L), rList);
	}

	@Test
	public void testAsValuesSubToArray() {
		populateStore(-3, -1, 1, 3);

		assertEquals(0, map.subMap(0L, true, 0L, false).values().toArray().length);

		List<Long> list = new ArrayList<>();
		for (Object o : map.tailMap(0L, true).values().toArray()) {
			list.add(((MyObject) o).getKey());
		}
		assertEquals(List.of(1L, 3L), list);

		List<Long> rList = new ArrayList<>();
		for (Object o : rMap.tailMap(0L, true).values().toArray()) {
			rList.add(((MyObject) o).getKey());
		}
		assertEquals(List.of(-1L, -3L), rList);
	}

	@Test
	public void testAsValuesSubToTypedArray() {
		populateStore(-3, 3, 1, -1);

		assertEquals(0, map.subMap(0L, true, 0L, false).values().toArray(new MyObject[0]).length);

		List<Long> list = Arrays.asList(map.tailMap(0L, true).values().toArray(new MyObject[0]))
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(1L, 3L), list);

		List<Long> rList = Arrays.asList(rMap.tailMap(0L, true).values().toArray(new MyObject[0]))
				.stream()
				.map(MyObject::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(-1L, -3L), rList);
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsValuesSubRemove() {
		DBCachedObjectStoreValueSubCollection<MyObject> tailValues = map.tailMap(0L).values();
		try (UndoableTransaction tid = trans()) {
			MyObject objN3 = store.create(-3);
			MyObject objP3 = store.create(3);

			assertFalse(tailValues.remove(null));
			assertFalse(tailValues.remove("Wrong type"));
			assertFalse(tailValues.remove(objN3));
			assertTrue(tailValues.remove(objP3));
			assertFalse(tailValues.remove(objP3));

			assertEquals(1, store.getRecordCount());
			assertFalse(store.contains(objP3));
			assertTrue(store.contains(objN3));
		}
	}

	@Test
	public void testAsValuesSubContainsAll() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreValueSubCollection<MyObject> headValues = map.headMap(0L, true).values();
		MyObject objN3 = store.getObjectAt(-3);
		MyObject objN1 = store.getObjectAt(-1);
		MyObject objP3 = store.getObjectAt(3);
		assertFalse(headValues.containsAll(List.of(objN3, objN1, "Wrong type")));
		assertTrue(headValues.containsAll(List.of(objN3, objN1)));
		assertFalse(headValues.containsAll(List.of(objN3, objN1, objP3)));
	}

	@Test
	public void testAsValuesSubRemoveAll() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreValueSubCollection<MyObject> tailValues = map.tailMap(0L, true).values();
		MyObject objN3 = store.getObjectAt(-3);
		MyObject objN1 = store.getObjectAt(-1);
		MyObject objP3 = store.getObjectAt(3);

		try (UndoableTransaction tid = trans()) {
			assertFalse(tailValues.removeAll(List.of("Wrong type", objN3, objN1)));
			assertTrue(tailValues.removeAll(List.of("Wrong type", objP3)));
			assertFalse(tailValues.removeAll(List.of("Wrong type", objP3)));
		}

		assertEquals(3, store.getRecordCount());
		assertTrue(store.contains(objN3));
		assertTrue(store.contains(objN1));
		assertNotNull(store.getObjectAt(1));
		assertFalse(store.contains(objP3));
	}

	@Test
	public void testAsValuesSubRetainAll() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreValueSubCollection<MyObject> tailValues = map.tailMap(0L, true).values();
		MyObject objN3 = store.getObjectAt(-3);
		MyObject objP1 = store.getObjectAt(1);
		MyObject objP3 = store.getObjectAt(3);

		try (UndoableTransaction tid = trans()) {
			assertFalse(map.subMap(0L, 0L).values().retainAll(List.of()));
			assertFalse(tailValues.retainAll(List.of("Wrong type", objP3, objP1)));
			assertTrue(tailValues.retainAll(List.of("Wrong type", objP1)));
			assertFalse(tailValues.retainAll(List.of("Wrong type", objP1)));
		}

		assertEquals(3, store.getRecordCount());
		assertTrue(store.contains(objN3));
		assertNotNull(store.getObjectAt(-1));
		assertTrue(store.contains(objP1));
		assertFalse(store.contains(objP3));
	}

	@Test
	public void testAsValuesSubClear() {
		populateStore(-3, -1, 1, 3);

		try (UndoableTransaction tid = trans()) {
			map.subMap(0L, 0L).values().clear(); // NOP
			assertEquals(4, store.getRecordCount());
			map.tailMap(0L, true).values().clear();
		}

		assertEquals(2, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
	}

	protected Entry<Long, MyObject> ent(long k) {
		return ImmutablePair.of(k, null);
	}

	protected Entry<Long, MyObject> ent(MyObject o) {
		return ImmutablePair.of(o.getKey(), o);
	}

	@Test
	public void testAsEntrySetSize() {
		assertTrue(entrySet.isEmpty());
		assertEquals(0, entrySet.size());
		try (UndoableTransaction tid = trans()) {
			store.create();
		}
		assertFalse(entrySet.isEmpty());
		assertEquals(1, entrySet.size());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsEntrySetContains() {
		try (UndoableTransaction tid = trans()) {
			MyObject obj0 = store.create(0);
			MyObject obj1 = store.create(1);
			assertFalse(entrySet.contains(null));
			assertFalse(entrySet.contains("Wrong type"));
			assertFalse(entrySet.contains(ImmutablePair.of("Wrong key type", obj0)));
			assertFalse(entrySet.contains(ImmutablePair.of(0L, "Wrong value type")));
			assertFalse(entrySet.contains(ImmutablePair.of(0L, obj1)));
			assertTrue(entrySet.contains(ImmutablePair.of(0L, obj0)));
			store.delete(obj0);
			assertFalse(values.contains(ImmutablePair.of(0L, obj0)));
		}
	}

	@Test
	public void testAsEntrySetIterator() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = entrySet.stream().map(Entry::getKey).collect(Collectors.toList());
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);

		List<Long> rList = rEntrySet.stream().map(Entry::getKey).collect(Collectors.toList());
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testAsEntrySetToArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = new ArrayList<>(store.getRecordCount());
		for (Object o : entrySet.toArray()) {
			list.add(((Entry<Long, ?>) o).getKey());
		}
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);

		List<Long> rList = new ArrayList<>(store.getRecordCount());
		for (Object o : rEntrySet.toArray()) {
			rList.add(((Entry<Long, ?>) o).getKey());
		}
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Test
	public void testAsEntrySetToTypedArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list =
			((List<Entry<Long, ?>>) (List) Arrays.asList(entrySet.toArray(new Entry[0]))).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList());
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);
		list = ((List<Entry<Long, ?>>) (List) Arrays.asList(entrySet.toArray(new Entry[4])))
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(-3L, -1L, 1L, 3L), list);
		list = ((List<Entry<Long, ?>>) (List) Arrays.asList(entrySet.toArray(new Entry[5])))
				.stream()
				.map(nullable(Entry::getKey))
				.collect(Collectors.toList());
		assertEquals(Arrays.asList(new Long[] { -3L, -1L, 1L, 3L, null }), list);

		List<Long> rList =
			((List<Entry<Long, ?>>) (List) Arrays.asList(rEntrySet.toArray(new Entry[0]))).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList());
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
		rList = ((List<Entry<Long, ?>>) (List) Arrays.asList(rEntrySet.toArray(new Entry[4])))
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(3L, 1L, -1L, -3L), rList);
		rList = ((List<Entry<Long, ?>>) (List) Arrays.asList(rEntrySet.toArray(new Entry[5])))
				.stream()
				.map(nullable(Entry::getKey))
				.collect(Collectors.toList());
		assertEquals(Arrays.asList(new Long[] { 3L, 1L, -1L, -3L, null }), rList);
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsEntrySetRemove() {
		try (UndoableTransaction tid = trans()) {
			MyObject obj0 = store.create(0);
			MyObject obj1 = store.create(1);
			assertEquals(2, store.getRecordCount());

			assertFalse(entrySet.remove(null));
			assertFalse(entrySet.remove("Wrong type"));
			assertFalse(entrySet.remove(ImmutablePair.of("Wrong key type", obj0)));
			assertFalse(entrySet.remove(ImmutablePair.of(0L, "Wrong value type")));
			assertFalse(entrySet.remove(ImmutablePair.of(0L, obj1)));
			assertTrue(entrySet.remove(ImmutablePair.of(0L, obj0)));
			assertFalse(entrySet.remove(ImmutablePair.of(0L, obj0)));

			assertFalse(store.contains(obj0));
			assertEquals(1, store.getRecordCount());
		}
	}

	@Test
	public void testAsEntrySetContainsAll() {
		assertTrue(values.containsAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			Entry<Long, MyObject> ent0 = ent(store.create(0));
			Entry<Long, MyObject> ent1 = ent(store.create(1));
			assertFalse(entrySet.containsAll(List.of(ent0, ent1, "Wrong type")));
			assertTrue(entrySet.containsAll(List.of(ent0, ent1)));
			store.deleteKey(0);
			assertFalse(entrySet.containsAll(List.of(ent0, ent1)));
			assertTrue(entrySet.containsAll(List.of(ent1)));
		}
	}

	@Test
	public void testAsEntrySetRemoveAll() {
		assertFalse(entrySet.removeAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			store.create(0);
			Entry<Long, MyObject> ent1 = ent(store.create(1));
			assertFalse(entrySet.removeAll(List.of()));
			assertTrue(entrySet.removeAll(List.of(ent1)));
			assertTrue(store.containsKey(0));
			assertFalse(store.containsKey(1));
			assertFalse(entrySet.removeAll(List.of(ent1)));
		}
	}

	@Test
	public void testAsEntrySetRetainAll() {
		assertFalse(entrySet.retainAll(List.of()));
		try (UndoableTransaction tid = trans()) {
			Entry<Long, MyObject> ent0 = ent(store.create(0));
			Entry<Long, MyObject> ent1 = ent(store.create(1));
			assertFalse(entrySet.retainAll(List.of(ent0, ent1)));
			assertTrue(entrySet.retainAll(List.of(ent0)));
			assertTrue(store.containsKey(0));
			assertFalse(store.containsKey(1));
			assertFalse(entrySet.retainAll(List.of(ent0)));
		}
	}

	@Test
	public void testAsEntrySetClear() {
		try (UndoableTransaction tid = trans()) {
			store.create();
			store.create();
			assertEquals(2, store.getRecordCount());
			entrySet.clear();
			assertEquals(0, store.getRecordCount());
		}
	}

	@Test
	public void testAsEntrySetNavigable() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-3, entrySet.first().getKey().longValue());
		assertEquals(entrySet.first(), rEntrySet.last());
		assertEquals(3, entrySet.last().getKey().longValue());
		assertEquals(entrySet.last(), rEntrySet.first());

		assertEquals(-1, entrySet.lower(ent(0)).getKey().longValue());
		assertEquals(entrySet.lower(ent(0)), rEntrySet.higher(ent(0)));
		assertEquals(-1, entrySet.lower(ent(1)).getKey().longValue());
		assertEquals(entrySet.lower(ent(1)), rEntrySet.higher(ent(1)));

		assertEquals(-1, entrySet.floor(ent(0)).getKey().longValue());
		assertEquals(entrySet.floor(ent(0)), rEntrySet.ceiling(ent(0)));
		assertEquals(1, entrySet.floor(ent(1)).getKey().longValue());
		assertEquals(entrySet.floor(ent(1)), rEntrySet.ceiling(ent(1)));

		assertEquals(1, entrySet.ceiling(ent(0)).getKey().longValue());
		assertEquals(entrySet.ceiling(ent(0)), rEntrySet.floor(ent(0)));
		assertEquals(1, entrySet.ceiling(ent(1)).getKey().longValue());
		assertEquals(entrySet.ceiling(ent(1)), rEntrySet.floor(ent(1)));

		assertEquals(1, entrySet.higher(ent(0)).getKey().longValue());
		assertEquals(entrySet.higher(ent(0)), rEntrySet.lower(ent(0)));
		assertEquals(3, entrySet.higher(ent(1)).getKey().longValue());
		assertEquals(entrySet.higher(ent(1)), rEntrySet.lower(ent(1)));
	}

	@Test
	public void testAsEntrySetDescendingSet() {
		assertEquals(Direction.BACKWARD, entrySet.descendingSet().direction);
		assertEquals(Direction.FORWARD, entrySet.descendingSet().descendingSet().direction);
	}

	@Test
	public void testAsEntrySetDescendingIterator() {
		populateStore(-3, -1, 1, 3);

		assertEquals(List.of(3L, 1L, -1L, -3L), IteratorUtils.toList(entrySet.descendingIterator())
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(-3L, -1L, 1L, 3L), IteratorUtils.toList(rEntrySet.descendingIterator())
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
	}

	@Test
	public void testAsEntrySetSubSet() {
		assertEquals(map.subMap(1L, 2L).keySet().keyRange,
			entrySet.subSet(ent(1), ent(2)).keyRange);
		assertEquals(rMap.subMap(2L, 1L).keySet().keyRange,
			rEntrySet.subSet(ent(2), ent(1)).keyRange);
		assertEquals(map.subMap(1L, 2L).keySet().direction,
			entrySet.subSet(ent(1), ent(2)).direction);
		assertEquals(rMap.subMap(2L, 1L).keySet().direction,
			rEntrySet.subSet(ent(2), ent(1)).direction);

		populateStore(-5, -3, -1, 1, 3, 5);

		assertEquals(List.of(-1L, 1L),
			new ArrayList<>(entrySet.subSet(ent(-3), false, ent(3), false)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
		assertEquals(List.of(1L, -1L),
			new ArrayList<>(rEntrySet.subSet(ent(3), false, ent(-3), false)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));

		assertEquals(List.of(-3L, -1L, 1L),
			new ArrayList<>(entrySet.subSet(ent(-3), true, ent(3), false)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
		assertEquals(List.of(1L, -1L, -3L),
			new ArrayList<>(rEntrySet.subSet(ent(3), false, ent(-3), true)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
		assertEquals(List.of(-3L, -1L, 1L), new ArrayList<>(entrySet.subSet(ent(-3), ent(3)))
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));

		assertEquals(List.of(-1L, 1L, 3L),
			new ArrayList<>(entrySet.subSet(ent(-3), false, ent(3), true)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
		assertEquals(List.of(3L, 1L, -1L),
			new ArrayList<>(rEntrySet.subSet(ent(3), true, ent(-3), false)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
		assertEquals(List.of(3L, 1L, -1L), new ArrayList<>(rEntrySet.subSet(ent(3), ent(-3)))
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));

		assertEquals(List.of(-3L, -1L, 1L, 3L),
			new ArrayList<>(entrySet.subSet(ent(-3), true, ent(3), true)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
		assertEquals(List.of(3L, 1L, -1L, -3L),
			new ArrayList<>(rEntrySet.subSet(ent(3), true, ent(-3), true)).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
	}

	@Test
	public void testAsEntrySetHeadSet() {
		assertEquals(map.headMap(1L).keySet().keyRange, entrySet.headSet(ent(1)).keyRange);
		assertEquals(rMap.headMap(1L).keySet().keyRange, rEntrySet.headSet(ent(1)).keyRange);
		assertEquals(map.headMap(1L).keySet().direction, entrySet.headSet(ent(1)).direction);
		assertEquals(rMap.headMap(1L).keySet().direction, rEntrySet.headSet(ent(1)).direction);

		populateStore(-5, -3, -1, 1, 3, 5);

		assertEquals(List.of(-5L, -3L), new ArrayList<>(entrySet.headSet(ent(-1), false)).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(5L, 3L), new ArrayList<>(rEntrySet.headSet(ent(1), false)).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));

		assertEquals(List.of(-5L, -3L, -1L), new ArrayList<>(entrySet.headSet(ent(-1), true))
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(5L, 3L, 1L), new ArrayList<>(rEntrySet.headSet(ent(1), true)).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));

		assertEquals(List.of(-5L, -3L), new ArrayList<>(entrySet.headSet(ent(-1))).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(5L, 3L), new ArrayList<>(rEntrySet.headSet(ent(1))).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
	}

	@Test
	public void testAsEntrySetTailSet() {
		assertEquals(map.tailMap(1L).keySet().keyRange, entrySet.tailSet(ent(1)).keyRange);
		assertEquals(rMap.tailMap(1L).keySet().keyRange, rEntrySet.tailSet(ent(1)).keyRange);
		assertEquals(map.tailMap(1L).keySet().direction, entrySet.tailSet(ent(1)).direction);
		assertEquals(rMap.tailMap(1L).keySet().direction, rEntrySet.tailSet(ent(1)).direction);

		populateStore(-5, -3, -1, 1, 3, 5);

		assertEquals(List.of(3L, 5L), new ArrayList<>(entrySet.tailSet(ent(1), false)).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(-3L, -5L), new ArrayList<>(rEntrySet.tailSet(ent(-1), false)).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));

		assertEquals(List.of(1L, 3L, 5L), new ArrayList<>(entrySet.tailSet(ent(1), true)).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(-1L, -3L, -5L), new ArrayList<>(rEntrySet.tailSet(ent(-1), true))
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));

		assertEquals(List.of(1L, 3L, 5L), new ArrayList<>(entrySet.tailSet(ent(1))).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
		assertEquals(List.of(-1L, -3L, -5L), new ArrayList<>(rEntrySet.tailSet(ent(-1))).stream()
				.map(Entry::getKey)
				.collect(Collectors.toList()));
	}

	@Test
	public void testAsEntrySetSubFirst() {
		DBCachedObjectStoreEntrySubSet<MyObject> subSet =
			entrySet.subSet(ent(-2), true, ent(2), true);
		assertNull(subSet.first());
		populateStore(-3, -1, 1, 3);
		assertEquals(-1, subSet.first().getKey().longValue());
	}

	@Test
	public void testAsEntrySetSubLast() {
		DBCachedObjectStoreEntrySubSet<MyObject> subSet =
			entrySet.subSet(ent(-2), true, ent(2), true);
		assertNull(subSet.last());
		populateStore(-3, -1, 1, 3);
		assertEquals(1, subSet.last().getKey().longValue());
	}

	@Test
	public void testAsEntrySetSubSize() {
		populateStore(-3, -1, 1, 3);
		assertEquals(0, entrySet.subSet(ent(-2), true, ent(-2), false).size());
		assertTrue(entrySet.subSet(ent(-2), true, ent(-2), false).isEmpty());
		assertEquals(2, entrySet.subSet(ent(-2), true, ent(2), true).size());
		assertFalse(entrySet.subSet(ent(-2), true, ent(2), true).isEmpty());
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsEntrySetSubContains() {
		populateStore(-3, -1, 1, 3);
		Set<Entry<Long, MyObject>> subSet = entrySet.subSet(ent(-2), true, ent(2), true);

		MyObject objN3 = store.getObjectAt(-3);
		MyObject objP1 = store.getObjectAt(1);

		assertFalse(subSet.contains(null));
		assertFalse(subSet.contains("Wrong type"));
		assertFalse(subSet.contains(ImmutablePair.of("Wrong key type", objN3)));
		assertFalse(subSet.contains(ImmutablePair.of(1L, "Wrong value type")));
		assertFalse(subSet.contains(ImmutablePair.of(0L, objP1))); // absent key
		assertFalse(subSet.contains(ImmutablePair.of(1L, objN3))); // wrong key
		assertFalse(subSet.contains(ImmutablePair.of(-3L, objN3))); // out of range;
		assertTrue(subSet.contains(ImmutablePair.of(1L, objP1)));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testAsEntrySetSubToArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = new ArrayList<>(store.getRecordCount());
		for (Object o : entrySet.subSet(ent(-2), true, ent(2), true).toArray()) {
			list.add(((Entry<Long, ?>) o).getKey());
		}
		assertEquals(List.of(-1L, 1L), list);

		List<Long> rList = new ArrayList<>(store.getRecordCount());
		for (Object o : rEntrySet.subSet(ent(2), true, ent(-2), true).toArray()) {
			rList.add(((Entry<Long, ?>) o).getKey());
		}
		assertEquals(List.of(1L, -1L), rList);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	@Test
	public void testAsEntrySetSubToTypedArray() {
		populateStore(-3, 3, 1, -1);

		List<Long> list = ((List<Entry<Long, ?>>) (List) Arrays
				.asList(entrySet.subSet(ent(-2), true, ent(2), true).toArray(new Entry[0])))
						.stream()
						.map(Entry::getKey)
						.collect(Collectors.toList());
		assertEquals(List.of(-1L, 1L), list);
		list = ((List<Entry<Long, ?>>) (List) Arrays
				.asList(entrySet.subSet(ent(-2), true, ent(2), true).toArray(new Entry[2])))
						.stream()
						.map(Entry::getKey)
						.collect(Collectors.toList());
		assertEquals(List.of(-1L, 1L), list);
		list = ((List<Entry<Long, ?>>) (List) Arrays
				.asList(entrySet.subSet(ent(-2), true, ent(2), true).toArray(new Entry[3])))
						.stream()
						.map(nullable(Entry::getKey))
						.collect(Collectors.toList());
		assertEquals(Arrays.asList(new Long[] { -1L, 1L, null }), list);

		List<Long> rList = ((List<Entry<Long, ?>>) (List) Arrays
				.asList(rEntrySet.subSet(ent(2), true, ent(-2), true).toArray(new Entry[0])))
						.stream()
						.map(Entry::getKey)
						.collect(Collectors.toList());
		assertEquals(List.of(1L, -1L), rList);
		rList = ((List<Entry<Long, ?>>) (List) Arrays
				.asList(rEntrySet.subSet(ent(2), true, ent(-2), true).toArray(new Entry[2])))
						.stream()
						.map(Entry::getKey)
						.collect(Collectors.toList());
		assertEquals(List.of(1L, -1L), rList);
		rList = ((List<Entry<Long, ?>>) (List) Arrays
				.asList(rEntrySet.subSet(ent(2), true, ent(-2), true).toArray(new Entry[3])))
						.stream()
						.map(nullable(Entry::getKey))
						.collect(Collectors.toList());
		assertEquals(Arrays.asList(new Long[] { 1L, -1L, null }), rList);
	}

	@SuppressWarnings("unlikely-arg-type")
	@Test
	public void testAsEntrySetSubRemove() {
		Set<Entry<Long, MyObject>> tailSet = entrySet.tailSet(ent(0));
		try (UndoableTransaction tid = trans()) {
			MyObject objN3 = store.create(-3);
			MyObject objP3 = store.create(3);

			assertFalse(tailSet.remove(null));
			assertFalse(tailSet.remove("Wrong type"));
			assertFalse(tailSet.contains(ImmutablePair.of("Wrong key type", objN3)));
			assertFalse(tailSet.contains(ImmutablePair.of(1L, "Wrong value type")));
			assertFalse(tailSet.contains(ImmutablePair.of(0L, objP3))); // absent key
			assertFalse(tailSet.contains(ImmutablePair.of(1L, objN3))); // wrong key
			assertFalse(tailSet.contains(ImmutablePair.of(-3L, objN3))); // out of range;
			assertTrue(tailSet.remove(ImmutablePair.of(3L, objP3)));
			assertFalse(tailSet.remove(ImmutablePair.of(3L, objP3)));

			assertEquals(1, store.getRecordCount());
			assertFalse(store.contains(objP3));
			assertTrue(store.contains(objN3));
		}
	}

	@Test
	public void testAsEntrySetSubContainsAll() {
		populateStore(-3, -1, 1, 3);

		Entry<Long, MyObject> entN3 = ent(store.getObjectAt(-3));
		Entry<Long, MyObject> entN1 = ent(store.getObjectAt(-1));
		Entry<Long, MyObject> entP3 = ent(store.getObjectAt(3));

		Set<Entry<Long, MyObject>> headSet = entrySet.headSet(ent(0), true);
		assertFalse(headSet.containsAll(List.of(entN3, entN1, "Wrong type")));
		assertTrue(headSet.containsAll(List.of(entN3, entN1)));
		assertFalse(headSet.containsAll(List.of(entN3, entN1, entP3)));
	}

	@Test
	public void testAsEntrySetSubRetainAll() {
		populateStore(-3, -1, 1, 3);

		Set<Entry<Long, MyObject>> tailSet = entrySet.tailSet(ent(0), true);

		Entry<Long, MyObject> entP1 = ent(store.getObjectAt(1));
		Entry<Long, MyObject> entP3 = ent(store.getObjectAt(3));

		try (UndoableTransaction tid = trans()) {
			assertFalse(entrySet.subSet(ent(0), ent(0)).retainAll(List.of()));
			assertFalse(tailSet.retainAll(List.of("Wrong type", entP3, entP1)));
			assertTrue(tailSet.retainAll(List.of("Wrong type", entP1)));
			assertFalse(tailSet.retainAll(List.of("Wrong type", entP1)));
		}

		assertEquals(3, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
		assertTrue(store.containsKey(1));
		assertFalse(store.containsKey(3));
	}

	@Test
	public void testAsEntrySetSubRemoveAll() {
		populateStore(-3, -1, 1, 3);

		DBCachedObjectStoreEntrySubSet<MyObject> tailSet = entrySet.tailSet(ent(0), true);

		Entry<Long, MyObject> entN3 = ent(store.getObjectAt(-3));
		Entry<Long, MyObject> entN1 = ent(store.getObjectAt(-1));
		Entry<Long, MyObject> entP3 = ent(store.getObjectAt(3));

		try (UndoableTransaction tid = trans()) {
			assertFalse(tailSet.removeAll(List.of("Wrong type", entN3, entN1)));
			assertTrue(tailSet.removeAll(List.of("Wrong type", entP3)));
			assertFalse(tailSet.removeAll(List.of("Wrong type", entP3)));
		}

		assertEquals(3, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
		assertTrue(store.containsKey(1));
		assertFalse(store.containsKey(3));
	}

	@Test
	public void testAsEntrySetSubClear() {
		populateStore(-3, -1, 1, 3);

		try (UndoableTransaction tid = trans()) {
			entrySet.subSet(ent(0), ent(0)).clear(); // NOP
			assertEquals(4, store.getRecordCount());
			entrySet.tailSet(ent(0), true).clear();
		}

		assertEquals(2, store.getRecordCount());
		assertTrue(store.containsKey(-3));
		assertTrue(store.containsKey(-1));
	}

	@Test
	public void testAsEntrySetSubLower() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1,
			entrySet.subSet(ent(-2), true, ent(2), true).lower(ent(1)).getKey().longValue());
		assertEquals(-1,
			entrySet.subSet(ent(-2), true, ent(1), true).lower(ent(1)).getKey().longValue());
		assertEquals(-1,
			entrySet.subSet(ent(-2), true, ent(1), false).lower(ent(1)).getKey().longValue());
		assertNull(entrySet.subSet(ent(-2), true, ent(-1), false).lower(ent(1)));

		assertEquals(1,
			rEntrySet.subSet(ent(2), true, ent(-2), true).lower(ent(-1)).getKey().longValue());
		assertEquals(1,
			rEntrySet.subSet(ent(2), true, ent(-1), true).lower(ent(-1)).getKey().longValue());
		assertEquals(1,
			rEntrySet.subSet(ent(2), true, ent(-1), false).lower(ent(-1)).getKey().longValue());
		assertNull(rEntrySet.subSet(ent(2), true, ent(1), false).lower(ent(-1)));
	}

	@Test
	public void testAsEntrySetSubFloor() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1,
			entrySet.subSet(ent(-2), true, ent(2), true).floor(ent(1)).getKey().longValue());
		assertEquals(1,
			entrySet.subSet(ent(-2), true, ent(1), true).floor(ent(1)).getKey().longValue());
		assertEquals(-1,
			entrySet.subSet(ent(-2), true, ent(1), false).floor(ent(1)).getKey().longValue());
		assertNull(entrySet.subSet(ent(-2), true, ent(-1), false).floor(ent(1)));

		assertEquals(-1,
			rEntrySet.subSet(ent(2), true, ent(-2), true).floor(ent(-1)).getKey().longValue());
		assertEquals(-1,
			rEntrySet.subSet(ent(2), true, ent(-1), true).floor(ent(-1)).getKey().longValue());
		assertEquals(1,
			rEntrySet.subSet(ent(2), true, ent(-1), false).floor(ent(-1)).getKey().longValue());
		assertNull(rEntrySet.subSet(ent(2), true, ent(1), false).floor(ent(-1)));
	}

	@Test
	public void testAsEntrySetSubCeiling() {
		populateStore(-3, -1, 1, 3);

		assertEquals(-1,
			entrySet.subSet(ent(-2), true, ent(2), true).ceiling(ent(-1)).getKey().longValue());
		assertEquals(-1,
			entrySet.subSet(ent(-1), true, ent(2), true).ceiling(ent(-1)).getKey().longValue());
		assertEquals(1,
			entrySet.subSet(ent(-1), false, ent(2), true).ceiling(ent(-1)).getKey().longValue());
		assertNull(entrySet.subSet(ent(1), false, ent(2), true).ceiling(ent(-1)));

		assertEquals(1,
			rEntrySet.subSet(ent(2), true, ent(-2), true).ceiling(ent(1)).getKey().longValue());
		assertEquals(1,
			rEntrySet.subSet(ent(1), true, ent(-2), true).ceiling(ent(1)).getKey().longValue());
		assertEquals(-1,
			rEntrySet.subSet(ent(1), false, ent(-2), true).ceiling(ent(1)).getKey().longValue());
		assertNull(rEntrySet.subSet(ent(-1), false, ent(-2), true).ceiling(ent(1)));
	}

	@Test
	public void testAsEntrySetSubHigher() {
		populateStore(-3, -1, 1, 3);

		assertEquals(1,
			entrySet.subSet(ent(-2), true, ent(2), true).higher(ent(-1)).getKey().longValue());
		assertEquals(1,
			entrySet.subSet(ent(-1), true, ent(2), true).higher(ent(-1)).getKey().longValue());
		assertEquals(1,
			entrySet.subSet(ent(-1), false, ent(2), true).higher(ent(-1)).getKey().longValue());
		assertNull(entrySet.subSet(ent(1), false, ent(2), true).higher(ent(-1)));

		assertEquals(-1,
			rEntrySet.subSet(ent(2), true, ent(-2), true).higher(ent(1)).getKey().longValue());
		assertEquals(-1,
			rEntrySet.subSet(ent(1), true, ent(-2), true).higher(ent(1)).getKey().longValue());
		assertEquals(-1,
			rEntrySet.subSet(ent(1), false, ent(-2), true).higher(ent(1)).getKey().longValue());
		assertNull(rEntrySet.subSet(ent(-1), false, ent(-2), true).higher(ent(1)));
	}

	@Test
	public void testAsEntrySetSubIterator() {
		populateStore(-3, -1, 1, 3);

		assertTrue(IteratorUtils.toList(entrySet.subSet(ent(0), true, ent(0), false).iterator())
				.isEmpty());

		List<Long> list = IteratorUtils.toList(entrySet.tailSet(ent(0), true).iterator())
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(1L, 3L), list);

		List<Long> rList = IteratorUtils.toList(rEntrySet.tailSet(ent(0), true).iterator())
				.stream()
				.map(Entry::getKey)
				.collect(Collectors.toList());
		assertEquals(List.of(-1L, -3L), rList);
	}

	@Test
	public void testAsEntrySetSubDescendingSet() {
		populateStore(-3, -1, 1, 3);

		List<Long> list =
			new ArrayList<>(entrySet.subSet(ent(-2), true, ent(2), true).descendingSet()).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList());
		assertEquals(List.of(1L, -1L), list);

		List<Long> rList =
			new ArrayList<>(rEntrySet.subSet(ent(2), true, ent(-2), true).descendingSet()).stream()
					.map(Entry::getKey)
					.collect(Collectors.toList());
		assertEquals(List.of(-1L, 1L), rList);
	}

	@Test
	public void testAsEntrySetSubDescendingIterator() {
		populateStore(-3, -1, 1, 3);

		assertEquals(List.of(1L, -1L),
			IteratorUtils.toList(entrySet.subSet(ent(-2), true, ent(2), true).descendingIterator())
					.stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
		assertEquals(List.of(-1L, 1L),
			IteratorUtils.toList(rEntrySet.subSet(ent(2), true, ent(-2), true).descendingIterator())
					.stream()
					.map(Entry::getKey)
					.collect(Collectors.toList()));
	}

	@Test
	public void testAsEntrySetSubSubSet() {
		assertEquals(Range.closed(-2L, 2L), entrySet.subSet(ent(-2), true, ent(4), false)
				.subSet(ent(-4), true, ent(2), true).keyRange);
		assertEquals(Range.openClosed(-2L, 2L), rEntrySet.subSet(ent(4), true, ent(-2), false)
				.subSet(ent(2), true, ent(-4), true).keyRange);
	}

	@Test
	public void testAsEntrySetSubHeadSet() {
		assertEquals(Range.closed(-2L, 2L),
			entrySet.subSet(ent(-2), true, ent(4), false).headSet(ent(2), true).keyRange);
		assertEquals(Range.closed(-2L, 2L),
			rEntrySet.subSet(ent(2), true, ent(-4), false).headSet(ent(-2), true).keyRange);
	}

	@Test
	public void testAsEntrySetSubTailSet() {
		assertEquals(Range.closedOpen(-2L, 2L),
			entrySet.subSet(ent(-4), true, ent(2), false).tailSet(ent(-2), true).keyRange);
		assertEquals(Range.openClosed(-2L, 2L),
			rEntrySet.subSet(ent(4), true, ent(-2), false).tailSet(ent(2), true).keyRange);
	}

	@Test
	public void testGetIndexBadName() {
		try {
			store.getIndex(Integer.class, "Doesn't exist");
			fail();
		}
		catch (NoSuchElementException e) {
			// pass
		}
	}

	@Test
	public void testGetIndexNonIndexedColumn() {
		try {
			store.getIndex(Long.class, COL1_NAME);
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}
	}

	@Test
	public void testGetIndexWrongType() {
		try {
			store.getIndex(Long.class, COL2_NAME);
			fail();
		}
		catch (IllegalArgumentException e) {
			// pass
		}
	}

	protected DBCachedObjectIndex<Integer, MyObject> populateAndGetIndex() throws IOException {
		try (UndoableTransaction tid = trans()) {
			MyObject obj0 = store.create(0);
			obj0.setF2(10);
			obj0.updated();

			MyObject obj1 = store.create(1);
			obj1.setF2(5);
			obj1.updated();

			MyObject obj2 = store.create(2);
			obj2.setF2(5);
			obj2.updated();
		}
		DBCachedObjectIndex<Integer, MyObject> index = store.getIndex(int.class, COL2_NAME);
		return index;
	}

	@Test
	public void testGetIndexThenIterate() throws IOException {
		DBCachedObjectIndex<Integer, MyObject> index = populateAndGetIndex();

		List<MyObject> list = IterableUtils.toList(index.values());
		assertEquals(5, list.get(0).f2);
		assertEquals(5, list.get(1).f2);
		assertEquals(10, list.get(2).f2);

		List<MyObject> rList = IterableUtils.toList(index.descending().values());
		assertEquals(10, rList.get(0).f2);
		assertEquals(5, rList.get(1).f2);
		assertEquals(5, rList.get(2).f2);
	}

	@Test
	public void testFoundSize() throws IOException {
		DBCachedObjectIndex<Integer, MyObject> index = populateAndGetIndex();

		Collection<MyObject> found5 = index.get(5);
		assertEquals(2, found5.size());
		assertFalse(found5.isEmpty());

		Collection<MyObject> found6 = index.get(6);
		assertEquals(0, found6.size());
		assertTrue(found6.isEmpty());
	}

	@Test
	@SuppressWarnings("unlikely-arg-type")
	public void testFoundContains() throws IOException {
		DBCachedObjectIndex<Integer, MyObject> index = populateAndGetIndex();
		DBCachedObjectStoreFoundKeysValueCollection<MyObject> found5 = index.get(5);

		assertFalse(found5.contains(null));
		assertFalse(found5.contains("Wrong type"));
		assertTrue(found5.contains(store.getObjectAt(1)));
		assertFalse(found5.contains(store.getObjectAt(0)));
	}

	@Test
	public void testFoundIterator() throws IOException {
		DBCachedObjectIndex<Integer, MyObject> index = populateAndGetIndex();
		DBCachedObjectStoreFoundKeysValueCollection<MyObject> found5 = index.get(5);

		assertEquals(Set.of(store.getObjectAt(1), store.getObjectAt(2)),
			new HashSet<>(IteratorUtils.toList(found5.iterator())));
	}

	@Test
	public void testFoundToArray() throws IOException {
		DBCachedObjectIndex<Integer, MyObject> index = populateAndGetIndex();
		DBCachedObjectStoreFoundKeysValueCollection<MyObject> found5 = index.get(5);

		assertEquals(Set.of(store.getObjectAt(1), store.getObjectAt(2)),
			new HashSet<>(Arrays.asList(found5.toArray())));
	}

	@Test
	public void testFoundToTypedArray() throws IOException {
		DBCachedObjectIndex<Integer, MyObject> index = populateAndGetIndex();
		DBCachedObjectStoreFoundKeysValueCollection<MyObject> found5 = index.get(5);

		assertEquals(Set.of(store.getObjectAt(1), store.getObjectAt(2)),
			new HashSet<>(Arrays.asList(found5.toArray(new MyObject[0]))));
		assertEquals(Set.of(store.getObjectAt(1), store.getObjectAt(2)),
			new HashSet<>(Arrays.asList(found5.toArray(new MyObject[2]))));
		assertEquals(
			new HashSet<>(
				Arrays.asList(new MyObject[] { store.getObjectAt(1), store.getObjectAt(2), null })),
			new HashSet<>(Arrays.asList(found5.toArray(new MyObject[3]))));
	}

	@Test
	public void testFoundContainsAll() throws VersionException, IOException {
		DBCachedObjectIndex<Integer, MyObject> index = populateAndGetIndex();
		DBCachedObjectStoreFoundKeysValueCollection<MyObject> found5 = index.get(5);

		assertTrue(found5.containsAll(List.of()));
		assertFalse(found5.containsAll(List.of(store.getObjectAt(1), "Wrong Type")));
		assertTrue(found5.containsAll(List.of(store.getObjectAt(1))));
		assertFalse(found5.containsAll(List.of(store.getObjectAt(1), store.getObjectAt(0))));

		final MyObject altObj1;
		MyDomainObject altDomainObject = new MyDomainObject("Alternative Dummy", 500, 1000, this);
		try (UndoableTransaction tid =
			UndoableTransaction.start(altDomainObject, "Create Obj2", true)) {
			altObj1 = altDomainObject.store.create(1);
		}

		assertFalse(found5.containsAll(List.of(altObj1)));
	}
}
