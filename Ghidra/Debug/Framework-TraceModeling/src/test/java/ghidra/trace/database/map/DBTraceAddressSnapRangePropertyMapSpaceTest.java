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

import static ghidra.lifecycle.Unfinished.TODO;
import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.Map.Entry;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.junit.*;

import db.DBHandle;
import db.DBRecord;
import ghidra.lifecycle.Unfinished;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.util.DefaultLanguageService;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.TraceAddressSnapRange;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.annot.*;
import ghidra.util.database.spatial.SpatialMap;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.ConsoleTaskMonitor;

/**
 * TODO: Many of the features are tested indirectly through other manager tests. Those tests should
 * be applied here generically. Also, there are some classes which need test cases broken out for
 * them. The placeholder methods will become many actual test methods.
 *
 */
public class DBTraceAddressSnapRangePropertyMapSpaceTest
		extends AbstractGhidraHeadlessIntegrationTest implements Unfinished {
	protected static class MyObject extends DBCachedDomainObjectAdapter implements AutoCloseable {
		private final DBCachedObjectStoreFactory factory;
		private final Language toy;
		private DBTraceAddressSnapRangePropertyMapSpace<MyEntry, MyEntry> space1;
		private DBTraceAddressSnapRangePropertyMapSpace<MyEntry, MyEntry> space2;
		private DBTraceAddressSnapRangePropertyMapSpace<String, AltEntry> space3;

		protected MyObject(DBHandle dbh, DBOpenMode openMode, Language toy, Object consumer)
				throws VersionException, IOException {
			super(dbh, openMode, new ConsoleTaskMonitor(), "Testing", 500, 1000, consumer);
			this.toy = toy;
			this.factory = new DBCachedObjectStoreFactory(this);
			loadSpaces();
		}

		protected MyObject(Language toy, Object consumer) throws IOException, VersionException {
			this(new DBHandle(), DBOpenMode.CREATE, toy, consumer);
		}

		protected MyObject(File file, Language toy, Object consumer)
				throws IOException, VersionException {
			this(new DBHandle(file), DBOpenMode.UPDATE, toy, consumer);
		}

		protected void loadSpaces() throws VersionException, IOException {
			try (UndoableTransaction tid = UndoableTransaction.start(this, "Create Tables", true)) {
				this.space1 = new DBTraceAddressSnapRangePropertyMapSpace<>("Entries1", factory,
					getReadWriteLock(), toy.getDefaultSpace(), MyEntry.class, MyEntry::new);
				this.space2 = new DBTraceAddressSnapRangePropertyMapSpace<>("Entries2", factory,
					getReadWriteLock(), toy.getDefaultSpace(), MyEntry.class, MyEntry::new);
				this.space3 = new DBTraceAddressSnapRangePropertyMapSpace<>("Entries3", factory,
					getReadWriteLock(), toy.getDefaultSpace(), AltEntry.class, AltEntry::new);
			}
		}

		@Override
		public boolean isChangeable() {
			return true;
		}

		@Override
		public String getDescription() {
			return "Testing";
		}

		@Override
		public void close() {
			super.close();
		}

		@Override
		protected void clearCache(boolean all) {
			try (LockHold hold = LockHold.lock(rwLock.writeLock())) {
				// TODO: Should each space have an invalidateCache method?
				super.clearCache(all);
				try {
					loadSpaces();
				}
				catch (VersionException | IOException e) {
					throw new AssertionError(e);
				}
			}
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static class MyEntry extends AbstractDBTraceAddressSnapRangePropertyMapData<MyEntry> {

		public static final String NAME_COLUMN_NAME = "Name";

		@DBAnnotatedColumn(NAME_COLUMN_NAME)
		static DBObjectColumn NAME_COLUMN;

		@DBAnnotatedField(column = NAME_COLUMN_NAME, indexed = true)
		String name;

		public MyEntry(DBTraceAddressSnapRangePropertyMapTree<MyEntry, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(MyEntry value) {
			// Nothing: record is value
		}

		@Override
		protected MyEntry getRecordValue() {
			return this;
		}

		public void setName(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static class AltEntry extends AbstractDBTraceAddressSnapRangePropertyMapData<String> {

		public static final String VALUE_COLUMN_NAME = "Value";

		@DBAnnotatedColumn(VALUE_COLUMN_NAME)
		static DBObjectColumn VALUE_COLUMN;

		@DBAnnotatedField(column = VALUE_COLUMN_NAME)
		String value;

		public AltEntry(DBTraceAddressSnapRangePropertyMapTree<String, ?> tree,
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
	protected Language toy;

	protected Address addr(long offset) {
		return toy.getDefaultSpace().getAddress(offset);
	}

	protected TraceAddressSnapRange at(long offset, long snap) {
		return new ImmutableTraceAddressSnapRange(addr(offset), snap);
	}

	protected <T> Entry<TraceAddressSnapRange, T> ent(long offset, long snap, T value) {
		return new ImmutablePair<>(at(offset, snap), value);
	}

	protected <T> List<T> list(Collection<T> col) {
		return new ArrayList<>(col);
	}

	protected <T> Set<T> set(Collection<T> col) {
		return new HashSet<>(col);
	}

	@Before
	public void setUp() throws IOException, VersionException {
		toy = DefaultLanguageService.getLanguageService()
				.getLanguage(
					new LanguageID("Toy:BE:64:default"));
		obj = new MyObject(toy, this);
	}

	@After
	public void tearDown() {
		obj.release(this);
	}

	@Test
	public void testGetAddressSpace() {
		assertEquals(toy.getDefaultSpace(), obj.space1.getAddressSpace());
	}

	@Test
	public void testGetThread() {
		assertNull(obj.space1.getThread());
	}

	@Test
	public void testGetUserIndex() {
		assertNotNull(obj.space1.getUserIndex(String.class, MyEntry.NAME_COLUMN));
	}

	@Test
	public void testDeleteValue() {
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			MyEntry entry1 = obj.space1.put(at(0x1000, 5), null);
			MyEntry entry2 = obj.space2.put(at(0x1001, 5), null);
			String value3 = obj.space3.put(at(0x1002, 5), "Test");

			assertEquals(1, obj.space1.size());
			obj.space1.deleteValue(entry1);
			assertEquals(0, obj.space1.size());
			assertTrue(obj.space1.isEmpty());
			assertTrue(entry1.isDeleted());

			try {
				obj.space1.deleteValue(entry2);
				fail();
			}
			catch (IllegalArgumentException e) {
				// pass
			}

			try {
				obj.space3.deleteValue(value3);
				fail();
			}
			catch (UnsupportedOperationException e) {
				// pass
			}
		}
	}

	@Test
	@Ignore("TODO")
	public void testRemove() {
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			obj.space1.put(at(0x1000, 5), null);
			obj.space2.put(at(0x1000, 5), null);
			assertEquals(1, obj.space1.size());
			assertEquals(1, obj.space2.size());

			Entry<TraceAddressSnapRange, MyEntry> entry1 =
				obj.space1.reduce(TraceAddressSnapRangeQuery.at(addr(0x1000), 5)).firstEntry();
			assertNotNull(entry1);

			assertTrue(obj.space1.remove(entry1));
			assertTrue(obj.space1.isEmpty());
			assertTrue(entry1.getValue().isDeleted());
			assertTrue(obj.space2.remove(entry1)); // TODO: Should match by shape?
			TODO();
			assertTrue(obj.space2.isEmpty());

			MyEntry value = obj.space1.put(at(0x1000, 5), null);
			assertEquals(1, obj.space1.size());
			assertTrue(obj.space1.remove(at(0x1000, 5), value));
			assertTrue(obj.space1.isEmpty());
		}
	}

	@Test
	public void testSize() throws VersionException, IOException {
		assertEquals(0, obj.space1.size());
		assertTrue(obj.space1.isEmpty());

		SpatialMap<TraceAddressSnapRange, MyEntry, TraceAddressSnapRangeQuery> reduced =
			obj.space1.reduce(
				TraceAddressSnapRangeQuery.intersecting(addr(0x4000), addr(0x4fff), 0, 1000));
		assertEquals(0, reduced.size());
		assertTrue(reduced.isEmpty());
	}

	@Test
	public void testCollections() {
		MyEntry entry1;
		MyEntry entry2;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			entry1 = obj.space1.put(new ImmutableTraceAddressSnapRange(addr(0x1000), 5), null);
			entry2 = obj.space1.put(new ImmutableTraceAddressSnapRange(addr(0x1001), 6), null);
		}

		// NOTE: Default ordering is LEFTMOST first
		assertEquals(Set.of(ent(0x1000, 5, entry1), ent(0x1001, 6, entry2)),
			set(obj.space1.entries()));
		assertEquals(List.of(ent(0x1000, 5, entry1), ent(0x1001, 6, entry2)),
			list(obj.space1.orderedEntries()));

		assertEquals(Set.of(at(0x1000, 5), at(0x1001, 6)), set(obj.space1.keys()));
		assertEquals(List.of(at(0x1000, 5), at(0x1001, 6)), list(obj.space1.orderedKeys()));

		assertEquals(Set.of(entry1, entry2), set(obj.space1.values()));
		assertEquals(List.of(entry1, entry2), list(obj.space1.orderedValues()));
	}

	@Test
	public void testReduce() {
		MyEntry ent1;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			ent1 = obj.space1.put(at(0x1000, 5), null);
		}

		Entry<TraceAddressSnapRange, MyEntry> entry1 =
			obj.space1.reduce(TraceAddressSnapRangeQuery.at(addr(0x1000), 5)).firstEntry();
		assertEquals(at(0x1000, 5), entry1.getKey());
		assertEquals(ent1, entry1.getValue());
	}

	@Test
	public void testFirsts() {
		MyEntry entry1;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			entry1 = obj.space1.put(new ImmutableTraceAddressSnapRange(addr(0x1000), 5), null);
		}

		assertEquals(ent(0x1000, 5, entry1), obj.space1.firstEntry());
		assertEquals(at(0x1000, 5), obj.space1.firstKey());
		assertEquals(entry1, obj.space1.firstValue());
	}

	@Test
	public void testClear() {
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			MyEntry entry1 =
				obj.space1.put(new ImmutableTraceAddressSnapRange(addr(0x1000), 5), null);
			assertEquals(1, obj.space1.size());
			assertFalse(entry1.isDeleted());

			obj.space1.clear();
			assertTrue(entry1.isDeleted());
			assertTrue(obj.space1.isEmpty());
		}
	}

	@Test
	public void testGetDataByKey() {
		assertNull(obj.space1.getDataByKey(0));
		MyEntry entry1;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			entry1 = obj.space1.put(new ImmutableTraceAddressSnapRange(addr(0x1000), 5), null);
		}

		assertEquals(0, entry1.getKey());
		assertEquals(entry1, obj.space1.getDataByKey(0));
	}

	@Test
	@Ignore("TODO")
	public void testSaveAndLoad() throws IOException, CancelledException, VersionException {
		MyEntry entry1;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			entry1 = obj.space1.put(new ImmutableTraceAddressSnapRange(addr(0x1000), 5), null);
		}
		assertEquals(ent(0x1000, 5, entry1), obj.space1.firstEntry());

		Path tmp = Files.createTempFile("test", ".db");
		Files.delete(tmp); // saveAs must create the file
		obj.getDBHandle().saveAs(tmp.toFile(), false, new ConsoleTaskMonitor());

		try (MyObject rst = new MyObject(tmp.toFile(), toy, this)) {
			assertEquals(ent(0x1000, 5, entry1), rst.space1.firstEntry());
			TODO(); // Probably fails because entry1 is not considered equal
		}
	}

	@Test
	@Ignore("Related to GP-479")
	public void testUndoThenRedo() throws IOException {
		MyEntry entry1;
		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Create entries", true)) {
			entry1 = obj.space1.put(new ImmutableTraceAddressSnapRange(addr(0x1000), 5), null);
		}
		assertEquals(ent(0x1000, 5, entry1), obj.space1.firstEntry());

		try (UndoableTransaction tid = UndoableTransaction.start(obj, "Clear", true)) {
			obj.space1.clear();
		}
		assertNull(obj.space1.firstEntry());

		obj.undo();

		assertEquals(ent(0x1000, 5, entry1), obj.space1.firstEntry());
	}
}
