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
package ghidra.program.database;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import db.*;
import ghidra.program.model.address.KeyRange;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;
import ghidra.util.Lock;

/**
 */
public class ObjectCacheTest extends AbstractGhidraHeadedIntegrationTest {
	private DbCache<TestObj> cache;
	private Lock lock = new Lock("test");
	private Schema schema;
	private Map<Long, DBRecord> database = new HashMap<>();

	@Before
	public void setUp() {
		Field[] fields = { new IntField() };
		String[] fieldNames = { "Value" };

		schema = new Schema(1, "id", fields, fieldNames);
		cache = new DbCache<TestObj>(new TestFactory(), lock, 100);
	}

	@Test
	public void testDeleted() {
		TestObj obj1 = createTestObj(1, 1);
		deleteTestObj(obj1);
		try {
			obj1.setValue(10);
			fail("Should have thrown a concurrent modification excption here.");
		}
		catch (ConcurrentModificationException e) {
			// expected
		}
	}

	@Test
	public void testDeleteFromCacheSetsDeletedOnObject() {
		TestObj obj1 = createTestObj(1, 1);
		cache.delete(1);
		assertFalse(obj1.isValid());

		try {
			obj1.setValue(10);
			fail("Should have thrown a concurrent modification excption here.");
		}
		catch (ConcurrentModificationException e) {
			// expected
		}
	}

	@Test
	public void testDeleteUndoProblem() {
		TestObj obj1 = createTestObj(1, 1);
		deleteTestObj(obj1);
		assertFalse(obj1.refreshIfNeeded());
		assertTrue(obj1.isDeleted(lock));

		TestObj obj2 = createTestObj(1, 1);
		assertTrue(obj1 != obj2);

		obj1.getValue(); // previously, this would have caused obj2 to be removed
						// from the cache, thereby causing obj3 to be a new instance.

		TestObj obj3 = getTestObj(1);
		assertTrue(obj2 == obj3);

	}

	@Test
	public void testDeleteRange() {
		for (int i = 0; i < 10; i++) {
			createTestObj(i, i);
		}
		assertEquals(10, cache.size());
		cache.delete(Arrays.asList(new KeyRange(4, 6)));
		assertEquals(7, cache.size());
	}

	@Test
	public void testDeleteBigRange() {
		for (int i = 0; i < 10; i++) {
			createTestObj(i, i);
		}
		assertEquals(10, cache.size());
		cache.delete(Arrays.asList(new KeyRange(2, 100)));
		assertEquals(2, cache.size());
	}

	@Test
	public void testRefresh() {
		TestObj obj1 = createTestObj(1, 1);
		obj1.setInvalid();
		assertFalse(obj1.isValid());
		assertEquals(1, obj1.getValue());
		assertTrue(obj1.isValid());
	}

	@Test
	public void testInvalideCache() {
		TestObj obj1 = createTestObj(1, 1);
		TestObj obj2 = createTestObj(2, 2);
		TestObj obj3 = createTestObj(3, 3);

		assertTrue(obj1.isValid());
		assertTrue(obj1.isValid());
		assertTrue(obj1.isValid());

		cache.invalidate();

		assertFalse(obj1.isValid());
		assertFalse(obj1.isValid());
		assertFalse(obj1.isValid());

		assertTrue(obj1 == getTestObj(1));
		assertTrue(obj2 == getTestObj(2));
		assertTrue(obj3 == getTestObj(3));

		assertTrue(obj1.isValid());
		assertTrue(obj1.isValid());
		assertTrue(obj1.isValid());
	}

	private TestObj createTestObj(long key, int value) {
		DBRecord record = schema.createRecord(key);
		record.setIntValue(0, value);
		database.put(key, record);
		return cache.getCachedInstance(record);
	}

	private TestObj getTestObj(long key) {
		return cache.getCachedInstance(key);
	}

	private void deleteTestObj(TestObj obj) {
		database.remove(obj.getKey());
		obj.setInvalid();
	}

	class TestFactory implements DbFactory<TestObj> {

		@Override
		public TestObj instantiate(long key) {
			DBRecord record = database.get(key);
			return instantiate(record);
		}

		@Override
		public TestObj instantiate(DBRecord record) {
			return new TestObj(record);
		}

	}

	class TestObj extends DbObject {
		private DBRecord record;

		TestObj(DBRecord record) {
			super(record.getKey());
			this.record = record;
		}

		public void setValue(int value) {
			checkDeleted();
			record.setIntValue(0, value);
		}

		public int getValue() {
			refreshIfNeeded();
			return record.getIntValue(0);
		}

		@Override
		protected boolean refresh() {
			DBRecord refreshedRecord = database.get(record.getKey());
			if (refreshedRecord != null) {
				record = refreshedRecord;
				return true;
			}
			return false;
		}

	}
}
