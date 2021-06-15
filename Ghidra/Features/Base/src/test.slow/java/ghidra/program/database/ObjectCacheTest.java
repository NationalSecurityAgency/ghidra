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
/*
 *
 */
package ghidra.program.database;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.ConcurrentModificationException;

import org.junit.Test;

import ghidra.program.database.DBObjectCache;
import ghidra.program.database.DatabaseObject;
import ghidra.program.model.address.KeyRange;
import ghidra.test.AbstractGhidraHeadedIntegrationTest;

/**
 */
public class ObjectCacheTest extends AbstractGhidraHeadedIntegrationTest {
	private DBObjectCache<TestObj> cache = new DBObjectCache<TestObj>(100);

	/**
	 * Constructor for ObjectCacheTest.
	 * @param arg0
	 */
	public ObjectCacheTest() {
		super();
	}

	@Test
	public void testSetInvalid() {
		TestObj obj1 = getTestObj(1);
		obj1.setInvalid();
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
		TestObj obj1 = getTestObj(1);
		cache.delete(1);
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
		TestObj obj1 = getTestObj(1);
		obj1.setInvalid();
		obj1.checkIsValid();

		TestObj obj2 = getTestObj(1);
		assertTrue(obj1 != obj2);

		obj1.getValue(); // previously, this would have caused obj2 to be removed
						// from the cache, thereby causing obj3 to be a new instance.

		TestObj obj3 = getTestObj(1);
		assertTrue(obj2 == obj3);

	}

	@Test
	public void testDeleteRange() {
		for (int i = 0; i < 10; i++) {
			getTestObj(i);
		}
		assertEquals(10, cache.size());
		cache.delete(Arrays.asList(new KeyRange(4, 6)));
		assertEquals(7, cache.size());
	}

	@Test
	public void testDeleteBigRange() {
		for (int i = 0; i < 10; i++) {
			getTestObj(i);
		}
		assertEquals(10, cache.size());
		cache.delete(Arrays.asList(new KeyRange(2, 100)));
		assertEquals(2, cache.size());
	}

	private TestObj getTestObj(int key) {
		TestObj obj = cache.get(key);
		if (obj == null) {
			obj = new TestObj(cache, key);
		}
		return obj;
	}
}

class TestObj extends DatabaseObject {
	int value = -1;

	TestObj(DBObjectCache<TestObj> cache, long key) {
		super(cache, key);
	}

	public void setValue(int value) {
		checkDeleted();
		this.value = value;
	}

	public int getValue() {
		checkIsValid();
		return value;
	}

	@Override
	protected boolean refresh() {
		// return false to simulate the record has been deleted
		return false;
	}

}
