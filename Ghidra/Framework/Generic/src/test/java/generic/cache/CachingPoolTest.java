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
package generic.cache;

import static org.junit.Assert.*;

import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class CachingPoolTest extends AbstractGenericTest {

	private static final long TEST_CLEANUP_TIMEOUT = 500;

	private TestBasicFactory factory;
	private CachingPool<TestItem> pool;

	public CachingPoolTest() {
		super();
	}

	@Before
	public void setUp() throws Exception {
		factory = new TestBasicFactory();
		pool = new CachingPool<TestItem>(factory);
	}

	@Test
	public void testCacheCreatesItem() throws Exception {
		assertEquals(0, createdCount());

		TestItem item = pool.get();
		assertNotNull(item);

		pool.release(item);

		TestItem newItem = pool.get();
		assertNotNull(newItem);
		assertSame(item, newItem);
	}

	@Test
	public void testCacheCreatesAndReusesItems() throws Exception {
		assertEquals(0, createdCount());

		TestItem item1 = pool.get();
		TestItem item2 = pool.get();
		TestItem item3 = pool.get();

		assertNotNull(item1);
		assertNotNull(item2);
		assertNotNull(item3);

		pool.release(item2);

		TestItem newItem = pool.get();
		assertNotNull(newItem);
		assertSame(item2, newItem);
	}

	@Test
	public void testCacheDisposesItem() throws Exception {
		pool.setCleanupTimeout(TEST_CLEANUP_TIMEOUT);

		TestItem item1 = pool.get();

		assertFalse(item1.isDisposed());

		pool.release(item1);
		sleep(TEST_CLEANUP_TIMEOUT + (TEST_CLEANUP_TIMEOUT >> 1));

		assertTrue(item1.isDisposed());
	}

	@Test
	public void testCacheDisposesItems() throws Exception {
		pool.setCleanupTimeout(TEST_CLEANUP_TIMEOUT);

		TestItem item1 = pool.get();
		TestItem item2 = pool.get();
		TestItem item3 = pool.get();

		assertFalse(item1.isDisposed());
		assertFalse(item2.isDisposed());
		assertFalse(item3.isDisposed());

		pool.release(item1);
		pool.release(item2);
		pool.release(item3);
		sleep(TEST_CLEANUP_TIMEOUT + (TEST_CLEANUP_TIMEOUT >> 1));

		assertTrue(item1.isDisposed());
		assertTrue(item2.isDisposed());
		assertTrue(item3.isDisposed());
	}

//==================================================================================================
// Private Methods
//==================================================================================================	

	private int createdCount() {
		return factory.list.size();
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private class TestBasicFactory extends CountingBasicFactory<TestItem> {

		private ConcurrentSkipListSet<TestItem> list = new ConcurrentSkipListSet<TestItem>();

		@Override
		public TestItem doCreate(int itemNumber) throws Exception {
			TestItem testItem = new TestItem(itemNumber);
			list.add(testItem);
			return testItem;
		}

		@Override
		public void doDispose(TestItem t) {
			t.dispose();
		}
	}

	private class TestItem implements Comparable<TestItem> {
		private AtomicBoolean disposed = new AtomicBoolean();
		private final int ID;

		TestItem(int ID) {
			this.ID = ID;
		}

		void dispose() {
			disposed.set(true);
		}

		boolean isDisposed() {
			return disposed.get();
		}

		@Override
		public int compareTo(TestItem other) {
			return ID - other.ID;
		}
	}
}
