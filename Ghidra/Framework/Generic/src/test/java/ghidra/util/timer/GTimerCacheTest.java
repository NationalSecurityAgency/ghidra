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
package ghidra.util.timer;

import static org.junit.Assert.*;

import java.time.Duration;
import java.util.Deque;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGTest;

public class GTimerCacheTest extends AbstractGTest {
	private static long KEEP_TIME = 100;
	private static int MAX_SIZE = 4;
	private GTimerCache<String, Integer> cache;
	private Deque<Removed> removed = new ConcurrentLinkedDeque<>();

	@Before
	public void setup() {
		cache = new TestTimerCache();
	}

	@Test
	public void testValueExpiring() {
		cache.put("AAA", 5);
		assertEquals(1, cache.size());
		assertTrue(cache.containsKey("AAA"));

		sleep(KEEP_TIME - 10);
		assertEquals(1, cache.size());
		assertTrue(cache.containsKey("AAA"));
		assertTrue(removed.isEmpty());

		sleep(200);
		assertEquals(0, cache.size());
		assertNull(cache.get("AAA"));
		assertFalse(cache.containsKey("AAA"));
		assertFalse(removed.isEmpty());
		assertEquals(new Removed("AAA", 5), removed.getFirst());
	}

	@Test
	public void testAccessingValueKeepsAliveLonger() {
		cache.put("AAA", 5);
		sleep(KEEP_TIME - 50);
		assertEquals(5, (int) cache.get("AAA"));
		sleep(KEEP_TIME - 10);
		assertEquals(1, cache.size());
		sleep(20);
		assertEquals(0, cache.size());
	}

	@Test
	public void testAccessingValueReordersValues() {
		cache.put("AAA", 5);
		cache.put("BBB", 8);
		cache.get("AAA");
		sleep(KEEP_TIME + 10);
		assertEquals(0, cache.size());
		assertEquals(2, removed.size());
		assertEquals(new Removed("BBB", 8), removed.getFirst());
		assertEquals(new Removed("AAA", 5), removed.getLast());
	}

	@Test
	public void testMaxsize() {
		// max size is 4, so put in 6 and see that the first two are removed (And the "expired"
		// callback is called for them)

		cache.put("A", 1);
		cache.put("B", 2);
		cache.put("C", 3);
		cache.put("D", 4);
		cache.put("E", 5);
		cache.put("F", 6);

		assertEquals(4, cache.size());
		assertEquals(2, removed.size());
		assertEquals(new Removed("A", 1), removed.getFirst());
		assertEquals(new Removed("B", 2), removed.getLast());
	}

	@Test
	public void testRemove() {
		cache.put("A", 1);
		Integer removedValue = cache.remove("A");
		assertEquals(1, (int) removedValue);
		// verify that the expired consumer wasn't called with "A" since we deleted it before the
		// cache expired
		sleep(KEEP_TIME + 10);
		assertEquals(0, cache.size());
		assertEquals(1, removed.size());

	}

	@Test
	public void testRemoveNonExistent() {
		cache.put("A", 1);
		assertNull(cache.remove("B"));
	}

	@Test
	public void testClear() {
		cache.put("A", 1);
		cache.put("B", 2);

		cache.clear();
		assertEquals(2, removed.size());

	}

	@Test
	public void testSetCapacitySmaller() {
		// fill cache to current capacity (4)
		cache.put("A", 1);
		cache.put("B", 2);
		cache.put("C", 3);
		cache.put("D", 4);
		// set cache size to 2 and see that two items are removed
		assertEquals(4, cache.size());
		cache.setCapacity(2);
		assertEquals(2, cache.size());

		assertEquals(2, removed.size());
	}

	@Test
	public void testSetCapacityLarger() {
		// fill cache to current capacity (4)
		cache.put("A", 1);
		cache.put("B", 2);
		cache.put("C", 3);
		cache.put("D", 4);
		// set cache size to 6 and see the cache stays the same
		assertEquals(4, cache.size());
		cache.setCapacity(6);
		assertEquals(4, cache.size());

		assertEquals(0, removed.size());
	}

	@Test
	public void testSetDurationShorterWithTimeStillRemainingOnCachedItem() {
		cache.put("A", 1);
		cache.setDuration(Duration.ofMillis(50));
		sleep(40);
		assertEquals(1, cache.size());
		sleep(15);
		assertEquals(0, cache.size());
	}

	@Test
	public void testSetDurationShorterWithImmediateExpirationOnCachedItem() {
		cache.put("A", 1);
		sleep(50);
		cache.setDuration(Duration.ofMillis(40));
		assertEquals(0, cache.size());
		assertEquals(1, removed.size());
	}

	@Test
	public void testSetDurationLonger() {
		cache.put("A", 1);
		sleep(50);
		cache.setDuration(Duration.ofMillis(150));
		assertEquals(1, cache.size());
		sleep(60);
		assertEquals(1, cache.size());
		sleep(50);
		assertEquals(0, cache.size());
	}

	@Test
	public void testPuttingInNewValueWithSameKeyReportsOldValueAndCallsRemovedCallback() {
		assertNull(cache.put("A", 1));
		assertEquals(1, (int) cache.put("A", 2));
		assertEquals(1, removed.size());
		assertEquals("A", removed.getFirst().key());
		assertEquals(1, removed.getFirst().value());
	}

	@Test
	public void testPuttingInEqualValueWithSameKeyReportsOldValueAndDoesNotCallRemovedCallback() {
		assertNull(cache.put("A", 1));
		assertEquals(1, (int) cache.put("A", 1));
		assertEquals(0, removed.size());
	}

	@Test
	public void testTimerExpiredButShouldRemovedReturnedFalse() {
		cache = new KeepOnceTestTimerCache();
		cache.put("A", 1);
		sleep(110);
		assertEquals(1, cache.size()); // first time expired, the item should remain in cache
		assertEquals(0, removed.size());

		sleep(110);
		assertEquals(0, cache.size());
		assertEquals(1, removed.size());

	}

	class TestTimerCache extends GTimerCache<String, Integer> {

		public TestTimerCache() {
			super(Duration.ofMillis(KEEP_TIME), MAX_SIZE);

		}

		@Override
		protected void valueRemoved(String key, Integer value) {
			removed.add(new Removed(key, value));
		}

	}

	// keeps an item it the cache the first time it is ever called
	class KeepOnceTestTimerCache extends TestTimerCache {
		boolean shouldRemove = false;

		@Override
		protected boolean shouldRemoveFromCache(String key, Integer value) {
			// keeps it around for 1 expiration
			if (shouldRemove) {
				return true;
			}
			shouldRemove = true;
			return false;
		}

	}

	record Removed(String key, int value) {
	}

}
