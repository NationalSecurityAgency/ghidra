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

import static org.junit.Assert.assertEquals;

import java.util.HashMap;

import org.junit.Before;
import org.junit.Test;

import generic.test.AbstractGenericTest;

public class FixedSizeMRUCachingFactoryTest extends AbstractGenericTest {

	public FixedSizeMRUCachingFactoryTest() {
		super();
	}

	private HitCountIdentityFactory<Integer> callCountFactory;

	@Before
	public void setUp() throws Exception {

		callCountFactory = new HitCountIdentityFactory<Integer>();
	}

	@Test
	public void testCacheOfSize1() throws Exception {
		FixedSizeMRUCachingFactory<Integer, Integer> cache =
			new FixedSizeMRUCachingFactory<Integer, Integer>(callCountFactory, 1);

		//
		// Successive calls should only generate a single call count, as the value is cached.
		//		
		assertEquals(0, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(1, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(1, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(1, callCountFactory.calls(0));

		assertEquals(0, callCountFactory.calls(1));
		cache.get(1);
		assertEquals(1, callCountFactory.calls(1));
		cache.get(1);
		assertEquals(1, callCountFactory.calls(1));
		cache.get(1);
		assertEquals(1, callCountFactory.calls(1));

		//
		// The call count should go up for the original value that has since been pushed out of
		// the fixed size cache.
		//
		assertEquals(1, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(2, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(2, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(2, callCountFactory.calls(0));
	}

	@Test
	public void testCacheOfSize2() throws Exception {
		FixedSizeMRUCachingFactory<Integer, Integer> cache =
			new FixedSizeMRUCachingFactory<Integer, Integer>(callCountFactory, 2);
		assertEquals(0, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(1, callCountFactory.calls(0));

		assertEquals(0, callCountFactory.calls(1));
		cache.get(1);
		assertEquals(1, callCountFactory.calls(1));

		// blow out 0 with retrieve of 2
		assertEquals(0, callCountFactory.calls(2));
		cache.get(2);
		assertEquals(1, callCountFactory.calls(2));

		assertEquals(1, callCountFactory.calls(1));
		cache.get(1);
		assertEquals(1, callCountFactory.calls(1));

		// verify miss on 0
		assertEquals(1, callCountFactory.calls(0));
		cache.get(0);
		assertEquals(2, callCountFactory.calls(0));
	}

	@Test
	public void testCacheOfSize3() throws Exception {
		FixedSizeMRUCachingFactory<Integer, Integer> cache =
			new FixedSizeMRUCachingFactory<Integer, Integer>(callCountFactory, 3);

		// force 1 to be the one to fail
		cache.get(1);
		cache.get(0);
		cache.get(2);

		assertEquals(1, callCountFactory.calls(0));
		assertEquals(1, callCountFactory.calls(1));
		assertEquals(1, callCountFactory.calls(2));

		cache.get(3);
		cache.get(0);
		cache.get(2);
		cache.get(1);

		assertEquals(1, callCountFactory.calls(0));
		assertEquals(2, callCountFactory.calls(1));
		assertEquals(1, callCountFactory.calls(2));

		assertEquals(1, callCountFactory.calls(3));
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class HitCountIdentityFactory<K> implements Factory<K, K> {
		private HashMap<K, Integer> callCounter = new HashMap<K, Integer>();

		@Override
		public K get(K key) {
			Integer callCount = callCounter.get(key);
			if (callCount == null) {
				callCount = 0;
			}
			callCounter.put(key, callCount + 1);
			return key;
		}

		int calls(K key) {
			Integer callCount = callCounter.get(key);
			if (callCount == null) {
				callCount = 0;
			}
			return callCount;
		}
	}
}
