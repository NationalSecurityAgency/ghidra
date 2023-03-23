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
package ghidra.app.plugin.core.functiongraph.mvc;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;

import com.google.common.cache.*;

import ghidra.app.plugin.core.functiongraph.AbstractFunctionGraphTest;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class FunctionGraphCacheTest extends AbstractFunctionGraphTest {
	private Cache<Function, FGData> cache;
	private List<Address> disposedFunctionData = Collections.synchronizedList(new ArrayList<>());
	private List<Address> evictedFromCache = Collections.synchronizedList(new ArrayList<>());

	@Override
	@Before
	public void setUp() throws Exception {
		super.setUp();

		FGController controller = getFunctionGraphController();

		// go to an function address that is not used by this test (all tests use functions 0-2)
		goToAddress(functionAddrs.get(3));
		controller.clear();
		waitForSwing();

		RemovalListener<Function, FGData> listener = controller::cacheValueRemoved;

		//@formatter:off
		cache = CacheBuilder
			.newBuilder()
			.maximumSize(3)
			.removalListener(listener)
			.recordStats()
			.build()
			;
		//@formatter:on

		controller.setCache(cache);
		controller.setFGDataDisposedListener((data, evicted) -> {
			Function function = data.getFunction();
			if (function == null) {
				return;
			}
			Address address = data.getFunction().getEntryPoint();
			disposedFunctionData.add(address);
			if (evicted) {
				evictedFromCache.add(address);
			}
		});

		goToAddress(getStartingAddress());
	}

	@Test
	public void testNewFunctionIsCacheMiss() {
		goToAddress(functionAddrs.get(0));
		CacheStats stats1 = cache.stats();

		goToAddress(functionAddrs.get(1));
		CacheStats stats2 = cache.stats();

		assertEquals("Expected missCount to increment", stats1.missCount() + 1, stats2.missCount());
	}

	@Test
	public void testBackToOldFunctionIsCacheHit() {

		goToAddress(functionAddrs.get(0));
		goToAddress(functionAddrs.get(1));
		CacheStats stats1 = cache.stats();
		goToAddress(functionAddrs.get(0));
		CacheStats stats2 = cache.stats();

		assertEquals("Expected missCount to stay the same", stats1.missCount(), stats2.missCount());
	}

	@Test
	public void testCallbackWhenEvicted() {
		goToAddress(functionAddrs.get(0));
		goToAddress(functionAddrs.get(1));
		goToAddress(functionAddrs.get(2));
		goToAddress(functionAddrs.get(3));

		assertEquals(1, evictedFromCache.size()); // cache size is 3, so 4th access should remove first function
		assertEquals(getAddress(functionAddrs.get(0)), evictedFromCache.get(0));
		assertEquals(1, disposedFunctionData.size());
		assertEquals(getAddress(functionAddrs.get(0)), disposedFunctionData.get(0));
	}

	@Test
	public void testCacheHitDoesntDisposeCurrentFunction() {
		goToAddress(functionAddrs.get(0));
		goToAddress(functionAddrs.get(1));
		goToAddress(functionAddrs.get(0));

		assertEquals(0, evictedFromCache.size());
		assertEquals(0, disposedFunctionData.size());

	}

	@Test
	public void testForcedEvictionDisposesAllExceptCurrentFunction() {
		goToAddress(functionAddrs.get(0));
		goToAddress(functionAddrs.get(1));
		goToAddress(functionAddrs.get(2));
		assertEquals(3, cache.size());

		cache.invalidateAll();

		assertEquals(2, evictedFromCache.size());
		assertEquals(2, disposedFunctionData.size());
		assertTrue(disposedFunctionData.contains(getAddress(functionAddrs.get(0))));
		assertTrue(disposedFunctionData.contains(getAddress(functionAddrs.get(1))));
		assertTrue(!disposedFunctionData.contains(getAddress(functionAddrs.get(2))));
	}

}
