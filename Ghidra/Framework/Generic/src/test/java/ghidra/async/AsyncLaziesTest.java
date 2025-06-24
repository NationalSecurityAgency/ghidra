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
package ghidra.async;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.collections4.map.LazyMap;
import org.junit.Test;

public class AsyncLaziesTest {
	@Test
	public void testLazyValueAskTwice() {
		AtomicInteger calls = new AtomicInteger();
		CompletableFuture<String> future = new CompletableFuture<>();
		AsyncLazyValue<String> lazy = new AsyncLazyValue<>(() -> {
			calls.incrementAndGet();
			return future;
		});
		CompletableFuture<String> lazyReq1 = lazy.request();
		assertEquals(future, lazyReq1);
		CompletableFuture<String> lazyReq2 = lazy.request();
		assertEquals(future, lazyReq2);

		assertEquals(1, calls.get());
	}

	@Test
	public void testLazyMapAskTwice() {
		Map<String, AtomicInteger> calls =
			LazyMap.lazyMap(new HashMap<>(), () -> new AtomicInteger());
		Map<String, CompletableFuture<Integer>> reqs = new HashMap<>();
		AsyncLazyMap<String, Integer> lazyMap = new AsyncLazyMap<>(new HashMap<>(), (key) -> {
			CompletableFuture<Integer> req = new CompletableFuture<>();
			reqs.put(key, req);
			calls.get(key).incrementAndGet();
			return req;
		});

		CompletableFuture<Integer> req1a = lazyMap.get("One");
		CompletableFuture<Integer> req1b = lazyMap.get("One");
		CompletableFuture<Integer> req2a = lazyMap.get("Two");
		CompletableFuture<Integer> req2b = lazyMap.get("Two");

		assertEquals(req1a, req1b);
		assertEquals(req2a, req2b);

		assertEquals(1, calls.get("One").get());
		assertEquals(1, calls.get("Two").get());
		assertEquals(2, calls.size());
	}

	@Test
	public void testLazyMapCompletedMap() throws Exception {
		Map<String, CompletableFuture<Integer>> reqs = new HashMap<>();
		AsyncLazyMap<String, Integer> lazyMap = new AsyncLazyMap<>(new HashMap<>(), (key) -> {
			CompletableFuture<Integer> req = new CompletableFuture<>();
			reqs.put(key, req);
			return req;
		});

		CompletableFuture<Integer> req1 = lazyMap.get("One");

		assertEquals(Map.of(), lazyMap.getCompletedMap());

		reqs.get("One").complete(1);
		assertEquals(1, req1.get(1000, TimeUnit.MILLISECONDS).intValue());

		assertEquals(Map.of("One", 1), lazyMap.getCompletedMap());
	}

	@Test
	public void testLazyMapPut() throws InterruptedException, ExecutionException, TimeoutException {
		Map<String, CompletableFuture<Integer>> reqs = new HashMap<>();
		AsyncLazyMap<String, Integer> lazyMap = new AsyncLazyMap<>(new HashMap<>(), (key) -> {
			CompletableFuture<Integer> req = new CompletableFuture<>();
			reqs.put(key, req);
			return req;
		});

		CompletableFuture<Integer> req1 = lazyMap.get("One");

		AtomicInteger val1 = new AtomicInteger(0);
		req1.thenAccept(val1::set);

		assertEquals(0, val1.get());

		lazyMap.put("One", 1);
		assertEquals(1, req1.get(1000, TimeUnit.MILLISECONDS).intValue());
		assertEquals(1, val1.get());
	}
}
