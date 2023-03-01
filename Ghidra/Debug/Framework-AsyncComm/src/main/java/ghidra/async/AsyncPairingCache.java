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

import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.function.Function;

/**
 * A cache of futures which pairs each to its result by key
 * 
 * <p>
 * The cache accepts promises and results, storing unpaired entries for a timeout period. Each
 * promise is fulfilled when the cache accepts its corresponding result, determined by key.
 * Conversely, a cached result fulfills its corresponding promise, determined by key, when the cache
 * accepts that promise. Thus, the cache is two sided. When both the promise and the result for a
 * given key enter the cache, they are paired, the promise is fulfilled, and both are removed from
 * the cache.
 * 
 * <p>
 * If an entry is not paired within the timeout period, it is evicted. An evicted promise is likely
 * a recoverable error, e.g., a request timed out. An evicted result is likely a logic or
 * synchronization error. Requests, i.e., promises, are usually created before the result is
 * obtained. A result may enter the cache first due to variance in execution order, but the promise
 * usually enters soon after. If not, more than likely, the developer forgot to enter the request
 * into the cache, or if the result was reported out of band, it is gratuitous. Callbacks are
 * provided for eviction from either side of the cache.
 * 
 * @param <K> the type of keys
 * @param <V> the type of result values
 */
public abstract class AsyncPairingCache<K, V> {
	private final Map<K, V> results;
	private final Map<K, V> resultsView;

	private final Map<K, CompletableFuture<V>> promises;
	private final Map<K, CompletableFuture<V>> promisesView;

	/**
	 * Construct a new matching cache
	 * 
	 * @param maxPending the maximum number of pending promises or results before the eldest is
	 *            evicted. Each is counted independently, e.g., a value of 5 permits 5 pending
	 *            promises and 5 pending results simultaneously.
	 */
	public AsyncPairingCache(int maxPending) {
		results = createResultCache(maxPending);
		resultsView = Collections.unmodifiableMap(results);

		promises = createPromiseCache(maxPending);
		promisesView = Collections.unmodifiableMap(promises);
	}

	protected abstract Map<K, V> createResultCache(int max);

	protected abstract Map<K, CompletableFuture<V>> createPromiseCache(int max);

	/**
	 * Enter a promise for the the given key into the cache
	 * 
	 * <p>
	 * If the result for the given key is already available, the promise does not enter the cache.
	 * Instead, the result is removed and the promise is completed.
	 * 
	 * @param key the key for the expected result
	 * @param promise the promise to be completed when the result is available
	 */
	public CompletableFuture<V> waitOn(K key) {
		return waitOn(key, k -> new CompletableFuture<>());
	}

	/**
	 * Enter a promise for the the given key into the cache
	 * 
	 * <p>
	 * If the result for the given key is already available, the promise does not enter the cache.
	 * Instead, the result is removed and the promise is completed.
	 * 
	 * @param key the key for the expected result
	 * @param promise the promise to be completed when the result is available
	 */
	public CompletableFuture<V> waitOn(K key, Function<K, CompletableFuture<V>> futureFactory) {
		V value;
		synchronized (this) {
			value = results.remove(key);
			if (value == null) {
				return promises.computeIfAbsent(key, futureFactory);
			}
		}
		CompletableFuture<V> future = futureFactory.apply(key);
		future.complete(value);
		return future;
	}

	/**
	 * Enter a result for the given key into the cache
	 * 
	 * <p>
	 * If a promise for the key already exists, the result does not enter the cache. Instead, the
	 * promise is removed and completed.
	 * 
	 * @param key the key for the provided result
	 * @param value the result
	 */
	public void fulfill(K key, V value) {
		CompletableFuture<V> promise;
		synchronized (this) {
			promise = promises.remove(key);
			if (promise == null) {
				results.put(key, value);
				return;
			}
		}
		promise.complete(value);
	}

	/**
	 * Flush the cache, completing all pending requests exceptionally
	 * 
	 * <p>
	 * Both sides of the cache are cleared.
	 * 
	 * @param exc the exception for completing the requests
	 */
	public void flush(Throwable exc) {
		Set<CompletableFuture<V>> copy = new HashSet<>();
		synchronized (this) {
			copy.addAll(promises.values());
			promises.clear();
			results.clear();
		}
		for (CompletableFuture<V> p : copy) {
			p.completeExceptionally(exc);
		}
	}

	/**
	 * Get the map view of unpaired promises
	 * 
	 * @return the map
	 */
	public Map<K, CompletableFuture<V>> getUnpairedPromises() {
		return promisesView;
	}

	/**
	 * Get the map view of unpaired results
	 * 
	 * @return the map
	 */
	public Map<K, V> getUnpairedResults() {
		return resultsView;
	}
}
