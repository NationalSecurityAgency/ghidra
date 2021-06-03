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
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import com.google.common.cache.*;

/**
 * A cache of futures which pairs each to its result by key
 * 
 * The cache accepts promises and results, storing unpaired entries for a timeout period. Each
 * promise is fulfilled when the cache accepts its corresponding result, determined by key.
 * Conversely, a cached result fulfills its corresponding promise, determined by key, when the cache
 * accepts that promise. Thus, the cache is two sided. When both the promise and the result for a
 * given key enter the cache, they are paired, the promise is fulfilled, and both are removed from
 * the cache.
 * 
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
	 * @param concurrencyLevel the maximum number of thread expected to simultaneously access the
	 *            cache
	 * @param timeoutMillis the amount of time (in milliseconds) a promise or result may pend before
	 *            eviction
	 * @param maxPending the maximum number of pending promises or results before the eldest is
	 *            evicted. Each is counted independently, e.g., a value of 5 permits 5 pending
	 *            promises and 5 pending results simultaneously.
	 */
	public AsyncPairingCache(int concurrencyLevel, int timeoutMillis, int maxPending) {
		results = CacheBuilder.newBuilder()
				.concurrencyLevel(concurrencyLevel)
				.expireAfterWrite(timeoutMillis, TimeUnit.MILLISECONDS)
				.maximumSize(maxPending)
				.removalListener(this::resultRemoved)
				.build()
				.asMap();
		resultsView = Collections.unmodifiableMap(results);

		promises = CacheBuilder.newBuilder()
				.concurrencyLevel(concurrencyLevel)
				.expireAfterWrite(timeoutMillis, TimeUnit.MILLISECONDS)
				.maximumSize(maxPending)
				.removalListener(this::promiseRemoved)
				.build()
				.asMap();
		promisesView = Collections.unmodifiableMap(promises);
	}

	/**
	 * Called when a result is removed
	 * 
	 * Eviction is likely due to a logic bug or a gratuitous result from an external source.
	 * 
	 * @param rn the removal notification for the result entry
	 */
	protected abstract void resultRemoved(RemovalNotification<K, V> rn);

	/**
	 * Called when a promise is removed
	 * 
	 * The most common implementation is to complete the future exceptionally. The default
	 * implementation completes the future with a {@link RuntimeException}. Extensions should
	 * override this method. Note that this method is called for removal as a result of normal
	 * completion, too. In that case {@link RemovalNotification#getCause()} will return
	 * {@link RemovalCause#EXPLICIT}.
	 * 
	 * @param rn the removal notification for the promise entry
	 */
	protected void promiseRemoved(RemovalNotification<K, CompletableFuture<V>> rn) {
		if (rn.getCause() != RemovalCause.EXPLICIT) {
			rn.getValue()
					.completeExceptionally(new RuntimeException(
						"Promise with key " + rn.getKey() +
							" was evicted with the default handler"));
		}
	}

	/**
	 * Enter a promise for the the given key into the cache
	 * 
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
	 * Both sides of the cache are cleared. Note that this will invoke the removal callback for each
	 * entry giving {@link RemovalCause#EXPLICIT} as the cause. For requests, the callback ought not
	 * to complete the request, exceptionally or otherwise, since the flush is about to complete it
	 * with the given exception. The implementor may freely choose how to handle flushed pending
	 * results.
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
