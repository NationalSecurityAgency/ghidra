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
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.function.BiPredicate;
import java.util.function.Function;

import org.apache.commons.lang3.exception.ExceptionUtils;

/**
 * A map of cached values computed upon the first request, asynchronously
 * 
 * <p>
 * Each key present in the cache behaves similarly to {@link AsyncLazyValue}. The cache starts
 * empty. Whenever a key is requested, a computation for that key is started, but a future is
 * immediately returned. If the computation succeeds, the completed future is cached indefinitely,
 * and the result is recorded. Any subsequent requests for the same key return the same future, even
 * if the computation for that key has not yet completed. Thus, when it completes, all requests for
 * that key will be fulfilled by the result of the first request. If the computation completes
 * exceptionally, the key is optionally removed from the cache. Thus, a subsequent request for a
 * failed key may retry the computation.
 * 
 * <p>
 * Values can also be provided "out of band." That is, they may be provided by an alternative
 * computation. This is accomplished using {@link #get(Object, Function)}, {@link #put(Object)} or
 * {@link #put(Object, Object)}. The last immediately provides a value and completes any outstanding
 * requests, even if there was an active computation for the key. The first claims the key and
 * promises to provide the value at a later time.
 * 
 * <p>
 * At any point, an unmodifiable view of the completed, cached values may be obtained.
 *
 * @param <K> the type of keys
 * @param <V> the type of values
 */
public class AsyncLazyMap<K, V> {
	public static class KeyedFuture<K, V> extends CompletableFuture<V> {
		protected final K key;
		protected CompletableFuture<V> future;

		public KeyedFuture(K key) {
			this.key = key;
		}

		public KeyedFuture(K key, V value) {
			this(key);
			complete(value);
		}

		@Override
		public String toString() {
			return key + "=" + super.toString();
		}

		public K getKey() {
			return key;
		}

		public CompletableFuture<V> getFuture() {
			return future;
		}
	}

	protected final Map<K, KeyedFuture<K, V>> futures = new HashMap<>();

	protected final Map<K, V> map;
	protected final Map<K, V> unmodifiable;
	protected final Function<K, CompletableFuture<V>> function;

	protected BiPredicate<? super K, ? super Throwable> forgetErrors = (k, t) -> true;
	protected BiPredicate<? super K, ? super V> forgetValues = (k, v) -> false;

	/**
	 * Construct a lazy map for the given function
	 * 
	 * @param map the backing map. The lazy map ought to have an exclusive reference to this map.
	 *            Mutations to the map outside of those caused by the lazy map may cause undefined
	 *            behavior.
	 * @param function specifies the computation, given a key
	 */
	public AsyncLazyMap(Map<K, V> map, Function<K, CompletableFuture<V>> function) {
		this.map = map;
		this.unmodifiable = Collections.unmodifiableMap(map);
		this.function = function;
	}

	protected void putFuture(K key, KeyedFuture<K, V> future) {
		futures.put(key, future);
		future.exceptionally((exc) -> {
			synchronized (this) {
				if (forgetErrors.test(key, exc)) {
					//Msg.debug(this, "Work failed for " + key + " -> " + exc);
					futures.remove(key);
				}
			}
			return ExceptionUtils.rethrow(exc);
		}).thenAccept(val -> {
			synchronized (this) {
				if (futures.get(key) != future) {
					// The pending future was invalidated
					return;
				}
				if (forgetValues.test(key, val)) {
					futures.remove(key);
					return;
				}
				//Msg.debug(this, "Work completed for " + key + " -> " + value);
				map.put(key, val);
			}
		});
	}

	/**
	 * Sets a predicate to determine which errors to forget (i.e., retry)
	 * 
	 * 
	 * <p>
	 * A request resulting in an error that is remembered will not be retried until the cache is
	 * invalidated. For a forgotten error, the request is retried if re-requested later.
	 * 
	 * <p>
	 * This will replace the behavior of any previous error-testing predicate.
	 * 
	 * @param predicate the predicate
	 * @return this lazy map
	 */
	public synchronized AsyncLazyMap<K, V> forgetErrors(
			BiPredicate<? super K, ? super Throwable> predicate) {
		forgetErrors = predicate;
		return this;
	}

	/**
	 * Sets a predicate to determine which errors to remember
	 * 
	 * @see #forgetErrors(BiPredicate)
	 * @param predicate the predicate
	 * @return this lazy map
	 */
	public AsyncLazyMap<K, V> rememberErrors(
			BiPredicate<? super K, ? super Throwable> predicate) {
		return forgetErrors((k, t) -> !predicate.test(k, t));
	}

	/**
	 * Sets a predicate to determine which values to forget
	 * 
	 * <p>
	 * The predicate is applied to a cached entry when its key is re-requested. If forgotten, the
	 * request will launch a fresh computation. The predicate is also applied at the time a
	 * computation is completed. An entry that is forgotten still completes normally; however, it
	 * never enters the cache, thus a subsequent request for the same key will launch a fresh
	 * computation.
	 * 
	 * <p>
	 * This will replace the behavior of any previous value-testing predicate.
	 * 
	 * @param predicate
	 * @return this lazy map
	 */
	public synchronized AsyncLazyMap<K, V> forgetValues(
			BiPredicate<? super K, ? super V> predicate) {
		forgetValues = predicate;
		return this;
	}

	/**
	 * Sets a predicate to determine which values to remember
	 * 
	 * @see #forgetValues(BiPredicate)
	 * @param predicate
	 * @return this lazy map
	 */
	public synchronized AsyncLazyMap<K, V> rememberValues(
			BiPredicate<? super K, ? super V> predicate) {
		return forgetValues((k, v) -> !predicate.test(k, v));
	}

	/**
	 * Request the value for a given key, using an alternative computation
	 * 
	 * <p>
	 * If this is called before any other get or put, the given function is launched for the given
	 * key. A {@link CompletableFuture} is returned immediately. Subsequent gets or puts on the same
	 * key will return the same future without starting any new computation.
	 * 
	 * @param key the key
	 * @param func an alternative computation function, given a key
	 * @return a future, possibly already completed, for the key's value
	 */
	public synchronized KeyedFuture<K, V> get(K key, Function<K, CompletableFuture<V>> func) {
		/**
		 * NOTE: I must populate the key's entry before invoking the function. Since the lock is
		 * re-entrant, it's possible (likely even) that the same thread comes back around for the
		 * same entry. If the key is not associated with a pending future, that will cause the
		 * function to be re-invoked.
		 */
		// Don't refactor as put, since I need to know whether or not it existed
		KeyedFuture<K, V> future = futures.get(key);
		if (future != null) {
			if (!future.isDone() || !forgetValues.test(key, future.getNow(null))) {
				return future;
			}
		}
		final KeyedFuture<K, V> f = new KeyedFuture<>(key);
		putFuture(key, f);
		CompletableFuture<V> dep = func.apply(key);
		f.future = dep;
		dep.handle(AsyncUtils.copyTo(f));
		return f;
	}

	/**
	 * Request the value for a given key
	 * 
	 * <p>
	 * If this is called before any other get or put, the computation given at construction is
	 * launched for the given key. A {@link CompletableFuture} is returned immediately. Subsequent
	 * calls gets or puts on the same key return the same future without starting any new
	 * computation.
	 * 
	 * @param key the key
	 * @return a future, possible already completed, for the key's value
	 */
	public synchronized KeyedFuture<K, V> get(K key) {
		return get(key, function);
	}

	/**
	 * Immediately provide an out-of-band value for a given key
	 * 
	 * <p>
	 * On occasion, the value for a key may become known outside of the specified computation. This
	 * method circumvents the function given during construction by providing the value for a key.
	 * If there is an outstanding request for the key's value -- a rare occasion -- it is completed
	 * immediately with the provided value. Calling this method for a key that has already completed
	 * has no effect.
	 * 
	 * <p>
	 * This is equivalent to the code {@code map.put(k).complete(value)}, but atomic.
	 * 
	 * @param key the key whose value to provide
	 * @param value the provided value
	 * @return true if the key was completed by this call, false if the key had already been
	 *         completed
	 */
	public synchronized boolean put(K key, V value) {
		//Msg.debug(this, "Inserting finished work for " + key + ": " + value);
		KeyedFuture<K, V> future = futures.get(key);
		if (future != null) {
			return future.complete(value); // should cause map.put given in #get(K)
		}
		future = new KeyedFuture<>(key, value);
		futures.put(key, future);
		map.put(key, value);
		return true;
	}

	/**
	 * Provide an out-of-band value for a given key
	 * 
	 * <p>
	 * If this is called before {@link #get(Object)}, the computation given at construction is
	 * ignored for the given key. A new {@link CompletableFuture} is returned instead. The caller
	 * must see to this future's completion. Subsequent calls to either {@link #get(Object)} or
	 * {@link #put(Object)} on the same key return this same future without starting any
	 * computation.
	 * 
	 * <p>
	 * Under normal circumstances, the caller cannot determine whether or not it has "claimed" the
	 * computation for the key. If the usual computation is already running, then the computations
	 * are essentially in a race. As such, it is essential that alternative computations result in
	 * the same value for a given key as the usual computation. In other words, the functions must
	 * not differ, but the means of computation can differ. Otherwise, race conditions may arise.
	 * 
	 * @param key the key whose value to provide
	 * @return a promise that the caller must fulfill or arrange to have fulfilled
	 */
	public synchronized KeyedFuture<K, V> put(K key) {
		KeyedFuture<K, V> future = futures.get(key);
		if (future != null) {
			return future;
		}
		future = new KeyedFuture<>(key);
		putFuture(key, future);
		return future;
	}

	/**
	 * Remove a key from the map, without canceling any pending computation
	 * 
	 * <p>
	 * If the removed future has not yet completed, its value will never be added to the map of
	 * values. Subsequent gets or puts to the invalidated key will behave as if the key had never
	 * been requested.
	 * 
	 * @param key the key to remove
	 * @return the invalidated future
	 */
	public synchronized CompletableFuture<V> forget(K key) {
		map.remove(key);
		return futures.remove(key);
	}

	/**
	 * Remove a key from the map, canceling any pending computation
	 * 
	 * @param key the key to remove
	 */
	public V remove(K key) {
		KeyedFuture<K, V> f;
		V val;
		synchronized (this) {
			f = futures.remove(key);
			val = map.remove(key);
		}
		if (f != null) {
			f.cancel(false);
		}
		return val;
	}

	/**
	 * Get a view of completed keys with values
	 * 
	 * <p>
	 * The view is unmodifiable, but the backing map may still be modified as more keys are
	 * completed. Thus, access to the view ought to be synchronized on this lazy map.
	 * 
	 * @return a map view of keys to values
	 */
	public Map<K, V> getCompletedMap() {
		return unmodifiable;
	}

	/**
	 * Get a copy of the keys which are requested but not completed
	 * 
	 * <p>
	 * This should only be used for diagnostics.
	 * 
	 * @return a copy of the pending key set
	 */
	public synchronized Set<K> getPendingKeySet() {
		Set<K> result = new LinkedHashSet<>();
		for (KeyedFuture<K, V> f : futures.values()) {
			if (!f.isDone()) {
				result.add(f.key);
			}
		}
		return result;
	}

	/**
	 * Clear the lazy map, including pending requests
	 * 
	 * <p>
	 * Pending requests will be cancelled
	 */
	public void clear() {
		Set<KeyedFuture<K, V>> copy = new LinkedHashSet<>();
		synchronized (this) {
			copy.addAll(futures.values());
			futures.clear();
			map.clear();
		}
		for (KeyedFuture<K, V> f : copy) {
			f.cancel(false);
		}
	}

	/**
	 * Retain only those entries whose keys appear in the given collection
	 * 
	 * <p>
	 * All removed entries with pending computations will be canceled
	 * 
	 * @param keys the keys to retain
	 */
	public void retainKeys(Collection<K> keys) {
		Set<KeyedFuture<K, V>> removed = new LinkedHashSet<>();
		synchronized (this) {
			for (Iterator<Entry<K, KeyedFuture<K, V>>> it = futures.entrySet().iterator(); it
					.hasNext();) {
				Entry<K, KeyedFuture<K, V>> ent = it.next();
				if (!keys.contains(ent.getKey())) {
					removed.add(ent.getValue());
					it.remove();
				}
			}
			map.keySet().retainAll(keys);
		}
		for (KeyedFuture<K, V> f : removed) {
			f.cancel(false);
		}
	}

	/**
	 * Check if a given key is in the map, pending or completed
	 * 
	 * @param key the key to check
	 * @return true if present, false otherwise
	 */
	public synchronized boolean containsKey(K key) {
		return futures.containsKey(key) || map.containsKey(key);
	}
}
