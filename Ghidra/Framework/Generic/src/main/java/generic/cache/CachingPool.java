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

import java.util.*;

import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

/**
 * A thread-safe pool that knows how to create instances as needed.  When clients are done
 * with the pooled item they then call {@link  #release(Object)}, thus enabling them to be
 * re-used in the future.
 *
 * <p>Calling {@link #setCleanupTimeout(long)} with a non-negative value will start a timer when
 * {@link #release(Object)} is called to {@link BasicFactory#dispose(Object)} any objects in the
 * pool.   By default, the cleanup timer does not run.
 *
 * <p>Once {@link #dispose()} has been called on this class, items created or released will no
 * longer be pooled.
 *
 * @param <T> the type of object to pool
 */
public class CachingPool<T> {

	// Use -1 to signal the cleanup timer should not be used
	private static final long TIMEOUT = -1;

	private boolean isDisposed;
	private BasicFactory<T> factory;
	private Deque<T> cache = new ArrayDeque<T>();

	private long disposeTimeout = TIMEOUT;
	private GTimerMonitor timerMonitor;

	/**
	 * Creates a new pool that uses the given factory to create new items as needed
	 *
	 * @param factory the factory used to create new items
	 */
	public CachingPool(BasicFactory<T> factory) {
		this.factory = Objects.requireNonNull(factory);
	}

	/**
	 * Sets the time to wait for released items to be disposed by this pool by calling
	 * {@link BasicFactory#dispose(Object)}.  A negative timeout value signals to disable
	 * the cleanup task.
	 *
	 * <p>When clients call {@link #get()}, the timer will not be running.  It will be restarted
	 * again once {@link #release(Object)} has been called.
	 *
	 * @param timeout the new timeout.
	 */
	public void setCleanupTimeout(long timeout) {
		this.disposeTimeout = timeout;
	}

	/**
	 * Returns a cached or new {@code T}
	 *
	 * @return a cached or new {@code T}
	 * @throws Exception if there is a problem instantiating a new instance
	 */
	public synchronized T get() throws Exception {
		stopCleanupTimer();
		if (cache.isEmpty() || isDisposed) {
			return factory.create();
		}
		return cache.pop();
	}

	/**
	 * Signals that the given object is no longer being used.  The object will be placed back into
	 * the pool until it is disposed via the cleanup timer, if it is running.
	 * @param t the item to release
	 */
	public synchronized void release(T t) {
		restartCleanupTimer();
		if (isDisposed) {
			factory.dispose(t);
			return;
		}
		cache.push(t);
	}

	/**
	 * Triggers all pooled object to be disposed via this pool's factory.   Future calls to
	 * {@link #get()} will still create new objects, but the internal cache will no longer be used.
	 */
	public synchronized void dispose() {
		stopCleanupTimer();
		isDisposed = true;

		disposeCachedItems();
	}

	private synchronized void disposeCachedItems() {
		for (T t : cache) {
			factory.dispose(t);
		}
	}

	private void stopCleanupTimer() {
		if (timerMonitor != null) {
			timerMonitor.cancel();
		}
	}

	private void restartCleanupTimer() {
		if (timerMonitor != null) {
			timerMonitor.cancel();
		}
		timerMonitor = GTimer.scheduleRunnable(disposeTimeout, this::disposeCachedItems);
	}
}
