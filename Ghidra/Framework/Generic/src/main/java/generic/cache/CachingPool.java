/* ###
 * IP: GHIDRA
 * REVIEWED: YES
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

import ghidra.util.timer.GTimer;
import ghidra.util.timer.GTimerMonitor;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A thread-safe pool class that knows how to create instances as needed.  When clients are done
 * with the pooled item they then call {@link  #release(Object)}.
 *
 * @param <T> the type of object to pool
 */
public class CachingPool<T> {

	private static final long TIMEOUT = 0;

	private AtomicBoolean isDisposed = new AtomicBoolean(false);
	private BasicFactory<T> factory;
	private Deque<T> cache = new ArrayDeque<T>();

	private long disposeTimeout = TIMEOUT;
	private GTimerMonitor timerMonitor;
	private Runnable cleanupRunnable = new Runnable() {
		@Override
		public void run() {
			synchronized (CachingPool.this) {
				for (T t : cache) {
					factory.dispose(t);
				}
			}
		}
	};

	public CachingPool(BasicFactory<T> factory) {
		if (factory == null) {
			throw new IllegalArgumentException("factory cannot be null");
		}
		this.factory = factory;
	}

	/**
	 * Sets the time to wait for released items to be automatically disposed.  The 
	 * default is {@link #TIMEOUT}.
	 * 
	 * @param timeout the new timeout.
	 */
	public void setCleanupTimeout(long timeout) {
		this.disposeTimeout = timeout;
	}

	/**
	 * Returns a cached or new {@link T}
	 * 
	 * @return a cached or new {@link T}
	 * @throws Exception if there is a problem instantiating a new instance
	 */
	public synchronized T get() throws Exception {
		cancel();
		if (cache.isEmpty()) {
			return factory.create();
		}
		return cache.pop();
	}

	public synchronized void release(T t) {
		restart();
		if (isDisposed.get()) {
			factory.dispose(t);
			return;
		}
		cache.push(t);
	}

	public synchronized void dispose() {
		cancel();
		isDisposed.set(true);

		for (T t : cache) {
			factory.dispose(t);
		}
	}

	private void cancel() {
		if (timerMonitor != null) {
			timerMonitor.cancel();
		}
	}

	private void restart() {
		if (timerMonitor != null) {
			timerMonitor.cancel();
		}
		timerMonitor = GTimer.scheduleRunnable(disposeTimeout, cleanupRunnable);
	}
}
