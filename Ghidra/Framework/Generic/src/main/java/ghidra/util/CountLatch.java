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
package ghidra.util;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.AbstractQueuedSynchronizer;

/**
 * Latch that has a count that can be incremented and decremented.  Threads that call await() will
 * block until the count is 0.
 *
 */
public class CountLatch {
	private static final class Sync extends AbstractQueuedSynchronizer {
		Sync() {
			setState(0);
		}

		int getCount() {
			return getState();
		}

		void increment() {
			for (;;) {
				int count = getState();
				int nextCount = count + 1;
				if (compareAndSetState(count, nextCount)) {
					return;
				}
			}
		}

		void decrement() {
			for (;;) {
				int count = getState();
				if (count == 0) {
					return;
				}
				int nextCount = count - 1;
				if (compareAndSetState(count, nextCount)) {
					releaseShared(0);		// kicks any waiting threads
					return;
				}
			}
		}

		@Override
		protected boolean tryReleaseShared(int ignored) {
			// This is only called indirectly by decrement to kick waiting threads.
			return getState() == 0;
		}

		@Override
		protected int tryAcquireShared(int ignored) {
			return getState() == 0 ? 1 : -1;
		}
	}

	private Sync sync;

	public CountLatch() {
		this.sync = new Sync();
	}

	/**
	 * Increments the latch count.
	 */
	public void increment() {
		sync.increment();
	}

	/**
	 * Decrements the latch count and releases any waiting threads when the count reaches 0.
	 */
	public void decrement() {
		sync.decrement();
	}

	public int getCount() {
		return sync.getCount();
	}

	/**
	 * Causes the current thread to wait until the latch count is
	 * zero, unless the thread is {@linkplain Thread#interrupt interrupted}.
	 *
	 * <p>If the current count is zero then this method returns immediately.
	 *
	 * <p>If the current count is greater than zero then the current
	 * thread becomes disabled for thread scheduling purposes and lies
	 * dormant until one of two things happen:
	 * <ul>
	 * <li>The count reaches zero due to invocations of the
	 * {@link #decrement} method; or
	 * <li>Some other thread {@linkplain Thread#interrupt interrupts}
	 * the current thread.
	 * </ul>
	 *
	 * <p>If the current thread:
	 * <ul>
	 * <li>has its interrupted status set on entry to this method; or
	 * <li>is {@linkplain Thread#interrupt interrupted} while waiting,
	 * </ul>
	 * then {@link InterruptedException} is thrown and the current thread's
	 * interrupted status is cleared.
	 *
	 * @throws InterruptedException if the current thread is interrupted
	 *         while waiting
	 */
	public void await() throws InterruptedException {
		sync.acquireSharedInterruptibly(1);
	}

	/**
	 * Causes the current thread to wait until the latch count is
	 * zero, unless the thread is {@linkplain Thread#interrupt interrupted},
	 * or the specified waiting time elapses.
	 *
	 * <p>If the current count is zero then this method returns immediately
	 * with the value {@code true}.
	 *
	 * <p>If the current count is greater than zero then the current
	 * thread becomes disabled for thread scheduling purposes and lies
	 * dormant until one of three things happen:
	 * <ul>
	 * <li>The count reaches zero due to invocations of the
	 * {@link #decrement} method; or
	 * <li>Some other thread {@linkplain Thread#interrupt interrupts}
	 * the current thread; or
	 * <li>The specified waiting time elapses.
	 * </ul>
	 *
	 * <p>If the count reaches zero then the method returns with the
	 * value {@code true}.
	 *
	 * <p>If the current thread:
	 * <ul>
	 * <li>has its interrupted status set on entry to this method; or
	 * <li>is {@linkplain Thread#interrupt interrupted} while waiting,
	 * </ul>
	 * then {@link InterruptedException} is thrown and the current thread's
	 * interrupted status is cleared.
	 *
	 * <p>If the specified waiting time elapses then the value {@code false}
	 * is returned.  If the time is less than or equal to zero, the method
	 * will not wait at all.
	 *
	 * @param timeout the maximum time to wait
	 * @param unit the time unit of the {@code timeout} argument
	 * @return {@code true} if the count reached zero and {@code false}
	 *         if the waiting time elapsed before the count reached zero
	 * @throws InterruptedException if the current thread is interrupted
	 *         while waiting
	 */
	public boolean await(long timeout, TimeUnit unit) throws InterruptedException {
		return sync.tryAcquireSharedNanos(1, unit.toNanos(timeout));
	}

}
