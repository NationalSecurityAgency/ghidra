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
package generic.concurrent;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A class to synchronize and track the progress of the items being processed by a concurrentQ. It 
 * provides various wait methods for when one item is completed or all items are completed. 
 */
class ProgressTracker {
	private long totalCount;
	private long inProgressCount;
	private long completedOrCancelledCount;
	private long nextID = 0;

	private final ReentrantLock lock;
	private final Condition done;        // notifies when all items have been completed or cancelled 
	private final Condition itemCompleted; // notifies when an item is processed or cancelled

	ProgressTracker(ReentrantLock lock) {
		this.lock = lock;
		done = lock.newCondition();
		itemCompleted = lock.newCondition();
	}

	void itemsAdded(int n) {
		lock.lock();
		try {
			totalCount += n;
		}
		finally {
			lock.unlock();
		}
	}

	void itemStarted() {
		lock.lock();
		try {
			inProgressCount++;
		}
		finally {
			lock.unlock();
		}
	}

	void inProgressItemCompletedOrCancelled() {
		lock.lock();
		try {
			completedOrCancelledCount++;
			inProgressCount--;
			if (isDone()) {
				done.signalAll();
			}
			itemCompleted.signalAll();
		}
		finally {
			lock.unlock();
		}
	}

	void neverStartedItemsRemoved(int n) {
		lock.lock();
		try {
			completedOrCancelledCount += n;
			if (isDone()) {
				done.signalAll();
			}
			itemCompleted.signalAll();
		}
		finally {
			lock.unlock();
		}
	}

	public long getCompletedItemCount() {
		lock.lock();
		try {
			return completedOrCancelledCount;
		}
		finally {
			lock.unlock();
		}
	}

	public long getTotalItemCount() {
		lock.lock();
		try {
			return totalCount;
		}
		finally {
			lock.unlock();
		}
	}

	public long getItemsInProgressCount() {
		lock.lock();
		try {
			return inProgressCount;
		}
		finally {
			lock.unlock();
		}
	}

	boolean isDone() {
		lock.lock();
		try {
			return completedOrCancelledCount == totalCount;
		}
		finally {
			lock.unlock();
		}
	}

	void waitUntilDone() throws InterruptedException {
		lock.lockInterruptibly();
		try {
			while (!isDone()) {
				done.await();
			}
		}
		finally {
			lock.unlock();
		}
	}

	void waitForNext() throws InterruptedException {
		lock.lockInterruptibly();
		try {
			if (!isDone()) {
				itemCompleted.await();
			}
		}
		finally {
			lock.unlock();
		}
	}

	public boolean waitUntilDone(long timeout, TimeUnit unit) throws InterruptedException {
		lock.lockInterruptibly();
		try {
			if (!isDone()) {
				done.await(timeout, unit);
			}
			return isDone();
		}
		finally {
			lock.unlock();
		}
	}

	public long getNextID() {
		lock.lock();
		try {
			return ++nextID;
		}
		finally {
			lock.unlock();
		}
	}
}
