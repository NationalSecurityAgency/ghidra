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
package ghidra.util;

/**
 * Ghidra synchronization lock. This class allows creation of named locks for
 * synchroniing modification of multiple tables in the Ghidra database.
 */
public class Lock {
	private Thread owner;
	private int lockAquireCount = 0;
	private int waiterCount = 0;
	private String name;

	/**
	 * Creates an instance of a lock for synchronization within Ghidra.
	 * 
	 * @param name the name of this lock
	 */
	public Lock(String name) {
		this.name = name;
	}

	/**
	 * Acquire this synchronization lock. (i.e. begin synchronizing on this named
	 * lock.)
	 */
	public synchronized void acquire() {
		Thread currThread = Thread.currentThread();

		while (true) {
			if (owner == null) {
				lockAquireCount = 1;
				owner = currThread;
				return;
			}
			else if (owner == currThread) {
				lockAquireCount++;
				return;
			}
			try {
				waiterCount++;
				wait();
			}
			catch (InterruptedException e) {
				// exception from another threads notify(), ignore
				// and try to get lock again
			}
			finally {
				waiterCount--;
			}
		}
	}

	/**
	 * Releases this lock, since you are through with the code that needed
	 * synchronization.
	 */
	public synchronized void release() {
		Thread currThread = Thread.currentThread();

		if (lockAquireCount > 0 && (owner == currThread)) {
			if (--lockAquireCount == 0) {
				owner = null;
				// This is purely to help sample profiling.  If notify() is called the
				// sampler can attribute time to the methods calling this erroneously.  For some reason
				// the visualvm sampler gets a sample more often when notify() is called.
				if (waiterCount != 0) {
					notify();
				}
			}
		}
		else {
			throw new IllegalStateException("Attempted to release an unowned lock: " + name);
		}
	}

	/**
	 * Gets the thread that currently owns the lock.
	 * 
	 * @return the thread that owns the lock or null.
	 */
	public Thread getOwner() {
		return owner;
	}
}
