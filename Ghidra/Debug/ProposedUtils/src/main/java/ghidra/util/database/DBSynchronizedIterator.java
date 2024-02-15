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
package ghidra.util.database;

import java.util.Iterator;
import java.util.concurrent.locks.ReadWriteLock;

import ghidra.util.LockHold;

public class DBSynchronizedIterator<T> implements Iterator<T> {
	private final Iterator<T> iterator;
	private final ReadWriteLock lock;

	public DBSynchronizedIterator(Iterator<T> iterator, ReadWriteLock lock) {
		this.iterator = iterator;
		this.lock = lock;
	}

	@Override
	public boolean hasNext() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return iterator.hasNext();
		}
	}

	@Override
	public T next() {
		try (LockHold hold = LockHold.lock(lock.readLock())) {
			return iterator.next();
		}
	}

	@Override
	public void remove() {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			iterator.remove();
		}
	}
}
