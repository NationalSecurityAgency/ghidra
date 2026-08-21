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

import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Supplier;

import utility.function.Callback;

/**
 * Ghidra synchronization read/write lock that provides read and write methods for acquiring either
 * a shared read access or an exclusive write access.
 * <P>
 * It extends Java's ReentrantReadWriteLock, but
 * adds convenient methods to get either a read or write lock that returns an {@link AutoCloseable}
 * object that can be used in a try with resources block that will auto release the lock when
 * the try block is exited.
 * <P>
 * To use a lock for share read access the general pattern is something like:
 * <PRE>
 * int getSize() {
 *     try (Closeable c = lock.read()) {
 *         return record.getIntValue(SIZE);
 *     }
 * }
 * </PRE>
 * <P>
 * Similarly, to get exclusive access for modification:
 * <PRE>
 * int getSize() {
 *     try (Closeable c = lock.write()) {
 * 	       return record.setIntValue(SIZE);
 *         database.updateRecord(record);	
 *     }
 * }
 * </PRE>
 * 
 */
public class Lock extends ReentrantReadWriteLock {
	private String name;

	/**
	 * Creates an instance of a lock for synchronization within Ghidra.
	 * 
	 * @param name the name of this lock
	 */
	public Lock(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return name + " Lock";
	}

	/**
	 * Acquires the read lock that can allow simultaneous access by all read threads. Will block
	 * if any thread already has a write lock.
	 * @return An AutoCloseable handle to the lock that be used in a try with resources block to
	 * automatically release the lock when the block is exited.
	 */
	public Closeable read() {
		super.readLock().lock();
		return () -> super.readLock().unlock();

	}

	/**
	 * Acquires the exclusive write lock that prevents any other thread, reader or writer, from
	 * getting a lock while the write lock is held. Will block if any other thread has either
	 * a read or write lock. VERY IMPORTANT, any thread that attempts to acquire the write lock
	 * while already holding the read lock, will cause an immediate deadlock.
	 * @return An AutoCloseable handle to the lock that be used in a try with resources block to
	 * automatically release the lock when the block is exited.
	 */
	public Closeable write() {
		super.writeLock().lock();
		return () -> super.writeLock().unlock();
	}

	/**
	 * Gets the thread that currently owns the lock.
	 * 
	 * @return the thread that owns the lock or null.
	 */
	@Override
	public Thread getOwner() {
		return super.getOwner();
	}

	/**
	 * A convenience method for acquiring a read lock, executing a supplier object,
	 * then releasing the lock. 
	 * @param <T> the supplier return type
	 * @param supplier the supplier to execute while holding a read lock.
	 * @return the result from the supplier
	 */
	public <T> T withRead(Supplier<T> supplier) {
		readLock().lock();
		try {
			return supplier.get();
		}
		finally {
			readLock().unlock();
		}
	}

	/**
	 * A convenience method for acquiring a write lock, executing a callback object,
	 * then releasing the lock. 
	 * @param callback the callback to execute while holding a write lock.
	 */
	public void withWrite(Callback callback) {
		writeLock().lock();
		try {
			callback.call();
		}
		finally {
			writeLock().unlock();
		}
	}

	/**
	 * Object to auto close an acquired read or write lock. Note that we can't just use the 
	 * java {@link java.io.Closeable} because it throws an exception on the close call that
	 * we don't want.
	 */
	public interface Closeable extends AutoCloseable {
		@Override
		public void close();
	}
}
