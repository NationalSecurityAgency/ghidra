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

import java.util.concurrent.locks.ReentrantReadWriteLock;

import db.DBHandle;
import ghidra.framework.data.DBDomainObjectSupport;
import ghidra.framework.data.OpenMode;
import ghidra.util.*;
import ghidra.util.task.TaskMonitor;

/**
 * A domain object that can use {@link DBCachedObjectStoreFactory}.
 *
 * <p>
 * Technically, this only introduces a read-write lock to the domain object. The
 * {@link DBCachedObjectStoreFactory} and related require this read-write lock. Sadly, this idea
 * didn't pan out, and that read-write lock is just a degenerate wrapper of the Ghidra
 * {@link ghidra.util.Lock}, which is not a read-write lock. This class may disappear.
 */
public abstract class DBCachedDomainObjectAdapter extends DBDomainObjectSupport {

	static class SwingAwareReadWriteLock extends ReentrantReadWriteLock {
		private SwingAwareReadLock readerLock = new SwingAwareReadLock(this);
		private SwingAwareWriteLock writerLock = new SwingAwareWriteLock(this);

		static class SwingAwareReadLock extends ReadLock {
			protected SwingAwareReadLock(ReentrantReadWriteLock lock) {
				super(lock);
			}

			@Override
			public void lock() {
				long blockStartTime = System.currentTimeMillis();
				super.lock();
				long blockEndTime = System.currentTimeMillis();
				long lapsed = blockEndTime - blockStartTime;
				if (Swing.isSwingThread() && lapsed > 30) {
					Msg.warn(this, "Read-Locked the swing thread for " + lapsed + " ms!");
				}
			}
		}

		static class SwingAwareWriteLock extends WriteLock {
			protected SwingAwareWriteLock(ReentrantReadWriteLock lock) {
				super(lock);
			}

			@Override
			public void lock() {
				long blockStartTime = System.currentTimeMillis();
				super.lock();
				long blockEndTime = System.currentTimeMillis();
				long lapsed = blockEndTime - blockStartTime;
				if (Swing.isSwingThread() && lapsed > 30) {
					Msg.warn(this, "Write-Locked the swing thread for " + lapsed + " ms!");
				}
			}
		}

		@Override
		public ReadLock readLock() {
			return readerLock;
		}

		@Override
		public WriteLock writeLock() {
			return writerLock;
		}
	}

	/**
	 * @see DBDomainObjectSupport
	 */
	protected DBCachedDomainObjectAdapter(DBHandle dbh, OpenMode openMode, TaskMonitor monitor,
			String name, int timeInterval, int bufSize, Object consumer) {
		super(dbh, openMode, monitor, name, timeInterval, bufSize, consumer);
	}

	/**
	 * Get the "read-write" lock
	 * 
	 * @return the lock
	 */
	public Lock getReadWriteLock() {
		return lock;
	}
}
