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

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.*;

import db.DBHandle;
import ghidra.framework.data.DBDomainObjectSupport;
import ghidra.util.Msg;
import ghidra.util.Swing;
import ghidra.util.task.TaskMonitor;

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
	 * Adapts a {@link ghidra.util.Lock} to the {@link Lock} interface
	 * 
	 * <p>
	 * Not all operations are supported. In particular, no {@link #lockInterruptibly()},
	 * {@link #tryLock(long,TimeUnit)}, nor {@link #newCondition()}.
	 */
	static class GhidraLockWrappingLock implements Lock {
		private final ghidra.util.Lock ghidraLock;

		public GhidraLockWrappingLock(ghidra.util.Lock ghidraLock) {
			this.ghidraLock = ghidraLock;
		}

		@Override
		public void lock() {
			ghidraLock.acquire();
		}

		@Override
		public void lockInterruptibly() throws InterruptedException {
			throw new UnsupportedOperationException();
		}

		@Override
		public boolean tryLock() {
			synchronized (ghidraLock) { // Yes, sync on the lock's intrinsic lock
				Thread lockOwner = ghidraLock.getOwner();
				if (lockOwner == null || lockOwner == Thread.currentThread()) {
					ghidraLock.acquire();
					return true;
				}
				return false;
			}
		}

		@Override
		public boolean tryLock(long time, TimeUnit unit) throws InterruptedException {
			throw new UnsupportedOperationException();
		}

		@Override
		public void unlock() {
			ghidraLock.release();
		}

		@Override
		public Condition newCondition() {
			throw new UnsupportedOperationException();
		}
	}

	/**
	 * Not a true read-write lock, but adapts a {@link ghidra.util.Lock} to the
	 * {@link ReadWriteLock} interface. The read lock and the write lock are just the same lock
	 */
	static class GhidraLockWrappingRWLock implements ReadWriteLock {
		private final GhidraLockWrappingLock oneLock;

		public GhidraLockWrappingRWLock(ghidra.util.Lock ghidraLock) {
			this.oneLock = new GhidraLockWrappingLock(ghidraLock);
		}

		@Override
		public Lock readLock() {
			return oneLock;
		}

		@Override
		public Lock writeLock() {
			return oneLock;
		}
	}

	protected ReadWriteLock rwLock;

	protected DBCachedDomainObjectAdapter(DBHandle dbh, DBOpenMode openMode, TaskMonitor monitor,
			String name, int timeInterval, int bufSize, Object consumer) {
		super(dbh, openMode, monitor, name, timeInterval, bufSize, consumer);
		this.rwLock = new GhidraLockWrappingRWLock(lock);
	}

	public ReadWriteLock getReadWriteLock() {
		return rwLock;
	}
}
