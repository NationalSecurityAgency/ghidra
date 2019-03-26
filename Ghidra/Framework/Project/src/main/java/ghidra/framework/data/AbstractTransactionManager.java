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
package ghidra.framework.data;

import java.io.IOException;

import db.TerminatedTransactionException;
import ghidra.framework.model.*;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.exception.AssertException;

abstract class AbstractTransactionManager {

	protected static final int NUM_UNDOS = 50;

	private volatile LockingTaskMonitor lockingTaskMonitor;

	protected int lockCount = 0;
	protected String lockReason;

	boolean transactionTerminated;

	abstract DomainObjectAdapterDB[] getDomainObjects();

	abstract void addTransactionListener(DomainObjectAdapterDB domainObj,
			TransactionListener listener);

	abstract void removeTransactionListener(DomainObjectAdapterDB domainObj,
			TransactionListener listener);

	abstract void clearTransactions();

	synchronized boolean isLocked() {
		return lockCount != 0;
	}

	final boolean lock(String reason) {

		checkLockingTask();

		synchronized (this) {
			if (getCurrentTransaction() != null && !transactionTerminated) {
				return false;
			}
			if (lockCount == 0) {
				for (DomainObjectAdapterDB domainObj : getDomainObjects()) {
					if (domainObj.isChanged()) {
						domainObj.prepareToSave();
					}
				}
			}
			lockReason = reason;
			++lockCount;
			return true;
		}
	}

	/**
	 * Attempt to obtain a modification lock on the domain object when generating a
	 * background snapshot.
	 * @param domainObj domain object corresponding to snapshot
	 * @param hasProgress true if monitor has progress indicator
	 * @param title title to be used for monitor
	 * @return monitor object if lock obtained successfully, else null which indicates that a
	 * modification is in process.
	 */
	final synchronized LockingTaskMonitor lockForSnapshot(DomainObjectAdapterDB domainObj,
			boolean hasProgress, String title) {
		if (SystemUtilities.isInHeadlessMode()) {
			Msg.warn(this, "Snapshot not supported in headless mode");
			return null;
		}
		checkDomainObject(domainObj);
		if (lockCount != 0 || getCurrentTransaction() != null || lockingTaskMonitor != null) {
			return null;
		}
		++lockCount; // prevent prepareToSave
		try {
			if (lock("snapshot")) {
				lockingTaskMonitor = new LockingTaskMonitor(domainObj, hasProgress, title);
				return lockingTaskMonitor;
			}
		}
		finally {
			--lockCount;
		}
		return null;
	}

	final void forceLock(boolean rollback, String reason) {

		synchronized (this) {
			if (lockingTaskMonitor != null) {
				lockingTaskMonitor.cancel();
			}
		}

		checkLockingTask();

		synchronized (this) {
			lockReason = reason;
			++lockCount;
		}

		terminateTransaction(rollback, true);
	}

	abstract void terminateTransaction(boolean rollback, boolean notify);

	final synchronized void unlock() {
		if (lockCount == 0)
			throw new AssertException();
		--lockCount;
	}

	/**
	 * Release the modification lock which is associated with the specified LockingTaskHandler.
	 */
	final synchronized void unlock(LockingTaskMonitor handler) {
		if (handler == null) {
			throw new IllegalArgumentException("null handler");
		}
		if (lockCount != 1 || handler != lockingTaskMonitor) {
			throw new AssertException();
		}
		unlock();
		lockingTaskMonitor = null;
	}

	/**
	 * Block on active locking task.
	 * Do not invoke this method from within a synchronized block.
	 */
	final void checkLockingTask() {
		synchronized (this) {
			if (!isLocked() || lockingTaskMonitor == null) {
				return;
			}
		}
		lockingTaskMonitor.waitForTaskCompletion();
	}

	/**
	 * Throw lock exception if currently locked
	 * @throws DomainObjectLockedException if currently locked
	 */
	final void verifyNoLock() throws DomainObjectLockedException {
		if (lockCount != 0) {
			throw new DomainObjectLockedException(lockReason);
		}
	}

	void checkDomainObject(DomainObjectAdapterDB object) {
		boolean found = false;
		for (DomainObjectAdapterDB obj : getDomainObjects()) {
			if (obj == object) {
				found = true;
				break;
			}
		}
		if (!found) {
			throw new IllegalArgumentException("invalid domain object");
		}
	}

	final int startTransaction(DomainObjectAdapterDB object, String description,
			AbortedTransactionListener listener, boolean notify) {

		checkLockingTask();

		synchronized (this) {
			checkDomainObject(object);

			if (getCurrentTransaction() != null && transactionTerminated) {
				throw new TerminatedTransactionException();
			}

			return startTransaction(object, description, listener, false, notify);
		}
	}

	abstract int startTransaction(DomainObjectAdapterDB object, String description,
			AbortedTransactionListener listener, boolean force, boolean notify);

	abstract Transaction endTransaction(DomainObjectAdapterDB object, int transactionID,
			boolean commit, boolean notify);

	/**
	 * Returns the undo stack depth.
	 * (The number of items on the undo stack)
	 * This method is for JUnits.
	 * @return the undo stack depth
	 */
	abstract int getUndoStackDepth();

	abstract boolean canRedo();

	abstract boolean canUndo();

	abstract String getRedoName();

	abstract String getUndoName();

	abstract Transaction getCurrentTransaction();

	final void redo() throws IOException {

		checkLockingTask();

		synchronized (this) {
			if (getCurrentTransaction() != null) {
				throw new IllegalStateException("Can not redo while transaction is open");
			}
			verifyNoLock();
			doRedo(true);
		}
	}

	abstract void doRedo(boolean notify) throws IOException;

	final void undo() throws IOException {

		checkLockingTask();

		synchronized (this) {
			if (getCurrentTransaction() != null) {
				throw new IllegalStateException("Can not undo while transaction is open: " +
					getCurrentTransaction().getDescription());
			}
			verifyNoLock();
			doUndo(true);
		}
	}

	abstract void doUndo(boolean notify) throws IOException;

	abstract void clearUndo(boolean notifyListeners);

	final synchronized boolean hasTerminatedTransaction() {
		return transactionTerminated;
	}

	final synchronized void close(DomainObjectAdapterDB object) {

		checkDomainObject(object);

		if (lockingTaskMonitor != null && lockingTaskMonitor.getDomainObject() == object) {
			// TODO: Should we wait for lock release after cancel? 
			lockingTaskMonitor.cancel();
		}
		verifyNoLock();
		doClose(object);
	}

	abstract void doClose(DomainObjectAdapterDB object);

}
