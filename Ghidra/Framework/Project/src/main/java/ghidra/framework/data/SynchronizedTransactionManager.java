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
import java.util.LinkedList;

import ghidra.framework.model.*;
import ghidra.framework.store.LockException;
import ghidra.util.Msg;

class SynchronizedTransactionManager extends AbstractTransactionManager {

	private LinkedList<SynchronizedTransaction> undoList = new LinkedList<>();
	private LinkedList<SynchronizedTransaction> redoList = new LinkedList<>();

	//private Map<DomainObjectAdapterDB, DomainObjectTransactionManager> domainObjects = new HashMap<DomainObjectAdapterDB, DomainObjectTransactionManager>();

	private DomainObjectAdapterDB[] domainObjects = new DomainObjectAdapterDB[0];
	private DomainObjectTransactionManager[] domainObjectTransactionManagers =
		new DomainObjectTransactionManager[0];

	private SynchronizedTransaction transaction;

	SynchronizedTransactionManager() {
		super();
	}

	@Override
	DomainObjectAdapterDB[] getDomainObjects() {
		return domainObjects;
	}

	@Override
	synchronized void clearTransactions() {
		for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
			mgr.clearTransactions();
		}
		undoList.clear();
		redoList.clear();
	}

	void addDomainObject(DomainObjectAdapterDB domainObj) throws LockException {
		synchronized (this) {
			AbstractTransactionManager mgr = domainObj.getTransactionManager();
			if (!(mgr instanceof DomainObjectTransactionManager)) {
				throw new IllegalArgumentException("domain object has invalid transaction manager");
			}
			if (isLocked() || mgr.isLocked() || getCurrentTransaction() != null ||
				mgr.getCurrentTransaction() != null) {
				throw new LockException("domain object(s) are busy/locked");
			}
			if (!mgr.lock("Transaction manager join")) {
				throw new LockException("domain object is busy");
			}
			clearTransactions();
			int count = domainObjects.length + 1;
			DomainObjectAdapterDB[] updatedDomainObjects = new DomainObjectAdapterDB[count];
			DomainObjectTransactionManager[] updatedManagers =
				new DomainObjectTransactionManager[count];
			System.arraycopy(domainObjects, 0, updatedDomainObjects, 0, domainObjects.length);
			updatedDomainObjects[count - 1] = domainObj;
			System.arraycopy(domainObjectTransactionManagers, 0, updatedManagers, 0,
				domainObjectTransactionManagers.length);
			updatedManagers[count - 1] =
				(DomainObjectTransactionManager) domainObj.getTransactionManager();
			domainObjects = updatedDomainObjects;
			domainObjectTransactionManagers = updatedManagers;
			domainObj.setTransactionManager(this);
			updatedManagers[count - 1].lockCount = 0;
		}
		notifyUndoableListeners();
	}

	synchronized void removeDomainObject(DomainObjectAdapterDB domainObj) throws LockException {
		if (getCurrentTransaction() != null) {
			throw new LockException(
				"domain object has open transaction: " + getCurrentTransaction().getDescription());
		}
		if (isLocked()) {
			throw new LockException("domain object is locked!");
		}
		if (domainObj.getTransactionManager() != this) {
			throw new IllegalArgumentException("domain object has different transaction manager");
		}
		int index = -1;
		for (int i = 0; i < domainObjects.length; i++) {
			if (domainObjects[i] == domainObj) {
				index = i;
				break;
			}
		}
		if (index < 0) {
			throw new IllegalArgumentException("invalid domain object");
		}
		clearTransactions();
		DomainObjectTransactionManager restoredMgr = domainObjectTransactionManagers[index];
		int count = domainObjects.length - 1;
		DomainObjectAdapterDB[] updatedDomainObjects = new DomainObjectAdapterDB[count];
		DomainObjectTransactionManager[] updatedManagers =
			new DomainObjectTransactionManager[count];
		System.arraycopy(domainObjects, 0, updatedDomainObjects, 0, index);
		System.arraycopy(domainObjectTransactionManagers, 0, updatedManagers, 0, index);
		if (index < count) {
			System.arraycopy(domainObjects, index + 1, updatedDomainObjects, index, count - index);
			System.arraycopy(domainObjectTransactionManagers, index + 1, updatedManagers, index,
				count - index);
		}
		domainObjects = updatedDomainObjects;
		domainObjectTransactionManagers = updatedManagers;

		domainObj.setTransactionManager(restoredMgr);
		restoredMgr.notifyUndoStackChanged();

		if (count == 1) {
			removeDomainObject(domainObjects[0]);
		}
		else {
			notifyUndoableListeners();
		}
	}

	@Override
	void terminateTransaction(boolean rollback, boolean notify) {
		if (transaction == null || transactionTerminated) {
			return;
		}
		for (AbstractTransactionManager mgr : domainObjectTransactionManagers) {
			mgr.terminateTransaction(rollback, false);
		}
		transactionTerminated = true;
		if (notify) {
			notifyEndTransaction();
		}
	}

	@Override
	synchronized int startTransaction(DomainObjectAdapterDB object, String description,
			AbortedTransactionListener listener, boolean force, boolean notify) {

		if (!force) {
			verifyNoLock();
		}

		if (transaction == null) {
			transactionTerminated = false;
			transaction = new SynchronizedTransaction(domainObjectTransactionManagers);
			int txId = transaction.addEntry(object, description, listener);
			if (notify) {
				notifyStartTransaction();
			}
			return txId;
		}
		if (transactionTerminated) {
			Msg.warn(this,
				"Aborted transaction still pending, new transaction will also be aborted: " +
					description);
		}
		int txId = transaction.addEntry(object, description, listener);
		if (notify) {
			notifyStartTransaction();
		}
		return txId;
	}

	@Override
	synchronized Transaction endTransaction(DomainObjectAdapterDB object, int transactionID,
			boolean commit, boolean notify) {
		if (transaction == null) {
			throw new IllegalStateException("No transaction is open");
		}
		Transaction returnedTransaction = transaction;
		transaction.endEntry(object, transactionID, commit && !transactionTerminated);
		int status = transaction.getStatus();
		if (status == Transaction.COMMITTED) {
			boolean committed = transaction.endAll(true);
			if (committed) {
				redoList.clear();
				undoList.addLast(transaction);
				if (undoList.size() > NUM_UNDOS) {
					undoList.removeFirst();
				}
			}
			transaction = null;
			if (notify) {
				notifyEndTransaction();
			}
		}
		else if (status == Transaction.ABORTED) {
			if (!transactionTerminated) {
				transaction.endAll(false);
			}
			transaction = null;
			if (notify) {
				notifyEndTransaction();
			}
		}
		return returnedTransaction;
	}

	/**
	 * Returns the undo stack depth.
	 * (The number of items on the undo stack)
	 * This method is for JUnits.
	 * @return the undo stack depth
	 */
	@Override
	int getUndoStackDepth() {
		return undoList.size();
	}

	@Override
	synchronized boolean canRedo() {
		if (redoList.size() > 0) {
			for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
				if (mgr.canRedo()) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	synchronized boolean canUndo() {
		if (undoList.size() > 0) {
			for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
				if (mgr.canUndo()) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	synchronized String getRedoName() {
		if (redoList.size() > 0) {
			Transaction t = redoList.getLast();
			return t.getDescription();
		}
		return "";
	}

	@Override
	synchronized String getUndoName() {
		if (undoList.size() > 0) {
			Transaction t = undoList.getLast();
			return t.getDescription();
		}
		return "";
	}

	@Override
	Transaction getCurrentTransaction() {
		return transaction;
	}

	@Override
	void doRedo(boolean notify) throws IOException {
		if (canRedo()) {
			SynchronizedTransaction t = redoList.removeLast();
			undoList.addLast(t);
			t.redo();
			if (notify) {
				notifyUndoableListeners();
			}
		}
	}

	@Override
	void doUndo(boolean notify) throws IOException {
		if (canUndo()) {
			SynchronizedTransaction t = undoList.removeLast();
			redoList.addLast(t);
			t.undo();
			if (notify) {
				notifyUndoableListeners();
			}
		}
	}

	@Override
	synchronized void clearUndo(boolean notifyListeners) {
		if (!undoList.isEmpty() || !redoList.isEmpty()) {

			undoList.clear();
			redoList.clear();

			for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
				mgr.clearUndo(false);
			}
			if (notifyListeners) {
				notifyUndoableListeners();
			}
		}
	}

	@Override
	void doClose(DomainObjectAdapterDB object) {
		try {
			removeDomainObject(object);
		}
		catch (LockException e) {
			throw new IllegalStateException(e);
		}
		object.getTransactionManager().close(object);
	}

	@Override
	synchronized void addTransactionListener(DomainObjectAdapterDB object,
			TransactionListener listener) {
		for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
			if (mgr.getDomainObject() == object) {
				mgr.addTransactionListener(object, listener);
				return;
			}
		}
		throw new IllegalArgumentException("invalid domain object");
	}

	@Override
	synchronized void removeTransactionListener(DomainObjectAdapterDB object,
			TransactionListener listener) {
		for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
			if (mgr.getDomainObject() == object) {
				mgr.removeTransactionListener(object, listener);
				return;
			}
		}
		throw new IllegalArgumentException("invalid domain object");
	}

	private void notifyUndoableListeners() {
		for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
			mgr.notifyUndoStackChanged();
		}
	}

	private void notifyStartTransaction() {
		for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
			mgr.notifyStartTransaction(transaction);
		}
	}

	private void notifyEndTransaction() {
		for (DomainObjectTransactionManager mgr : domainObjectTransactionManagers) {
			mgr.notifyEndTransaction();
		}
	}

}
