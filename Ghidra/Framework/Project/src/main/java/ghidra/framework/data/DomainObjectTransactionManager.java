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
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;

class DomainObjectTransactionManager extends AbstractTransactionManager {

	private LinkedList<DomainObjectDBTransaction> undoList =
		new LinkedList<>();
	private LinkedList<DomainObjectDBTransaction> redoList =
		new LinkedList<>();

	private WeakSet<TransactionListener> transactionListeners =
		WeakDataStructureFactory.createCopyOnWriteWeakSet();

	private DomainObjectAdapterDB domainObj;
	private DomainObjectAdapterDB[] domainObjAsArray;

	private DomainObjectDBTransaction transaction;

	DomainObjectTransactionManager(DomainObjectAdapterDB domainObj) {
		super();
		this.domainObj = domainObj;
		domainObj.dbh.setMaxUndos(NUM_UNDOS);
		domainObjAsArray = new DomainObjectAdapterDB[] { domainObj };
	}

	DomainObjectAdapterDB getDomainObject() {
		return domainObj;
	}

	@Override
	DomainObjectAdapterDB[] getDomainObjects() {
		return domainObjAsArray;
	}

	@Override
	void checkDomainObject(DomainObjectAdapterDB object) {
		if (object != domainObj) {
			throw new IllegalArgumentException("invalid domain object");
		}
	}

	@Override
	void clearTransactions() {
		domainObj.dbh.setMaxUndos(0);
		domainObj.dbh.setMaxUndos(NUM_UNDOS);
		if (domainObj.changeSet != null) {
			domainObj.changeSet.clearUndo();
		}
		undoList.clear();
		redoList.clear();
	}

	@Override
	void terminateTransaction(boolean rollback, boolean notify) {
		synchronized (this) {
			if (transaction == null || transactionTerminated) {
				return;
			}
			try {
				domainObj.dbh.terminateTransaction(transaction.getID(), !rollback);
			}
			catch (IOException e) {
				domainObj.dbError(e);
			}
			transaction.abort();
			transactionTerminated = true;
			if (domainObj.changeSet != null) {
				domainObj.changeSet.endTransaction(!rollback);
			}
			domainObj.clearCache(false);
		}

		domainObj.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
		if (notify) {
			notifyEndTransaction();
		}
	}

	@Override
	synchronized int startTransaction(DomainObjectAdapterDB object, String description,
			AbortedTransactionListener listener, boolean force, boolean notify) {

		if (object != domainObj) {
			throw new IllegalArgumentException("invalid domain object");
		}

		if (!force) {
			verifyNoLock();
		}

		if (transaction == null) {
			transactionTerminated = false;
			transaction =
				new DomainObjectDBTransaction(domainObj.dbh.startTransaction(), domainObj);
			if (domainObj.changeSet != null) {
				domainObj.changeSet.startTransaction();
			}
			int id = transaction.addEntry(description, listener);
			if (notify) {
				notifyStartTransaction(transaction);
			}
			return id;
		}
		if (transactionTerminated) {
			Msg.warn(this,
				"Aborted transaction still pending, new transaction will also be aborted: " +
					description);
		}
		return transaction.addEntry(description, listener);
	}

	private void flushDomainObjectEvents() {
		// In headless mode this method will block
		SystemUtilities.runSwingLater(() -> domainObj.flushEvents());
	}

	@Override
	synchronized Transaction endTransaction(DomainObjectAdapterDB object, int transactionID,
			boolean commit, boolean notify) {
		if (object != domainObj) {
			throw new IllegalArgumentException("invalid domain object");
		}
		if (transaction == null) {
			throw new IllegalStateException("No transaction is open");
		}
		DomainObjectDBTransaction returnedTransaction = transaction;
		try {
			transaction.endEntry(transactionID, commit && !transactionTerminated);
			int status = transaction.getStatus();
			if (status == Transaction.COMMITTED) {
				object.flushWriteCache();
				boolean committed = domainObj.dbh.endTransaction(transaction.getID(), true);
				if (committed) {
					returnedTransaction.setHasCommittedDBTransaction();
					domainObj.changed = true;
					redoList.clear();
					undoList.addLast(transaction);
					if (undoList.size() > NUM_UNDOS) {
						undoList.removeFirst();
					}
					flushDomainObjectEvents();
				}
				if (domainObj.changeSet != null) {
					domainObj.changeSet.endTransaction(committed);
				}
				if (notify) {
					notifyEndTransaction();
				}
				transaction = null;
			}
			else if (status == Transaction.ABORTED) {
				object.invalidateWriteCache();
				if (!transactionTerminated) {
					domainObj.dbh.endTransaction(transaction.getID(), false);
					if (domainObj.changeSet != null) {
						domainObj.changeSet.endTransaction(false);
					}
				}
				domainObj.clearCache(false);
				if (notify) {
					notifyEndTransaction();
				}
				domainObj.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
				transaction.restoreToolStates(true);
				transaction = null;
			}
		}
		catch (IOException e) {
			transaction = null;
			domainObj.dbError(e);
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
		if (transaction == null && redoList.size() > 0) {
			return domainObj.dbh.canRedo();
		}
		return false;
	}

	@Override
	synchronized boolean canUndo() {
		if (transaction == null && undoList.size() > 0) {
			return domainObj.dbh.canUndo();
		}
		return false;
	}

	@Override
	synchronized String getRedoName() {
		if (transaction == null && redoList.size() > 0) {
			Transaction t = redoList.getLast();
			return t.getDescription();
		}
		return "";
	}

	@Override
	synchronized String getUndoName() {
		if (transaction == null && undoList.size() > 0) {
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
			DomainObjectDBTransaction t = redoList.removeLast();
			domainObj.dbh.redo();
			domainObj.clearCache(false);
			if (domainObj.changeSet != null) {
				domainObj.changeSet.redo();
			}
			domainObj.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
			undoList.addLast(t);
			t.restoreToolStates(false);
			if (notify) {
				notifyUndoRedo();
			}
		}
	}

	@Override
	void doUndo(boolean notify) throws IOException {
		if (canUndo()) {
			DomainObjectDBTransaction t = undoList.removeLast();
			t.initAfterState(domainObj);
			domainObj.dbh.undo();
			if (domainObj.changeSet != null) {
				domainObj.changeSet.undo();
			}
			domainObj.clearCache(false);
			domainObj.fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
			redoList.addLast(t);
			t.restoreToolStates(true);
			if (notify) {
				notifyUndoRedo();
			}
		}
	}

	@Override
	synchronized void clearUndo(boolean notifyListeners) {
		if (!undoList.isEmpty() || !redoList.isEmpty()) {
			undoList.clear();
			redoList.clear();
			DomainFile df = domainObj.getDomainFile();
			if (domainObj.changeSet != null) {
				domainObj.changeSet.clearUndo(df != null && df.isCheckedOut());
			}
			if (notifyListeners) {
				notifyUndoStackChanged();
			}
		}
	}

	@Override
	void doClose(DomainObjectAdapterDB object) {
		// don't care
	}

	@Override
	void addTransactionListener(DomainObjectAdapterDB object, TransactionListener listener) {
		if (object != domainObj) {
			throw new IllegalArgumentException("invalid domain object");
		}
		transactionListeners.add(listener);
	}

	@Override
	void removeTransactionListener(DomainObjectAdapterDB object, TransactionListener listener) {
		if (object != domainObj) {
			throw new IllegalArgumentException("invalid domain object");
		}
		transactionListeners.remove(listener);
	}

	void notifyStartTransaction(Transaction tx) {
		SystemUtilities.runSwingLater(() -> {
			for (TransactionListener listener : transactionListeners) {
				listener.transactionStarted(domainObj, tx);
				listener.undoStackChanged(domainObj);
			}
		});
	}

	void notifyEndTransaction() {
		SystemUtilities.runSwingLater(() -> {
			for (TransactionListener listener : transactionListeners) {
				listener.transactionEnded(domainObj);
				listener.undoStackChanged(domainObj);
			}
		});
	}

	void notifyUndoStackChanged() {
		SystemUtilities.runSwingLater(() -> {
			for (TransactionListener listener : transactionListeners) {
				listener.undoStackChanged(domainObj);
			}
		});
	}

	void notifyUndoRedo() {
		SystemUtilities.runSwingLater(() -> {
			for (TransactionListener listener : transactionListeners) {
				listener.undoRedoOccurred(domainObj);
				listener.undoStackChanged(domainObj);
			}
		});
	}

}
