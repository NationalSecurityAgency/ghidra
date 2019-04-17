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
package ghidra.framework.data;

import ghidra.framework.model.AbortedTransactionListener;
import ghidra.framework.model.Transaction;

import java.io.IOException;
import java.util.ArrayList;

/**
 * <code>SynchronizedTransaction</code> represents an atomic undoable operation performed
 * on a synchronized set of domain objects.
 */
class SynchronizedTransaction implements Transaction {

	private DomainObjectTransactionManager[] managers;
	private int[] holdTransactionIds;
	private boolean[] hasChanges;
	private String[] descriptions;
	private int[] activeCounts;

	private int status = NOT_DONE;
	private final long id;

	SynchronizedTransaction(DomainObjectTransactionManager[] managers) {
		this.managers = managers;
		holdTransactionIds = new int[managers.length];
		hasChanges = new boolean[managers.length];
		descriptions = new String[managers.length];
		activeCounts = new int[managers.length];
		id = DomainObjectDBTransaction.getNextBaseId();

		for (int i = 0; i < managers.length; i++) {
			DomainObjectTransactionManager mgr = managers[i];
			holdTransactionIds[i] = mgr.startTransaction(mgr.getDomainObject(), "", null, false,
				false);
		}
	}

	@Override
	public String getDescription() {
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < managers.length; i++) {
			if (descriptions[i] != null) {
				if (buf.length() != 0) {
					buf.append('\n');
				}
				buf.append(getDomainObjectName(managers[i]));
				buf.append(": ");
				buf.append(descriptions[i]);
			}
		}
		return buf.toString();
	}

	private String getDomainObjectName(DomainObjectTransactionManager manager) {
		DomainObjectAdapterDB domainObject = manager.getDomainObject();
		return domainObject.getDomainFile().getName();
	}

	@Override
	public long getID() {
		return id;
	}

	@Override
	public ArrayList<String> getOpenSubTransactions() {
		ArrayList<String> list = new ArrayList<String>();
		int status = getStatus();
		if (status == ABORTED || status == COMMITTED) {
			return list;
		}
		for (int i = 0; i < managers.length; i++) {
			String name = getDomainObjectName(managers[i]);
			for (String str : managers[i].getCurrentTransaction().getOpenSubTransactions()) {
				list.add(name + ": " + str);
			}
		}
		return list;
	}

	private boolean isActive() {
		for (int activeCount : activeCounts) {
			if (activeCount != 0) {
				return true;
			}
		}
		return false;
	}

	@Override
	public int getStatus() {
		if (status == ABORTED && isActive()) {
			return NOT_DONE_BUT_ABORTED;
		}
		return status;
	}

	int addEntry(DomainObjectAdapterDB domainObj, String description,
			AbortedTransactionListener listener) {
		int index = findDomainObject(domainObj);
		int txId = managers[index].startTransaction(domainObj, description, listener, false, false);
		++activeCounts[index];
		if (descriptions[index] == null && description != null && description.length() != 0) {
			descriptions[index] = description;
		}
		return txId;
	}

	void endEntry(DomainObjectAdapterDB domainObj, int transactionID, boolean commit) {
		int index = findDomainObject(domainObj);
		managers[index].endTransaction(domainObj, transactionID, commit, false);
		if (!commit) {
			status = ABORTED;
		}
		--activeCounts[index];
		if (!isActive() && status == NOT_DONE) {
			status = COMMITTED;
		}
	}

	private int findDomainObject(DomainObjectAdapterDB domainObj) {
		for (int i = 0; i < managers.length; i++) {
			if (managers[i].getDomainObject() == domainObj) {
				return i;
			}
		}
		throw new IllegalStateException("unknown domain object");
	}

	/**
	 * End all domain object transactions and keep track as to which ones 
	 * resulted in a low-level transaction.
	 * @param commit indicates if all domain object hold transactions
	 * should be committed or rolled-back
	 * @return true if this transaction produced any low-level transaction
	 */
	boolean endAll(boolean commit) {
		boolean hasChange = false;
		for (int i = 0; i < managers.length; i++) {
			Transaction transaction = managers[i].endTransaction(managers[i].getDomainObject(),
				holdTransactionIds[i], commit, false);
			if (commit && transaction.hasCommittedDBTransaction()) {
				hasChanges[i] = true;
				hasChange = true;
			}
			else {
				descriptions[i] = null;
			}
		}
		return hasChange;
	}

	void redo() throws IOException {
		for (int i = 0; i < managers.length; i++) {
			if (hasChanges[i]) {
				managers[i].doRedo(false);
			}
		}
	}

	void undo() throws IOException {
		for (int i = 0; i < managers.length; i++) {
			if (hasChanges[i]) {
				managers[i].doUndo(false);
			}
		}
	}

	@Override
	public boolean hasCommittedDBTransaction() {
		for (int i = 0; i < managers.length; i++) {
			if (hasChanges[i]) {
				return true;
			}
		}
		return false;
	}

}
