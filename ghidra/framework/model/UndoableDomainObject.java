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
package ghidra.framework.model;

import ghidra.framework.store.LockException;

import db.TerminatedTransactionException;

/**
 * <code>UndoableDomainObject</code> extends a domain object to provide transaction
 * support and the ability to undo and redo changes made within a stack of 
 * recent transactions.  Each transactions may contain many sub-transactions which
 * reflect concurrent changes to the domain object.  If any sub-transaction fails to commit,
 * all concurrent sub-transaction changes will be rolled-back. 
 * <P>
 * NOTE: A <i>transaction</i> must be started in order
 * to make any change to this domain object - failure to do so will result in a 
 * IOException.
 * @see #startTransaction(String)
 * @see #endTransaction(int, boolean)
 */
public interface UndoableDomainObject extends DomainObject, Undoable {

	/**
	 * Start a new transaction in order to make changes to this domain object.
	 * All changes must be made in the context of a transaction. 
	 * If a transaction is already in progress, a sub-transaction 
	 * of the current transaction will be returned.
	 * @param description brief description of transaction
	 * @return transaction ID
	 * @throws DomainObjectLockedException the domain object is currently locked
	 * @throws TerminatedTransactionException an existing transaction which has not yet ended was terminated early.
	 * Sub-transactions are not permitted until the terminated transaction ends.
	 */
	public int startTransaction(String description);

	/**
	 * Start a new transaction in order to make changes to this domain object.
	 * All changes must be made in the context of a transaction. 
	 * If a transaction is already in progress, a sub-transaction 
	 * of the current transaction will be returned.
	 * @param description brief description of transaction
	 * @param listener listener to be notified if the transaction is aborted.
	 * @return transaction ID
	 * @throws DomainObjectLockedException the domain object is currently locked
	 * @throws TerminatedTransactionException an existing transaction which has not yet ended was terminated early.
	 * Sub-transactions are not permitted until the terminated transaction ends.
	 */
	public int startTransaction(String description, AbortedTransactionListener listener);

	/**
	 * Terminate the specified transaction for this domain object.
	 * @param transactionID transaction ID obtained from startTransaction method
	 * @param commit if true the changes made in this transaction will be marked for commit,
	 * if false this and any concurrent transaction will be rolled-back.
	 */
	public void endTransaction(int transactionID, boolean commit);

	/**
	 * Returns the current transaction
	 * @return the current transaction
	 */
	public Transaction getCurrentTransaction();

	/**
	 * Returns true if the last transaction was terminated externally from the action that
	 * started it.
	 */
	public boolean hasTerminatedTransaction();

	/**
	 * Return array of all domain objects synchronized with a 
	 * shared transaction manager.
	 * @return returns array of synchronized domain objects or
	 * null if this domain object is not synchronized with others.
	 */
	public DomainObject[] getSynchronizedDomainObjects();

	/**
	 * Synchronize the specified domain object with this domain object
	 * using a shared transaction manager.  If either or both is already shared, 
	 * a transition to a single shared transaction manager will be 
	 * performed.  
	 * @param domainObj
	 * @throws LockException if lock or open transaction is active on either
	 * this or the specified domain object
	 */
	public void addSynchronizedDomainObject(DomainObject domainObj) throws LockException;

	/**
	 * Remove this domain object from a shared transaction manager.  If
	 * this object has not been synchronized with others via a shared
	 * transaction manager, this method will have no affect.
	 * @throws LockException if lock or open transaction is active
	 */
	public void releaseSynchronizedDomainObject() throws LockException;

}
