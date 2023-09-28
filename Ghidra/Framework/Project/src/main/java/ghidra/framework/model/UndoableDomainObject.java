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
package ghidra.framework.model;

import db.TerminatedTransactionException;
import db.Transaction;
import ghidra.framework.store.LockException;
import utility.function.ExceptionalCallback;
import utility.function.ExceptionalSupplier;

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
	 * Open new transaction.  This should generally be done with a try-with-resources block:
	 * <pre>
	 * try (Transaction tx = dobj.openTransaction(description)) {
	 * 	// ... Do something
	 * }
	 * </pre>
	 * 
	 * @param description a short description of the changes to be made.
	 * @return transaction object
	 * @throws IllegalStateException if this {@link DomainObject} has already been closed.
	 */
	public Transaction openTransaction(String description) throws IllegalStateException;

	/**
	 * Performs the given callback inside of a transaction.  Use this method in place of the more
	 * verbose try/catch/finally semantics.
	 * <p>
	 * <pre>
	 * program.withTransaction("My Description", () -> {
	 * 	// ... Do something
	 * });
	 * </pre>
	 * 
	 * <p>
	 * Note: the transaction created by this method will always be committed when the call is 
	 * finished.  If you need the ability to abort transactions, then you need to use the other 
	 * methods on this interface.
	 * 
	 * @param description brief description of transaction
	 * @param callback the callback that will be called inside of a transaction
	 * @throws E any exception that may be thrown in the given callback
	 */
	public default <E extends Exception> void withTransaction(String description,
			ExceptionalCallback<E> callback) throws E {
		int id = startTransaction(description);
		try {
			callback.call();
		}
		finally {
			endTransaction(id, true);
		}
	}

	/**
	 * Calls the given supplier inside of a transaction.  Use this method in place of the more
	 * verbose try/catch/finally semantics.
	 * <p>
	 * <pre>
	 * program.withTransaction("My Description", () -> {
	 * 	// ... Do something
	 * 	return result;
	 * });
	 * </pre>
	 * <p>
	 * If you do not need to supply a result, then use 
	 * {@link #withTransaction(String, ExceptionalCallback)} instead.
	 * 
	 * @param <E> the exception that may be thrown from this method 
	 * @param <T> the type of result returned by the supplier
	 * @param description brief description of transaction
	 * @param supplier the supplier that will be called inside of a transaction
	 * @return the result returned by the supplier
	 * @throws E any exception that may be thrown in the given callback
	 */
	public default <E extends Exception, T> T withTransaction(String description,
			ExceptionalSupplier<T, E> supplier) throws E {
		T t = null;
		boolean success = false;
		int id = startTransaction(description);
		try {
			t = supplier.get();
			success = true;
		}
		finally {
			endTransaction(id, success);
		}
		return t;
	}

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
	 * Returns the current transaction info
	 * @return the current transaction info
	 */
	public TransactionInfo getCurrentTransactionInfo();

	/**
	 * Returns true if the last transaction was terminated from the action that started it.
	 * @return true if the last transaction was terminated from the action that started it.
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
	 * @param domainObj the domain object
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
