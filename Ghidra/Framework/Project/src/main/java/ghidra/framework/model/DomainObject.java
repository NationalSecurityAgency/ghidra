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

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import db.TerminatedTransactionException;
import db.Transaction;
import ghidra.framework.data.DomainObjectFileListener;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import utility.function.ExceptionalCallback;
import utility.function.ExceptionalSupplier;

/**
 * <CODE>DomainObject</CODE> is the interface that must be supported by
 * data objects that are persistent. <CODE>DomainObject</CODE>s maintain an
 * association with a <CODE>DomainFile</CODE>. A <CODE>DomainObject</CODE> that
 * has never been saved will have a null <CODE>DomainFile</CODE>.
 * <P>
 * Supports transactions and the ability to undo/redo changes made within a stack of 
 * recent transactions.  Each transactions may contain many sub-transactions which
 * reflect concurrent changes to the domain object.  If any sub-transaction fails to commit,
 * all concurrent sub-transaction changes will be rolled-back. 
 * <P>
 * NOTE: A <i>transaction</i> must be started in order
 * to make any change to this domain object - failure to do so will result in a 
 * IOException.
 * <P>
 * Note: Previously (before 11.1), domain object change event types were defined in this file as
 * integer constants. Event ids have since been converted to enum types. The defines in this file  
 * have been converted to point to the new enum values to make it easier to convert to this new way  
 * and to clearly see how the old values map to the new enums. In future releases, these defines 
 * will be removed.
 */
public interface DomainObject {

	/**
	 * Event type generated when the domain object is saved.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static EventType DO_OBJECT_SAVED = DomainObjectEvent.SAVED;

	/**
	 * Event type generated when the domain file associated with
	 * the domain object changes.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static EventType DO_DOMAIN_FILE_CHANGED = DomainObjectEvent.FILE_CHANGED;

	/**
	 * Event type generated when the object name changes.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public final static EventType DO_OBJECT_RENAMED = DomainObjectEvent.RENAMED;

	/**
	 * Event type generated when domain object is restored.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final EventType DO_OBJECT_RESTORED = DomainObjectEvent.RESTORED;

	/**
	 * Event type generated when a property on this DomainObject is changed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final EventType DO_PROPERTY_CHANGED = DomainObjectEvent.PROPERTY_CHANGED;

	/**
	 * Event type generated when this domain object is closed.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final EventType DO_OBJECT_CLOSED = DomainObjectEvent.CLOSED;

	/**
	 * Event type generated when a fatal error occurs which renders the domain object invalid.
	 * @deprecated Event type numeric constants have been changed to enums. Use the enum directly.
	 */
	@Deprecated
	public static final EventType DO_OBJECT_ERROR = DomainObjectEvent.ERROR;

	/**
	 * Object to synchronize on for undo/redo operations.
	 */
	public final static Object undoLock = new Object();

	/**
	 * Returns whether the object has changed.
	 * @return whether the object has changed.
	 */
	public boolean isChanged();

	/**
	 * Set the temporary state of this object.
	 * If this object is temporary, the isChanged() method will
	 * always return false.  The default temporary state is false.
	 * @param state if true object is marked as temporary
	 */
	public void setTemporary(boolean state);

	/**
	 * Returns true if this object has been marked as Temporary.
	 * @return true if this object has been marked as Temporary.
	 */
	public boolean isTemporary();

	/**
	 * Returns true if changes are permitted.
	 * @return true if changes are permitted.
	 */
	public boolean isChangeable();

	/**
	 * Returns true if this object can be saved; a read-only file cannot be saved.
	 * @return true if this object can be saved
	 */
	public boolean canSave();

	/**
	 * Saves changes to the DomainFile.
	 * @param comment comment used for new version
	 * @param monitor monitor that shows the progress of the save
	 * @throws IOException thrown if there was an error accessing this
	 * domain object
	 * @throws ReadOnlyException thrown if this DomainObject is read only
	 * and cannot be saved
	 * @throws CancelledException thrown if the user canceled the save
	 * operation
	 */
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException;

	/**
	 * Saves (i.e., serializes) the current content to a packed file.
	 * @param outputFile packed output file
	 * @param monitor progress monitor
	 * @throws IOException if an exception occurs
	 * @throws CancelledException if the user cancels
	 * @throws UnsupportedOperationException if not supported by object implementation
	 */
	public void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException;

	/**
	 * Notify the domain object that the specified consumer is no longer using it.
	 * When the last consumer invokes this method, the domain object will be closed
	 * and will become invalid.
	 * @param consumer the consumer (e.g., tool, plugin, etc) of the domain object
	 * previously established with the addConsumer method.
	 */
	public void release(Object consumer);

	/**
	 * Adds a listener for this object.
	 * @param dol listener notified when any change occurs to this domain object
	 */
	public void addListener(DomainObjectListener dol);

	/**
	 * Remove the listener for this object.
	 * @param dol listener
	 */
	public void removeListener(DomainObjectListener dol);

	/**
	 * Adds a listener that will be notified when this DomainObject is closed.  This is meant
	 * for clients to have a chance to cleanup, such as reference removal.
	 *
	 * @param listener the reference to add
	 */
	public void addCloseListener(DomainObjectClosedListener listener);

	/**
	 * Removes the given close listener.
	 *
	 * @param listener the listener to remove.
	 */
	public void removeCloseListener(DomainObjectClosedListener listener);

	/**
	 * Adds a listener that will be notified when this DomainFile associated with this
	 * DomainObject changes, such as when a 'Save As' action occurs. Unlike DomainObject events,
	 * these notifications are not buffered and happen immediately when the DomainFile is changed.
	 *
	 * @param listener the listener to be notified when the associated DomainFile changes
	 */
	public void addDomainFileListener(DomainObjectFileListener listener);

	/**
	 * Removes the given DomainObjectFileListener listener.
	 *
	 * @param listener the listener to remove.
	 */
	public void removeDomainFileListener(DomainObjectFileListener listener);

	/**
	 * Creates a private event queue that can be flushed independently from the main event queue.
	 * @param listener the listener to be notified of domain object events.
	 * @param maxDelay the time interval (in milliseconds) used to buffer events.
	 * @return a unique identifier for this private queue.
	 */
	public EventQueueID createPrivateEventQueue(DomainObjectListener listener, int maxDelay);

	/**
	 * Removes the specified private event queue
	 * @param id the id of the queue to remove.
	 * @return true if the id represents a valid queue that was removed.
	 */
	public boolean removePrivateEventQueue(EventQueueID id);

	/**
	 * Returns a word or short phrase that best describes or categorizes
	 * the object in terms that a user will understand.
	 * @return the description
	 */
	public String getDescription();

	/**
	 * Get the name of this domain object.
	 * @return the name
	 */
	public String getName();

	/**
	 * Set the name for this domain object.
	 * @param name object name
	 */
	public void setName(String name);

	/**
	 * Get the domain file for this domain object.
	 * @return the associated domain file
	 */
	public DomainFile getDomainFile();

	/**
	 * Adds the given object as a consumer.  The release method must be invoked
	 * with this same consumer instance when this domain object is no longer in-use.
	 * @param consumer domain object consumer
	 * @return false if this domain object has already been closed
	 */
	public boolean addConsumer(Object consumer);

	/**
	 * Returns the list of consumers on this domainObject
	 * @return the list of consumers.
	 */
	public List<Object> getConsumerList();

	/**
	 * Returns true if the given consumer is using (has open) this domain object.
	 * @param consumer the object to test to see if it is a consumer of this domain object.
	 * @return true if the given consumer is using (has open) this domain object;
	 */
	public boolean isUsedBy(Object consumer);

	/**
	 * If true, domain object change events are sent. If false, no events are sent.
	 * <p>
	 * <b>
	 * NOTE: disabling events could cause plugins to be out of sync!
	 * </b>
	 * <p>
	 * NOTE: when re-enabling events, an event will be sent to the system to signal that
	 *       every listener should update.
	 *
	 *
	 * @param enabled true means to enable events
	 */
	public void setEventsEnabled(boolean enabled);

	/**
	 * Returns true if this object is sending out events as it is changed.  The default is
	 * true.  You can change this value by calling {@link #setEventsEnabled(boolean)}.
	 *
	 * @return true if sending events
	 * @see #setEventsEnabled(boolean)
	 */
	public boolean isSendingEvents();

	/**
	 * Makes sure all pending domainEvents have been sent.
	 */
	public void flushEvents();

	/**
	 * Flush events from the specified event queue.
	 * @param id the id specifying the event queue to be flushed.
	 */
	public void flushPrivateEventQueue(EventQueueID id);

	/**
	 * Returns true if a modification lock can be obtained on this
	 * domain object.  Care should be taken with using this method since
	 * this will not prevent another thread from modifying the domain object.
	 * @return true if can lock
	 */
	public boolean canLock();

	/**
	 * Returns true if the domain object currently has a modification lock enabled.
	 * @return true if locked
	 */
	public boolean isLocked();

	/**
	 * Attempt to obtain a modification lock on the domain object.  Multiple locks may be granted
	 * on this domain object, although all lock owners must release their lock in a timely fashion.
	 * @param reason very short reason for requesting lock
	 * @return true if lock obtained successfully, else false which indicates that a modification
	 * is in process.
	 */
	public boolean lock(String reason);

	/**
	 * Force transaction lock and terminate current transaction.
	 * @param rollback true if rollback of non-commited changes should occurs, false if commit
	 * should be done.  NOTE: it can be potentially detrimental to commit an incomplete transaction
	 * which should be avoided.
	 * @param reason very short reason for requesting lock
	 */
	public void forceLock(boolean rollback, String reason);

	/**
	 * Release a modification lock previously granted with the lock method.
	 */
	public void unlock();

	/**
	 * Returns all properties lists contained by this domain object.
	 *
	 * @return all property lists contained by this domain object.
	 */
	public List<String> getOptionsNames();

	/**
	 * Get the property list for the given name.
	 * @param propertyListName name of property list
	 * @return the options
	 */
	public Options getOptions(String propertyListName);

	/**
	 * Returns true if this domain object has been closed as a result of the last release
	 * @return true if closed
	 */
	public boolean isClosed();

	/**
	 * Returns true if the user has exclusive access to the domain object.  Exclusive access means
	 * either the object is not shared or the user has an exclusive checkout on the object.
	 * @return true if has exclusive access
	 */
	public boolean hasExclusiveAccess();

	/**
	 * Returns a map containing all the stored metadata associated with this domain object.  The map
	 * contains key,value pairs and are ordered by their insertion order.
	 * @return a map containing all the stored metadata associated with this domain object.
	 */
	public Map<String, String> getMetadata();

	/**
	 * Returns a long value that gets incremented every time a change, undo, or redo takes place.
	 * Useful for implementing a lazy caching system.
	 * @return a long value that is incremented for every change to the program.
	 */
	public long getModificationNumber();

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

	/**
	 * Returns true if there is a previous state to "undo" to.
	 */
	boolean canUndo();

	/**
	 * Returns true if there is a later state to "redo" to.
	 */
	boolean canRedo();

	/**
	 * Clear all undoable/redoable transactions
	 */
	public void clearUndo();

	/**
	 * Returns to the previous state.  Normally, this will cause the current state
	 * to appear on the "redo" stack.  This method will do nothing if there are
	 * no previous states to "undo".
	 * @throws IOException if an IO error occurs
	 */
	void undo() throws IOException;

	/**
	 * Returns to a latter state that exists because of an undo.  Normally, this
	 * will cause the current state to appear on the "undo" stack.  This method
	 * will do nothing if there are no latter states to "redo".
	 * @throws IOException if an IO error occurs
	 */
	void redo() throws IOException;

	/**
	 * Returns a description of the change that would be "undone".
	 * @return a description of the change that would be "undone". 
	 */
	public String getUndoName();

	/**
	 * Returns a description of the change that would be "redone".
	 * @return a description of the change that would be "redone".
	 */
	public String getRedoName();

	/**
	 * Returns a list of the names of all current undo transactions
	 * @return a list of the names of all current undo transactions
	 */
	public List<String> getAllUndoNames();

	/**
	 * Returns a list of the names of all current redo transactions
	 * @return a list of the names of all current redo transactions
	 */
	public List<String> getAllRedoNames();

	/**
	 * Adds the given transaction listener to this domain object
	 * @param listener the new transaction listener to add
	 */
	public void addTransactionListener(TransactionListener listener);

	/**
	 * Removes the given transaction listener from this domain object.
	 * @param listener the transaction listener to remove
	 */
	public void removeTransactionListener(TransactionListener listener);

}
