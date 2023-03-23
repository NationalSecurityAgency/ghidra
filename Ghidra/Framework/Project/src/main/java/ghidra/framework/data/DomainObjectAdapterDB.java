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

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.function.Function;

import db.*;
import db.util.ErrorHandler;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.SubOptions;
import ghidra.framework.store.LockException;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.util.Msg;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Database version of the DomainObjectAdapter; this version adds the
 * concept of starting a transaction before a change is made to the
 * domain object and ending the transaction. The transaction allows for
 * undo/redo changes.
 *
 * The implementation class must also satisfy the following requirements:
 * <pre>
 *
 * 1. The following constructor signature must be implemented:
 *
 * 		 **
 *		 * Constructs new Domain Object
 *		 * @param dbh a handle to an open domain object database.
 *		 * @param openMode one of:
 *		 * 		READ_ONLY: the original database will not be modified
 *		 * 		UPDATE: the database can be written to.
 *		 * 		UPGRADE: the database is upgraded to the latest schema as it is opened.
 *		 * @param monitor TaskMonitor that allows the open to be cancelled.
 *	     * @param consumer the object that keeping the program open.
 *		 *
 *		 * @throws IOException if an error accessing the database occurs.
 *		 * @throws VersionException if database version does not match implementation. UPGRADE may be possible.
 *		 **
 *		 public DomainObjectAdapterDB(DBHandle dbh, int openMode, TaskMonitor monitor, Object consumer) throws IOException, VersionException
 *
 * 2. The following static field must be provided:
 *
 * 		 public static final String CONTENT_TYPE
 *
 * </pre>
 */
public abstract class DomainObjectAdapterDB extends DomainObjectAdapter
		implements UndoableDomainObject, ErrorHandler, DBConstants {

	protected static final int NUM_UNDOS = 50;

	protected DBHandle dbh;

	protected DomainObjectDBChangeSet changeSet;

	protected OptionsDB options;

	volatile boolean closed = false;

	private volatile boolean fatalErrorOccurred = false;

	private AbstractTransactionManager transactionMgr;

	//
	// This exception handler will sleep, allowing the startTransaction() method to ignore
	// the exception and then try again, since it is using a while(true) loop.   This can
	// happen if clients try to start a transaction during a long running operation, such as
	// a program save.
	//
	Function<DomainObjectLockedException, Boolean> tryForeverExceptionHandler = e -> {
		try {
			Thread.sleep(100);
		}
		catch (InterruptedException ie) {
			Msg.debug(this, "Thread interrupted while waiting for program lock: '" +
				Thread.currentThread().getName() + "'", ie);
		}
		return true;
	};

	/**
	 * Construct a new DomainObjectAdapterDB object.
	 * If construction of this object fails, be sure to release with consumer
	 * @param dbh database handle
	 * @param name name of the domain object
	 * @param timeInterval the time (in milliseconds) to wait before the
	 * event queue is flushed.  If a new event comes in before the time expires,
	 * the timer is reset.
	 * @param consumer the object that created this domain object
	 */
	protected DomainObjectAdapterDB(DBHandle dbh, String name, int timeInterval, Object consumer) {
		super(name, timeInterval, consumer);
		this.dbh = dbh;
		options = new OptionsDB(this);
		transactionMgr = new DomainObjectTransactionManager(this);
	}

	void setTransactionManager(AbstractTransactionManager transactionMgr) {
		this.transactionMgr = transactionMgr;
	}

	AbstractTransactionManager getTransactionManager() {
		return transactionMgr;
	}

	/**
	 * Flush any pending database changes.
	 * This method will be invoked by the transaction manager
	 * prior to closing a transaction.
	 */
	public void flushWriteCache() {
	}

	/**
	 * Invalidate (i.e., clear) any pending database changes not yet written.
	 * This method will be invoked by the transaction manager
	 * prior to aborting a transaction.
	 */
	public void invalidateWriteCache() {
	}

	/**
	 * Return array of all domain objects synchronized with a
	 * shared transaction manager.
	 * @return returns array of synchronized domain objects or
	 * null if this domain object is not synchronized with others.
	 */
	@Override
	public DomainObject[] getSynchronizedDomainObjects() {
		if (transactionMgr instanceof SynchronizedTransactionManager) {
			return transactionMgr.getDomainObjects();
		}
		return null;
	}

	/**
	 * Synchronize the specified domain object with this domain object
	 * using a shared transaction manager.  If either or both is already shared,
	 * a transition to a single shared transaction manager will be
	 * performed.
	 * @param domainObj
	 * @throws LockException if lock or open transaction is active on either
	 * this or the specified domain object
	 */
	@Override
	public void addSynchronizedDomainObject(DomainObject domainObj) throws LockException {
		if (!(domainObj instanceof DomainObjectAdapterDB)) {
			Msg.debug(this,
				"Attempted to synchronize to a domainObject that is not a domainObjectDB: " +
					domainObj.getClass());
			return;
		}

		DomainObjectAdapterDB other = (DomainObjectAdapterDB) domainObj;
		SynchronizedTransactionManager manager;
		if (transactionMgr instanceof SynchronizedTransactionManager) {
			if (!(other.transactionMgr instanceof DomainObjectTransactionManager)) {
				throw new IllegalStateException();
			}
			manager = (SynchronizedTransactionManager) transactionMgr;
			manager.addDomainObject(other);
		}
		else if (other.transactionMgr instanceof SynchronizedTransactionManager) {
			if (!(transactionMgr instanceof DomainObjectTransactionManager)) {
				throw new IllegalStateException();
			}
			manager = (SynchronizedTransactionManager) other.transactionMgr;
			manager.addDomainObject(this);
		}
		else {
			manager = new SynchronizedTransactionManager();
			manager.addDomainObject(this);
			manager.addDomainObject(other);
		}
	}

	/**
	 * Release this domain object from a shared transaction manager.  If
	 * this object has not been synchronized with others via a shared
	 * transaction manager, this method will have no affect.
	 * @throws LockException if lock or open transaction is active
	 */
	@Override
	public void releaseSynchronizedDomainObject() throws LockException {
		if (!(transactionMgr instanceof SynchronizedTransactionManager)) {
			return;
		}
		((SynchronizedTransactionManager) transactionMgr).removeDomainObject(this);
	}

	/**
	 * Returns the open handle to the underlying database.
	 */
	public DBHandle getDBHandle() {
		return dbh;
	}

	/**
	 * Returns the user data object or null if not supported by this domain object.
	 */
	protected DomainObjectAdapterDB getUserData() {
		return null;
	}

	/**
	 * Returns the change set corresponding to all unsaved changes in this domain object.
	 * @return the change set corresponding to all unsaved changes in this domain object
	 */
	public DomainObjectDBChangeSet getChangeSet() {
		return changeSet;
	}

	@Override
	public void dbError(IOException e) {
		fatalErrorOccurred = true;
		fatalErrorOccurred(e);
	}

	/**
	 * Returns all properties lists contained by this domain object.
	 *
	 * @return all property lists contained by this domain object.
	 */
	@Override
	public List<String> getOptionsNames() {
		List<Options> childOptions = options.getChildOptions();
		List<String> names = new ArrayList<>(childOptions.size());
		for (Options options : childOptions) {
			names.add(options.getName());
		}
		return names;
	}

	@Override
	public Options getOptions(String propertyListName) {
		return new SubOptions(options, propertyListName, propertyListName + Options.DELIMITER);
	}

	/**
	 * This method can be used to perform property list alterations resulting from renamed or obsolete
	 * property paths.  This should only be invoked during an upgrade.
	 * WARNING! Should only be called during construction of domain object
	 * @see OptionsDB#performAlterations(Map)
	 */
	protected void performPropertyListAlterations(Map<String, String> propertyAlterations,
			TaskMonitor monitor) throws IOException {
		monitor.setProgress(0);
		monitor.setMessage("Fixing Properties...");
		options.performAlterations(propertyAlterations);
	}

	@Override
	public boolean canLock() {
		return transactionMgr.getCurrentTransactionInfo() == null && !closed;
	}

	@Override
	public boolean isLocked() {
		return transactionMgr.isLocked();
	}

	@Override
	public boolean lock(String reason) {
		return transactionMgr.lock(reason);
	}

	void prepareToSave() {
		int txId = transactionMgr.startTransaction(this, "Update Metadata", null, true, true);
		try {
			updateMetadata();
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			transactionMgr.endTransaction(this, txId, true, true);
		}
	}

	/**
	 * Attempt to obtain a modification lock on the domain object when generating a
	 * background snapshot.
	 * @param hasProgress true if monitor has progress indicator
	 * @param title title to be used for monitor
	 * @return monitor object if lock obtained successfully, else null which indicates that a
	 * modification is in process.
	 */
	LockingTaskMonitor lockForSnapshot(boolean hasProgress, String title) {
		return transactionMgr.lockForSnapshot(this, hasProgress, title);
	}

	@Override
	public void forceLock(boolean rollback, String reason) {
		transactionMgr.forceLock(rollback, reason);
	}

	@Override
	public void unlock() {
		transactionMgr.unlock();
	}

	/**
	 * Release the modification lock which is associated with the specified LockingTaskHandler.
	 */
	void unlock(LockingTaskMonitor handler) {
		transactionMgr.unlock(handler);
	}

	@Override
	public Transaction openTransaction(String description)
			throws TerminatedTransactionException, IllegalStateException {
		return new Transaction() {

			int txId = startTransaction(description);

			@Override
			protected boolean endTransaction(boolean commit) {
				DomainObjectAdapterDB.this.endTransaction(txId, commit);
				return commit;
			}

			@Override
			public boolean isSubTransaction() {
				return true;
			}
		};
	}

	@Override
	public int startTransaction(String description) throws TerminatedTransactionException {
		return startTransaction(description, null);
	}

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener)
			throws TerminatedTransactionException {
		return startTransaction(description, listener, tryForeverExceptionHandler);
	}

	// open for testing
	int startTransaction(String description, AbortedTransactionListener listener,
			Function<DomainObjectLockedException, Boolean> exceptionHandler)
			throws TerminatedTransactionException {

		while (true) {
			try {
				return transactionMgr.startTransaction(this, description, listener, true);
			}
			catch (DomainObjectLockedException e) {
				if (!exceptionHandler.apply(e)) {
					return -1;
				}
			}
		}
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) throws IllegalStateException {
		transactionMgr.endTransaction(this, transactionID, commit, true);
	}

	/**
	 * Adds the given transaction listener to this domain object
	 * @param listener the new transaction listener to add
	 */
	@Override
	public void addTransactionListener(TransactionListener listener) {
		transactionMgr.addTransactionListener(this, listener);
	}

	/**
	 * Removes the given transaction listener from this domain object.
	 * @param listener the transaction listener to remove
	 */
	@Override
	public void removeTransactionListener(TransactionListener listener) {
		transactionMgr.removeTransactionListener(this, listener);
	}

	/**
	 * Returns the undo stack depth.
	 * (The number of items on the undo stack)
	 * This method is for JUnits.
	 * @return the undo stack depth
	 */
	public int getUndoStackDepth() {
		return transactionMgr.getUndoStackDepth();
	}

	@Override
	public boolean canRedo() {
		return transactionMgr.canRedo();
	}

	@Override
	public boolean canUndo() {
		return transactionMgr.canUndo();
	}

	@Override
	public String getRedoName() {
		return transactionMgr.getRedoName();
	}

	@Override
	public String getUndoName() {
		return transactionMgr.getUndoName();
	}

	@Override
	public TransactionInfo getCurrentTransactionInfo() {
		return transactionMgr.getCurrentTransactionInfo();
	}

	@Override
	public void redo() throws IOException {
		transactionMgr.redo();
	}

	@Override
	public void undo() throws IOException {
		transactionMgr.undo();
	}

	@Override
	public boolean isChanged() {
		if (dbh == null) {
			return false;
		}
		return super.isChanged() && dbh.isChanged();
	}

	@Override
	protected void setChanged(boolean b) {
		super.setChanged(b);
		if (!b) {
			clearUndo(true);
		}
	}

	/**
	 * Notification of property change
	 * @param propertyName
	 * @param oldValue
	 * @param newValue
	 * @return true if change is OK, false value should be reverted
	 */
	protected boolean propertyChanged(String propertyName, Object oldValue, Object newValue) {
		setChanged(true);
		fireEvent(
			new DomainObjectChangeRecord(DomainObject.DO_PROPERTY_CHANGED, propertyName, newValue));
		return true;
	}

	@Override
	public void clearUndo() {
		clearUndo(true);
	}

	protected void clearUndo(boolean notifyListeners) {
		transactionMgr.clearUndo(notifyListeners);
	}

	protected void clearCache(boolean all) {
		options.clearCache();
	}

	@Override
	public synchronized boolean canSave() {
		DomainFile df = getDomainFile();
		if (df instanceof GhidraFile) {
			return df.isInWritableProject() && dbh.canUpdate() && !df.isReadOnly();
		}
		return dbh.canUpdate();
	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {
		if (!canSave()) {
			throw new ReadOnlyException("File is read-only");
		}

		boolean wasSaved = false;
		if (!lock("save")) {
			throw new IOException("Unable to lock due to active transaction");
		}
		try {

			synchronized (this) {
				if (changed) {
					dbh.save(comment, getChangeSet(), monitor);
					setChanged(false);
					wasSaved = true;
				}
			}

			DomainObjectAdapterDB userData = getUserData();
			if (userData != null && userData.isChanged()) {
				userData.save(comment, monitor);
			}
		}
		finally {
			unlock();
		}

		if (wasSaved) {
			fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_SAVED));

			DomainFile df = getDomainFile();
			if (df instanceof GhidraFile) {
				((GhidraFile) df).fileChanged();
			}
		}
	}

	@Override
	public void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException {

		transactionMgr.checkLockingTask();

		if (!lock("saveToPackedFile")) {
			throw new IOException("Unable to lock due to active transaction");
		}
		try {

			ContentHandler ch = DomainObjectAdapter.getContentHandler(this);
			PackedDatabase.packDatabase(dbh, name, ch.getContentType(), outputFile, monitor);

			// TODO :( output method will cause Redo-able transactions to be cleared
			// and may cause older Undo-able transactions to be cleared.
			// Should implement transaction listener to properly maintain domain object
			// transaction sychronization

		}
		finally {
			unlock();
		}
	}

	/**
	 * This method is called before a save, saveAs, or saveToPackedFile
	 * to update common meta data
	 * @throws IOException
	 */
	protected void updateMetadata() throws IOException {
		saveMetadata();
	}

	@Override
	protected void close() {

		synchronized (transactionMgr) {
			transactionMgr.close(this);
			closed = true;
		}

		DomainObjectAdapterDB userData = getUserData();
		if (userData != null && userData.isChanged() && (getDomainFile() instanceof GhidraFile)) {
			try {
				userData.prepareToSave();
				userData.save(null, TaskMonitor.DUMMY);
			}
			catch (CancelledException e) {
			}
			catch (IOException e) {
				Msg.warn(this, "Failed to save user data for: " + getDomainFile().getName());
			}
		}

		super.close();
		dbh.close(fatalErrorOccurred);

		if (userData != null) {
			userData.close();
		}
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	public boolean hasTerminatedTransaction() {
		return transactionMgr.hasTerminatedTransaction();
	}

	protected void loadMetadata() throws IOException {
		MetadataManager.loadData(this, metadata);
	}

	protected void saveMetadata() throws IOException {
		MetadataManager.saveData(this, metadata);
	}
}
