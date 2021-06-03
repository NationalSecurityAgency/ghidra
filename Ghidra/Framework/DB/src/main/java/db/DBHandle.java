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
package db;

import java.io.File;
import java.io.IOException;
import java.util.Hashtable;
import java.util.Iterator;

import db.buffers.*;
import ghidra.util.Msg;
import ghidra.util.UniversalIdGenerator;
import ghidra.util.datastruct.WeakDataStructureFactory;
import ghidra.util.datastruct.WeakSet;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * <code>DBHandle</code> provides access to an open database.
 */
public class DBHandle {

	protected BufferMgr bufferMgr;
	private DBParms dbParms;
	private MasterTable masterTable;
	private Hashtable<String, Table> tables;

	private long databaseId;  // Universal database identifier introduced with Ghidra 2.3

	private DBHandle scratchPad;

	private WeakSet<DBListener> listenerList = WeakDataStructureFactory.createCopyOnReadWeakSet();

	private long lastTransactionID;
	private boolean txStarted = false;
	private boolean waitingForNewTransaction = false;

	private long checkpointNum;
	private long lastRecoverySnapshotId;

	/**
	 * Construct a temporary database handle.
	 * The saveAs method must be used to save the database.
	 * @throws IOException if a IO error occurs
	 */
	public DBHandle() throws IOException {
		this(BufferMgr.DEFAULT_BUFFER_SIZE, BufferMgr.DEFAULT_CACHE_SIZE);
	}

	/**
	 * Construct a temporary database handle.
	 * The saveAs method must be used to save the database.
	 * @param requestedBufferSize requested buffer size.  Actual buffer size may vary.
	 * @throws IOException if a IO error occurs
	 */
	public DBHandle(int requestedBufferSize) throws IOException {
		this(requestedBufferSize, BufferMgr.DEFAULT_CACHE_SIZE);
	}

	/**
	 * Construct a temporary database handle.
	 * The saveAs method must be used to save the database.
	 * @param requestedBufferSize requested buffer size.  Actual buffer size may vary.
	 * @param approxCacheSize approximate size of cache in Bytes.
	 * @throws IOException if a IO error occurs
	 */
	public DBHandle(int requestedBufferSize, long approxCacheSize) throws IOException {
		bufferMgr =
			new BufferMgr(requestedBufferSize, approxCacheSize, BufferMgr.DEFAULT_CHECKPOINT_COUNT);
		dbParms = new DBParms(bufferMgr, true);
		dbParms.set(DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM, -1);
		masterTable = new MasterTable(this);
		initDatabaseId();
		bufferMgr.clearCheckpoints();
		tables = new Hashtable<>();
	}

	/**
	 * Open the database contained within the specified
	 * bufferFile.  The update mode is determined by the buffer file.
	 * @param bufferFile database buffer file
	 * @throws IOException if IO error occurs
	 */
	public DBHandle(BufferFile bufferFile) throws IOException {
		bufferMgr = new BufferMgr(bufferFile);
		dbParms = new DBParms(bufferMgr, false);
		readDatabaseId();
		if (databaseId == 0 && bufferMgr.canSave()) {
			// Database is updatable - establish missing databaseId
			initDatabaseId();
			bufferMgr.clearCheckpoints();
		}
		masterTable = new MasterTable(this);
		loadTables();
	}

	/**
	 * Open the database contained within the specified
	 * bufferFile.  The update mode is determined by the buffer file.
	 * @param bufferFile database buffer file
	 * @param recover if true an attempt will be made to recover unsaved data if the file is open for update
	 * @param monitor recovery monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if buffer file recovery is cancelled 
	 */
	public DBHandle(BufferFile bufferFile, boolean recover, TaskMonitor monitor)
			throws IOException, CancelledException {
		bufferMgr = new BufferMgr(bufferFile);
		if (bufferMgr.canSave()) {
			if (recover) {
				bufferMgr.recover(monitor);
			}
			else {
				bufferMgr.clearRecoveryFiles();
			}
		}
		dbParms = new DBParms(bufferMgr, false);
		readDatabaseId();
		if (databaseId == 0 && bufferMgr.canSave()) {
			// Database is updatable - establish missing databaseId
			initDatabaseId();
		}
		bufferMgr.clearCheckpoints();
		masterTable = new MasterTable(this);
		loadTables();
	}

	/**
	 * Open a specific buffer file containing a database
	 * for non-update use.  This method is provided primarily
	 * for testing.
	 * @param file buffer file
	 * @throws IOException if IO error occurs
	 */
	public DBHandle(File file) throws IOException {
		BufferFile bfile = new LocalBufferFile(file, true);
		boolean success = false;
		try {
			bufferMgr = new BufferMgr(bfile);
			dbParms = new DBParms(bufferMgr, false);
			readDatabaseId();
			masterTable = new MasterTable(this);
			loadTables();
			success = true;
		}
		finally {
			if (!success) {
				bfile.close();
			}
		}
	}

	/**
	 * Check the consistency of this database.
	 * @param monitor task monitor
	 * @return true if consistency check passed, else false
	 * @throws CancelledException if consistency check is cancelled
	 */
	public boolean isConsistent(TaskMonitor monitor) throws CancelledException {
		int consistentCount = 0;
		for (Table table : getTables()) {
			try {
				if (table.isConsistent(monitor)) {
					++consistentCount;
				}
			}
			catch (IOException e) {
				Msg.error(this,
					"Consistency check error while processing table: " + table.getName(), e);
			}
		}
		return consistentCount == tables.size();
	}

	/**
	 * Rebuild database tables to resolve certain consistency problems.  Use of this
	 * method does not recover lost data which may have occurred during original 
	 * database corruption.
	 * @param monitor task monitor
	 * @return true if rebuild succeeded, else false
	 * @throws CancelledException if rebuild is cancelled
	 */
	public boolean rebuild(TaskMonitor monitor) throws CancelledException {
		for (Table table : getTables()) {
			try {
				table.rebuild(monitor);
			}
			catch (IOException e) {
				Msg.error(this, "Rebuild failed while processing table: " + table.getName(), e);
				return false;
			}
		}
		return true;
	}

	/**
	 * Reset the database ID contained within the specified database file.
	 * This method is intended to be used when unpacking a packed database
	 * to ensure that a duplicate database ID does not exist within the project.
	 * WARNING! Use with extreme caution since this modifies
	 * the original file and could destroy data if used
	 * improperly.
	 * @param file database buffer file to be updated
	 * @throws IOException if IO error occurs
	 */
	public static void resetDatabaseId(File file) throws IOException {
		long databaseId = UniversalIdGenerator.nextID().getValue();
		DBParms.poke(file, DBParms.DATABASE_ID_HIGH_PARM, (int) (databaseId >> 32));
		DBParms.poke(file, DBParms.DATABASE_ID_LOW_PARM, (int) databaseId);
	}

	private void setDatabaseId(long id) throws IOException {
		databaseId = id;
		dbParms.set(DBParms.DATABASE_ID_HIGH_PARM, (int) (databaseId >> 32));
		dbParms.set(DBParms.DATABASE_ID_LOW_PARM, (int) databaseId);
	}

	private void initDatabaseId() throws IOException {
		setDatabaseId(UniversalIdGenerator.nextID().getValue());
	}

	/**
	 * Read current databaseId
	 * @throws IOException if IO error occurs
	 */
	private void readDatabaseId() throws IOException {
		try {
			databaseId = ((long) dbParms.get(DBParms.DATABASE_ID_HIGH_PARM) << 32) +
				(dbParms.get(DBParms.DATABASE_ID_LOW_PARM) & 0x0ffffffffL);
		}
		catch (ArrayIndexOutOfBoundsException e) {
			// DBParams is still at version 1
		}
	}

	/**
	 * @return unique database ID or 0 if this is an older read-only database.
	 */
	public long getDatabaseId() {
		return databaseId;
	}

	/**
	 * Returns the recovery changeSet data file for reading or null if one is not available.
	 * The caller must dispose of the returned file before peforming generating any new
	 * recovery snapshots.
	 * @return recovery changeSet data file for reading or null if one is not available.
	 * @throws IOException if IO error occurs
	 */
	public LocalBufferFile getRecoveryChangeSetFile() throws IOException {
		return bufferMgr.getRecoveryChangeSetFile();
	}

	/**
	 * Request a recovery snapshot be taken of any unsaved changes;
	 * @param changeSet an optional database-backed change set which reflects changes 
	 * made since the last version.
	 * @param monitor task monitor
	 * @return true if snapshot successful or not needed, false if an active transaction prevented snapshot
	 * @throws CancelledException if cancelled by monitor
	 * @throws IOException if IO error occurs
	 */
	public boolean takeRecoverySnapshot(DBChangeSet changeSet, TaskMonitor monitor)
			throws CancelledException, IOException {
		long cpNum;
		synchronized (this) {
			if (!bufferMgr.modifiedSinceSnapshot()) {
				return true;
			}
			if (txStarted) {
				return false;
			}
			if (lastRecoverySnapshotId == checkpointNum) {
				return true;
			}
			cpNum = checkpointNum;
		}
		if (!bufferMgr.takeRecoverySnapshot(changeSet, monitor)) {
			return false;
		}
		synchronized (this) {
			lastRecoverySnapshotId = cpNum;
		}
		return true;
	}

	/**
	 * Returns a shared temporary database handle.
	 * This temporary handle will remain open unitl either this 
	 * handle is closed or closeScratchPad is invoked.
	 * @return shared temporary database handle.
	 * @throws IOException if IO error occurs
	 */
	public DBHandle getScratchPad() throws IOException {
		if (scratchPad == null) {
			scratchPad = new DBHandle();
			scratchPad.startTransaction();
		}
		return scratchPad;
	}

	/**
	 * Close the scratch-pad database handle if it open.
	 */
	public void closeScratchPad() {
		if (scratchPad != null) {
			scratchPad.close();
			scratchPad = null;
		}
	}

	/**
	 * Add Database listener
	 * @param listener database listener
	 */
	public void addListener(DBListener listener) {
		listenerList.add(listener);
	}

	private void dbRestored() {
		for (DBListener listener : listenerList) {
			listener.dbRestored(this);
		}
	}

	private void dbClosed() {
		for (DBListener listener : listenerList) {
			listener.dbClosed(this);
		}
	}

	private void tableAdded(Table table) {
		for (DBListener listener : listenerList) {
			listener.tableAdded(this, table);
		}
	}

	void tableDeleted(Table table) {
		for (DBListener listener : listenerList) {
			listener.tableDeleted(this, table);
		}
	}

	/**
	 * @return the master database table
	 */
	MasterTable getMasterTable() {
		return masterTable;
	}

	/**
	 * @return the buffer manager
	 */
	BufferMgr getBufferMgr() {
		return bufferMgr;
	}

	/**
	 * Enable and start source file pre-cache if appropriate.
	 * WARNING! EXPERIMENTAL !!!
	 */
	public void enablePreCache() {
		bufferMgr.enablePreCache();
	}

	/**
	 * @return the database parameters
	 */
	DBParms getDBParms() {
		return dbParms;
	}

	/**
	 * Verify that a valid transaction has been started.
	 * @throws NoTransactionException if transaction has not been started
	 * @throws TerminatedTransactionException transaction was prematurely terminated
	 */
	public void checkTransaction() {
		if (!txStarted) {
			if (waitingForNewTransaction) {
				throw new TerminatedTransactionException();
			}
			throw new NoTransactionException();
		}
	}

	/**
	 * @return true if transaction is currently active
	 */
	public boolean isTransactionActive() {
		return txStarted;
	}

	/**
	 * Start a new transaction
	 * @return transaction ID
	 */
	public synchronized long startTransaction() {
		if (txStarted) {
			throw new IllegalStateException("Transaction already started");
		}
		waitingForNewTransaction = false;
		txStarted = true;
		return ++lastTransactionID;
	}

	/**
	 * Terminate transaction.  If commit is false, Table instances may be added 
	 * or removed/invalidated.
	 * @param id transaction ID
	 * @param commit if true a new checkpoint will be established, if
	 * false all changes since the previous checkpoint will be discarded.
	 * @return true if new checkpoint established.
	 * @throws IOException if IO error occurs
	 */
	public synchronized boolean endTransaction(long id, boolean commit) throws IOException {
		if (id != lastTransactionID) {
			throw new IllegalStateException("Transaction id is not active");
		}
		try {
			if (bufferMgr != null && !bufferMgr.atCheckpoint()) {
				if (commit) {
					masterTable.flush();
					if (bufferMgr.checkpoint()) {
						++checkpointNum;
						return true;
					}
					return false;
				}
				// rollback
				bufferMgr.undo(false);
				reloadTables();
			}
		}
		finally {
			txStarted = false;
		}
		return false;
	}

	/**
	 * Returns true if there are uncommitted changes to the database.
	 * @return  true if there are uncommitted changes to the database.
	 */
	public synchronized boolean hasUncommittedChanges() {
		return (bufferMgr != null && !bufferMgr.atCheckpoint());
	}

	public synchronized void terminateTransaction(long id, boolean commit) throws IOException {
		endTransaction(id, commit);
		waitingForNewTransaction = true;
	}

	/**
	 * Determine if there are any changes which can be undone.
	 * @return true if an undo can be performed.
	 */
	public boolean canUndo() {
		return !txStarted && bufferMgr != null && bufferMgr.hasUndoCheckpoints();
	}

	/**
	 * Undo changes made during the previous transaction checkpoint.
	 * All upper-levels must clear table-based cached data prior to 
	 * invoking this method.
	 * @return true if an undo was successful
	 * @throws IOException if IO error occurs
	 */
	public synchronized boolean undo() throws IOException {
		if (canUndo() && bufferMgr.undo(true)) {
			++checkpointNum;
			reloadTables();
			return true;
		}
		return false;
	}

	/**
	 * @return number of undo-able transactions
	 */
	public int getAvailableUndoCount() {
		return bufferMgr != null ? bufferMgr.getAvailableUndoCount() : 0;
	}

	/**
	 * @return the number of redo-able transactions
	 */
	public int getAvailableRedoCount() {
		return bufferMgr != null ? bufferMgr.getAvailableRedoCount() : 0;
	}

	/**
	 * Determine if there are any changes which can be redone
	 * @return true if a redo can be performed.
	 */
	public boolean canRedo() {
		return !txStarted && bufferMgr != null && bufferMgr.hasRedoCheckpoints();
	}

	/**
	 * Redo previously undone transaction checkpoint.
	 * Moves forward by one checkpoint only.
	 * All upper-levels must clear table-based cached data prior to 
	 * invoking this method.
	 * @return boolean
	 * @throws IOException if IO error occurs
	 */
	public synchronized boolean redo() throws IOException {
		if (canRedo() && bufferMgr.redo()) {
			++checkpointNum;
			reloadTables();
			return true;
		}
		return false;
	}

	/**
	 * Set the maximum number of undo transaction checkpoints maintained by the
	 * underlying buffer manager.
	 * @param maxUndos maximum number of undo checkpoints.  An illegal 
	 * value restores the default value.
	 */
	public synchronized void setMaxUndos(int maxUndos) {
		bufferMgr.setMaxUndos(maxUndos);
	}

	/**
	 * Return the number of tables defined within the master table.
	 * @return int number of tables.
	 */
	public int getTableCount() {
		return tables.size();
	}

	/**
	 * Revert the current database version to an older version.
	 * @param oldVersion
	 * @param monitor
	 * @return boolean
	 * @throws IllegalStateException if the database has modified prior to
	 * invoking this method.
	 * @throws IllegalArgumentException if this method is invoked more than
	 * once or the version file(s) are corrupt.
	 */
//	boolean revert(int oldVersion, TaskMonitor monitor) throws IOException {
//		for (int v = (version-1); v >= oldVersion; --v) {
//			monitor.setMessage("Processing Version " + v);
//			bufferMgr.applyVersionFile(db.getVersionFile(v), monitor);
//			if (monitor.isCancelled())
//				return false;
//		}
//		return true;
//	}

	/**
	 * Close the database and dispose of the underlying buffer manager.
	 * Any existing recovery data will be discarded.
	 */
	public synchronized void close() {
		close(false);
	}

	/**
	 * Close the database and dispose of the underlying buffer manager.
	 * @param keepRecoveryData true if existing recovery data should be retained or false to remove
	 * any recovery data
	 */
	public synchronized void close(boolean keepRecoveryData) {
		closeScratchPad();
		if (bufferMgr != null) {
			dbClosed();
			bufferMgr.dispose(keepRecoveryData);
			bufferMgr = null;
		}
	}

	/**
	 * @return true if unsaved changes have been made.
	 */
	public synchronized boolean isChanged() {
		return bufferMgr != null && bufferMgr.isChanged();
	}

	/**
	 * @return true if this database handle has been closed.
	 */
	public boolean isClosed() {
		return bufferMgr == null;
	}

	/**
	 * Save this database to a new version.
	 * @param comment if version history is maintained, this comment will be 
	 * associated with the new version.
	 * @param changeSet an optional database-backed change set which reflects changes 
	 * made since the last version.
	 * @param monitor progress monitor
	 * @throws CancelledException if task monitor cancelled operation.
	 * @throws IOException thrown if an IO error occurs.
	 */
	public synchronized void save(String comment, DBChangeSet changeSet, TaskMonitor monitor)
			throws IOException, CancelledException {

//TODO: Does not throw ReadOnlyException - should it?

		if (txStarted) {
			throw new AssertException("Can't save during transaction");
		}

		long txId = startTransaction();
		try {
			masterTable.flush();
		}
		finally {
			endTransaction(txId, true); // saved file may be corrupt on IOException
		}

		bufferMgr.save(comment, changeSet, monitor);
	}

	/**
	 * Save the database to the specified buffer file.
	 * @param outFile buffer file open for writing
	 * @param associateWithNewFile if true the outFile will be associated with this DBHandle as the 
	 * current source file, if false no change will be made to this DBHandle's state and the outFile
	 * will be written and set as read-only.  The caller is responsbile for disposing the outFile if 
	 * this parameter is false.
	 * @param monitor progress monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if monitor cancels operation
	 */
	public synchronized void saveAs(BufferFile outFile, boolean associateWithNewFile,
			TaskMonitor monitor) throws IOException, CancelledException {

		if (txStarted) {
			throw new AssertException("Can't save during transaction");
		}

		long txId = startTransaction();
		boolean addedTx = false;
		try {
			// About to create copy of existing file - assign new databaseId
			if (bufferMgr.getSourceFile() != null) {
				initDatabaseId();
			}
			masterTable.flush();
		}
		finally {
			addedTx = endTransaction(txId, true); // saved file may be corrupt on IOException
		}

		bufferMgr.saveAs(outFile, associateWithNewFile, monitor);

		if (addedTx && !associateWithNewFile) {
			// Restore state and original databaseId
			undo();
			readDatabaseId();
		}
	}

	/**
	 * Save the database to the specified buffer file and a newDatabaseId.
	 * Open handle will always be associated with the new file.
	 * NOTE: This method is intended for use in transforming one database to
	 * match another existing database.
	 * @param outFile buffer file open for writing
	 * @param newDatabaseId database ID to be forced for new database or null to generate 
	 * new database ID
	 * @param monitor progress monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if monitor cancels operation
	 */
	protected synchronized void saveAs(BufferFile outFile, Long newDatabaseId, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (txStarted) {
			throw new IllegalStateException("Can't save during transaction");
		}

		long txId = startTransaction();
		try {
			if (newDatabaseId == null) {
				initDatabaseId();
			}
			else if (databaseId != newDatabaseId.longValue()) {
				setDatabaseId(newDatabaseId);
			}
			masterTable.flush();
		}
		finally {
			endTransaction(txId, true); // saved file may be corrupt on IOException
		}

		bufferMgr.saveAs(outFile, true, monitor);
	}

	/**
	 * Save the database to the specified buffer file.
	 * @param file buffer file to be created
	 * @param associateWithNewFile if true the outFile will be associated with this DBHandle as the 
	 * current source file, if false no change will be made to this DBHandle's state and the outFile
	 * will be written and set as read-only.  The caller is responsbile for disposing the outFile if 
	 * this parameter is false.
	 * @param monitor progress monitor
	 * @throws DuplicateFileException if file already exists.
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if monitor cancels operation
	 */
	public synchronized void saveAs(File file, boolean associateWithNewFile, TaskMonitor monitor)
			throws IOException, CancelledException {

		if (file.exists()) {
			throw new DuplicateFileException("File already exists: " + file);
		}

		LocalBufferFile outFile = new LocalBufferFile(file, bufferMgr.getBufferSize());
		boolean success = false;
		try {
			saveAs(outFile, associateWithNewFile, monitor);
			success = true;
		}
		finally {
			if (!success) {
				outFile.delete();
			}
			else if (!associateWithNewFile) {
				outFile.dispose();
			}
		}
	}

	/**
	 * Create a new buffer with the specified length.
	 * This method may only be invoked while a database transaction 
	 * is in progress. A database transaction must also be in progress
	 * when invoking the various put, delete and setSize methods on the returned buffer.
	 * @param length the size of the buffer to create
	 * @return Buffer the newly created buffer
	 * @throws IOException if an I/O error occurs while creating the buffer.
	 */
	public DBBuffer createBuffer(int length) throws IOException {
		checkTransaction();
		return new DBBuffer(this, new ChainedBuffer(length, true, bufferMgr));
	}

	/**
	 * Create a new buffer that layers on top of another buffer.  This buffer
	 * will return values from the shadowBuffer unless they have been changed in this buffer.
	 * This method may only be invoked while a database transaction 
	 * is in progress. A database transaction must also be in progress
	 * when invoking the various put, delete and setSize methods on the returned buffer.
	 * @param shadowBuffer the source of the byte values to use unless they have been changed.
	 * @return Buffer the newly created buffer
	 * @throws IOException if an I/O error occurs while creating the buffer.
	 */
	public DBBuffer createBuffer(DBBuffer shadowBuffer) throws IOException {
		checkTransaction();
		return new DBBuffer(this,
			new ChainedBuffer(shadowBuffer.length(), true, shadowBuffer.buf, 0, bufferMgr));
	}

	/**
	 * Get an existing buffer.  This method should be used with care to avoid 
	 * providing an improper id.  A database transaction must be in progress
	 * when invoking the various put, delete and setSize methods on the returned buffer.
	 * @param id the buffer id.
	 * @return Buffer the buffer associated with the given id.
	 * @throws IOException if an I/O error occurs while getting the buffer.
	 */
	public DBBuffer getBuffer(int id) throws IOException {
		return new DBBuffer(this, new ChainedBuffer(bufferMgr, id));
	}

	/**
	 * Get an existing buffer that uses a shadowBuffer for byte values if they haven't been
	 * explicitly changed in this buffer.  This method should be used with care to avoid 
	 * providing an improper id.  A database transaction must be in progress
	 * when invoking the various put, delete and setSize methods on the returned buffer.
	 * @param id the buffer id.
	 * @param shadowBuffer the buffer to use for byte values if they haven't been changed in 
	 * this buffer.
	 * @return Buffer the buffer associated with the given id.
	 * @throws IOException if an I/O error occurs while getting the buffer.
	 */
	public DBBuffer getBuffer(int id, DBBuffer shadowBuffer) throws IOException {
		return new DBBuffer(this, new ChainedBuffer(bufferMgr, id, shadowBuffer.buf, 0));
	}

	/**
	 * Determine if this database can be updated.
	 * @return true if this database handle is intended for update
	 */
	public boolean canUpdate() {
		try {
			return bufferMgr != null && bufferMgr.canSave();
		}
		catch (IOException e) {
			return false;
		}
	}

	/**
	 * Load existing tables from database.
	 * @throws IOException thrown if IO error occurs.
	 */
	private void loadTables() throws IOException {

		tables = new Hashtable<>();
		TableRecord[] tableRecords = masterTable.getTableRecords();
		for (TableRecord tableRecord : tableRecords) {

			// Process each primary tables
			if (tableRecord.getIndexedColumn() < 0) {
				Table table = new Table(this, tableRecord);
				tables.put(table.getName(), table);
			}
			else {	//secondary table indexes
				IndexTable.getIndexTable(this, tableRecord);
			}
		}
	}

	/**
	 * Reload tables from database following an undo or redo.
	 * @throws IOException thrown if IO error occurs.
	 */
	private void reloadTables() throws IOException {

		dbParms.refresh();

		Hashtable<String, Table> oldTables = tables;
		tables = new Hashtable<>();
		TableRecord[] tableRecords = masterTable.refreshTableRecords();
		for (TableRecord tableRecord : tableRecords) {

			String tableName = tableRecord.getName();

			// Process each primary tables
			if (tableRecord.getIndexedColumn() < 0) {
				Table t = oldTables.get(tableName);
				if (t == null || t.isInvalid()) {
					oldTables.remove(tableName);
					t = new Table(this, tableRecord);
					tableAdded(t);
				}
				tables.put(tableName, t);
			}

			// secondary table indexes
			else if (!oldTables.containsKey(tableName)) {
				IndexTable.getIndexTable(this, tableRecord);
			}
		}
		dbRestored();
	}

	/**
	 * Returns the Table that was created with the given name or null if
	 * no such table exists.
	 * @param name of requested table
	 * @return table instance or null if not found
	 */
	public Table getTable(String name) {
		return tables.get(name);
	}

	/**
	 * Get all tables defined within the database.
	 * @return Table[] tables
	 */
	public Table[] getTables() {
		Table[] t = new Table[tables.size()];

		Iterator<Table> it = tables.values().iterator();
		int i = 0;
		while (it.hasNext()) {
			t[i++] = it.next();
		}
		return t;
	}

	/**
	 * Creates a new table with the given name and schema.
	 * @param name table name
	 * @param schema table schema
	 * @return new table instance
	 * @throws IOException if IO error occurs during table creation
	 */
	public Table createTable(String name, Schema schema) throws IOException {
		return createTable(name, schema, null);
	}

	/**
	 * Creates a new table with the given name and schema.
	 * Create secondary indexes as specified by the array of column indexes.
	 * @param name table name
	 * @param schema table schema
	 * @param indexedColumns array of column indices which should have an index associated with them
	 * @return new table instance
	 * @throws IOException if IO error occurs during table creation
	 */
	public synchronized Table createTable(String name, Schema schema, int[] indexedColumns)
			throws IOException {

		if (tables.containsKey(name)) {
			throw new IOException("Table already exists");
		}
		Table table = new Table(this, masterTable.createTableRecord(name, schema, -1));
		tables.put(name, table);
		if (indexedColumns != null) {
			for (int indexedColumn : indexedColumns) {
				IndexTable.createIndexTable(table, indexedColumn);
			}
		}
		tableAdded(table);
		return table;
	}

	/**
	 * Changes the name of an existing table.
	 * @param oldName the old name of the table
	 * @param newName the new name of the table
	 * @throws DuplicateNameException if a table with the new name already exists
	 * @return true if the name was changed successfully
	 */
	public synchronized boolean setTableName(String oldName, String newName)
			throws DuplicateNameException {
		if (!tables.containsKey(oldName)) {
			return false;
		}
		checkTransaction();
		if (tables.containsKey(newName)) {
			throw new DuplicateNameException("Table already exists");
		}
		Table table = tables.remove(oldName);
		if (table == null) {
			return false;
		}
		masterTable.changeTableName(oldName, newName);
		tables.put(newName, table);
		return true;
	}

	/**
	 * Delete the specified table from the database.
	 * @param name table name
	 * @throws IOException if there is an I/O error or the table does not exist
	 */
	public synchronized void deleteTable(String name) throws IOException {
		Table table = tables.get(name);
		if (table == null) {
			return;
		}
		int[] indexedColumns = table.getIndexedColumns();
		for (int indexedColumn : indexedColumns) {
			table.removeIndex(indexedColumn);
		}
		table.deleteAll();
		masterTable.deleteTableRecord(table.getTableNum());
		tables.remove(name);
	}

	/**
	 * @return number of buffer cache hits
	 */
	public long getCacheHits() {
		return bufferMgr.getCacheHits();
	}

	/**
	 * @return number of buffer cache misses
	 */
	public long getCacheMisses() {
		return bufferMgr.getCacheMisses();
	}

	/**
	 * @return low water mark (minimum buffer pool size)
	 */
	public int getLowBufferCount() {
		return bufferMgr.getLowBufferCount();
	}

	/*
	 * @see java.lang.Object#finalize()
	 */
	@Override
	protected void finalize() throws Throwable {
		close(true);
	}

	/**
	 * Returns size of buffers utilized within the underlying
	 * buffer file.  This may be larger than than the requested 
	 * buffer size.  This value may be used to instatiate a 
	 * new BufferFile which is compatible with this database
	 * when using the saveAs method.
	 * @return buffer size utilized by this database
	 */
	public int getBufferSize() {
		return bufferMgr.getBufferSize();
	}

}
