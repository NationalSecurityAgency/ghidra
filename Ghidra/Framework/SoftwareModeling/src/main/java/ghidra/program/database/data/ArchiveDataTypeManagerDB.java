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
package ghidra.program.database.data;

import java.io.IOException;
import java.util.*;

import db.DBHandle;
import db.Transaction;
import db.util.ErrorHandler;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.RuntimeIOException;
import ghidra.program.database.DBStringMapAdapter;
import ghidra.program.database.dtarchive.DataTypeStoreDBModule;
import ghidra.program.database.dtarchive.DataTypeArchiveDB;
import ghidra.program.model.data.*;
import ghidra.program.model.dtarchive.DataTypeArchive;
import ghidra.program.model.lang.LanguageVersionException;
import ghidra.program.util.ProgramEvent;
import ghidra.util.Lock;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Basic implementation of the DataTypeManger interface for those data type managers that
 * originate in an archive and not a program.
 */
public abstract class ArchiveDataTypeManagerDB extends DataTypeManagerDB
		implements ArchiveDataTypeManager, DataTypeStoreDBModule {

	protected DataTypeArchiveDB archive;

	private boolean detectedReadOnlyDataOrgChange;

	/**
	 * Constructor for a transient data-type manager instance using a new {@link DBHandle}.
	 * 
	 * @throws RuntimeIOException if there is a problem creating the database
	 */
	protected ArchiveDataTypeManagerDB() throws RuntimeIOException {
		super();
	}

	/**
	 * Constructor for a data-type manager using a specified DBHandle.
	 *
	 * @param handle open database  handle
	 * @param openMode open mode CREATE, READ_ONLY or UPDATE
	 * @param errHandler the database I/O error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if task cancelled
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database I/O error occurs.
	 */
	protected ArchiveDataTypeManagerDB(DBHandle handle, OpenMode openMode,
			ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		super(handle, openMode, null, null, errHandler, lock, monitor);
		if (openMode != OpenMode.CREATE && hasDataOrganizationChange(true)) {
			handleDataOrganizationChange(openMode, monitor);
		}
	}

	/**
	 * Get the manager's data map which may be needed by DtArchiveDB to access properties
	 * which get migrated to DtArchiveDB's data map during an upgrade.  This data map is used to
	 * retain a copy of the data organization and had previously been used 
	 * @return manager's data map if one exists
	 * @throws IOException if an IO error occurs
	 */
	public DBStringMapAdapter getDataMap() throws IOException {
		return getDataMap(false);
	}

	/**
	 * Save the current data organization to facilitate future change detection and 
	 * upgrades.  This method must be invoked by {@link DataTypeArchiveDB} during the final
	 * stage of archive creation (i.e., openMode == CREATE).
	 * @throws IOException if failure occurred while saving data organization.
	 */
	@Override
	public void saveDataOrganization() throws IOException {
		super.saveDataOrganization();
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		invalidateCache();
	}

	@Override
	public void setDomainObject(DataTypeArchiveDB archive) {
		this.archive = archive;
		try {
			// Set the program architecture for this datatype manager as established 
			// by the archive during its instantiation process.  Any architecture related
			// upgrades/changes must already be complete.

			//
			// NOTE: There are currently two facets that are affected by a language
			// version change:
			//
			// 1. Variable storage upgrades - handled by StandAloneDataStoreDB during 
			//    architecture initialization (e.g., register address changes),
			//
			// 2. Data organization changes - handled at time of ArchivDataTypeManagerDB 
			//    instantiation by handleDataOrganizationChange method.
			//

			setProgramArchitecture(archive.getProgramArchitecture(),
				archive.getVariableStorageManager(), false, TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertException(e); // unexpected - no IO performed
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
	}

	@Override
	public void domainObjectReady(OpenMode openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode == OpenMode.UPGRADE) {
			doSourceArchiveUpdates(monitor);
			migrateOldFlexArrayComponentsIfRequired(monitor);
		}
	}

	@Override
	public DataTypeArchive getDataStore() {
		return archive;
	}

	/**
	 * Complete changes related to an archive's change in program architecture.
	 * <p>
	 * The data organization will be obtained from the compiler spec specified by
	 * the program architecture.  Fixup of all composites will be performed, if store is
	 * true, to reflect any changes in the data organization.
	 * The caller is responsible for ensuring that this setting is done consistent 
	 * with the {@link #addrMap} setting used during construction if applicable.
	 * <br>
	 * If not storing caller may need to check for data organization change to communicate
	 * change or to facilitate an upgrade situation.
	 * 
	 * @param monitor the task monitor
	 * @throws CancelledException if the change is cancelled
	 * @throws IOException if an I/O exception occurs during the operation
	 */
	public void programArchitectureChanged(TaskMonitor monitor)
			throws CancelledException, IOException {
		lock.writeLock().lock();
		try {
			setProgramArchitecture(archive.getProgramArchitecture(),
				archive.getVariableStorageManager(), true, monitor);
		}
		finally {
			invalidateCache();
			lock.writeLock().unlock();
		}
	}

	@Override
	protected void handleDataOrganizationChange(OpenMode openMode, TaskMonitor monitor)
			throws LanguageVersionException, CancelledException, IOException {
		if (openMode == OpenMode.IMMUTABLE) {
			detectedReadOnlyDataOrgChange = true;
		}
		super.handleDataOrganizationChange(openMode, monitor);
	}

	public boolean hasReadOnlyDataOrgChange() {
		return detectedReadOnlyDataOrgChange;
	}

	/**
	 * Determine if a program architecture change is permitted
	 * @return true if change allowed else false if disallowed
	 */
	protected boolean isArchitectureChangeAllowed() {
		return true;
	}

	@Override
	public String getName() {
		return archive.getName();
	}

	@Override
	public Transaction openTransaction(String description) throws IllegalStateException {
		return archive.openTransaction(description);
	}

	@Override
	public int startTransaction(String description) {
		return archive.startTransaction(description);
	}

	@Override
	public boolean endTransaction(int transactionID, boolean commit) {
		return archive.endTransaction(transactionID, commit);
	}

	@Override
	public void undo() {
		try {
			archive.undo();
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	@Override
	public void redo() {
		try {
			archive.redo();
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	/**
	 * Determine if there is a transaction previously undone (see {@link #undo()}) that can be 
	 * redone (see {@link #redo()}).
	 * 
	 * @return true if there is a transaction previously undone that can be redone, else false
	 */
	@Override
	public boolean canRedo() {
		return archive.canRedo();
	}

	/**
	 * Determine if there is a previous transaction that can be reverted/undone (see {@link #undo()}).
	 * 
	 * @return true if there is a previous transaction that can be reverted/undone, else false.
	 */
	@Override
	public boolean canUndo() {
		return archive.canUndo();
	}

	/**
	 * Get the transaction name that is available for {@link #redo()} (see {@link #canRedo()}).
	 * @return transaction name that is available for {@link #redo()} or empty String.
	 */
	@Override
	public String getRedoName() {
		return archive.getRedoName();
	}

	/**
	 * Get the transaction name that is available for {@link #undo()} (see {@link #canUndo()}).
	 * @return transaction name that is available for {@link #undo()} or empty String.
	 */
	@Override
	public String getUndoName() {
		return archive.getRedoName();
	}

	/**
	 * Get all transaction names that are available within the {@link #undo()} stack.
	 * 
	 * @return all transaction names that are available within the {@link #undo()} stack.
	 */
	@Override
	public synchronized List<String> getAllUndoNames() {
		return archive.getAllUndoNames();
	}

	/**
	 * Get all transaction names that are available within the {@link #redo()} stack.
	 * 
	 * @return all transaction names that are available within the {@link #redo()} stack.
	 */
	@Override
	public synchronized List<String> getAllRedoNames() {
		return archive.getAllRedoNames();
	}

	@Override
	public void flushEvents() {
		archive.flushEvents();
	}

	@Override
	public void dataTypeChanged(DataType dt, boolean isAutoChange) {
		super.dataTypeChanged(dt, isAutoChange);
		// NOTE: During upgrades at time of instantiation dataTypeArchive will be null
		if (archive != null) {
			archive.dataTypeChanged(getID(dt), ProgramEvent.DATA_TYPE_CHANGED, isAutoChange,
				null, dt);
		}
	}

	@Override
	protected void dataTypeAdded(DataType newDt, DataType originalDataType) {
		super.dataTypeAdded(newDt, originalDataType);
		archive.dataTypeAdded(getID(newDt), ProgramEvent.DATA_TYPE_ADDED, null, newDt);
	}

	@Override
	protected void dataTypeReplaced(long existingDtID, DataTypePath existingPath,
			DataType replacementDt) {
		super.dataTypeReplaced(existingDtID, existingPath, replacementDt);
		archive.dataTypeChanged(existingDtID, ProgramEvent.DATA_TYPE_REPLACED, false,
			existingPath, replacementDt);
	}

	@Override
	protected void dataTypeDeleted(long deletedID, DataTypePath deletedDataTypePath) {
		super.dataTypeDeleted(deletedID, deletedDataTypePath);
		archive.dataTypeChanged(deletedID, ProgramEvent.DATA_TYPE_REMOVED, false,
			deletedDataTypePath, null);
	}

	@Override
	protected void dataTypeMoved(DataType dt, DataTypePath oldPath, DataTypePath newPath) {
		super.dataTypeMoved(dt, oldPath, newPath);
		Category category = getCategory(oldPath.getCategoryPath());
		archive.dataTypeChanged(getID(dt), ProgramEvent.DATA_TYPE_MOVED, false, category,
			dt);
	}

	@Override
	protected void dataTypeNameChanged(DataType dt, String oldName) {
		super.dataTypeNameChanged(dt, oldName);
		archive.dataTypeChanged(getID(dt), ProgramEvent.DATA_TYPE_RENAMED, false, oldName,
			dt);
	}

	@Override
	protected void categoryCreated(Category newCategory) {
		super.categoryCreated(newCategory);
		archive.categoryAdded(newCategory.getID(), ProgramEvent.DATA_TYPE_CATEGORY_ADDED,
			newCategory.getParent(), newCategory);
	}

	@Override
	protected void categoryRenamed(CategoryPath oldPath, Category category) {
		super.categoryRenamed(oldPath, category);
		archive.categoryChanged(category.getID(), ProgramEvent.DATA_TYPE_CATEGORY_RENAMED,
			oldPath.getName(), category);
	}

	@Override
	protected void categoryRemoved(Category parent, String categoryName, long categoryID) {
		super.categoryRemoved(parent, categoryName, categoryID);
		archive.categoryChanged(categoryID, ProgramEvent.DATA_TYPE_CATEGORY_REMOVED, parent,
			categoryName);
	}

	@Override
	protected void categoryMoved(CategoryPath oldPath, Category category) {
		super.categoryMoved(oldPath, category);
		archive.categoryChanged(category.getID(), ProgramEvent.DATA_TYPE_CATEGORY_MOVED,
			oldPath.getParent(), category);
	}

	@Override
	protected void replaceDataTypesUsed(Map<Long, Long> dataTypeReplacementMap) {
		// do nothing
	}

	@Override
	protected void deleteDataTypesUsed(Set<Long> deletedIds) {
		// do nothing
	}

	@Override
	protected String getDomainFileID() {
		return null;
	}

	/**
	 * Update custom storage for function definitions to be unassigned.
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled
	 */
	public void clearCustomStorageUse(TaskMonitor monitor) throws CancelledException {
		// This method is for future development related to custom storage
//
//		lock.writeLock().lock();
//		try {
//
//			// Get copy of all function defs to avoid concurrent modification of underlaying table
//			List<FunctionDefinition> defs = CollectionUtils.asList(getAllFunctionDefinitions());
//
//			monitor.initialize(defs.size());
//			monitor.setMessage("Clear custom storage use...");
//
//			//		for (FunctionDefinition def : ImmutableList.copyOf(getAllFunctionDefinitions())) {
//			monitor.checkCancelled();
//			//			monitor.incrementProgress(1);
//			//
//			//			// TODO: update function definition
//			//			if (def.hasCustomStorage()) {
//			//				
//			//				
//			//			}
//			//		}
//
//		}
//		finally {
//			invalidateCache();
//			lock.writeLock().unlock();
//		}
//
	}

}
