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
package ghidra.program.database;

import java.io.IOException;
import java.util.LinkedList;

import javax.help.UnsupportedOperationException;

import db.*;
import db.util.ErrorHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.store.LockException;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.DataTypeArchiveChangeManager;
import ghidra.util.InvalidNameException;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for managing data types in a project archive
 * NOTE: default data organization is used.
 */
public class ProjectDataTypeManager extends StandAloneDataTypeManager
		implements ProjectArchiveBasedDataTypeManager {

	private final DataTypeArchiveDB dataTypeArchive;

	/**
	 * Constructor for a data-type manager using a specified DBHandle.
	 * <p>
	 * <B>NOTE:</B> If archive has an assigned architecture, issues may arise due to a revised or
	 * missing {@link Language}/{@link CompilerSpec} which will result in a warning but not
	 * prevent the archive from being opened.  Such a warning condition will ne logged and may 
	 * result in missing or stale information for existing datatypes which have architecture related
	 * data.  In some case it may be appropriate to 
	 * {@link FileDataTypeManager#getWarning() check for warnings} on the returned archive
	 * object prior to its use.
	 * 
	 * @param dataTypeArchive associated archive
	 * @param handle open database  handle
	 * @param openMode the program open mode
	 * @param errHandler the database I/O error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database I/O error occurs.
	 */
	ProjectDataTypeManager(DataTypeArchiveDB dataTypeArchive, DBHandle handle, int openMode,
			ErrorHandler errHandler, Lock lock,
			TaskMonitor monitor) throws CancelledException, VersionException, IOException {
		super(handle, openMode, errHandler, lock, monitor);
		this.dataTypeArchive = dataTypeArchive;
		reportWarning();
	}

	@Override
	public String getName() {
		return dataTypeArchive.getDomainFile().getName();
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		if (name == null || name.length() == 0) {
			throw new InvalidNameException("Name is invalid: " + name);
		}

		dataTypeArchive.setName(name);
		categoryRenamed(CategoryPath.ROOT, null);
	}

	@Override
	public void clearProgramArchitecture(TaskMonitor monitor)
			throws CancelledException, IOException, LockException {
		dataTypeArchive.checkExclusiveAccess();
		super.clearProgramArchitecture(monitor);
	}

	@Override
	public void setProgramArchitecture(Language language, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			LockException, UnsupportedOperationException, IncompatibleLanguageException,
			CancelledException {
		dataTypeArchive.checkExclusiveAccess();
		super.setProgramArchitecture(language, compilerSpecId, updateOption, monitor);
	}

	////////////////////
	@Override
	public void dataTypeChanged(DataType dt, boolean isAutoChange) {
		super.dataTypeChanged(dt, isAutoChange);
//		dataTypeArchive.getCodeManager().invalidateCache(false);
		// TODO
		dataTypeArchive.dataTypeChanged(getID(dt),
			DataTypeArchiveChangeManager.DOCR_DATA_TYPE_CHANGED, isAutoChange, null, dt);
	}

	@Override
	protected void dataTypeAdded(DataType newDt, DataType originalDataType) {
		super.dataTypeAdded(newDt, originalDataType);
//		saveArchiveName(originalDataType);
		dataTypeArchive.dataTypeAdded(getID(newDt),
			DataTypeArchiveChangeManager.DOCR_DATA_TYPE_ADDED, null, newDt);
	}

	@Override
	protected void dataTypeReplaced(long existingDtID, DataTypePath existingPath,
			DataType replacementDt) {
		super.dataTypeReplaced(existingDtID, existingPath, replacementDt);
		dataTypeArchive.dataTypeChanged(existingDtID,
			DataTypeArchiveChangeManager.DOCR_DATA_TYPE_REPLACED, false, existingPath,
			replacementDt);
	}

	@Override
	protected void dataTypeDeleted(long deletedID, DataTypePath deletedDataTypePath) {
		super.dataTypeDeleted(deletedID, deletedDataTypePath);
		dataTypeArchive.dataTypeChanged(deletedID,
			DataTypeArchiveChangeManager.DOCR_DATA_TYPE_REMOVED, false, deletedDataTypePath, null);
	}

	@Override
	protected void dataTypeMoved(DataType dt, DataTypePath oldPath, DataTypePath newPath) {
		super.dataTypeMoved(dt, oldPath, newPath);
		Category category = getCategory(oldPath.getCategoryPath());
		dataTypeArchive.dataTypeChanged(getID(dt),
			DataTypeArchiveChangeManager.DOCR_DATA_TYPE_MOVED, false, category, dt);
	}

	@Override
	protected void dataTypeNameChanged(DataType dt, String oldName) {
		super.dataTypeNameChanged(dt, oldName);
		dataTypeArchive.dataTypeChanged(getID(dt),
			DataTypeArchiveChangeManager.DOCR_DATA_TYPE_RENAMED, false, oldName, dt);
	}

	@Override
	protected void categoryCreated(Category newCategory) {
		super.categoryCreated(newCategory);
		dataTypeArchive.categoryAdded(newCategory.getID(),
			DataTypeArchiveChangeManager.DOCR_CATEGORY_ADDED, newCategory.getParent(), newCategory);
	}

	@Override
	protected void categoryRenamed(CategoryPath oldPath, Category category) {
		super.categoryRenamed(oldPath, category);
		dataTypeArchive.categoryChanged(category.getID(),
			DataTypeArchiveChangeManager.DOCR_CATEGORY_RENAMED, oldPath.getName(), category);
	}

	@Override
	protected void categoryRemoved(Category parent, String name, long categoryID) {
		super.categoryRemoved(parent, name, categoryID);
		dataTypeArchive.categoryChanged(categoryID,
			DataTypeArchiveChangeManager.DOCR_CATEGORY_REMOVED, parent, name);
	}

	@Override
	protected void categoryMoved(CategoryPath oldPath, Category category) {
		super.categoryMoved(oldPath, category);
		dataTypeArchive.categoryChanged(category.getID(),
			DataTypeArchiveChangeManager.DOCR_CATEGORY_MOVED, oldPath.getParent(), category);
	}

	@Override
	protected void favoritesChanged(DataType dataType, boolean isFavorite) {
		super.favoritesChanged(dataType, isFavorite);
	}

	///////////////////
	@Override
	protected void replaceDataTypeIDs(long oldDataTypeID, long newDataTypeID) {
		// do nothing
	}

	@Override
	protected void deleteDataTypeIDs(LinkedList<Long> deletedIds, TaskMonitor monitor) {
		// do nothing
	}

	@Override
	public Transaction openTransaction(String description) throws IllegalStateException {
		return dataTypeArchive.openTransaction(description);
	}

	@SuppressWarnings("sync-override")
	@Override
	public int startTransaction(String description) {
		return dataTypeArchive.startTransaction(description);
	}

	@Override
	public void flushEvents() {
		dataTypeArchive.flushEvents();
	}

	@SuppressWarnings("sync-override")
	@Override
	public void endTransaction(int transactionID, boolean commit) {
		dataTypeArchive.endTransaction(transactionID, commit);
	}

	@Override
	public DomainFile getDomainFile() {
		return dataTypeArchive.getDomainFile();
	}

	@Override
	public String getDomainFileID() {
		DomainFile domainFile = getDomainFile(); // Can be null if it has never been saved.
		return (domainFile != null) ? domainFile.getFileID() : null;
	}

	@Override
	public String getPath() {
		DomainFile domainFile = getDomainFile(); // Can be null if it has never been saved.
		return (domainFile != null) ? domainFile.getPathname() : null;
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.PROJECT;
	}

	public void archiveReady(int openMode, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode == DBConstants.UPGRADE) {
			doSourceArchiveUpdates(monitor);
			migrateOldFlexArrayComponentsIfRequired(monitor);
		}
	}

	@Override
	public void close() {
		// do nothing - cannot close a project data type manager
		// dispose should be invoked by the owner of the instance
	}

}
