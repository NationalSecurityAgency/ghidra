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
import java.util.Iterator;
import java.util.LinkedList;

import db.DBConstants;
import db.DBHandle;
import db.util.ErrorHandler;
import ghidra.framework.model.DomainFile;
import ghidra.program.database.DataTypeArchiveDB;
import ghidra.program.model.data.*;
import ghidra.program.util.DataTypeArchiveChangeManager;
import ghidra.util.InvalidNameException;
import ghidra.util.Lock;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for managing data types in a project archive
 */
public class ProjectDataTypeManager extends DataTypeManagerDB
		implements ProjectArchiveBasedDataTypeManager {

//	private static final String DT_ARCHIVE_FILENAMES = "DataTypeArchiveFilenames";
//	private static final String FILENAME_SEPARATOR = ";";
//	private static final String ARCHIVE_DIR = "typeinfo";
//	private static final String RELATIVE_PATH_PREFIX = ".";
	private DataTypeArchiveDB dataTypeArchive;

//	private ArrayList<String> filenameList = new ArrayList<String>(); // Archives used to get data types for this program.

	/**
	 * Constructor
	 * @param handle open database  handle
	 * @param openMode the program open mode
	 * @param errHandler the database I/O error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database I/O error occurs.
	 */
	public ProjectDataTypeManager(DBHandle handle, int openMode, ErrorHandler errHandler, Lock lock,
			TaskMonitor monitor) throws CancelledException, VersionException, IOException {
		super(handle, null, openMode, errHandler, lock, monitor);
	}

	/**
	 * @see ghidra.program.database.ManagerDB#setProgram(ghidra.program.database.ProgramDB)
	 */
	public void setDataTypeArchive(DataTypeArchiveDB dtArchive) {
		this.dataTypeArchive = dtArchive;
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManager#getName()
	 */
	@Override
	public String getName() {
		return dataTypeArchive.getDomainFile().getName();
	}

	@Override
	public Pointer getPointer(DataType dt) {
		return PointerDataType.getPointer(dt, dataTypeArchive.getDefaultPointerSize());
	}

	/**
	 * @see ghidra.program.model.data.DataTypeManager#setName(java.lang.String)
	 */
	@Override
	public void setName(String name) throws InvalidNameException {
		if (name == null || name.length() == 0) {
			throw new InvalidNameException("Name is invalid: " + name);
		}

		dataTypeArchive.setName(name);
		categoryRenamed(CategoryPath.ROOT, null);
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
//		dataTypeArchive.getCodeManager().replace(oldID, newID, monitor);
		// TODO
	}

	@Override
	protected void deleteDataTypeIDs(LinkedList<Long> deletedIds, TaskMonitor monitor)
			throws CancelledException {
		long[] ids = new long[deletedIds.size()];
		Iterator<Long> it = deletedIds.iterator();
		int i = 0;
		while (it.hasNext()) {
			ids[i++] = it.next().longValue();
		}
//		dataTypeArchive.getCodeManager().clearData(ids, monitor);
		// TODO
	}

	@Override
	public int startTransaction(String description) {
		return dataTypeArchive.startTransaction(description);
	}

	@Override
	public void flushEvents() {
		dataTypeArchive.flushEvents();
	}

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

	public void archiveReady(int openMode, TaskMonitor monitor) throws CancelledException {
		if (openMode == DBConstants.UPGRADE) {
			doSourceArchiveUpdates(null, monitor);
		}
	}

	@Override
	public void close() {
		// do nothing - cannot close a project data type manager
		// dispose should be invoked by the owner of the instance
	}

}
