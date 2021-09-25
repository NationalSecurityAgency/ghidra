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
import ghidra.framework.options.Options;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.SymbolManager;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

/**
 * Class for managing data types in a program
 */
public class ProgramDataTypeManager extends DataTypeManagerDB
		implements ManagerDB, ProgramBasedDataTypeManager {

	private static final String OLD_DT_ARCHIVE_FILENAMES = "DataTypeArchiveFilenames"; // eliminated with Ghidra 4.3

	private ProgramDB program;
	private boolean upgrade;

	/**
	 * Constructor
	 * @param handle open database  handle
	 * @param addrMap the address map
	 * @param openMode the program open mode
	 * @param errHandler the database io error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database io error occurs.
	 */
	public ProgramDataTypeManager(DBHandle handle, AddressMap addrMap, int openMode,
			ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		super(handle, addrMap, openMode, errHandler, lock, monitor);
		upgrade = (openMode == DBConstants.UPGRADE);
	}

	@Override
	public void setProgram(ProgramDB p) {
		this.program = p;
		dataOrganization = p.getCompilerSpec().getDataOrganization();
		removeOldFileNameList();
		if (upgrade) {
			removeOldFileNameList();
		}
	}

	private void removeOldFileNameList() {
		Options options = program.getOptions(Program.PROGRAM_INFO);
		if (options.contains(OLD_DT_ARCHIVE_FILENAMES)) {
			options.removeOption(OLD_DT_ARCHIVE_FILENAMES);
		}
	}

	@Override
	public void invalidateCache(boolean all) throws IOException {
		super.invalidateCache();
	}

	@Override
	public void programReady(int openMode, int currentRevision, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode == DBConstants.UPGRADE) {
			doSourceArchiveUpdates(program.getCompilerSpec(), monitor);
			migrateOldFlexArrayComponentsIfRequired(monitor);
		}
	}

	@Override
	public String getName() {
		return program.getName();
	}

	@Override
	public Pointer getPointer(DataType dt) {
		return PointerDataType.getPointer(dt, this);
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		if (name == null || name.length() == 0) {
			throw new InvalidNameException("Name is invalid: " + name);
		}

		program.setName(name);
		Category root = getRootCategory();
		categoryRenamed(CategoryPath.ROOT, root);
	}

	@Override
	public void sourceArchiveChanged(UniversalID sourceArchiveID) {
		super.sourceArchiveChanged(sourceArchiveID);
		program.sourceArchiveChanged(sourceArchiveID, ChangeManager.DOCR_SOURCE_ARCHIVE_CHANGED);
	}

	@Override
	protected void sourceArchiveAdded(UniversalID sourceArchiveID) {
		super.sourceArchiveAdded(sourceArchiveID);
		program.sourceArchiveAdded(sourceArchiveID, ChangeManager.DOCR_SOURCE_ARCHIVE_ADDED);
	}

	@Override
	public void dataTypeChanged(DataType dt, boolean isAutoChange) {
		super.dataTypeChanged(dt, isAutoChange);
		if (!isCreatingDataType()) {
			program.getCodeManager().invalidateCache(false);
			program.getFunctionManager().invalidateCache(false);
			program.dataTypeChanged(getID(dt), ChangeManager.DOCR_DATA_TYPE_CHANGED,
				isAutoChange, null, dt);
		}
	}

	@Override
	protected void dataTypeAdded(DataType newDt, DataType originalDataType) {
		super.dataTypeAdded(newDt, originalDataType);
		program.dataTypeAdded(getID(newDt), ChangeManager.DOCR_DATA_TYPE_ADDED, null, newDt);
	}

	@Override
	protected void dataTypeReplaced(long existingDtID, DataTypePath existingPath,
			DataType replacementDt) {
		super.dataTypeReplaced(existingDtID, existingPath, replacementDt);
		program.dataTypeChanged(existingDtID, ChangeManager.DOCR_DATA_TYPE_REPLACED, true,
			existingPath,
			replacementDt);
	}

	@Override
	protected void dataTypeDeleted(long deletedID, DataTypePath deletedDataTypePath) {
		super.dataTypeDeleted(deletedID, deletedDataTypePath);
		program.dataTypeChanged(deletedID, ChangeManager.DOCR_DATA_TYPE_REMOVED,
			false, deletedDataTypePath, null);
	}

	@Override
	protected void dataTypeMoved(DataType dt, DataTypePath oldPath, DataTypePath newPath) {
		super.dataTypeMoved(dt, oldPath, newPath);
		Category category = getCategory(oldPath.getCategoryPath());
		program.dataTypeChanged(getID(dt), ChangeManager.DOCR_DATA_TYPE_MOVED, false, category, dt);
	}

	@Override
	protected void dataTypeNameChanged(DataType dt, String oldName) {
		super.dataTypeNameChanged(dt, oldName);
		program.dataTypeChanged(getID(dt), ChangeManager.DOCR_DATA_TYPE_RENAMED, false, oldName, dt);
	}

	@Override
	protected void categoryCreated(Category newCategory) {
		super.categoryCreated(newCategory);
		program.categoryAdded(newCategory.getID(), ChangeManager.DOCR_CATEGORY_ADDED,
			newCategory.getParent(), newCategory);
	}

	@Override
	protected void categoryRenamed(CategoryPath oldPath, Category category) {
		super.categoryRenamed(oldPath, category);
		program.categoryChanged(category.getID(), ChangeManager.DOCR_CATEGORY_RENAMED,
			oldPath.getName(), category);
	}

	@Override
	protected void categoryRemoved(Category parent, String name, long categoryID) {
		super.categoryRemoved(parent, name, categoryID);
		program.categoryChanged(categoryID, ChangeManager.DOCR_CATEGORY_REMOVED, parent, name);
	}

	@Override
	protected void categoryMoved(CategoryPath oldPath, Category category) {
		super.categoryMoved(oldPath, category);
		program.categoryChanged(category.getID(), ChangeManager.DOCR_CATEGORY_MOVED,
			oldPath.getParent(), category);
	}

	@Override
	protected void favoritesChanged(DataType dataType, boolean isFavorite) {
		super.favoritesChanged(dataType, isFavorite);
	}

	@Override
	protected void replaceDataTypeIDs(long oldDataTypeID, long newDataTypeID) {
		if (oldDataTypeID == newDataTypeID) {
			return;
		}
		program.getCodeManager().replaceDataTypes(oldDataTypeID, newDataTypeID);
		((SymbolManager) program.getSymbolTable()).replaceDataTypes(oldDataTypeID, newDataTypeID);
		((FunctionManagerDB) program.getFunctionManager()).replaceDataTypes(oldDataTypeID,
			newDataTypeID);
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
		program.getCodeManager().clearData(ids, monitor);
		program.getFunctionManager().invalidateCache(false);
	}

	@Override
	public boolean isUpdatable() {
		return program.isChangeable();
	}

	@Override
	public int startTransaction(String description) {
		return program.startTransaction(description);
	}

	@Override
	public void flushEvents() {
		program.flushEvents();
	}

	@Override
	public void endTransaction(int transactionID, boolean commit) {
		program.endTransaction(transactionID, commit);

	}

	@Override
	public void close() {
		// do nothing - cannot close the program's data type manager
		// dispose should be invoked by the owner of the instance
	}

	@Override
	public Program getProgram() {
		return program;
	}

	@Override
	public DomainFile getDomainFile() {
		return program.getDomainFile();
	}

	@Override
	public String getDomainFileID() {
		DomainFile domainFile = program.getDomainFile(); // Can be null if it has never been saved.
		return (domainFile != null) ? domainFile.getFileID() : null;
	}

	@Override
	public String getPath() {
		DomainFile domainFile = program.getDomainFile(); // Can be null if it has never been saved.
		return (domainFile != null) ? domainFile.getPathname() : null;
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.PROGRAM;
	}

	@Override
	public DataOrganization getDataOrganization() {
		if (dataOrganization == null) {
			dataOrganization = program.getCompilerSpec().getDataOrganization();
		}
		return dataOrganization;
	}
}
