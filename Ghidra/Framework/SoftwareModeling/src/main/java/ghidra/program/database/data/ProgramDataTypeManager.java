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

import db.*;
import db.util.ErrorHandler;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.Options;
import ghidra.program.database.ManagerDB;
import ghidra.program.database.ProgramDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ChangeManager;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Class for managing data types in a program
 */
public class ProgramDataTypeManager extends ProgramBasedDataTypeManagerDB
		implements ManagerDB {

	private static final String OLD_DT_ARCHIVE_FILENAMES = "DataTypeArchiveFilenames"; // eliminated with Ghidra 4.3

	private ProgramDB program;
	private boolean upgrade;

	/**
	 * Constructor
	 * @param handle open database  handle
	 * @param addrMap the address map
	 * @param openMode the program open mode (see {@link DBConstants})
	 * @param errHandler the database io error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database IO error occurs.
	 */
	public ProgramDataTypeManager(DBHandle handle, AddressMap addrMap, int openMode,
			ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		super(handle, addrMap, openMode, null, errHandler, lock, monitor);
		upgrade = (openMode == DBConstants.UPGRADE);
	}

	@Override
	protected void dataSettingChanged(Address dataAddr) {
		program.setChanged(ChangeManager.DOCR_DATA_TYPE_SETTING_CHANGED, dataAddr,
			dataAddr, null, null);
	}

	@Override
	public boolean allowsDefaultBuiltInSettings() {
		return true;
	}

	@Override
	public void setProgram(ProgramDB p) {
		this.program = p;
		try {
			setProgramArchitecture(p, p.getSymbolTable().getVariableStorageManager(), false,
				TaskMonitor.DUMMY);
		}
		catch (CancelledException e) {
			throw new AssertException(e); // unexpected - no IO performed
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
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
			doSourceArchiveUpdates(monitor);
			migrateOldFlexArrayComponentsIfRequired(monitor);
		}
	}

	/**
	 * Update program-architecture information following a language upgrade/change
	 * @param monitor task monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task monitor cancelled
	 */
	public void languageChanged(TaskMonitor monitor) throws IOException, CancelledException {
		setProgramArchitecture(program, program.getSymbolTable().getVariableStorageManager(), true,
			monitor);
	}
	
	@Override
	public String getName() {
		return program.getName();
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
		program.getSymbolTable().replaceDataTypes(oldDataTypeID, newDataTypeID);
		program.getFunctionManager().replaceDataTypes(oldDataTypeID, newDataTypeID);
	}

	@Override
	protected void deleteDataTypeIDs(LinkedList<Long> deletedIds, TaskMonitor monitor)
			throws CancelledException {
		// TODO: SymbolManager/FunctionManager do not appear to handle datatype removal update.
		// Suspect it handles indirectly through detection of deleted datatype.  Old deleted ID
		// use could be an issue.
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
	public Transaction openTransaction(String description) throws IllegalStateException {
		return program.openTransaction(description);
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

}
