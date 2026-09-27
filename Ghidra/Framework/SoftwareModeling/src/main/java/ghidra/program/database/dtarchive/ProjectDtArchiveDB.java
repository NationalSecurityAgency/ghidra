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
package ghidra.program.database.dtarchive;

import java.io.IOException;
import java.util.*;

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.data.ProjectDataTypeManagerDB;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.dtarchive.ProjectDataTypeArchive;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramEvent;
import ghidra.util.InvalidNameException;
import ghidra.util.Lock.Closeable;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * DataTypeArchives that are stored as an item in a Ghidra project.
 */
public class ProjectDtArchiveDB extends DataTypeArchiveDB
		implements ProjectDataTypeArchive {

	/** Name of data type archive settings property list */
	public static final String ARCHIVE_SETTINGS = "Data Type Archive Settings";

	private static final String DEFAULT_POINTER_SIZE = "Default Pointer Size";

	private boolean recordChanges;

	/**
	 * Constructs a new DataTypeArchiveDB within a project folder.
	 * @param folder folder within which the project archive will be created
	 * @param name the name of the data type archive
	 * @param consumer the object that is using this data type archive.
	 * @throws IOException if there is an error accessing the database.
	 * @throws InvalidNameException if the name contains invalid characters. 
	 * @throws DuplicateNameException if a DomainFile already exists in the given folder
	 * with the given name.
	 */
	ProjectDtArchiveDB(DomainFolder folder, String name, Object consumer)
			throws IOException, DuplicateNameException, InvalidNameException {
		super(new DBHandle(), name, consumer);

		recordChanges = false;

		if (!dbh.isClosed() && folder != null) {
			try {
				folder.createFile(name, this, TaskMonitor.DUMMY);
			}
			catch (CancelledException e) {
				throw new AssertException();
			}
		}
	}

	/**
	 * Constructs a new DataTypeArchiveDB
	 * @param handle a handle to an open data type archive database.
	 * @param name the name of the archive
	 * @param openMode one of:
	 * 		READ_ONLY: the original database will not be modified
	 * 		UPDATE: the database can be written to.
	 * 		UPGRADE: the database is upgraded to the latest schema as it is opened.
	 * @param monitor TaskMonitor that allows the open to be canceled.
	 * @param consumer the object that keeping the program open.
	 * @throws IOException if an error accessing the database occurs.
	 * @throws VersionException if database version does not match implementation, UPGRADE may be possible.
	 * @throws CancelledException if instantiation is canceled by monitor
	 */
	ProjectDtArchiveDB(DBHandle handle, String name, OpenMode openMode,
			TaskMonitor monitor, Object consumer)
			throws IOException, VersionException, CancelledException {

		super(handle, name, openMode, monitor, consumer);
		recordChanges = true;
	}

	@Override
	protected ProjectDataTypeManagerDB createDataTypeManager(DBHandle handle, OpenMode openMode,
			TaskMonitor monitor)
			throws VersionException, IOException, CancelledException {
		return new ProjectDataTypeManagerDB(handle, openMode, this, lock, monitor);
	}

	@Override
	protected void setDomainFile(DomainFile df) {
		super.setDomainFile(df);
		recordChanges = true;
	}

	@Override
	protected boolean propertyChanged(String propertyName, Object oldValue, Object newValue) {
		if (propertyName.endsWith(DEFAULT_POINTER_SIZE) && (newValue instanceof Integer)) {
			if (!isValidDefaultpointerSize((Integer) newValue)) {
				return false;
			}
		}
		return super.propertyChanged(propertyName, oldValue, newValue);
	}

	private boolean isValidDefaultpointerSize(int pointerSize) {
		return pointerSize > 0 && pointerSize <= PointerDataType.MAX_POINTER_SIZE_BYTES;
	}

	@Override
	public ProjectDataTypeManagerDB getDataTypeManager() {
		return (ProjectDataTypeManagerDB) dataTypeManager;
	}

	public Date getCreationDate() {
		Options pl = getOptions(ARCHIVE_INFO);
		return pl.getDate(DATE_CREATED, new Date(0));
	}

	public int getDefaultPointerSize() {
		// Not sure what size this should be so use 4 for now.
		// Maybe this should prompt the user when it hasn't been set yet.
		Options pl = getOptions(ARCHIVE_SETTINGS);
		return pl.getInt(DEFAULT_POINTER_SIZE, 4);
	}

	@Override
	public void clearProgramArchitecture(TaskMonitor monitor)
			throws CancelledException, IOException, LockException {
		checkExclusiveAccess();
		super.clearProgramArchitecture(monitor);
	}

	@Override
	public void setProgramArchitecture(Language language, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			LockException, UnsupportedOperationException, IncompatibleLanguageException,
			CancelledException {
		checkExclusiveAccess();
		super.setProgramArchitecture(language, compilerSpecId, updateOption, monitor);
	}

	@Override
	public void setProgramArchitecture(LanguageID languageId, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			CancelledException, LockException, UnsupportedOperationException,
			IncompatibleLanguageException {
		checkExclusiveAccess();
		super.setProgramArchitecture(languageId, compilerSpecId, updateOption, monitor);
	}

	@Override
	public DataTypeArchiveDBChangeSet getChanges() {
		return (DataTypeArchiveDBChangeSet) changeSet;
	}

	/**
	 * notification the a data type has changed
	 * @param dataTypeID the id of the data type that changed.
	 * @param eventType the type of the change (moved, renamed, etc.)
	 * @param isAutoResponseChange true if change is an auto-response change caused by 
	 * another datatype's change (e.g., size, alignment), else false in which case this
	 * change will be added to archive change-set to aid merge conflict detection.
	 * @param oldValue the old data type.
	 * @param newValue the new data type.
	 */
	@Override
	public void dataTypeChanged(long dataTypeID, ProgramEvent eventType,
			boolean isAutoResponseChange, Object oldValue, Object newValue) {
		if (recordChanges && !isAutoResponseChange) {
			getChanges().dataTypeChanged(dataTypeID);
		}
		super.dataTypeChanged(dataTypeID, eventType, isAutoResponseChange, oldValue, newValue);
	}

	/**
	 * Notification that a data type was added.
	 * @param dataTypeID the id if the data type that was added.
	 * @param eventType should always be DATATYPE_ADDED
	 * @param oldValue always null
	 * @param newValue the data type added.
	 */
	@Override
	public void dataTypeAdded(long dataTypeID, ProgramEvent eventType, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			((DataTypeArchiveDBChangeSet) changeSet).dataTypeAdded(dataTypeID);
		}
		super.dataTypeAdded(dataTypeID, eventType, oldValue, newValue);
	}

	/**
	 * Notification that a category was changed.
	 * @param categoryID the id of the data type that was added.
	 * @param eventType the type of change
	 * @param oldValue old value depends on the type.
	 * @param newValue new value depends on the type.
	 */
	@Override
	public void categoryChanged(long categoryID, ProgramEvent eventType, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			((DataTypeArchiveDBChangeSet) changeSet).categoryChanged(categoryID);
		}
		super.categoryChanged(categoryID, eventType, oldValue, newValue);
	}

	/**
	 * Notification that a category was added.
	 * @param categoryID the id of the data type that was added.
	 * @param eventType the type of change (should always be CATEGORY_ADDED)
	 * @param oldValue always null
	 * @param newValue new value depends on the type.
	 */
	@Override
	public void categoryAdded(long categoryID, ProgramEvent eventType, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			((DataTypeArchiveDBChangeSet) changeSet).categoryAdded(categoryID);
		}
		super.categoryAdded(categoryID, eventType, oldValue, newValue);
	}

	@Override
	public void setName(String newName) {
		// Can't change the name of a program archive - it comes from the program
	}

	@Override
	public String getDescription() {
		return "Project Based Data Type Archive";
	}

	@Override
	protected void clearCache(boolean all) {
		try (Closeable c = lock.write()) {
			super.clearCache(all);
			dataTypeManager.invalidateCache();
		}
	}

	@Override
	protected void setChanged(boolean b) {
		super.setChanged(b);
	}

	@Override
	public Map<String, String> getMetadata() {

		metadata.clear();
		metadata.put("Data Type Archive Name", getName());
		metadata.put("# of Data Types", "" + getDataTypeManager().getDataTypeCount(true));
		metadata.put("# of Data Type Categories", "" + getDataTypeManager().getCategoryCount());

		Options propList = getOptions(Program.PROGRAM_INFO);
		List<String> propNames = propList.getOptionNames();
		Collections.sort(propNames);
		for (String propName : propNames) {
			if (propName.indexOf(Options.DELIMITER) >= 0) {
				continue; // ignore second tier options
			}
			String valueAsString = propList.getValueAsString(propName);
			if (valueAsString != null) {
				metadata.put(propName, propList.getValueAsString(propName));
			}
		}
		return metadata;
	}

	@Override
	protected void updateMetadata() throws IOException {
		getMetadata(); // updates metadata map
		super.updateMetadata();
	}

	@Override
	public ArchiveType getArchiveType() {
		return ArchiveType.PROJECT;
	}
}
