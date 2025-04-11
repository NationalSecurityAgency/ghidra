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

import java.io.File;
import java.io.IOException;
import java.util.*;

import db.*;
import ghidra.framework.Application;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.options.Options;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.listing.DataTypeArchive;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramChangeRecord;
import ghidra.program.util.ProgramEvent;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Database implementation for Data Type Archive. 
 */
public class DataTypeArchiveDB extends DomainObjectAdapterDB implements DataTypeArchive {

	/**
	 * DB_VERSION should be incremented any time a change is made to the overall
	 * database schema associated with any of the managers.
	 * 18-Sep-2008 - version 1 - Added fields for synchronizing program data types with project archives.
	 * 03-Dec-2009 - version 2 - Added source archive updating (consolidating windows.gdt, clib.gdt, ntddk.gdt)
	 * 14-Nov-2019 - version 3 - Corrected fixed length indexing implementation causing change
	 *                           in index table low-level storage for newly created tables. 
	 * 20-Apr-2023 - version 4 - Added architecture support and string-based function calling
	 *                           convention specification.
	 *                           
	 * NOTE: The true versioning is based on the underlying {@link StandAloneDataTypeManager}
	 * implementation and its ability to detect and manage versioning concerns.  Due to the need to
	 * always support opening in a read-only fashion we are unable to impose a forced upgrade
	 * requirement.
	 */
	static final int DB_VERSION = 4;

	/**
	 * UPGRADE_REQUIRED_BEFORE_VERSION should be changed to DB_VERSION any time the
	 * latest version requires a forced upgrade (i.e., Read-only mode not supported
	 * until upgrade is performed).  It is assumed that read-only mode is supported 
	 * if the data's version is &gt;= UPGRADE_REQUIRED_BEFORE_VERSION and &lt;= DB_VERSION. 
	 */
	private static final int UPGRADE_REQUIRED_BEFORE_VERSION = 1;

	/** Name of data type archive information property list */
	public static final String ARCHIVE_INFO = "Data Type Archive Information";

	/** Name of data type archive settings property list */
	public static final String ARCHIVE_SETTINGS = "Data Type Archive Settings";

	/** Name of date created property */
	public static final String DATE_CREATED = "Date Created";

	/** Name of Ghidra version property */
	public static final String CREATED_WITH_GHIDRA_VERSION = "Created With Ghidra Version";

	/** A date from January 1, 1970 */
	public static final Date JANUARY_1_1970 = new Date(0);

	private static final String ARCHIVE_DB_VERSION = "DB Version";
	private static final String TABLE_NAME = "Data Type Archive";

	private static final String DEFAULT_POINTER_SIZE = "Default Pointer Size";

	private final static Field[] COL_FIELDS = new Field[] { StringField.INSTANCE };
	private final static String[] COL_TYPES = new String[] { "Value" };
	private final static Schema SCHEMA =
		new Schema(0, StringField.INSTANCE, "Key", COL_FIELDS, COL_TYPES);

	private ProjectDataTypeManager dataTypeManager;

	private boolean recordChanges;
	private boolean changeable = true;
	private Table table;

	/**
	 * Constructs a new DataTypeArchiveDB within a project folder.
	 * @param folder folder within which the project archive will be created
	 * @param name the name of the data type archive
	 * @param consumer the object that is using this data type archive.
	 * @throws IOException if there is an error accessing the database.
	 * @throws InvalidNameException 
	 * @throws DuplicateNameException 
	 */
	public DataTypeArchiveDB(DomainFolder folder, String name, Object consumer)
			throws IOException, DuplicateNameException, InvalidNameException {
		super(new DBHandle(), name, 500, consumer);
		this.name = name;

		recordChanges = false;
		boolean success = false;
		try {
			int id = startTransaction("create data type archive");

			createDatabase();
			if (createManagers(OpenMode.CREATE, TaskMonitor.DUMMY) != null) {
				throw new AssertException("Unexpected version exception on create");
			}
			changeSet = new DataTypeArchiveDBChangeSet(NUM_UNDOS);
			initManagers(OpenMode.CREATE, TaskMonitor.DUMMY);
			propertiesCreate();
			endTransaction(id, true);
			clearUndo(false);

			if (folder != null) {
				folder.createFile(name, this, TaskMonitor.DUMMY);
			}

			success = true;
		}
		catch (CancelledException e) {
			throw new AssertException();
		}
		finally {
			dbh.closeScratchPad();
			if (!success) {
				release(consumer);
				dbh.close();
			}
		}

	}

	/**
	 * Constructs a new DataTypeArchiveDB
	 * @param dbh a handle to an open data type archive database.
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
	public DataTypeArchiveDB(DBHandle dbh, OpenMode openMode, TaskMonitor monitor, Object consumer)
			throws IOException, VersionException, CancelledException {

		super(dbh, "Untitled", 500, consumer);
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		boolean success = false;
		try {
			int id = startTransaction("create data type archive");
			recordChanges = false;
			changeable = (openMode != OpenMode.IMMUTABLE);

			// check DB version and read name
			VersionException dbVersionExc = initializeDatabase(openMode);

			VersionException versionExc = createManagers(openMode, monitor);
			if (dbVersionExc != null) {
				versionExc = dbVersionExc.combine(versionExc);
			}
			if (versionExc != null) {
				throw versionExc;
			}

			changeSet = new DataTypeArchiveDBChangeSet(NUM_UNDOS);

			initManagers(openMode, monitor);

			if (openMode == OpenMode.UPGRADE) {
				upgradeDatabase();
				changed = true;
			}
			propertiesRestore();
			recordChanges = true;
			endTransaction(id, true);
			clearUndo(false);
			success = true;
		}
		finally {
			dbh.closeScratchPad();
			if (!success) {
				release(consumer);
			}
		}

		if (openMode == OpenMode.IMMUTABLE) {
			setImmutable();
		}

	}

	@Override
	protected void close() {
		super.close();
		if (dataTypeManager != null) {
			dataTypeManager.dispose();
		}
	}

	@Override
	protected void setDomainFile(DomainFile df) {
		super.setDomainFile(df);
		recordChanges = true;
	}

	private void propertiesRestore() {
		Options pl = getOptions(ARCHIVE_INFO);
		boolean origChangeState = changed;
		pl.registerOption(CREATED_WITH_GHIDRA_VERSION, "4.3", null,
			"Version of Ghidra used to create this program.");
		pl.registerOption(DATE_CREATED, JANUARY_1_1970, null, "Date this program was created");
//	    registerDefaultPointerSize();
		changed = origChangeState;
	}

	private void propertiesCreate() {
		Options pl = getOptions(ARCHIVE_INFO);
		boolean origChangeState = changed;
		pl.setString(CREATED_WITH_GHIDRA_VERSION, Application.getApplicationVersion());
		pl.setDate(DATE_CREATED, new Date());
//	    registerDefaultPointerSize();
		changed = origChangeState;
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
	public ProjectDataTypeManager getDataTypeManager() {
		return dataTypeManager;
	}

	@Override
	public Date getCreationDate() {
		Options pl = getOptions(ARCHIVE_INFO);
		return pl.getDate(DATE_CREATED, new Date(0));
	}

	@Override
	public int getDefaultPointerSize() {
		// Not sure what size this should be so use 4 for now.
		// Maybe this should prompt the user when it hasn't been set yet.
		Options pl = getOptions(ARCHIVE_SETTINGS);
		return pl.getInt(DEFAULT_POINTER_SIZE, 4);
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
	public void dataTypeChanged(long dataTypeID, ProgramEvent eventType,
			boolean isAutoResponseChange, Object oldValue, Object newValue) {
		if (recordChanges && !isAutoResponseChange) {
			((DataTypeArchiveDBChangeSet) changeSet).dataTypeChanged(dataTypeID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(eventType, oldValue, newValue));
	}

	/**
	 * Notification that a data type was added.
	 * @param dataTypeID the id if the data type that was added.
	 * @param eventType should always be DATATYPE_ADDED
	 * @param oldValue always null
	 * @param newValue the data type added.
	 */
	public void dataTypeAdded(long dataTypeID, ProgramEvent eventType, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			((DataTypeArchiveDBChangeSet) changeSet).dataTypeAdded(dataTypeID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(eventType, oldValue, newValue));
	}

	/**
	 * Notification that a category was changed.
	 * @param categoryID the id of the data type that was added.
	 * @param eventType the type of change
	 * @param oldValue old value depends on the type.
	 * @param newValue new value depends on the type.
	 */
	public void categoryChanged(long categoryID, ProgramEvent eventType, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			((DataTypeArchiveDBChangeSet) changeSet).categoryChanged(categoryID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(eventType, oldValue, newValue));
	}

	/**
	 * Notification that a category was added.
	 * @param categoryID the id of the data type that was added.
	 * @param eventType the type of change (should always be CATEGORY_ADDED)
	 * @param oldValue always null
	 * @param newValue new value depends on the type.
	 */
	public void categoryAdded(long categoryID, ProgramEvent eventType, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			((DataTypeArchiveDBChangeSet) changeSet).categoryAdded(categoryID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(eventType, oldValue, newValue));
	}

	/**
	 * Mark the state this Data Type Archive as having changed and generate
	 * the event.  Any or all parameters may be null.
	 * @param eventType event type
	 * @param oldValue original value
	 * @param newValue new value
	 */
	public void setChanged(ProgramEvent eventType, Object oldValue, Object newValue) {

		changed = true;

		fireEvent(new ProgramChangeRecord(eventType, oldValue, newValue));
	}

	@Override
	public void setName(String newName) {
	}

	@Override
	public String getDescription() {
		return "Data Type Archive";
	}

	private void createDatabase() throws IOException {
		table = dbh.createTable(TABLE_NAME, SCHEMA);

		DBRecord record = SCHEMA.createRecord(new StringField(ARCHIVE_DB_VERSION));
		record.setString(0, Integer.toString(DB_VERSION));
		table.putRecord(record);
	}

	/**
	 * Initialize the following fields from the database and check the database version for an existing database:
	 * <ul>
	 * <li>name</li>
	 * <li>languageName</li>
	 * <li>languageVersion</li>
	 * <li>LanguageMinorVersion</li>
	 * </ul>
	 * @param openMode program open mode
	 * @return version exception if the current version is out of date and can be upgraded.
	 * @throws IOException
	 * @throws VersionException if the data is newer than this version of Ghidra and can not be
	 * upgraded or opened.
	 */
	private VersionException initializeDatabase(OpenMode openMode)
			throws IOException, VersionException {

		table = dbh.getTable(TABLE_NAME);
		if (table == null) {
			if (openMode == OpenMode.UPGRADE) {
				createDatabase();
			}
			else {
				throw new VersionException(true);
			}
		}

		int storedVersion = getStoredVersion();
		if (storedVersion > DB_VERSION) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
		if (openMode != OpenMode.UPGRADE && storedVersion < UPGRADE_REQUIRED_BEFORE_VERSION) {
			return new VersionException(true);
		}
		if (openMode == OpenMode.UPDATE && storedVersion < DB_VERSION) {
			return new VersionException(true);
		}
		return null;
	}

	private void upgradeDatabase() throws IOException {

		table = dbh.getTable(TABLE_NAME);
		DBRecord record = SCHEMA.createRecord(new StringField(ARCHIVE_DB_VERSION));
		record.setString(0, Integer.toString(DB_VERSION));
		table.putRecord(record);
	}

	private int getStoredVersion() throws IOException {
		DBRecord record = table.getRecord(new StringField(ARCHIVE_DB_VERSION));

		// DB Version
		// if record does not exist return 1;

		if (record != null) {
			String s = record.getString(0);
			try {
				return Integer.parseInt(s);
			}
			catch (NumberFormatException e) {
			}
		}
		return 1;
	}

	private void checkOldProperties(OpenMode openMode) {
//		Record record = table.getRecord(new StringField(EXECUTE_PATH));
//		if (record != null) {
//			if (openMode == READ_ONLY) {
//				return; // not important, get on path or format will return "unknown"
//			}
//			if (openMode != UPGRADE) {
//				throw new VersionException(true);
//			}	
//			options pl = getPropertyList(ARCHIVE_INFO);
//			String value = record.getString(0);
//			pl.setValue(EXECUTABLE_PATH, value);
//			table.deleteRecord(record.getKeyField());
//			record = table.getRecord(new StringField(EXECUTE_FORMAT));
//			if (record != null) {
//				pl.setValue(EXECUTABLE_FORMAT, value);
//				table.deleteRecord(record.getKeyField());
//			}
//		}
//		int storedVersion = getStoredVersion();
	}

	private VersionException createManagers(OpenMode openMode, TaskMonitor monitor)
			throws CancelledException, IOException {

		VersionException versionExc = null;
		monitor.checkCancelled();

//		try {
		checkOldProperties(openMode);
//		} catch (VersionException e) {
//			versionExc = e.combine(versionExc);
//		}

		try {
			dataTypeManager = new ProjectDataTypeManager(this, dbh, openMode, this, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCancelled();

		return versionExc;
	}

	private void initManagers(OpenMode openMode, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.checkCancelled();
		dataTypeManager.archiveReady(openMode, monitor);
	}

	@Override
	protected void clearCache(boolean all) {
		lock.acquire();
		try {
			super.clearCache(all);
			dataTypeManager.invalidateCache();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isChangeable() {
		return changeable;
	}

	@Override
	protected void setChanged(boolean b) {
		super.setChanged(b);
	}

	void setChangeSet(DataTypeArchiveDBChangeSet changeSet) {
		this.changeSet = changeSet;
	}

	@Override
	public void save(String comment, TaskMonitor monitor) throws IOException, CancelledException {
		try {
			super.save(comment, monitor);
		}
		finally {
			dataTypeManager.clearUndo();
		}
	}

	@Override
	public void saveToPackedFile(File outputFile, TaskMonitor monitor)
			throws IOException, CancelledException {
		try {
			super.saveToPackedFile(outputFile, monitor);
		}
		finally {
			dataTypeManager.clearUndo();
		}
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
	protected void domainObjectRestored() {
		super.domainObjectRestored();
		dataTypeManager.notifyRestored();
	}
}
