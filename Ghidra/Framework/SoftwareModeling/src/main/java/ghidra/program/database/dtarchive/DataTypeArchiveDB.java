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
import java.util.Date;

import javax.help.UnsupportedOperationException;

import db.DBHandle;
import db.TerminatedTransactionException;
import ghidra.framework.Application;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.AbortedTransactionListener;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.database.DBStringMapAdapter;
import ghidra.program.database.ProgramAddressFactory;
import ghidra.program.database.data.ArchiveDataTypeManagerDB;
import ghidra.program.database.symbol.VariableStorageManager;
import ghidra.program.database.symbol.VariableStorageManagerDB;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.data.ProgramArchitectureTranslator;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.dtarchive.ArchiveWarning;
import ghidra.program.model.dtarchive.DataTypeArchive;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.*;
import ghidra.util.Lock.Closeable;
import ghidra.util.Msg;
import ghidra.util.ReadOnlyException;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for non-program data type stores that use a database for storage.
 */
public abstract class DataTypeArchiveDB extends DomainObjectAdapterDB
		implements DataTypeArchive {
	/**
	 * DB_VERSION should be incremented any time a change is made to the overall
	 * database schema associated with any of the managers.
	 * 18-Sep-2008 - version 1 - Added fields for synchronizing program data types with project archives.
	 * 03-Dec-2009 - version 2 - Added source archive updating (consolidating windows.gdt, clib.gdt, ntddk.gdt)
	 * 14-Nov-2019 - version 3 - Corrected fixed length indexing implementation causing change
	 *                           in index table low-level storage for newly created tables. 
	 * 20-Apr-2023 - version 4 - Added architecture support and string-based function calling
	 *                           convention specification.
	 * 22-Jun-2026 - version 5 - standardized on use of DtArchiveDB Domain Object for all archives.
	 *                           
	 * NOTE: The true versioning is based on the underlying {@link StandAloneDataTypeManager}
	 * implementation and its ability to detect and manage versioning concerns.  Due to the need to
	 * always support opening in a read-only fashion we are unable to impose a forced upgrade
	 * requirement.
	 */
	static final int DB_VERSION = 5;
	/**
	 * UPGRADE_REQUIRED_BEFORE_VERSION should be changed to DB_VERSION any time the
	 * latest version requires a forced upgrade (i.e., Read-only mode not supported
	 * until upgrade is performed).  It is assumed that read-only mode is supported 
	 * if the data's version is &gt;= UPGRADE_REQUIRED_BEFORE_VERSION and &lt;= DB_VERSION. 
	 */
	private static final int UPGRADE_REQUIRED_BEFORE_VERSION = 1;
	/** Name of data type archive information property list */
	public static final String ARCHIVE_INFO = "Data Type Archive Information";

	/** Name of date created property */
	public static final String DATE_CREATED = "Date Created";

	/** Name of Ghidra version property */
	public static final String CREATED_WITH_GHIDRA_VERSION = "Created With Ghidra Version";

	private static final String ARCHIVE_DB_VERSION = "DB Version";

	/** If there is no stored creation date, use this as a default */
	public static final Date JANUARY_1_1970 = new Date(0);

	private static final String DATA_MAP_TABLE_NAME = "Data Type Archive";

	private static final String LANGUAGE_VERSION = "Language Version"; // major version only
	private static final String LANGUAGE_ID = "Language ID";
	private static final String COMPILER_SPEC_ID = "Compiler Spec ID";

	protected ArchiveDataTypeManagerDB dataTypeManager;
	private boolean immutable = false;

	private DBStringMapAdapter archiveDataMap; // may be null but always exists during UPGRADE

	private ProgramArchitecture programArchitecture; // may be null
	private String programArchitectureSummary;
	private VariableStorageManagerDB variableStorageMgr; // may be null
	private LanguageTranslator languageUpgradeTranslator;
	private ArchiveWarning warning = ArchiveWarning.NONE;
	private Exception warningDetail;

	/**
	 * Constructor for a new archive
	 * @param dbHandle the database handle
	 * @param name the name of the archive
	 * @param consumer the object that is using this data type archive.
	 * @throws IOException if there is an error accessing the database.
	 */
	protected DataTypeArchiveDB(DBHandle dbHandle, String name, Object consumer)
			throws IOException {
		super(dbHandle, name, 500, consumer);
		boolean success = false;
		try {
			int id = startTransaction("create data type archive");

			createArchiveInfo();
			if (createManagers(OpenMode.CREATE, TaskMonitor.DUMMY) != null) {
				throw new AssertException("Unexpected version exception on create");
			}
			changeSet = new DataTypeArchiveDBChangeSet(NUM_UNDOS);
			initManagers(OpenMode.CREATE, TaskMonitor.DUMMY);
			propertiesCreate();

			endTransaction(id, true);
			clearUndo(false);
			success = true;
		}
		catch (CancelledException e) {
			throw new AssertException();
		}
		finally {
			dbHandle.closeScratchPad();
			if (!success) {
				close();
			}
		}
	}

	/**
	 * Constructor for an existing archive
	 * @param handle a handle to an open data type archive database.
	 * @param name the name of the archive
	 * @param openMode one of:
	 * 		READ_ONLY: the original database will not be modified
	 * 		UPDATE: the database can be written to.
	 * 		UPGRADE: the database is upgraded to the latest schema as it is opened.
	 * @param monitor TaskMonitor that allows the open to be canceled.
	 * @param consumer the consumer used to open the archive 
	 * @throws IOException if an error accessing the database occurs.
	 * @throws VersionException if database version does not match implementation, 
	 *         If open mode is UPDATE, an UPGRADE may be possible as indicated by exception.
	 * @throws CancelledException if instantiation is canceled by monitor
	 */
	public DataTypeArchiveDB(DBHandle handle, String name, OpenMode openMode,
			TaskMonitor monitor,
			Object consumer) throws IOException, VersionException, CancelledException {

		super(handle, name, 500, consumer);

		if (openMode == OpenMode.CREATE) {
			throw new IllegalArgumentException("CREATE mode not allowed for this constructor");
		}
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}

		boolean success = false;
		try {
			int id = startTransaction("open data type archive");

			VersionException dbVersionExc = initArchiveInfo(openMode);

			VersionException versionExc = createManagers(openMode, monitor);
			if (dbVersionExc != null) {
				versionExc = dbVersionExc.combine(versionExc);
			}

			try {
				initArchitecture(openMode, monitor);
			}
			catch (VersionException e) {
				versionExc = e.combine(versionExc);
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

			endTransaction(id, true);
			clearUndo(false);

			// Force archive into a immutable state if database does not allow update 
			if (!handle.canUpdate()) {
				setImmutable();
			}

			success = true;
		}
		finally {
			handle.closeScratchPad();
			if (!success) {
				close();
			}
		}
	}

	private ArchitectureInfo getArchitectureInfo(OpenMode openMode) throws IOException {
		ArchitectureInfo info = readArchitecture(archiveDataMap);
		if (info != null) {
			return info;
		}
		// Check DTM for architecture info for older archives (pre-upgrade)
		DBStringMapAdapter dataTypeManagerMap = dataTypeManager.getDataMap();
		info = readArchitecture(dataTypeManagerMap);
		if (info == null) {
			return null;
		}

		if (openMode == OpenMode.UPGRADE) {
			// Migrate architecture data from DTM to archive's data map
			saveLanguageInfo(info.languageId, info.compilerID, info.languageVersion);
			dataTypeManagerMap.delete(LANGUAGE_ID);
			dataTypeManagerMap.delete(COMPILER_SPEC_ID);
			dataTypeManagerMap.delete(LANGUAGE_VERSION);
		}

		return null;

	}

	private void saveLanguageInfo(LanguageID languageId, CompilerSpecID compilerID, int version)
			throws IOException {
		archiveDataMap.put(LANGUAGE_ID, languageId.getIdAsString());
		archiveDataMap.put(COMPILER_SPEC_ID, compilerID.getIdAsString());
		archiveDataMap.put(LANGUAGE_VERSION, Integer.toString(version));

	}

	private void initArchitecture(OpenMode openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		ArchitectureInfo info = getArchitectureInfo(openMode);
		if (info == null) {
			return; // assume architecture info is missing
		}

		if (VariableStorageManagerDB.exists(dbh)) {
			variableStorageMgr =
				new VariableStorageManagerDB(dbh, null, openMode, this, lock, monitor);
		}

		programArchitectureSummary = ProgramArchitecture.getSummary(info.languageId,
			info.languageVersion, info.compilerID);

		Language language = getLanguage(info, openMode);
		if (language == null) {
			return;
		}
		CompilerSpec compilerSpec = getCompilerSpec(language, info);
		if (compilerSpec == null) {
			return;
		}

		if (warning == ArchiveWarning.LANGUAGE_UPGRADE_REQURED) {
			// openMode == UPGRADE assumed based on warning level
			if (variableStorageMgr != null) {
				variableStorageMgr.setLanguage(languageUpgradeTranslator, monitor);
			}
			saveLanguageInfo(language.getLanguageID(), compilerSpec.getCompilerSpecID(),
				language.getVersion());
			warning = ArchiveWarning.UPGRADED_LANGUAGE_VERSION;
		}

		programArchitecture = new ArchiveProgramArchitecture(language, compilerSpec);
		if (variableStorageMgr != null) {
			variableStorageMgr.setProgramArchitecture(getProgramArchitecture());
		}
	}

	private CompilerSpec getCompilerSpec(Language language, ArchitectureInfo info) {
		CompilerSpecID compilerSpecId = info.compilerID;
		if (languageUpgradeTranslator != null) {
			compilerSpecId = languageUpgradeTranslator.getNewCompilerSpecID(compilerSpecId);
		}

		try {
			return language.getCompilerSpecByID(compilerSpecId);
		}
		catch (CompilerSpecNotFoundException e) {
			warning = ArchiveWarning.COMPILER_SPEC_NOT_FOUND;
			warningDetail = e;
			return null; // allow archive to open without error
		}
	}

	private Language getLanguage(ArchitectureInfo info, OpenMode openMode)
			throws LanguageVersionException {
		Language language = null;
		LanguageVersionException languageVersionExc = null;
		try {
			LanguageService languageService = DefaultLanguageService.getLanguageService();
			language = languageService.getLanguage(info.languageId);
			languageVersionExc = LanguageVersionException.check(language, info.languageVersion, -1); // don't care about minor version
		}
		catch (LanguageNotFoundException e) {
			warning = ArchiveWarning.LANGUAGE_NOT_FOUND;
			warningDetail = e;
			try {
				languageVersionExc = LanguageVersionException.checkForLanguageChange(e,
					info.languageId, info.languageVersion);
			}
			catch (LanguageNotFoundException e2) {
				// Missing language or language translation
				warningDetail = e2;
				return null; // allow archive to open without error
			}
		}

		if (languageVersionExc != null && !languageVersionExc.isUpgradable()) {
			// Inability to translate language treated like language-not-found
			warning = ArchiveWarning.LANGUAGE_NOT_FOUND;
			warningDetail = languageVersionExc;
		}
		else if (languageVersionExc != null) {
			warning = ArchiveWarning.LANGUAGE_UPGRADE_REQURED;
			languageUpgradeTranslator = languageVersionExc.getLanguageTranslator();

			// language upgrade required
			if (openMode == OpenMode.IMMUTABLE) {
				// read-only mode - do not set program architecture - upgrade flag has been set
				return null;
			}

			if (openMode == OpenMode.UPDATE) {
				throw languageVersionExc;
			}

			// else UPGRADE mode falls-through
			language = languageUpgradeTranslator.getNewLanguage();
		}
		return language;
	}

	private ArchitectureInfo readArchitecture(DBStringMapAdapter adapter) throws IOException {
		if (adapter == null) {
			return null;
		}
		String languageName = adapter.get(LANGUAGE_ID);
		if (languageName == null) {
			return null;
		}
		String compilerName = adapter.get(COMPILER_SPEC_ID);
		int languageVersion = adapter.getInt(LANGUAGE_VERSION, 1);
		LanguageID languageId = new LanguageID(languageName);
		CompilerSpecID compilerSpecId = new CompilerSpecID(compilerName);
		return new ArchitectureInfo(languageId, compilerSpecId, languageVersion);
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
	 * @throws IOException if an error occurs reading/writing to the database
	 * @throws VersionException if the data is newer than this version of Ghidra and can not be
	 * upgraded or opened.
	 */
	private VersionException initArchiveInfo(OpenMode openMode)
			throws IOException, VersionException {

		// Update will always trigger upgrade situation if archive data map
		// does not exist, to ensure that it does exist during any update use.

		archiveDataMap = getArchiveDataMap(openMode == OpenMode.UPGRADE);

		if (archiveDataMap == null || getStoredVersion() < 5) {
			if (openMode == OpenMode.UPDATE) {
				throw new VersionException(true);
			}
			return null;
		}

		int storedVersion = archiveDataMap.getInt(ARCHIVE_DB_VERSION, 1);

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
		archiveDataMap.put(ARCHIVE_DB_VERSION, Integer.toString(DB_VERSION));
	}

	private void createArchiveInfo() throws IOException {
		archiveDataMap = getArchiveDataMap(true);
		archiveDataMap.put(ARCHIVE_DB_VERSION, Integer.toString(DB_VERSION));
	}

	private int getStoredVersion() throws IOException {
		if (archiveDataMap != null) {
			return archiveDataMap.getInt(ARCHIVE_DB_VERSION, 1);
		}
		return 1;
	}

	private void initManagers(OpenMode openMode, TaskMonitor monitor)
			throws IOException, CancelledException {
		monitor.checkCancelled();
		dataTypeManager.setDomainObject(this);

		warning = ArchiveWarning.NONE;
		if (openMode == OpenMode.CREATE) {
			getDataTypeManager().saveDataOrganization();
		}

		dataTypeManager.domainObjectReady(openMode, getStoredVersion(), monitor);
	}

	private void propertiesRestore() {
		Options pl = getOptions(ARCHIVE_INFO);
		boolean origChangeState = changed;
		pl.registerOption(CREATED_WITH_GHIDRA_VERSION, "4.3", null,
			"Version of Ghidra used to create this program.");
		pl.registerOption(DATE_CREATED, JANUARY_1_1970, null, "Date this program was created");
		changed = origChangeState;
	}

	private void propertiesCreate() {
		Options pl = getOptions(ARCHIVE_INFO);
		boolean origChangeState = changed;
		pl.setString(CREATED_WITH_GHIDRA_VERSION, Application.getApplicationVersion());
		pl.setDate(DATE_CREATED, new Date());
		changed = origChangeState;
	}

	/**
	 * Get the archive string data map.
	 * @param createIfNeeded if true map will be created if it does not exist
	 * @return manager string data map or null
	 * @throws IOException if an IO error occurs
	 */
	private DBStringMapAdapter getArchiveDataMap(boolean createIfNeeded) throws IOException {
		DBStringMapAdapter mapAdapter = null;
		boolean exists = (dbh.getTable(DATA_MAP_TABLE_NAME) != null);
		if (exists) {
			mapAdapter = new DBStringMapAdapter(dbh, DATA_MAP_TABLE_NAME, false);
		}
		else if (createIfNeeded) {
			mapAdapter = new DBStringMapAdapter(dbh, DATA_MAP_TABLE_NAME, true);
		}
		return mapAdapter;
	}

	protected VersionException createManagers(OpenMode openMode, TaskMonitor monitor)
			throws CancelledException, IOException {

		VersionException versionExc = null;
		try {
			dataTypeManager = createDataTypeManager(dbh, openMode, monitor);
			if (dataTypeManager.hasReadOnlyDataOrgChange()) {
				warning = ArchiveWarning.DATA_ORG_CHANGED;
			}

			//
			// NOTE: logWarning() must be invoked immediately after instantiating a 
			// StandAloneDataTypeManagerDB for an existing database after which
			// getName() and getPath() can be invoked safely.  In addition, it 
			// may be appropriate to use getWarning(), to check for warnings,
			// prior to use.
			//

			logWarning();
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		return versionExc;
	}

	/**
	 * Set change set during testing.
	 * @param changeSet archive DB change set
	 */
	void setChangeSet(DataTypeArchiveDBChangeSet changeSet) {
		this.changeSet = changeSet;
	}

	@Override
	public String getName() {
		return getDomainFile().getName();
	}

	@Override
	public boolean isChangeable() {
		return !immutable;
	}

	@Override
	protected void setImmutable() {
		super.setImmutable();
		immutable = true;
		changed = false;
	}

	@Override
	public boolean isUpdatable() {
		return dbh.canUpdate();
	}

	@Override
	protected void domainObjectRestored() {
		super.domainObjectRestored();
		dataTypeManager.notifyRestored();
	}

	@Override
	protected void clearCache(boolean all) {
		try (@SuppressWarnings("unused")
		Closeable c = lock.write()) {
			super.clearCache(all);
			dataTypeManager.invalidateCache();
		}
	}

	@Override
	protected void close() {
		closeManagers();
		super.close();
	}

	private void closeManagers() {
		if (dataTypeManager != null) {
			dataTypeManager.dispose();
			dataTypeManager = null;
		}
	}

	@Override
	public ArchiveDataTypeManagerDB getDataTypeManager() {
		return dataTypeManager;
	}

	@Override
	public ProgramArchitecture getProgramArchitecture() {
		return programArchitecture;
	}

	public VariableStorageManager getVariableStorageManager() {
		return variableStorageMgr;
	}

	/**
	 * Get the program architecture information which has been associated with this 
	 * datatype archive.  If {@link #getProgramArchitecture()} returns null this method
	 * may still return information if the program architecture was set on an archive 
	 * and either {@link #isProgramArchitectureMissing()} or 
	 * {@link #isProgramArchitectureUpgradeRequired()} returns true.
	 * @return program architecture summary if it has been set
	 */
	@Override
	public String getProgramArchitectureSummary() {
		if (programArchitectureSummary != null) {
			return programArchitectureSummary;
		}
		if (programArchitecture != null) {
			return programArchitecture.getSummary();
		}
		return null;
	}

	/**
	 * Determine if a program architecture change is permitted
	 * @return true if change allowed else false if disallowed
	 */
	protected boolean isArchitectureChangeAllowed() {
		return true;
	}

	@Override
	public void setProgramArchitecture(Language language, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			CancelledException, LockException, UnsupportedOperationException,
			IncompatibleLanguageException {

		lock.writeLock().lock();
		try {
			checkConditionsForSettingArchitecture(language, compilerSpecId);
			CompilerSpec compilerSpec = language.getCompilerSpecByID(compilerSpecId);
			int txId = startTransaction("Set Program Architecture");
			try {
				ProgramArchitectureTranslator translator = null;
				ProgramArchitecture oldArch = getProgramArchitecture();
				if (oldArch != null || isProgramArchitectureMissing()) {
					doSetArchiture(language, compilerSpecId, updateOption, monitor, translator,
						oldArch);
				}

				programArchitecture = new ArchiveProgramArchitecture(language, compilerSpec);
				updateVariableStorageManager();
				saveLanguageInfo(language.getLanguageID(), compilerSpecId, language.getVersion());
				warning = ArchiveWarning.NONE;
				dataTypeManager.programArchitectureChanged(monitor);
			}
			finally {
				// TODO: ensure state is restored if transaction rollback/cancel occurs
				endTransaction(txId, !monitor.isCancelled());
			}

			setChanged(DtArchiveEvent.ARCHIVE_ARCHITECTURE_CHANGED, null, null);

		}
		finally {
			clearCache(true);
			lock.writeLock().unlock();
		}
	}

	private void updateVariableStorageManager() throws IOException {
		if (variableStorageMgr == null) {
			try {
				variableStorageMgr =
					new VariableStorageManagerDB(dbh, null, OpenMode.CREATE,
						this, lock, TaskMonitor.DUMMY);
			}
			catch (VersionException | CancelledException e) {
				throw new AssertException(e); // unexpected
			}
		}
		variableStorageMgr.setProgramArchitecture(programArchitecture);
	}

	private void doSetArchiture(Language language, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor,
			ProgramArchitectureTranslator translator, ProgramArchitecture oldArch)
			throws IOException, CancelledException, LanguageNotFoundException,
			CompilerSpecNotFoundException, IncompatibleLanguageException {

		if (updateOption == LanguageUpdateOption.CLEAR) {
			deleteAllProgramArchitectureData(monitor);
			variableStorageMgr = null;
		}
		else if (isProgramArchitectureMissing()) {

			assert (variableStorageMgr == null);

			if (updateOption == LanguageUpdateOption.TRANSLATE) {
				// Go out on a limb and use any version of old language if available
				LanguageID oldLanguageId =
					new LanguageID(archiveDataMap.get(LANGUAGE_ID));
				CompilerSpecID oldCompilerSpecId =
					new CompilerSpecID(archiveDataMap.get(COMPILER_SPEC_ID));
				translator = new ProgramArchitectureTranslator(oldLanguageId, -1,
					oldCompilerSpecId, language, compilerSpecId);
			}

			if (VariableStorageManagerDB.exists(dbh)) {
				try {
					variableStorageMgr = new VariableStorageManagerDB(dbh, null,
						OpenMode.UPDATE, this, lock, monitor);
				}
				catch (VersionException e) {
					throw new IOException(
						"Unexpected version error for VariableStorageManagerDB");
				}
			}
		}
		else if (updateOption == LanguageUpdateOption.TRANSLATE) {
			translator = new ProgramArchitectureTranslator(oldArch.getLanguage(),
				oldArch.getCompilerSpec().getCompilerSpecID(), language,
				compilerSpecId);
		}

		if (translator != null && variableStorageMgr != null) {
			variableStorageMgr.setLanguage(translator, monitor);
		}
	}

	private void checkConditionsForSettingArchitecture(Language language,
			CompilerSpecID compilerSpecId) throws ReadOnlyException, LockException {

		if (!isArchitectureChangeAllowed()) {
			throw new UnsupportedOperationException(
				"Program-architecture change not permitted");
		}

		if (immutable) {
			throw new ReadOnlyException("Read-only Archive: " + getName());
		}

		if (!hasExclusiveAccess()) {
			throw new LockException("Exclusive access required for architecture change");
		}

		Msg.info(this,
			"Updating program-architecture for Archive: " + getName() + "\n   Language: " +
				language.getLanguageID() + " version " + language.getVersion() + ".x" +
				", CompilerSpec: " + compilerSpecId);

	}

	@Override
	public void setProgramArchitecture(LanguageID languageId, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			CancelledException, LockException, UnsupportedOperationException,
			IncompatibleLanguageException {

		// Verify that the specified language and compiler spec are valid 
		LanguageService languageService = DefaultLanguageService.getLanguageService();
		Language language = languageService.getLanguage(languageId);
		language.getCompilerSpecByID(compilerSpecId);

		setProgramArchitecture(language, compilerSpecId, updateOption, monitor);
	}

	/**
	 * Delete all program architecture related data in response to an
	 * architecture change when all related data should be removed.
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled
	 */
	private void deleteAllProgramArchitectureData(TaskMonitor monitor)
			throws IOException, CancelledException {

		archiveDataMap.delete(LANGUAGE_ID);
		archiveDataMap.delete(LANGUAGE_VERSION);
		archiveDataMap.delete(COMPILER_SPEC_ID);

		VariableStorageManagerDB.delete(dbh);

		warning = ArchiveWarning.NONE;
		programArchitecture = null;
	}

	@Override
	public void clearProgramArchitecture(TaskMonitor monitor)
			throws CancelledException, IOException, LockException {
		lock.writeLock().lock();
		try {

			if (!isArchitectureChangeAllowed()) {
				throw new UnsupportedOperationException(
					"Program-architecture change not permitted");
			}

			if (!dbh.canUpdate()) {
				throw new ReadOnlyException("Read-only Archive: " + getName());
			}

			if (getProgramArchitecture() == null && !isProgramArchitectureMissing()) {
				return;
			}

			Msg.info(this, "Removing program-architecture for Archive: " + getName());

			int txId = startTransaction("Remove Program Architecture");
			try {
				if (!isArchitectureChangeAllowed()) {
					throw new UnsupportedOperationException(
						"Program-architecture change not permitted");
				}
				dataTypeManager.clearCustomStorageUse(monitor);
				deleteAllProgramArchitectureData(monitor);
				dataTypeManager.programArchitectureChanged(monitor);
			}
			finally {
				// TODO: ensure state is restored if transaction rollback/cancel occurs
				endTransaction(txId, !monitor.isCancelled());

			}

			setChanged(DtArchiveEvent.ARCHIVE_ARCHITECTURE_CHANGED, null, null);
		}
		finally {
			clearCache(true);
			lock.writeLock().unlock();
		}
	}

	@Override
	public boolean isProgramArchitectureUpgradeRequired() {
		return warning == ArchiveWarning.LANGUAGE_UPGRADE_REQURED;
	}

	@Override
	public boolean isProgramArchitectureMissing() {
		return warning == ArchiveWarning.LANGUAGE_NOT_FOUND ||
			warning == ArchiveWarning.COMPILER_SPEC_NOT_FOUND;
	}

	@Override
	public ArchiveWarning getWarning() {
		return warning;
	}

	@Override
	public Exception getWarningDetail() {
		return warningDetail;
	}

	@Override
	public String getWarningMessage(boolean includeDetails) {
		String msg = null;
		switch (warning) {
			case LANGUAGE_NOT_FOUND:
				msg = "Language not found for Archive";
				if (includeDetails) {
					msg += " '" + getName() + "': " + warningDetail.getMessage();
				}
				break;
			case COMPILER_SPEC_NOT_FOUND:
				msg = "Compiler specification not found for Archive";
				if (includeDetails) {
					msg += " '" + getName() + "': " + warningDetail.getMessage();
				}
				break;
			case LANGUAGE_UPGRADE_REQURED:
				msg = "Language upgrade required for Archive";
				if (includeDetails) {
					msg += " '" + getName() + "': " + getProgramArchitectureSummary();
				}
				break;
			case UPGRADED_LANGUAGE_VERSION:
				msg = "Upgraded program-architecture for Archive";
				if (includeDetails) {
					ProgramArchitecture arch = getProgramArchitecture();
					LanguageDescription languageDescription =
						arch.getLanguage().getLanguageDescription();
					msg += " '" + getName() + "'\n   Language: " +
						languageDescription.getLanguageID() + " Version " +
						languageDescription.getVersion() + ".x" + ", CompilerSpec: " +
						arch.getCompilerSpec().getCompilerSpecID();
				}
				break;
			case DATA_ORG_CHANGED:
				msg = "Data organization upgrade required for Archive";
				if (includeDetails) {
					msg += " '" + getName() + "': " + getProgramArchitectureSummary();
				}
				break;
			default:
				break;
		}
		return msg;
	}

	/**
	 * Due to the suppression of error and warning conditions during instantiation this method should
	 * be invoked at the end of instantiation when {@link #getName()} and {@link #getPath()} are
	 * ready to be invoked safely.  Logging will be performed via {@link Msg}.
	 */
	public void logWarning() {
		String msg = getWarningMessage(true);
		if (msg == null) {
			return;
		}
		switch (warning.level) {
			case ERROR:
				Msg.error(this, msg);
				break;
			case WARN:
				Msg.warn(this, msg);
				break;
			default:
				Msg.info(this, msg);
				break;
		}

	}

	/**
	 * Get the appropriate {@link ArchiveDataTypeManagerDB} implementation during initialization
	 * of this archive.
	 * @param handle database handle
	 * @param openMode open mode
	 * @param monitor task monitor
	 * @return datatype manager instance
	 * @throws IOException if an error accessing the database occurs.
	 * @throws VersionException if database version does not match implementation, 
	 *         If open mode is UPDATE, an UPGRADE may be possible as indicated by exception.
	 * @throws CancelledException if instantiation is canceled by monitor
	 */
	protected abstract ArchiveDataTypeManagerDB createDataTypeManager(DBHandle handle,
			OpenMode openMode, TaskMonitor monitor)
			throws VersionException, IOException, CancelledException;

	@Override
	public int startTransaction(String description, AbortedTransactionListener listener)
			throws TerminatedTransactionException {
		// NOTE: All public start and open transaction invocations pass through this method
		if (immutable) {
			throw new TerminatedTransactionException("Transaction not permitted: read-only");
		}
		return super.startTransaction(description, listener);
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
	public void setChanged(DtArchiveEvent eventType, Object oldValue, Object newValue) {
		changed = true;
		fireEvent(new DtArchiveChangeRecord(this, eventType, oldValue, newValue));
	}

	private static class ArchiveProgramArchitecture implements ProgramArchitecture {
		private Language language;
		private CompilerSpec cspec;
		private AddressFactory addressFactory;

		ArchiveProgramArchitecture(Language language, CompilerSpec cspec) {
			this.language = language;
			this.cspec = cspec;
			this.addressFactory = new ProgramAddressFactory(language, cspec, null);
		}

		@Override
		public Language getLanguage() {
			return language;
		}

		@Override
		public AddressFactory getAddressFactory() {
			return addressFactory;
		}

		@Override
		public CompilerSpec getCompilerSpec() {
			return cspec;
		}
	}

	private static record ArchitectureInfo(LanguageID languageId, CompilerSpecID compilerID,
			int languageVersion) {}

}
