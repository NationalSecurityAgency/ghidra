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
package ghidra.program.model.data;

import java.io.Closeable;
import java.io.IOException;
import java.util.LinkedList;

import javax.help.UnsupportedOperationException;

import com.google.common.collect.ImmutableList;

import db.*;
import db.util.ErrorHandler;
import generic.jar.ResourceFile;
import ghidra.framework.store.LockException;
import ghidra.program.database.DBStringMapAdapter;
import ghidra.program.database.ProgramAddressFactory;
import ghidra.program.database.data.DataTypeManagerDB;
import ghidra.program.database.symbol.VariableStorageManager;
import ghidra.program.database.symbol.VariableStorageManagerDB;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.IncompatibleLanguageException;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.LanguageTranslator;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Basic implementation of the DataTypeManger interface
 */
public class StandAloneDataTypeManager extends DataTypeManagerDB implements Closeable {

	private static final String LANGUAGE_VERSION = "Language Version"; // major version only
	private static final String LANGUAGE_ID = "Language ID";
	private static final String COMPILER_SPEC_ID = "Compiler Spec ID";

	private int transactionCount;
	private Long transaction;
	private boolean commitTransaction;

	private LanguageTranslator languageUpgradeTranslator;
	private String programArchitectureSummary; // summary of expected program architecture

	protected String name;
	
	public static enum ArchiveWarning {
		/**
		 * {@link #NONE} indicates a normal archive condition
		 */
		NONE,

		/**
		 * {@link #UPGRADED_LANGUAGE_VERSION} indicates an archive which has been open for update
		 * was upgraded to a newer language version.  This is expected when the {@link Language}
		 * required by the associated {@link ProgramArchitecture} has a major version change 
		 * which involves significant {@link Register} changes.  Sharing an upgraded archive 
		 * may impact others who do not have access to the updated {@link Language} module.
		 */
		UPGRADED_LANGUAGE_VERSION,

		// programArchitectureSummary must be set for the warnings below

		/**
		 * {@link #LANGUAGE_NOT_FOUND} indicates the {@link Language} or its appropriate version, 
		 * required by the associated {@link ProgramArchitecture}, was not found or encountered
		 * a problem being loaded.  The {@link FileDataTypeManager#getWarningDetail()} may provide
		 * additional insight to the underlying cause. 
		 */
		LANGUAGE_NOT_FOUND,

		/**
		 * {@link #COMPILER_SPEC_NOT_FOUND} indicates the {@link CompilerSpec}, 
		 * required by the associated {@link ProgramArchitecture}, was not found or encountered
		 * a problem being loaded.  The {@link FileDataTypeManager#getWarningDetail()} may provide
		 * additional insight to the underlying cause.  This condition can only occur if the
		 * required {@link Language} was found. 
		 */
		COMPILER_SPEC_NOT_FOUND,

		/**
		 * {@link #LANGUAGE_UPGRADE_REQURED} indicates an archive which has been open read-only
		 * requires an upgraded to a newer language version.  This is expected when the 
		 * {@link Language} required by the associated {@link ProgramArchitecture} has a major 
		 * version change within the current installation.  Major version changes for a 
		 * {@link Language} rarely occur but are required when significant {@link Register} 
		 * or addressing changes have been made.  Upgrading a shared archive may impact others 
		 * who do not have access to the updated {@link Language} module and should be 
		 * coordinated with others who may be affected.
		 */
		LANGUAGE_UPGRADE_REQURED,
	}

	private ArchiveWarning warning;
	private Exception warningDetail;

	/**
	 * Constructor for new temporary data-type manager using the default DataOrganization.
	 * Note that this manager does not support the save or saveAs operation.
	 * @param rootName Name of the root category.
	 */
	public StandAloneDataTypeManager(String rootName) {
		super(DataOrganizationImpl.getDefaultOrganization());
		this.name = rootName;
	}

	/**
	 * Constructor for new temporary data-type manager using a specified DataOrganization.
	 * Note that this manager does not support the save or saveAs operation.
	 * @param rootName Name of the root category.
	 * @param dataOrganzation applicable data organization
	 */
	public StandAloneDataTypeManager(String rootName, DataOrganization dataOrganzation) {
		super(dataOrganzation);
		this.name = rootName;
	}

	/**
	 * Constructor for a data-type manager backed by a packed database file.
	 * When opening for UPDATE an automatic upgrade will be performed if required.
	 * <p>
	 * <B>NOTE:</B> {@link #reportWarning()} should be invoked immediately after 
	 * instantiating a {@link StandAloneDataTypeManager} for an existing database after 
	 * {@link #getName()} and {@link #getPath()} can be invoked safely.  In addition, it 
	 * may be appropriate to use {@link #getWarning() check for warnings} prior to use.
	 * 
	 * @param packedDbfile packed datatype archive file (i.e., *.gdt resource).
	 * @param openMode open mode CREATE, READ_ONLY or UPDATE (see {@link DBConstants})
	 * @throws IOException a low-level IO error.  This exception may also be thrown
	 * when a version error occurs (cause is VersionException).
	 */
	protected StandAloneDataTypeManager(ResourceFile packedDbfile, int openMode)
			throws IOException {
		super(packedDbfile, openMode);
	}

	/**
	 * Constructor for a data-type manager using a specified DBHandle.
	 * <p>
	 * <B>NOTE:</B> {@link #reportWarning()} should be invoked immediately after 
	 * instantiating a {@link StandAloneDataTypeManager} for an existing database after 
	 * {@link #getName()} and {@link #getPath()} can be invoked safely.  In addition, it 
	 * may be appropriate to use {@link #getWarning() check for warnings} prior to use.
	 * 
	 * @param handle open database  handle
	 * @param openMode the program open mode
	 * @param errHandler the database I/O error handler
	 * @param lock the program synchronization lock
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database I/O error occurs.
	 */
	protected StandAloneDataTypeManager(DBHandle handle, int openMode, ErrorHandler errHandler,
			Lock lock, TaskMonitor monitor)
			throws CancelledException, VersionException, IOException {
		super(handle, null, openMode, null, errHandler, lock, monitor);
	}

	/**
	 * Get the {@link ArchiveWarning} which may have occured immediately following 
	 * instatiation of this {@link StandAloneDataTypeManager}.  {@link ArchiveWarning#NONE}
	 * will be returned if not warning condition.
	 * @return warning type.
	 */
	public ArchiveWarning getWarning() {
		return warning;
	}

	/**
	 * Get the detail exception associated with {@link ArchiveWarning#LANGUAGE_NOT_FOUND} or
	 * {@link ArchiveWarning#COMPILER_SPEC_NOT_FOUND} warning (see {@link #getWarning()})
	 * immediately following instatiation of this {@link StandAloneDataTypeManager}.
	 * @return warning detail exception or null
	 */
	public Exception getWarningDetail() {
		return warningDetail;
	}

	/**
	 * Due to the supression of error and warning conditions during instantiation this method should
	 * be invoked at the end of instatiation when {@link #getName()} and {@link #getPath()} are
	 * ready to be invoked safely.  Logging will be performed via {@link Msg}.
	 */
	protected void reportWarning() {
		String msg;
		switch (warning) {
			case NONE:
				break;
			case LANGUAGE_NOT_FOUND:
				msg = "Language not found for Archive '" + getName() + "': " +
					warningDetail.getMessage();
				Msg.error(this, msg);
				break;
			case COMPILER_SPEC_NOT_FOUND:
				msg = "Compiler specification not found for Archive '" + getName() + "': " +
					warningDetail.getMessage();
				Msg.error(this, msg);
				break;
			case LANGUAGE_UPGRADE_REQURED:
				msg = "Language upgrade required for Archive '" + getName() + "': " +
					programArchitectureSummary;
				Msg.warn(this, msg);
				break;
			case UPGRADED_LANGUAGE_VERSION:
				ProgramArchitecture arch = getProgramArchitecture();
				LanguageDescription languageDescription =
					arch.getLanguage().getLanguageDescription();
				msg =
					"Upgraded program-architecture for Archive: '" + getName() +
						"'\n   Language: " +
						languageDescription.getLanguageID() + " Version " +
						languageDescription.getVersion() + ".x" +
						", CompilerSpec: " + arch.getCompilerSpec().getCompilerSpecID();
				Msg.info(this, msg);
		}

	}

	@Override
	protected void initializeOtherAdapters(int openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {

		warning = ArchiveWarning.NONE;
		if (openMode == DBConstants.CREATE) {
			return; // optional program architecture is set after initialization is complete
		}

		// Check for optional program architecture data (LanguageID, etc.)
		// The DB data map is also used by the base implementation to store the data organization
		DBStringMapAdapter dataMap = getDataMap(false);
		if (dataMap == null) {
			return;
		}

		String languageIdStr = dataMap.get(LANGUAGE_ID);
		if (languageIdStr == null) {
			return; // assume architecture info is missing
		}
		LanguageID languageId = new LanguageID(languageIdStr);
		CompilerSpecID compilerSpecId = new CompilerSpecID(dataMap.get(COMPILER_SPEC_ID));
		int languageVersion = 1;
		try {
			languageVersion = Integer.parseInt(dataMap.get(LANGUAGE_VERSION));
		}
		catch (Exception e) {
			// Ignore
		}

		VariableStorageManagerDB variableStorageMgr = null;
		if (VariableStorageManagerDB.exists(dbHandle)) {
			variableStorageMgr =
				new VariableStorageManagerDB(dbHandle, null, openMode, errHandler, lock, monitor);
		}

		programArchitectureSummary =
			getProgramArchitectureSummary(languageId, languageVersion, compilerSpecId);

		Language language = null;
		LanguageVersionException languageVersionExc = null;
		try {
			language = DefaultLanguageService.getLanguageService().getLanguage(languageId);
			languageVersionExc =
				LanguageVersionException.check(language, languageVersion, -1); // don't care about minor version
		}
		catch (LanguageNotFoundException e) {
			warning = ArchiveWarning.LANGUAGE_NOT_FOUND;
			warningDetail = e;
			try {
				languageVersionExc =
					LanguageVersionException.checkForLanguageChange(e, languageId, languageVersion);
			}
			catch (LanguageNotFoundException e2) {
				// Missing language or language translation
				warningDetail = e2;
				return; // allow archive to open without error
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
			if (openMode == DBConstants.READ_ONLY) {
				// read-only mode - do not set program architecture - upgrade flag has been set
				return;
			}

			if (openMode == DBConstants.UPDATE) {
				throw languageVersionExc;
			}

			// else UPGRADE mode falls-through
			language = languageUpgradeTranslator.getNewLanguage();
			compilerSpecId = languageUpgradeTranslator.getNewCompilerSpecID(compilerSpecId);
		}

		assert (language != null);

		CompilerSpec compilerSpec;
		try {
			compilerSpec = language.getCompilerSpecByID(compilerSpecId);
		}
		catch (CompilerSpecNotFoundException e) {
			warning = ArchiveWarning.COMPILER_SPEC_NOT_FOUND;
			warningDetail = e;
			return; // allow archive to open without error
		}

		if (warning == ArchiveWarning.LANGUAGE_UPGRADE_REQURED) {

			if (variableStorageMgr != null) {
				variableStorageMgr.setLanguage(languageUpgradeTranslator, monitor);
			}

			// update data map with language upgrade info
			dataMap.put(LANGUAGE_ID, language.getLanguageID().getIdAsString());
			dataMap.put(LANGUAGE_VERSION, Integer.toString(language.getVersion()));
			dataMap.put(COMPILER_SPEC_ID, compilerSpecId.getIdAsString());

			warning = ArchiveWarning.UPGRADED_LANGUAGE_VERSION;
		}

		programArchitectureSummary = null; // not needed

		final Language lang = language;
		final CompilerSpec cspec = compilerSpec;
		final AddressFactory addrFactory = new ProgramAddressFactory(lang, cspec);

		super.setProgramArchitecture(new ProgramArchitecture() {

			@Override
			public Language getLanguage() {
				return lang;
			}

			@Override
			public CompilerSpec getCompilerSpec() {
				return cspec;
			}

			@Override
			public AddressFactory getAddressFactory() {
				return addrFactory;
			}
		}, variableStorageMgr, false, monitor);

		if (variableStorageMgr != null) {
			variableStorageMgr.setProgramArchitecture(getProgramArchitecture());
		}

	}

	/**
	 * Get the program architecture information which has been associated with this 
	 * datatype manager.  If {@link #getProgramArchitecture()} returns null this method
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
		return super.getProgramArchitectureSummary();
	}

	/**
	 * Delete all program architecture related data in response to an
	 * architecture change when all related data should be removed.
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled
	 */
	private void deleteAllProgramArchitectureData(TaskMonitor monitor)
			throws IOException, CancelledException {

		clearCustomStorageUse(monitor);

		DBStringMapAdapter dataMap = getDataMap(false);
		if (dataMap != null) {
			dataMap.delete(LANGUAGE_ID);
			dataMap.delete(LANGUAGE_VERSION);
			dataMap.delete(COMPILER_SPEC_ID);
		}

		VariableStorageManagerDB.delete(dbHandle);

		warning = ArchiveWarning.NONE;
		programArchitectureSummary = null;
	}

	private VariableStorageManagerDB createProgramArchitectureData(
			ProgramArchitecture programArchitecture, VariableStorageManagerDB variableStorageMgr)
			throws IOException {
		Language newLanguage = programArchitecture.getLanguage();
		LanguageID newLanguageId = newLanguage.getLanguageID();
		CompilerSpec newCompilerSpec = programArchitecture.getCompilerSpec();
		CompilerSpecID newCmpilerSpecID = newCompilerSpec.getCompilerSpecID();

		DBStringMapAdapter dataMap = getDataMap(true);
		dataMap.put(LANGUAGE_ID, newLanguageId.getIdAsString());
		dataMap.put(COMPILER_SPEC_ID, newCmpilerSpecID.getIdAsString());
		dataMap.put(LANGUAGE_VERSION, Integer.toString(newLanguage.getVersion())); // major version only

		if (variableStorageMgr == null) { // TODO: may re-use if translation performed
			try {
				variableStorageMgr = new VariableStorageManagerDB(dbHandle, null,
					DBConstants.CREATE, errHandler, lock, TaskMonitor.DUMMY);
				variableStorageMgr.setProgramArchitecture(programArchitecture);
			}
			catch (VersionException | CancelledException e) {
				throw new AssertException(e); // unexpected
			}
		}

		variableStorageMgr.setProgramArchitecture(programArchitecture);

		warning = ArchiveWarning.NONE;
		programArchitectureSummary = null;

		return variableStorageMgr;
	}

	/**
	 * Indicates that an program architecture upgrade is required in order
	 * to constitute associated data.  If true, the associated archive
	 * must be open for update to allow the upgrade to complete, or a new
	 * program architecture may be set/cleared if such an operation is supported.
	 * @return true if a program architecture upgrade is required, else false
	 */
	public boolean isProgramArchitectureUpgradeRequired() {
		return warning == ArchiveWarning.LANGUAGE_UPGRADE_REQURED;
	}

	/**
	 * Indicates that a failure occured establishing the program architecture 
	 * for the associated archive.
	 * @return true if a failure occured establishing the program architecture 
	 */
	public boolean isProgramArchitectureMissing() {
		return warning == ArchiveWarning.LANGUAGE_NOT_FOUND ||
			warning == ArchiveWarning.COMPILER_SPEC_NOT_FOUND;
	}


	/**
	 * Clear the program architecture setting and all architecture-specific data from this archive.
	 * Archive will revert to using the default {@link DataOrganization}.
	 * Archive must be open for update for this method to be used.
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled.  If thrown, this data type manager is no longer 
	 * stable and should be closed without saving.
	 * @throws IOException if IO error occurs
	 * @throws LockException failure if exclusive access is required
	 * @throws UnsupportedOperationException if architecture change is not permitted by 
	 * implementation (e.g., {@link BuiltInDataTypeManager}).
	 */
	public void clearProgramArchitecture(TaskMonitor monitor)
			throws CancelledException, IOException, LockException {
		lock.acquire();
		try {

			if (!isArchitectureChangeAllowed()) {
				throw new UnsupportedOperationException(
					"Program-architecture change not permitted");
			}

			if (!dbHandle.canUpdate()) {
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
				deleteAllProgramArchitectureData(monitor);

				super.setProgramArchitecture((ProgramArchitecture) null, null, true, monitor);
			}
			finally {
				// TODO: ensure state is restored if transaction rollback/cancel occurs
				endTransaction(txId, !monitor.isCancelled());
			}

			defaultListener.programArchitectureChanged(this);
		}
		finally {
			invalidateCache();
			lock.release();
		}
	}

	public static enum LanguageUpdateOption {
		/**
		 * All existing storage data should be cleared
		 */
		CLEAR,
		/**
		 * An attempt should be made to translate from old-to-new language.
		 * This has limitations (i.e., similar architecture) and may result in 
		 * poor register mappings.
		 */
		TRANSLATE,
		/**
		 * Variable storage data will be retained as-is but may not de-serialize 
		 * properly when used.
		 */
		UNCHANGED // TODO: Need to test to see if this option is safe and useable
	}

	/**
	 * Establish the program architecture for this datatype manager.  The current setting can be 
	 * determined from {@link #getProgramArchitecture()}.  Archive must be open for update for 
	 * this method to be used.
	 * @param language language
	 * @param compilerSpecId compiler specification ID defined by the language.
	 * @param updateOption indicates how variable storage data should be transitioned.  If {@link #isProgramArchitectureMissing()}
	 * is true and {@link LanguageUpdateOption#TRANSLATE} specified, the translator will be based on whatever language version can 
	 * be found.  In this situation it may be best to force a  {@link LanguageUpdateOption#CLEAR}.
	 * @param monitor task monitor (cancel not permitted to avoid corrupt state)
	 * @throws CompilerSpecNotFoundException if invalid compilerSpecId specified for language
	 * @throws LanguageNotFoundException if current language is not found (if required for data transition)
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if task cancelled.  If thrown, this data type manager is no longer 
	 * stable and should be closed without saving.
	 * @throws LockException failure if exclusive access is required
	 * @throws UnsupportedOperationException if architecture change is not permitted
	 * @throws IncompatibleLanguageException if translation requested but not possible due to incompatible language architectures
	 */
	public void setProgramArchitecture(Language language, CompilerSpecID compilerSpecId,
			LanguageUpdateOption updateOption, TaskMonitor monitor)
			throws CompilerSpecNotFoundException, LanguageNotFoundException, IOException,
			CancelledException, LockException, UnsupportedOperationException,
			IncompatibleLanguageException {

		lock.acquire();
		try {
			
			if (!isArchitectureChangeAllowed()) {
				throw new UnsupportedOperationException(
					"Program-architecture change not permitted");
			}
			
			if (!dbHandle.canUpdate()) {
				throw new ReadOnlyException("Read-only Archive: " + getName());
			}

			Msg.info(this,
				"Updating program-architecture for Archive: " + getName() + "\n   Language: " +
					language.getLanguageID() + " version " + language.getVersion() + ".x" +
					", CompilerSpec: " + compilerSpecId);

			CompilerSpec compilerSpec = language.getCompilerSpecByID(compilerSpecId);
			
			// This type of datatype manager only uses VariableStorageManagerDB
			VariableStorageManagerDB variableStorageMgr =
				(VariableStorageManagerDB) getVariableStorageManager();
			
			int txId = startTransaction("Set Program Architecture");
			try {
				ProgramArchitectureTranslator translator = null;
				
				ProgramArchitecture oldArch = getProgramArchitecture();
				if (oldArch != null || isProgramArchitectureMissing()) {
					
					if (updateOption == LanguageUpdateOption.CLEAR) {
						deleteAllProgramArchitectureData(monitor);
						variableStorageMgr = null;
					}
					else if (isProgramArchitectureMissing()) {

						assert (variableStorageMgr == null);

						if (updateOption == LanguageUpdateOption.TRANSLATE) {
							// Go out on a limb and use any version of old language if available
							DBStringMapAdapter dataMap = getDataMap(false);
							LanguageID oldLanguageId =
								new LanguageID(getDataMap(false).get(LANGUAGE_ID));
							CompilerSpecID oldCompilerSpecId =
								new CompilerSpecID(dataMap.get(COMPILER_SPEC_ID));
							translator = new ProgramArchitectureTranslator(oldLanguageId, -1,
								oldCompilerSpecId, language, compilerSpecId);
						}

						if (VariableStorageManagerDB.exists(dbHandle)) {
							try {
								variableStorageMgr = new VariableStorageManagerDB(dbHandle, null,
									DBConstants.UPDATE, errHandler, lock, monitor);
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
				
				ProgramArchitecture programArchitecture = new ProgramArchitecture() {

					@Override
					public Language getLanguage() {
						return language;
					}

					@Override
					public CompilerSpec getCompilerSpec() {
						return compilerSpec;
					}

					@Override
					public AddressFactory getAddressFactory() {
						return language.getAddressFactory();
					}
				};

				variableStorageMgr =
					createProgramArchitectureData(programArchitecture, variableStorageMgr);

				super.setProgramArchitecture(programArchitecture, variableStorageMgr, true,
					monitor);
			}
			finally {
				// TODO: ensure state is restored if transaction rollback/cancel occurs
				endTransaction(txId, !monitor.isCancelled());
			}

			defaultListener.programArchitectureChanged(this);
		}
		finally {
			invalidateCache();
			lock.release();
		}
	}

	/**
	 * Set the architecture-specific details associated with a new datatype manager.
	 * This method is intended to be used during instantiation of derived implementations.
	 * @param programArchitecture program architecture details (required)
	 * @param variableStorageMgr variable storage manager.  Must be null.
	 * @param store if true database update will occur and datatypes will be updated if
	 * any change to the data organization is detected (a stored copy may be used to
	 * detect this condition).  This should never be passed as true if opened read-only.
	 * If true and no variable storage is specified it will be created.
	 * @param monitor task monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException  if task cancelled
	 * @throws UnsupportedOperationException if language was previously set
	 */
	@Override
	protected void setProgramArchitecture(ProgramArchitecture programArchitecture,
			VariableStorageManager variableStorageMgr, boolean store, TaskMonitor monitor)
			throws IOException, CancelledException {

		// TODO: Determine if cancelling can leave in bad state

		if (programArchitecture == null) {
			throw new IllegalArgumentException("ProgramArchitecture must be specified");
		}
		if (variableStorageMgr != null) {
			throw new IllegalArgumentException("VariableStorageManager may not be specified");
		}

		if (getProgramArchitecture() != null || isProgramArchitectureUpgradeRequired() ||
			isProgramArchitectureMissing()) {
				throw new UnsupportedOperationException(
					"Program-architecture change not permitted with this method");
		}

		if (store) {
			variableStorageMgr = createProgramArchitectureData(programArchitecture, null);
		}

		// super handles possible change to data organization and update if store is true
		super.setProgramArchitecture(programArchitecture, variableStorageMgr, store, monitor);
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
		return name;
	}

	@Override
	public void setName(String name) throws InvalidNameException {
		if (name == null || name.length() == 0) {
			throw new InvalidNameException("Name is invalid: " + name);
		}
		this.name = name;

		defaultListener.categoryRenamed(this, CategoryPath.ROOT, CategoryPath.ROOT);
	}
	
	@Override
	public Transaction openTransaction(String description) throws IllegalStateException {
		return new Transaction() {

			private int txId = startTransaction(description);

			@Override
			protected boolean endTransaction(boolean commit) {
				StandAloneDataTypeManager.this.endTransaction(txId, commit);
				return commitTransaction;
			}

			@Override
			public boolean isSubTransaction() {
				return true;
			}
		};
	}

	@Override
	public synchronized int startTransaction(String description) {
		if (transaction == null) {
			transaction = dbHandle.startTransaction();
			commitTransaction = true;
		}
		transactionCount++;
		return transaction.intValue();
	}

	@Override
	public void flushEvents() {
		// do nothing
	}

	@Override
	public synchronized void endTransaction(int transactionID, boolean commit) {
		if (transaction == null) {
			throw new IllegalStateException("No Transaction Open");
		}
		if (transaction.intValue() != transactionID) {
			throw new IllegalArgumentException("Transaction id does not match current transaction");
		}
		if (!commit) {
			commitTransaction = false;
		}
		if (--transactionCount == 0) {
			try {
				dbHandle.endTransaction(transaction.longValue(), commitTransaction);
				transaction = null;
			}
			catch (IOException e) {
				dbError(e);
			}
		}
	}

	@Override
	protected void replaceDataTypeIDs(long oldID, long newID) {
		// do nothing
	}

	@Override
	protected void deleteDataTypeIDs(LinkedList<Long> deletedIds, TaskMonitor monitor) {
		// do nothing
	}

	@Override
	public void close() {
		if (!dbHandle.isClosed()) {
			dbHandle.close();
		}
		super.close();
	}

	@Override
	public void finalize() {
		close();
	}

	@Override
	protected String getDomainFileID() {
		return null;
	}

	/**
	 * Get the path name associated with the storage of this stand alone
	 * datatype manager. 
	 * @return path name or null if not applicable
	 */
	@Override
	public String getPath() {
		return null;
	}

	@Override
	public ArchiveType getType() {
		return ArchiveType.TEST;
	}

	/**
	 * Update custom storage for function definitions to be unassigned.
	 * @param monitor task monitor
	 * @throws CancelledException if task cancelled
	 */
	private void clearCustomStorageUse(TaskMonitor monitor) throws CancelledException {

		// Get copy of all function defs to avoid concurrent modification of underlaying table
		ImmutableList<FunctionDefinition> defs = ImmutableList.copyOf(getAllFunctionDefinitions());

		monitor.initialize(defs.size());
		monitor.setMessage("Clear custom storage use...");

//		for (FunctionDefinition def : ImmutableList.copyOf(getAllFunctionDefinitions())) {
		monitor.checkCancelled();
//			monitor.incrementProgress(1);
//
//			// TODO: update function definition
//			if (def.hasCustomStorage()) {
//				
//				
//			}
//		}

	}
}
