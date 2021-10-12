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
import java.math.BigInteger;
import java.util.*;

import db.*;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.framework.Application;
import ghidra.framework.data.DomainObjectAdapterDB;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.store.FileSystem;
import ghidra.framework.store.LockException;
import ghidra.program.database.bookmark.BookmarkDBManager;
import ghidra.program.database.code.CodeManager;
import ghidra.program.database.code.InstructionDB;
import ghidra.program.database.data.ProgramDataTypeManager;
import ghidra.program.database.external.ExternalManagerDB;
import ghidra.program.database.function.FunctionManagerDB;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.map.AddressMapDB;
import ghidra.program.database.mem.MemoryMapDB;
import ghidra.program.database.module.TreeManager;
import ghidra.program.database.oldfunction.OldFunctionManager;
import ghidra.program.database.properties.DBPropertyMapManager;
import ghidra.program.database.references.ReferenceDBManager;
import ghidra.program.database.register.ProgramRegisterContextDB;
import ghidra.program.database.reloc.RelocationManager;
import ghidra.program.database.symbol.*;
import ghidra.program.database.util.AddressSetPropertyMapDB;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.reloc.RelocationTable;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.AddressSetPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.util.*;
import ghidra.util.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Database implementation for Program. 
 */
public class ProgramDB extends DomainObjectAdapterDB implements Program, ChangeManager {

	public static final String CONTENT_TYPE = "Program";

	private static final String UNKNOWN = "unknown";

	/**
	 * DB_VERSION should be incremented any time a change is made to the overall
	 * database schema associated with any of the managers.
	 *             - version  7 - for changes to addressMapDB for deleted overlay spaces.
	 *             - version  8 - for removal of code manager fall-through maps
	 * 8-Aug-2007  - version  9 - analysis options moved
	 * 25-Oct-2007 - version 10 - added VariableStorageManager (upgrade required)
	 * 11-Jan-2008 - version 11 - added metadata (no changes, but want to force an upgrade)
	 * 31-Jan-2008 - version 12 - eliminated use of Variable addresses for references
	 * 12-Mar-2008 - version 13 - version 12 references upgrade was incomplete
	 * 18-Sep-2008 - version 14 - added fields for synchronizing program data types with project archives.
	 * 27-Aug-2009 - version 15 - added BigRefList support and modified datatype storage tables for alignment support
	 * 16-Jan-2010 - version 16 - force cleanup of renamed analysis properties (see ObsoleteProgramProperties)
	 * 13-Jul-2012 - version 17 - eliminated SymbolType.EXTERNAL (changed to external CODE)
	 *               PENDING: correct pointers wrapped in function (should no longer occur)
	 * 12-Sep-2012 - version 18 - transitioned to VariableStorage use with support for
	 *                            compound storage and the ability compute return/param
	 *                            storage dynamically
	 * 4-Dec-2014  - version 19 - added support for auto-parameters and forced-indirect
	 *                            parameters.  Function upgrade needed to remove 'this'
	 *                            parameter if dynamic parameter storage enabled.
	 * 18-Jul-2018 - version 20 - added support for external locations storing both
	 *                            address and original-imported-name packed into symbol data3.
	 *                            Read of old symbol data3 format does not require upgrade.
	 * 14-May-2020 - version 21 - added support for overlay mapped blocks and byte mapping
	 *                            schemes other than the default 1:1
	 * 19-Jun-2020 - version 22 - Corrected fixed length indexing implementation causing
	 *                            change in index table low-level storage for newly
	 *                            created tables. 
	 * 18-Feb-2021 - version 23   Added support for Big Reflist for tracking FROM references.
	 *                            Primarily used for large numbers of Entry Point references.
	 * 31-Mar-2021 - version 24   Added support for CompilerSpec extensions     
	 */
	static final int DB_VERSION = 24;

	/**
	 * UPGRADE_REQUIRED_BFORE_VERSION should be changed to DB_VERSION anytime the
	 * latest version requires a forced upgrade (i.e., Read-only mode not supported
	 * until upgrade is performed).  It is assumed that read-only mode is supported 
	 * if the data's version is &gt;= UPGRADE_REQUIRED_BEFORE_VERSION and &lt;= DB_VERSION. 
	 */
	private static final int UPGRADE_REQUIRED_BEFORE_VERSION = 19;

	/**
	 * Key version numbers which require special upgrade handling
	 */
	//private static final int REGISTER_CONTEXT_UPGRADE_VERSION = 6;
	public static final int ANALYSIS_OPTIONS_MOVED_VERSION = 9;
	public static final int ADDED_VARIABLE_STORAGE_MANAGER_VERSION = 10;
	public static final int METADATA_ADDED_VERSION = 11;
	public static final int EXTERNAL_FUNCTIONS_ADDED_VERSION = 17;
	public static final int COMPOUND_VARIABLE_STORAGE_ADDED_VERSION = 18;
	public static final int AUTO_PARAMETERS_ADDED_VERSION = 19;

	private static final String LANG_DEFAULT_VERSION = "1.0";

	private static final String PROGRAM_NAME = "Program Name";
	private static final String PROGRAM_DB_VERSION = "DB Version";
	private static final String LANGUAGE_VERSION = "Language Version";
	private static final String OLD_LANGUAGE_NAME = "Language Name";
	private static final String LANGUAGE_ID = "Language ID";
	private static final String COMPILER_SPEC_ID = "Compiler Spec ID";
	private static final String COMPILER = "Compiler";
	private static final String EXECUTABLE_PATH = "Executable Location";
	private static final String EXECUTABLE_FORMAT = "Executable Format";
	private static final String EXECUTABLE_MD5 = "Executable MD5";
	private static final String EXECUTABLE_SHA256 = "Executable SHA256";
	private static final String TABLE_NAME = "Program";
	private static final String EXECUTE_PATH = "Execute Path";
	private static final String EXECUTE_FORMAT = "Execute Format";
	private static final String IMAGE_OFFSET = "Image Offset";

	private final static Field[] COL_FIELDS = new Field[] { StringField.INSTANCE };
	private final static String[] COL_TYPES = new String[] { "Value" };
	private final static Schema SCHEMA =
		new Schema(0, StringField.INSTANCE, "Key", COL_FIELDS, COL_TYPES);

	//
	// The numbering of managers controls the order in which they are notified.
	// The following ManagerDB methods are invoked for each manager starting with index 0:
	//   - setProgram, programReady, clearCache
	// The following ManagerDB methods are invoked for each manager in the REVERSE order, 
	// starting with index NUM_MANAGERS-1:
	//   - deleteAddressRange, moveAddressRange
	// NOTE: for deleting a range the order of the FunctionManager, the
	//  SymbolManager, and the NamespaceManager matters for the following
	//  reasons:
	// (1) the Function ID is the Symbol ID so the Function must be removed before the
	//   symbol is removed.
	// (2) the FunctionManager relies on the NamespaceManager to get the 
	//   functions that overlap a given address set, so the NamespaceManager's
	//   deleteAddressRange method must be called AFTER that of the 
	//   FunctionManager.
	// 
	private static final int MEMORY_MGR = 0;
	private static final int CODE_MGR = 1;
	private static final int SYMBOL_MGR = 2; // do not change the order
	private static final int NAMESPACE_MGR = 3; // do not change the order
	private static final int FUNCTION_MGR = 4; // do not change the order
	private static final int EXTERNAL_MGR = 5; // do not change the order
	private static final int REF_MGR = 6; // do not change the order
	private static final int DATA_MGR = 7;
	private static final int EQUATE_MGR = 8;
	private static final int BOOKMARK_MGR = 9;
	private static final int CONTEXT_MGR = 10;
	private static final int PROPERTY_MGR = 11;
	private static final int TREE_MGR = 12;
	private static final int RELOC_MGR = 13;

	private static final int NUM_MANAGERS = 14;

	private ManagerDB[] managers = new ManagerDB[NUM_MANAGERS];
	private OldFunctionManager oldFunctionMgr;
	private MemoryMapDB memoryManager;
	private GlobalNamespace globalNamespace;

	private boolean changeable = true;
	private ProgramAddressFactory addressFactory;
	private AddressMapDB addrMap;
	private ListingDB listing;
	private ProgramUserDataDB programUserData;
	private Table table;
	private Language language;
	private CompilerSpec compilerSpec;

	private boolean languageUpgradeRequired;
	private LanguageID languageID;
	private CompilerSpecID compilerSpecID;
	private int languageVersion;
	private int languageMinorVersion;
	private LanguageTranslator languageUpgradeTranslator;

	private Address storedImageBase; // current image base maintained by addrMap
	private boolean imageBaseOverride = false;
	private boolean recordChanges;

	private OverlaySpaceAdapterDB overlaySpaceAdapter;

	private Map<String, AddressSetPropertyMapDB> addrSetPropertyMap = new HashMap<>();
	private Map<String, IntRangeMapDB> intRangePropertyMap = new HashMap<>();

	/**
	 * Constructs a new ProgramDB
	 * @param name the name of the program
	 * @param language the Language used by this program
	 * @param compilerSpec compiler specification
	 * @param consumer the object that is using this program.
	 * @throws IOException if there is an error accessing the database.
	 */
	public ProgramDB(String name, Language language, CompilerSpec compilerSpec, Object consumer)
			throws IOException {
		super(new DBHandle(), name, 500, 1000, consumer);

		if (!(compilerSpec instanceof BasicCompilerSpec)) {
			throw new IllegalArgumentException(
				"unsupported compilerSpec: " + compilerSpec.getClass().getName());
		}

		this.language = language;
		this.compilerSpec = ProgramCompilerSpec.getProgramCompilerSpec(this, compilerSpec);

		languageID = language.getLanguageID();
		compilerSpecID = compilerSpec.getCompilerSpecID();
		languageVersion = language.getVersion();
		languageMinorVersion = language.getMinorVersion();

		addressFactory = new ProgramAddressFactory(language, compilerSpec);

		recordChanges = false;
		boolean success = false;
		try {
			int id = startTransaction("create program");

			createDatabase();
			if (createManagers(CREATE, TaskMonitor.DUMMY) != null) {
				throw new AssertException("Unexpected version exception on create");
			}
			listing = new ListingDB();
			changeSet = new ProgramDBChangeSet(addrMap, NUM_UNDOS);
			initManagers(CREATE, TaskMonitor.DUMMY);
			propertiesCreate();
			programUserData = new ProgramUserDataDB(this);
			endTransaction(id, true);
			clearUndo(false);
			registerCompilerSpecOptions();
			getCodeManager().activateContextLocking();
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

		// for tracking during testing
		ProgramUtilities.addTrackedProgram(this);
	}

	/**
	 * Constructs a new ProgramDB
	 * @param dbh a handle to an open program database.
	 * @param openMode one of:
	 * 		READ_ONLY: the original database will not be modified
	 * 		UPDATE: the database can be written to.
	 * 		UPGRADE: the database is upgraded to the latest schema as it is opened.
	 * @param monitor TaskMonitor that allows the open to be canceled.
	 * @param consumer the object that keeping the program open.
	 * @throws IOException if an error accessing the database occurs.
	 * @throws VersionException if database version does not match implementation, UPGRADE may be possible.
	 * @throws CancelledException if instantiation is canceled by monitor
	 * @throws LanguageNotFoundException if a language cannot be found for this program
	 */
	public ProgramDB(DBHandle dbh, int openMode, TaskMonitor monitor, Object consumer)
			throws IOException, VersionException, LanguageNotFoundException, CancelledException {

		super(dbh, "Untitled", 500, 1000, consumer);

		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}

		boolean success = false;
		try {
			int id = startTransaction("create program");
			recordChanges = false;
			changeable = (openMode != READ_ONLY);

			// check DB version and read name, languageName, languageVersion and languageMinorVersion
			VersionException dbVersionExc = initializeDatabase(openMode);

			VersionException languageVersionExc = null;

			try {
				language = DefaultLanguageService.getLanguageService().getLanguage(languageID);
				languageVersionExc = checkLanguageVersion(openMode);
			}
			catch (LanguageNotFoundException e) {
				languageVersionExc = checkForLanguageChange(e, openMode);
			}

			initCompilerSpec();

			addressFactory = new ProgramAddressFactory(language, compilerSpec);

			VersionException versionExc = createManagers(openMode, monitor);
			if (dbVersionExc != null) {
				versionExc = dbVersionExc.combine(versionExc);
			}
			if (languageVersionExc != null) {
				languageUpgradeRequired = true;
				if (openMode != UPGRADE) {
					// Language upgrade required
					versionExc = languageVersionExc.combine(versionExc);
				}
			}

			if (versionExc != null) {
				throw versionExc;
			}

			listing = new ListingDB();
			changeSet = new ProgramDBChangeSet(addrMap, NUM_UNDOS);

			initManagers(openMode, monitor);

			if (openMode == UPGRADE) {
				int oldVersion = getStoredVersion();
				upgradeDatabase(monitor);
				if (languageUpgradeRequired) {
					try {
						// languageUpgradeTranslator will be null for minor version upgrade
						setLanguage(languageUpgradeTranslator, null, false, monitor);
					}
					catch (IllegalStateException e) {
						if (e.getCause() instanceof CancelledException) {
							throw (CancelledException) e.getCause();
						}
						throw e;
					}
					catch (LockException e) {
						throw new AssertException("Upgrade mode requires exclusive access");
					}
					languageUpgradeRequired = false;
				}
				postUpgrade(oldVersion, monitor);
				changed = true;
			}

			propertiesRestore();
			recordChanges = true;
			endTransaction(id, true);
			clearUndo(false);
			SpecExtension.checkFormatVersion(this);
			installExtensions();
			registerCompilerSpecOptions();
			getCodeManager().activateContextLocking();
			success = true;
		}
		finally {
			dbh.closeScratchPad();
			if (!success) {
				release(consumer);
			}
		}

		// for tracking during testing
		ProgramUtilities.addTrackedProgram(this);
	}

	/**
	 * Determine if program initialization requires a language upgrade
	 * @return true if language upgrade is pending
	 */
	public boolean isLanguageUpgradePending() {
		return languageUpgradeRequired;
	}

	/**
	 * Initialize program compiler specification.
	 * During a language upgrade this will provide a temporary spec until setLanguage is complete.
	 * @throws CompilerSpecNotFoundException if the compiler spec cannot be found
	 */
	private void initCompilerSpec() throws CompilerSpecNotFoundException {
		CompilerSpec langSpec;
		try {
			if (languageUpgradeTranslator != null) {
				langSpec = languageUpgradeTranslator.getOldCompilerSpec(compilerSpecID);
			}
			else {
				langSpec = language.getCompilerSpecByID(compilerSpecID);
			}
		}
		catch (CompilerSpecNotFoundException e) {
			Msg.error(this,
				"Compiler Spec " + compilerSpecID + " for Language " +
					language.getLanguageDescription().getDescription() +
					" Not Found, using default: " + e);
			langSpec = language.getDefaultCompilerSpec();
			if (compilerSpec == null) {
				throw e;
			}
			compilerSpecID = compilerSpec.getCompilerSpecID();
		}
		compilerSpec = ProgramCompilerSpec.getProgramCompilerSpec(this, langSpec);
	}

	/**
	 * Language corresponding to languageId was found.  Check language version
	 * for language upgrade situation.
	 * @param openMode one of:
	 * 		READ_ONLY: the original database will not be modified
	 * 		UPDATE: the database can be written to.
	 * 		UPGRADE: the database is upgraded to the latest schema as it is opened.
	 * @throws LanguageNotFoundException if a language cannot be found for this program
	 * @return VersionException if language upgrade required
	 */
	private VersionException checkLanguageVersion(int openMode) throws LanguageNotFoundException {

		if (language.getVersion() > languageVersion) {

			Language newLanguage = language;

			Language oldLanguage = OldLanguageFactory.getOldLanguageFactory()
					.getOldLanguage(languageID, languageVersion);
			if (oldLanguage == null) {
				// Assume minor version behavior - old language does not exist for current major version
				Msg.error(this, "Old language specification not found: " + languageID +
					" (Version " + languageVersion + ")");
				return new VersionException(true);
			}

			// Ensure that we can upgrade the language
			languageUpgradeTranslator = LanguageTranslatorFactory.getLanguageTranslatorFactory()
					.getLanguageTranslator(oldLanguage, newLanguage);
			if (languageUpgradeTranslator == null) {

// TODO: This is a bad situation!! Most language revisions should be supportable, if not we have no choice but to throw 
// a LanguageNotFoundException  until we figure out how to deal with nasty translations which require
// a complete redisassembly and possibly auto analysis.

				throw new LanguageNotFoundException(language.getLanguageID(),
					"(Ver " + languageVersion + "." + languageMinorVersion + " -> " +
						newLanguage.getVersion() + "." + newLanguage.getMinorVersion() +
						") language version translation not supported");
			}
			language = oldLanguage;
			return new VersionException(true);
		}
		else if (language.getVersion() == languageVersion &&
			language.getMinorVersion() > languageMinorVersion) {
			// Minor version change - translator not needed (languageUpgradeTranslator is null)
			return new VersionException(true);
		}
		else if (language.getMinorVersion() != languageMinorVersion ||
			language.getVersion() != languageVersion) {
			throw new LanguageNotFoundException(language.getLanguageID(), languageVersion,
				languageMinorVersion);
		}
		return null;
	}

	/**
	 * Language specified by languageName was not found.  Check for 
	 * valid language translation/migration.  Old language version specified by
	 * languageVersion.
	 * @param openMode one of:
	 * 		READ_ONLY: the original database will not be modified
	 * 		UPDATE: the database can be written to.
	 * 		UPGRADE: the database is upgraded to the latest schema as it is opened.
	 * @return true if language upgrade required
	 * @throws LanguageNotFoundException if a suitable replacement language not found
	 */
	private VersionException checkForLanguageChange(LanguageNotFoundException e, int openMode)
			throws LanguageNotFoundException {

		languageUpgradeTranslator = LanguageTranslatorFactory.getLanguageTranslatorFactory()
				.getLanguageTranslator(languageID, languageVersion);
		if (languageUpgradeTranslator == null) {
			throw e;
		}

		language = languageUpgradeTranslator.getOldLanguage();
		languageID = language.getLanguageID();

		VersionException ve = new VersionException(true);
		LanguageID oldLangName = languageUpgradeTranslator.getOldLanguage().getLanguageID();
		LanguageID newLangName = languageUpgradeTranslator.getNewLanguage().getLanguageID();
		String message;
		if (oldLangName.equals(newLangName)) {
			message = "Program requires a processor language version change";
		}
		else {
			message = "Program requires a processor language change to: " + newLangName;
		}
		ve.setDetailMessage(message);
		return ve;
	}

	@Override
	protected void setDomainFile(DomainFile df) {
		super.setDomainFile(df);
		recordChanges = true;
	}

	private void propertiesRestore() {
		Options pl = getOptions(PROGRAM_INFO);
		boolean origChangeState = changed;
		pl.registerOption(EXECUTABLE_PATH, UNKNOWN, null, "Original import path of program image");
		pl.registerOption(EXECUTABLE_FORMAT, UNKNOWN, null, "Original program image format");
		pl.registerOption(CREATED_WITH_GHIDRA_VERSION, "3.0 or earlier", null,
			"Version of Ghidra used to create this program.");
		pl.registerOption(DATE_CREATED, JANUARY_1_1970, null, "Date this program was created");
		changed = origChangeState;
	}

	private void propertiesCreate() {
		Options pl = getOptions(PROGRAM_INFO);
		boolean origChangeState = changed;
		pl.setString(EXECUTABLE_PATH, UNKNOWN);
		pl.setString(EXECUTABLE_FORMAT, UNKNOWN);
		pl.setString(CREATED_WITH_GHIDRA_VERSION, Application.getApplicationVersion());
		pl.setDate(DATE_CREATED, new Date());
		changed = origChangeState;
	}

	void setProgramUserData(ProgramUserDataDB programUserData) {
		this.programUserData = programUserData;
	}

	@Override
	public ProgramUserData getProgramUserData() {
		if (programUserData == null) {
			try {
				programUserData = new ProgramUserDataDB(this);
			}
			catch (IOException e) {
				dbError(e);
			}
		}
		return programUserData;
	}

	@Override
	protected FileSystem getAssociatedUserFilesystem() {
		// expose to this package
		return super.getAssociatedUserFilesystem();
	}

	@Override
	protected DomainObjectAdapterDB getUserData() {
		return programUserData;
	}

	@Override
	public Listing getListing() {
		return listing;
	}

	@Override
	public SymbolTable getSymbolTable() {
		return (SymbolTable) managers[SYMBOL_MGR];
	}

	@Override
	public ExternalManager getExternalManager() {
		return (ExternalManager) managers[EXTERNAL_MGR];
	}

	@Override
	public EquateTable getEquateTable() {
		return (EquateTable) managers[EQUATE_MGR];
	}

	@Override
	public Memory getMemory() {
		return memoryManager;
	}

	public NamespaceManager getNamespaceManager() {
		return (NamespaceManager) managers[NAMESPACE_MGR];
	}

	@Override
	public ReferenceManager getReferenceManager() {
		return (ReferenceManager) managers[REF_MGR];
	}

	public CodeManager getCodeManager() {
		return (CodeManager) managers[CODE_MGR];
	}

	public TreeManager getTreeManager() {
		return (TreeManager) managers[TREE_MGR];
	}

	@Override
	public ProgramDataTypeManager getDataTypeManager() {
		return (ProgramDataTypeManager) managers[DATA_MGR];
	}

	@Override
	public FunctionManager getFunctionManager() {
		return (FunctionManagerDB) managers[FUNCTION_MGR];
	}

	@Override
	public BookmarkManager getBookmarkManager() {
		return (BookmarkManager) managers[BOOKMARK_MGR];
	}

	@Override
	public RelocationTable getRelocationTable() {
		return (RelocationManager) managers[RELOC_MGR];
	}

	@Override
	public String getCompiler() {
		String compiler = null;
		Options pl = getOptions(PROGRAM_INFO);
		compiler = pl.getString(COMPILER, UNKNOWN);
		return compiler == null ? UNKNOWN : compiler;
	}

	@Override
	public void setCompiler(String compiler) {
		Options pl = getOptions(PROGRAM_INFO);
		pl.setString(COMPILER, compiler);
		changed = true;
	}

	@Override
	public String getExecutablePath() {
		String path = null;
		Options pl = getOptions(PROGRAM_INFO);
		path = pl.getString(EXECUTABLE_PATH, UNKNOWN);
		return path == null ? UNKNOWN : path;
	}

	@Override
	public void setExecutablePath(String path) {
		Options pl = getOptions(PROGRAM_INFO);
		pl.setString(EXECUTABLE_PATH, path);
		changed = true;
	}

	@Override
	public String getExecutableFormat() {
		String format = null;
		try {
			Options pl = getOptions(PROGRAM_INFO);
			format = pl.getString(EXECUTABLE_FORMAT, (String) null);
		}
		catch (Exception e) {
			// handled below
		}
		return format == null ? UNKNOWN : format;
	}

	@Override
	public void setExecutableFormat(String format) {
		Options pl = getOptions(PROGRAM_INFO);
		pl.setString(EXECUTABLE_FORMAT, format);
		changed = true;
	}

	@Override
	public String getExecutableMD5() {
		String format = null;
		try {
			Options pl = getOptions(PROGRAM_INFO);
			format = pl.getString(EXECUTABLE_MD5, (String) null);
		}
		catch (Exception e) {
			// handled below
		}
		return format == null ? UNKNOWN : format;
	}

	@Override
	public void setExecutableMD5(String md5) {
		Options pl = getOptions(PROGRAM_INFO);
		pl.setString(EXECUTABLE_MD5, md5);
		changed = true;
	}

	@Override
	public String getExecutableSHA256() {
		String format = null;
		try {
			Options pl = getOptions(PROGRAM_INFO);
			format = pl.getString(EXECUTABLE_SHA256, (String) null);
		}
		catch (Exception e) {
			// handled below
		}
		return format == null ? UNKNOWN : format;
	}

	@Override
	public void setExecutableSHA256(String sha256) {
		Options pl = getOptions(PROGRAM_INFO);
		pl.setString(EXECUTABLE_SHA256, sha256);
		changed = true;
	}

	@Override
	public Date getCreationDate() {
		Options pl = getOptions(PROGRAM_INFO);
		return pl.getDate(Program.DATE_CREATED, new Date(0));
	}

	@Override
	public int getDefaultPointerSize() {
		return compilerSpec.getDataOrganization().getPointerSize();
	}

	@Override
	public LanguageID getLanguageID() {
		return languageID;
	}

	@Override
	public Language getLanguage() {
		return language;
	}

	@Override
	public CompilerSpec getCompilerSpec() {
		return compilerSpec;
	}

	@Override
	public PropertyMapManager getUsrPropertyManager() {
		return (PropertyMapManager) managers[PROPERTY_MGR];
	}

	@Override
	public ProgramContext getProgramContext() {
		return (ProgramContext) managers[CONTEXT_MGR];
	}

	@Override
	public Address getMinAddress() {
		return memoryManager.getMinAddress();
	}

	@Override
	public Address getMaxAddress() {
		return memoryManager.getMaxAddress();
	}

	@Override
	public ProgramChangeSet getChanges() {
		return (ProgramChangeSet) changeSet;
	}

	@Override
	public AddressFactory getAddressFactory() {
		return addressFactory;
	}

	/**
	 * Returns this programs address map.
	 * NOTE: This method has been dropped from the Program interface to help
	 * discourage the use of the program's address map since bad assumptions 
	 * are frequently made about address keys which may not be ordered or sequential
	 * across an entire address space.
	 */
	@Override
	public AddressMap getAddressMap() {
		return addrMap;
	}

	@Override
	public Address[] parseAddress(String addrStr) {
		return parseAddress(addrStr, true);
	}

	@Override
	public Address[] parseAddress(String addrStr, boolean caseSensitive) {
		int pos = addrStr.lastIndexOf(":");
		if (pos >= 0) {
			String spaceName = addrStr.substring(0, pos);
			if (spaceName.endsWith(":")) {
				spaceName = spaceName.substring(0, spaceName.length() - 1);
			}
			String offsetStr = addrStr.substring(pos + 1);

			MemoryBlock[] blocks = memoryManager.getBlocks();
			for (MemoryBlock block : blocks) {
				if (StringUtilities.equals(spaceName, block.getName(), caseSensitive)) {

					try {
						Address addr = block.getStart().getAddress(offsetStr);
						if ((addr != null) && block.contains(addr)) {
							return new Address[] { addr };
						}
					}
					catch (AddressFormatException e) {
						return new Address[0];
					}
				}
			}
		}
		if (addrStr.endsWith("h")) {
			addrStr = addrStr.substring(0, addrStr.length() - 1);
		}
		return addressFactory.getAllAddresses(addrStr, caseSensitive);
	}

	/**
	 * notification the a datatype has changed
	 * @param dataTypeID the id of the datatype that changed.
	 * @param type the type of the change (moved, renamed, etc.)
	 * @param isAutoChange true if change was an automatic change in response to 
	 * another datatype's change (e.g., size, alignment), else false in which case this
	 * change will be added to program change-set to aid merge conflict detection.
	 * @param oldValue the old datatype.
	 * @param newValue the new datatype.
	 */
	public void dataTypeChanged(long dataTypeID, int type, boolean isAutoChange, Object oldValue,
			Object newValue) {
		// TODO: do not need to record type changes for packed composite change which is in repsonse
		// to component size or alignment change.
		if (recordChanges && !isAutoChange) {
			((ProgramDBChangeSet) changeSet).dataTypeChanged(dataTypeID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, null, oldValue, newValue));
		try {
			managers[SYMBOL_MGR].invalidateCache(true);
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	/**
	 * Notification that a datatype was added.
	 * @param dataTypeID the id if the datatype that was added.
	 * @param type should always be DATATYPE_ADDED
	 * @param oldValue always null
	 * @param newValue the datatype added.
	 */
	public void dataTypeAdded(long dataTypeID, int type, Object oldValue, Object newValue) {
		if (recordChanges) {
			((ProgramDBChangeSet) changeSet).dataTypeAdded(dataTypeID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, null, oldValue, newValue));
	}

	/**
	 * Notification that a category was changed.
	 * @param categoryID the id of the datatype that was added.
	 * @param type the type of changed
	 * @param oldValue old value depends on the type.
	 * @param newValue new value depends on the type.
	 */
	public void categoryChanged(long categoryID, int type, Object oldValue, Object newValue) {
		if (recordChanges) {
			((ProgramDBChangeSet) changeSet).categoryChanged(categoryID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, null, oldValue, newValue));
	}

	/**
	 * Notification that a category was added.
	 * @param categoryID the id of the datatype that was added.
	 * @param type the type of changed (should always be CATEGORY_ADDED)
	 * @param oldValue always null
	 * @param newValue new value depends on the type.
	 */
	public void categoryAdded(long categoryID, int type, Object oldValue, Object newValue) {
		if (recordChanges) {
			((ProgramDBChangeSet) changeSet).categoryAdded(categoryID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, null, oldValue, newValue));
	}

	public void sourceArchiveAdded(UniversalID sourceArchiveID, int type) {
		if (recordChanges) {
			((ProgramDBChangeSet) changeSet).sourceArchiveAdded(sourceArchiveID.getValue());
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, sourceArchiveID, null, null));
	}

	public void sourceArchiveChanged(UniversalID sourceArchiveID, int type) {
		if (recordChanges) {
			((ProgramDBChangeSet) changeSet).sourceArchiveChanged(sourceArchiveID.getValue());
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, sourceArchiveID, null, null));
	}

	/**
	 * Notification that a program tree was added.
	 * @param id the id of the program tree that was added.
	 * @param type the type of changed
	 * @param oldValue old value is null
	 * @param newValue new value depends the tree that was added.
	 */
	public void programTreeAdded(long id, int type, Object oldValue, Object newValue) {
		if (recordChanges) {
			((ProgramDBChangeSet) changeSet).programTreeAdded(id);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, null, oldValue, newValue));
	}

	/**
	 * Notification that a program tree was changed.
	 * @param id the id of the program tree that was changed.
	 * @param type the type of change
	 * @param affectedObj the object that was changed
	 * @param oldValue old value depends on the type of the change
	 * @param newValue old value depends on the type of the change
	 */
	public void programTreeChanged(long id, int type, Object affectedObj, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			((ProgramDBChangeSet) changeSet).programTreeChanged(id);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, affectedObj, oldValue, newValue));
	}

	/**
	 * Notification that a {@link FunctionTag} was changed. This can be either an
	 * edit or a delete.
	 * 
	 * @param tag the tag that was changed.
	 * @param type the type of change
	 * @param oldValue old value 
	 * @param newValue new value
	 */
	public void tagChanged(FunctionTag tag, int type, Object oldValue, Object newValue) {
		if (recordChanges) {
			long tagID = tag.getId();
			((ProgramDBChangeSet) changeSet).tagChanged(tagID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, tag, oldValue, newValue));
	}

	/**
	 * Notification that a new {@link FunctionTag} was created.
	 * 
	 * @param tag the tag that was created.
	 * @param type the type of change
	 */
	public void tagCreated(FunctionTag tag, int type) {
		if (recordChanges) {
			long tagID = tag.getId();
			((ProgramDBChangeSet) changeSet).tagCreated(tagID);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, tag, null, null));
	}

	/**
	 * Notification that a symbol was changed.
	 * @param symbol the symbol that was changed.
	 * @param type the type of change
	 * @param addr the address of the symbol that changed
	 * @param affectedObj the object that was changed
	 * @param oldValue old value depends on the type of the change
	 * @param newValue old value depends on the type of the change
	 */
	public void symbolChanged(Symbol symbol, int type, Address addr, Object affectedObj,
			Object oldValue, Object newValue) {
		if (recordChanges) {
			// Only add the symbol ID to the change set if it isn't a default symbol.
			if (!symbol.isDynamic()) {
				long symbolID = symbol.getID();
				((ProgramDBChangeSet) changeSet).symbolChanged(symbolID);
			}
			if (symbol instanceof VariableSymbolDB) {
				Namespace parentNamespace = symbol.getParentNamespace();
				if (parentNamespace instanceof Function) {
					Function function = (Function) parentNamespace;
					Address entryPoint = function.getEntryPoint();
					updateChangeSet(entryPoint, entryPoint);
					fireEvent(new ProgramChangeRecord(DOCR_FUNCTION_CHANGED, entryPoint, entryPoint,
						function, null, null));
				}
			}
			if (addr != null) {
				updateChangeSet(addr, addr);
			}
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, addr, addr, affectedObj, oldValue, newValue));
	}

	/**
	 * Notification that a symbol was added.
	 * @param symbol the symbol that was added.
	 * @param type the type of change
	 * @param addr the address of the symbol that added
	 * @param oldValue old value depends on the type of the change
	 * @param newValue old value depends on the type of the change
	 */
	public void symbolAdded(Symbol symbol, int type, Address addr, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			if (!symbol.isDynamic()) {
				long symbolID = symbol.getID();
				((ProgramDBChangeSet) changeSet).symbolAdded(symbolID);
			}
			if (symbol instanceof VariableSymbolDB) {
				long nameSpaceID = symbol.getParentNamespace().getID();
				Function function = getFunctionManager().getFunction(nameSpaceID);
				if (function != null) {
					Address entryPoint = function.getEntryPoint();
					updateChangeSet(entryPoint, entryPoint);
					fireEvent(new ProgramChangeRecord(DOCR_FUNCTION_CHANGED, entryPoint, entryPoint,
						function, null, null));
				}
			}
			if (addr != null) {
				updateChangeSet(addr, addr);
			}
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, addr, addr, null, oldValue, newValue));
	}

	@Override
	public void setRegisterValuesChanged(Register register, Address start, Address end) {
		if (recordChanges) {
			if (register != null && register.isProcessorContext()) {
				// treat context-register change same as code unit change
				updateChangeSet(start, end);
			}
			else {
				((ProgramDBChangeSet) changeSet).addRegisterRange(start, end);
			}
		}
		changed = true;
		fireEvent(
			new ProgramChangeRecord(DOCR_REGISTER_VALUES_CHANGED, start, end, null, null, null));
	}

	@Override
	public void setChanged(int type, Object oldValue, Object newValue) {
		setChanged(type, (Address) null, (Address) null, oldValue, newValue);
	}

	@Override
	public void setChanged(int type, Address start, Address end, Object oldValue, Object newValue) {

		Address newstart = null;
		Address newend = null;

		if (start != null) {
			newstart = start;
		}
		if (end != null) {
			newend = end;
		}
		if (recordChanges) {
			updateChangeSet(newstart, newend);
		}
		changed = true;

		fireEvent(new ProgramChangeRecord(type, newstart, newend, null, oldValue, newValue));
	}

	@Override
	public void setObjChanged(int type, Object affectedObj, Object oldValue, Object newValue) {
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, affectedObj, oldValue, newValue));
	}

	@Override
	public void setObjChanged(int type, int subType, Object affectedObj, Object oldValue,
			Object newValue) {
		changed = true;
		fireEvent(
			new ProgramChangeRecord(type, subType, null, null, affectedObj, oldValue, newValue));
	}

	@Override
	public void setObjChanged(int type, Address addr, Object affectedObj, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			updateChangeSet(addr, addr);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, addr, addr, affectedObj, oldValue, newValue));
	}

	@Override
	public void setObjChanged(int type, int subType, Address addr, Object affectedObj,
			Object oldValue, Object newValue) {
		if (recordChanges) {
			updateChangeSet(addr, addr);
		}
		changed = true;
		fireEvent(
			new ProgramChangeRecord(type, subType, addr, addr, affectedObj, oldValue, newValue));
	}

	@Override
	public void setObjChanged(int type, AddressSetView addrSet, Object affectedObj, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			updateChangeSet(addrSet);
		}
		changed = true;
		fireEvent(new ProgramChangeRecord(type, null, null, affectedObj, oldValue, newValue));
	}

	private void updateChangeSet(Address start, Address end) {
		ProgramDBChangeSet pcs = (ProgramDBChangeSet) changeSet;
		if (start != null) {
			pcs.addRange(start, end != null ? end : start);
		}
		else if (end != null) {
			pcs.addRange(end, end);
		}
	}

	private void updateChangeSet(AddressSetView addrSet) {
		if (addrSet != null) {
			((ProgramDBChangeSet) changeSet).add(addrSet);
		}
	}

	@Override
	public void setPropertyChanged(String propertyName, Address codeUnitAddr, Object oldValue,
			Object newValue) {
		if (recordChanges) {
			updateChangeSet(codeUnitAddr, null);
		}
		changed = true;
		fireEvent(new CodeUnitPropertyChangeRecord(propertyName, codeUnitAddr, oldValue, newValue));
	}

	@Override
	public void setPropertyRangeRemoved(String propertyName, Address start, Address end) {
		if (recordChanges) {
			updateChangeSet(start, end);
		}
		changed = true;
		fireEvent(new CodeUnitPropertyChangeRecord(propertyName, start, end));
	}

	void userDataChanged(String propertyName, Address codeUnitAddr, Object oldValue,
			Object newValue) {
		// Do not update change set!
		fireEvent(new CodeUnitUserDataChangeRecord(propertyName, codeUnitAddr, oldValue, newValue));
	}

	protected void userDataChanged(String propertyName, Object oldValue, Object newValue) {
		fireEvent(new UserDataChangeRecord(propertyName, name, name));
	}

	@Override
	public void setName(String newName) {
		lock.acquire();
		try {
			if (name.equals(newName)) {
				return;
			}
			DBRecord record = table.getRecord(new StringField(PROGRAM_NAME));
			record.setString(0, newName);
			table.putRecord(record);
			getTreeManager().setProgramName(name, newName);
			super.setName(newName);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private void refreshName() throws IOException {
		DBRecord record = table.getRecord(new StringField(PROGRAM_NAME));
		name = record.getString(0);
	}

	private void refreshImageBase() throws IOException {
		long baseOffset = getStoredBaseImageOffset();
		storedImageBase = addressFactory.getDefaultAddressSpace().getAddress(baseOffset);
		if (!imageBaseOverride) {
			Address currentImageBase = getImageBase();
			if (!currentImageBase.equals(storedImageBase)) {
				currentImageBase = storedImageBase;
				addrMap.setImageBase(currentImageBase);
			}
		}
	}

	/**
	 * Create a new OverlayAddressSpace based upon the given overlay blockName and base AddressSpace
	 * @param blockName the name of the overlay memory block which corresponds to the new overlay address
	 * space to be created.  This name may be modified to produce a valid overlay space name and avoid 
	 * duplication.
	 * @param originalSpace the base AddressSpace to overlay	
	 * @param minOffset the min offset of the space
	 * @param maxOffset the max offset of the space
	 * @return the new space
	 * @throws LockException if the program is shared and not checked out exclusively.
	 * @throws MemoryConflictException if image base override is active
	 */
	public AddressSpace addOverlaySpace(String blockName, AddressSpace originalSpace,
			long minOffset, long maxOffset) throws LockException, MemoryConflictException {

		checkExclusiveAccess();
		if (imageBaseOverride) {
			throw new MemoryConflictException(
				"Overlay spaces may not be created while an image-base override is active");
		}

		OverlayAddressSpace ovSpace = null;
		lock.acquire();
		try {
			ovSpace = addressFactory.addOverlayAddressSpace(blockName, false, originalSpace,
				minOffset, maxOffset);
			overlaySpaceAdapter.addOverlaySpace(ovSpace);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return ovSpace;
	}

	public void renameOverlaySpace(String oldOverlaySpaceName, String newName)
			throws LockException {
		checkExclusiveAccess();
		String revisedName = addressFactory.renameOverlaySpace(oldOverlaySpaceName, newName);
		if (!revisedName.equals(oldOverlaySpaceName)) {
			try {
				overlaySpaceAdapter.renameOverlaySpace(oldOverlaySpaceName, revisedName);
				addrMap.renameOverlaySpace(oldOverlaySpaceName, revisedName);
			}
			catch (IOException e) {
				dbError(e);
			}
		}
	}

	public boolean removeOverlaySpace(AddressSpace overlaySpace) throws LockException {
		lock.acquire();
		try {
			checkExclusiveAccess();
			MemoryBlock[] blocks = memoryManager.getBlocks();
			for (MemoryBlock block : blocks) {
				if (block.getStart().getAddressSpace().equals(overlaySpace)) {
					return false;
				}
			}
			addressFactory.removeOverlaySpace(overlaySpace.getName());
			overlaySpaceAdapter.removeOverlaySpace(overlaySpace.getName());
			addrMap.deleteOverlaySpace(overlaySpace.getName());
			clearCache(true);
			return true;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	private long getStoredBaseImageOffset() throws IOException {
		DBRecord rec = table.getRecord(new StringField(IMAGE_OFFSET));
		if (rec != null) {
			return (new BigInteger(rec.getString(0), 16)).longValue();
		}
		return 0;
	}

	@Override
	public Address getImageBase() {
		return addrMap.getImageBase();
	}

	@Override
	public void setImageBase(Address base, boolean commit)
			throws AddressOverflowException, LockException, IllegalStateException {

		if (commit) {
			checkExclusiveAccess();
		}
		lock.acquire();
		try {
			Address currentImageBase = getImageBase();
			if (!(commit && imageBaseOverride) && base.equals(currentImageBase)) {
				return;
			}
// image base can be changed with overlays - they simply will not move.
// A block move must be done to relate an overlay
//			// Unsupported if overlay spaces exist
//			AddressSpace[] spaces = addressFactory.getAllAddressSpaces();
//			for (AddressSpace space : spaces) {
//				if (space.isOverlaySpace()) {
//					throw new IllegalStateException("setImageBase is unsupported if an overlay space exists!");
//				}
//			}
			if (!addressFactory.getDefaultAddressSpace().equals(base.getAddressSpace())) {
				throw new IllegalArgumentException("Base address must be default space");
			}

			// make sure current image "fits"
			// check all blocks in default address space
			MemoryBlock[] blocks = getMemory().getBlocks();
			for (MemoryBlock block : blocks) {
				if (block.getStart().hasSameAddressSpace(base)) {
					try {
						long distanceFromBase = block.getStart().subtract(currentImageBase);
						Address newStart = base.addWrap(distanceFromBase);
						newStart.addNoWrap(block.getSize() - 1);
					}
					catch (AddressOverflowException e) {
						throw new AddressOverflowException(
							"wrapped memory block: " + block.getName());
					}
				}
			}

			Address oldBase = currentImageBase;
			addrMap.setImageBase(base);

			if (commit) {
				try {
					DBRecord record = SCHEMA.createRecord(new StringField(IMAGE_OFFSET));
					record.setString(0, Long.toHexString(base.getOffset()));
					table.putRecord(record);

					storedImageBase = base;
					imageBaseOverride = false;

					setChanged(ChangeManager.DOCR_IMAGE_BASE_CHANGED, oldBase, base);
					invalidate();
					((SymbolManager) managers[SYMBOL_MGR]).imageBaseChanged(oldBase, base);
					changed = true;
				}
				catch (IOException e) {
					dbError(e);
				}

// TODO: Perform relocation fixups

			}
			else {
				imageBaseOverride = true;
			}
			invalidate();
		}
		finally {
			lock.release();
		}
		//NOTE:
		//this needs to be outside the lock...
		((TreeManager) managers[TREE_MGR]).imageBaseChanged(commit);
		flushEvents();
	}

	@Override
	public void restoreImageBase() {
		if (!imageBaseOverride) {
			return;
		}
		lock.acquire();
		try {
			imageBaseOverride = false;
			invalidate();
		}
		finally {
			lock.release();
		}
		//NOTE:
		//this needs to be outside the lock...
		((TreeManager) managers[TREE_MGR]).imageBaseChanged(false);
		flushEvents();
	}

	@Override
	public String getDescription() {
		return "Program";
	}

	private void createDatabase() throws IOException {
		table = dbh.createTable(TABLE_NAME, SCHEMA);
		DBRecord record = SCHEMA.createRecord(new StringField(PROGRAM_NAME));
		record.setString(0, name);
		table.putRecord(record);

		// NOTE: Keep unused language name record for backward compatibility to avoid NPE
		record = SCHEMA.createRecord(new StringField(OLD_LANGUAGE_NAME));
		record.setString(0, languageID.getIdAsString());
		table.putRecord(record);

		record = SCHEMA.createRecord(new StringField(LANGUAGE_ID));
		record.setString(0, languageID.getIdAsString());
		table.putRecord(record);

		record = SCHEMA.createRecord(new StringField(COMPILER_SPEC_ID));
		record.setString(0, compilerSpecID.getIdAsString());
		table.putRecord(record);

		record = SCHEMA.createRecord(new StringField(LANGUAGE_VERSION));
		record.setString(0, languageVersion + "." + languageMinorVersion);
		table.putRecord(record);

		record = SCHEMA.createRecord(new StringField(PROGRAM_DB_VERSION));
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
	 * @return version exception if the current version is out of date and can be upgraded
	 * @throws IOException if there is an exception at the database level
	 * @throws VersionException if the data is newer than this version of Ghidra and can not be
	 * upgraded or opened.
	 */
	private VersionException initializeDatabase(int openMode)
			throws IOException, VersionException, LanguageNotFoundException {
		boolean requiresUpgrade = false;

		table = dbh.getTable(TABLE_NAME);
		if (table == null) {
			throw new IOException("Unsupported File Content");
		}
		DBRecord record = table.getRecord(new StringField(PROGRAM_NAME));
		name = record.getString(0);

		record = table.getRecord(new StringField(LANGUAGE_ID));
		if (record == null) { // must be in old style combined language/compiler spec format
			record = table.getRecord(new StringField(OLD_LANGUAGE_NAME));
			String oldLanguageName = record.getString(0);
			LanguageCompilerSpecPair languageCompilerSpecPair =
				OldLanguageMappingService.lookupMagicString(oldLanguageName, false);
			if (languageCompilerSpecPair == null) {
				throw new LanguageNotFoundException(oldLanguageName);
			}
			languageID = languageCompilerSpecPair.languageID;
			compilerSpecID = languageCompilerSpecPair.compilerSpecID;
			if (openMode != DBConstants.UPGRADE) {
				requiresUpgrade = true;
			}
			else {
				record = SCHEMA.createRecord(new StringField(LANGUAGE_ID));
				record.setString(0, languageID.getIdAsString());
				table.putRecord(record);
				record = SCHEMA.createRecord(new StringField(COMPILER_SPEC_ID));
				record.setString(0, compilerSpecID.getIdAsString());
				table.putRecord(record);
			}
		}
		else {
			languageID = new LanguageID(record.getString(0));
			record = table.getRecord(new StringField(COMPILER_SPEC_ID));
			compilerSpecID = new CompilerSpecID(record.getString(0));
		}

		record = table.getRecord(new StringField(LANGUAGE_VERSION));
		String languageVersionStr = record == null ? LANG_DEFAULT_VERSION : record.getString(0);
		String[] vs = languageVersionStr.split("\\.");
		languageVersion = 1;
		languageMinorVersion = 0;
		try {
			languageVersion = Integer.parseInt(vs[0]);
			languageMinorVersion = Integer.parseInt(vs[1]);
		}
		catch (Exception e) {
			// Ignore
		}

		int storedVersion = getStoredVersion();
		if (storedVersion > DB_VERSION) {
			throw new VersionException(VersionException.NEWER_VERSION, false);
		}
		if (openMode != DBConstants.UPGRADE && storedVersion < UPGRADE_REQUIRED_BEFORE_VERSION) {
			requiresUpgrade = true;
		}
		if (openMode == DBConstants.UPDATE && storedVersion < DB_VERSION) {
			requiresUpgrade = true;
		}
		return requiresUpgrade ? new VersionException(true) : null;
	}

	private void upgradeDatabase(TaskMonitor monitor) throws IOException, CancelledException {

		performPropertyListAlterations(
			ObsoleteProgramPropertiesService.getObsoleteProgramProperties(), monitor);

		checkFunctionWrappedPointers(monitor);

		// Update stored database version
		table = dbh.getTable(TABLE_NAME);
		Field key = new StringField(PROGRAM_DB_VERSION);
		String versionStr = Integer.toString(DB_VERSION);
		DBRecord record = table.getRecord(key);
		if (record != null && versionStr.equals(record.getString(0))) {
			return; // already has correct version
		}
		record = SCHEMA.createRecord(key);
		record.setString(0, versionStr);
		table.putRecord(record);
	}

	/*
	 * Perform more complex upgrades which require all language version translation to be completed 
	 */
	private void postUpgrade(int oldVersion, TaskMonitor monitor)
			throws CancelledException, IOException {

		if (oldVersion < ProgramDB.COMPOUND_VARIABLE_STORAGE_ADDED_VERSION) {
			// Implemented compound VariableStorage and return "parameter"
			// Added signature SourceType stored in function flags
			// Added support for dynamic return/param storage
			((FunctionManagerDB) getFunctionManager()).initSignatureSource(monitor);
		}
		// versions prior to COMPOUND_VARIABLE_STORAGE_ADDED_VERSION did not support
		// dynamic storage so the following upgrade is unnecessary
		else if (oldVersion < ProgramDB.AUTO_PARAMETERS_ADDED_VERSION) {
			// Implemented auto and forced-indirect parameters -
			// must eliminate fix __thiscall functions using dynamic storage
			// to eliminate default 'this' parameter
			((FunctionManagerDB) getFunctionManager()).removeExplicitThisParameters(monitor);
		}

	}

	public int getStoredVersion() throws IOException {
		DBRecord record = table.getRecord(new StringField(PROGRAM_DB_VERSION));
		if (record != null) {
			String s = record.getString(0);
			try {
				return Integer.parseInt(s);
			}
			catch (NumberFormatException e) {
				// return 1 for invalid value
			}
		}
		return 1;
	}

	private void checkOldProperties(int openMode, TaskMonitor monitor)
			throws IOException, VersionException {
		DBRecord record = table.getRecord(new StringField(EXECUTE_PATH));
		if (record != null) {
			if (openMode == READ_ONLY) {
				return; // not important, get on path or format will return "unknown"
			}
			if (openMode != UPGRADE) {
				throw new VersionException(true);
			}
			Options pl = getOptions(PROGRAM_INFO);
			String value = record.getString(0);
			pl.setString(EXECUTABLE_PATH, value);
			table.deleteRecord(record.getKeyField());
			record = table.getRecord(new StringField(EXECUTE_FORMAT));
			if (record != null) {
				pl.setString(EXECUTABLE_FORMAT, value);
				table.deleteRecord(record.getKeyField());
			}
		}
		int storedVersion = getStoredVersion();
		if (storedVersion < ANALYSIS_OPTIONS_MOVED_VERSION) {
			if (openMode == READ_ONLY) {
				return;
			}
			if (openMode != UPGRADE) {
				throw new VersionException(true);
			}
			Options oldList = getOptions("Analysis");
			for (String propertyName : oldList.getOptionNames()) {
				oldList.removeOption(propertyName);
			}
		}
		if (storedVersion < METADATA_ADDED_VERSION) {
			if (openMode == READ_ONLY) {
				return;
			}
			if (openMode != UPGRADE) {
				throw new VersionException(true);
			}
		}

	}

	/*
	 * External function pointers had previously been wrapped in a function.  This should know be
	 * handled by creating an external function which corresponds to the pointers external location
	 * reference.
	 */
	private void checkFunctionWrappedPointers(TaskMonitor monitor)
			throws IOException, CancelledException {
		int storedVersion = getStoredVersion();
		if (storedVersion < EXTERNAL_FUNCTIONS_ADDED_VERSION) {
			FunctionManager functionManager = getFunctionManager();
			SymbolTable symbolTable = getSymbolTable();
			monitor.setProgress(0);
			monitor.setMaximum(functionManager.getFunctionCount());
			int cnt = 0;
			for (Symbol functionSymbol : symbolTable.getSymbols(memoryManager, SymbolType.FUNCTION,
				true)) {
				monitor.checkCanceled();
				ProgramUtilities.convertFunctionWrappedExternalPointer(functionSymbol);
				monitor.setProgress(++cnt);
			}
		}
		else {
			return;
		}
	}

	private VersionException createManagers(int openMode, TaskMonitor monitor)
			throws CancelledException, IOException {

		VersionException versionExc = null;
		overlaySpaceAdapter = new OverlaySpaceAdapterDB(dbh);
		overlaySpaceAdapter.initializeOverlaySpaces(addressFactory);
		monitor.checkCanceled();

		try {
			checkOldProperties(openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}

		long baseImageOffset = getStoredBaseImageOffset();

		// the memoryManager should always be created first because it is needed to resolve
		// segmented addresses from longs that other manages may need while upgrading.
		try {
			addrMap = new AddressMapDB(dbh, openMode, addressFactory, baseImageOffset, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
			try {
				addrMap =
					new AddressMapDB(dbh, READ_ONLY, addressFactory, baseImageOffset, monitor);
			}
			catch (VersionException e1) {
				if (e1.isUpgradable()) {
					Msg.error(this,
						"AddressMapDB is upgradeable but failed to support READ-ONLY mode!");
				}
				// Unable to proceed without addrMap !
				return versionExc;
			}
		}
		monitor.checkCanceled();

		try {
			memoryManager =
				new MemoryMapDB(dbh, addrMap, openMode, language.isBigEndian(), lock, monitor);
			managers[MEMORY_MGR] = memoryManager;
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[CODE_MGR] = new CodeManager(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[FUNCTION_MGR] = new FunctionManagerDB(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			if (!e.isUpgradable()) {
				// Attempt to instantiate the old function manager which may be used for upgrades
				try {
					oldFunctionMgr = new OldFunctionManager(dbh, this, addrMap);
					if (openMode != UPGRADE) {
						// Indicate that program is upgradable
						oldFunctionMgr = null;
						versionExc = (new VersionException(true)).combine(versionExc);
					}
					else {
						// Prepare for upgrade of function manager
						managers[FUNCTION_MGR] =
							new FunctionManagerDB(dbh, addrMap, CREATE, lock, monitor);
					}
				}
				catch (VersionException e1) {
					// TODO why does this happen?  should we log this?
				}
			}
			else {
				versionExc = e.combine(versionExc);
			}
		}
		monitor.checkCanceled();

		try {
			managers[EXTERNAL_MGR] = new ExternalManagerDB(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[SYMBOL_MGR] = new SymbolManager(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[NAMESPACE_MGR] =
				new NamespaceManager(dbh, this, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[REF_MGR] = new ReferenceDBManager(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[EQUATE_MGR] = new EquateManager(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[DATA_MGR] =
				new ProgramDataTypeManager(dbh, addrMap, openMode, this, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[PROPERTY_MGR] =
				new DBPropertyMapManager(dbh, this, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[BOOKMARK_MGR] = new BookmarkDBManager(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[TREE_MGR] = new TreeManager(dbh, this, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[RELOC_MGR] = new RelocationManager(dbh, addrMap, openMode, lock, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		monitor.checkCanceled();

		try {
			managers[CONTEXT_MGR] = new ProgramRegisterContextDB(dbh, this, language, compilerSpec,
				addrMap, lock, openMode, (CodeManager) managers[CODE_MGR], monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}

		monitor.checkCanceled();

		return versionExc;
	}

	private void initManagers(int openMode, TaskMonitor monitor)
			throws CancelledException, IOException {
		globalNamespace = new GlobalNamespace(getMemory());
		for (int i = 0; i < NUM_MANAGERS; i++) {
			monitor.checkCanceled();
			managers[i].setProgram(this);
		}
		listing.setProgram(this);

		monitor.checkCanceled();

		// Upgrade Function Manager 
		if (openMode == UPGRADE && oldFunctionMgr != null) {
			oldFunctionMgr.upgrade(this, monitor);
		}

		for (int i = 0; i < NUM_MANAGERS; i++) {
			monitor.checkCanceled();
			managers[i].programReady(openMode, getStoredVersion(), monitor);
		}

	}

	@Override
	protected void clearCache(boolean all) {
		lock.acquire();
		try {
			super.clearCache(all);
			refreshName();
			overlaySpaceAdapter.updateOverlaySpaces(addressFactory);
			addrMap.invalidateCache();
			if (!imageBaseOverride) {
				refreshImageBase();
			}
			for (int i = 0; i < NUM_MANAGERS; i++) {
				managers[i].invalidateCache(all);
			}
			installExtensions(); // Reload any extensions
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void invalidate() {
		clearCache(false);
		fireEvent(new DomainObjectChangeRecord(DomainObject.DO_OBJECT_RESTORED));
	}

	@Override
	public boolean isChangeable() {
		return changeable;
	}

	@Override
	public Register getRegister(Address addr) {
		return language.getRegister(getGlobalAddress(addr), 0);
	}

	@Override
	public Register[] getRegisters(Address addr) {
		return language.getRegisters(getGlobalAddress(addr));
	}

	@Override
	public Register getRegister(Address addr, int size) {
		return language.getRegister(getGlobalAddress(addr), size);
	}

	@Override
	public Register getRegister(Varnode varnode) {
		return language.getRegister(getGlobalAddress(varnode.getAddress()), varnode.getSize());
	}

	/**
	 * This method is required to handle old register addresses which
	 * have a namespace.
	 * @param addr register address
	 * @return converted register address which does not have a namespace setting.
	 */
	private Address getGlobalAddress(Address addr) {
		if (addr instanceof OldGenericNamespaceAddress) {
			return ((OldGenericNamespaceAddress) addr).getGlobalAddress();
		}
		return addr;
	}

	@Override
	public Register getRegister(String regName) {
		return language.getRegister(regName);
	}

	@Override
	protected void setChanged(boolean b) {
		super.setChanged(b);
	}

	void setChangeSet(ProgramDBChangeSet changeSet) {
		this.changeSet = changeSet;
	}

	/**
	 * Deletes given range from the program.
	 * @param startAddr the first address in the range.
	 * @param endAddr the last address in the range.
	 * @param monitor the task monitor to use while deleting information in the given range.
	 * @throws RollbackException if the user cancelled the operation via the task monitor.
	 */
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws RollbackException {

// TODO: ensure that managers are notified with address ranges which correspond to a sequential set of address keys
		lock.acquire();
		try {
			for (int i = NUM_MANAGERS - 1; i >= 0; i--) {
				managers[i].deleteAddressRange(startAddr, endAddr, monitor);
			}
			clearCache(false);
			Iterator<String> iter = addrSetPropertyMap.keySet().iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				AddressSetPropertyMapDB pm = addrSetPropertyMap.get(iter.next());
				pm.remove(startAddr, endAddr);
			}

			iter = intRangePropertyMap.keySet().iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				IntRangeMap map = intRangePropertyMap.get(iter.next());
				map.clearValue(startAddr, endAddr);
			}
		}
		catch (CancelledException e) {
			throw new RollbackException("Operation cancelled");
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Moves all information stored in the given range to the new location
	 * 
	 * @param fromAddr the first address in the range to be moved
	 * @param toAddr the address to move to
	 * @param length the number of addresses to move
	 * @param monitor the task monitor to use while deleting information in the given range
	 * @throws AddressOverflowException if there is a problem moving address ranges
	 * @throws RollbackException if the user cancelled the operation via the task monitor
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws AddressOverflowException, RollbackException {

// TODO: ensure that managers are notified with address ranges which correspond to a sequential set of address keys

// TODO: WARNING! fromAddr range may no longer exist in memory map which could affect certain database iterators

		lock.acquire();
		try {
			for (int i = NUM_MANAGERS - 1; i >= 0; i--) {
				managers[i].moveAddressRange(fromAddr, toAddr, length, monitor);
			}
			clearCache(false);
			Iterator<String> iter = addrSetPropertyMap.keySet().iterator();
			while (iter.hasNext()) {
				AddressSetPropertyMapDB pm = addrSetPropertyMap.get(iter.next());
				pm.moveAddressRange(fromAddr, toAddr, length, monitor);
			}

			iter = intRangePropertyMap.keySet().iterator();
			while (iter.hasNext()) {
				IntRangeMap map = intRangePropertyMap.get(iter.next());
				map.moveAddressRange(fromAddr, toAddr, length, monitor);
			}
		}
		catch (CancelledException e) {
			throw new RollbackException("Operation cancelled");
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Namespace getGlobalNamespace() {
		return globalNamespace;
	}

	@Override
	public void setLanguage(Language newLanguage, CompilerSpecID newCompilerSpecID,
			boolean forceRedisassembly, TaskMonitor monitor)
			throws IllegalStateException, IncompatibleLanguageException, LockException {
		if (newLanguage == language) {
			setLanguage((LanguageTranslator) null, newCompilerSpecID, forceRedisassembly, monitor);
			return;
		}
		LanguageTranslator languageTranslator =
			LanguageTranslatorFactory.getLanguageTranslatorFactory()
					.getLanguageTranslator(language, newLanguage);
		if (languageTranslator == null) {
			throw new IncompatibleLanguageException("Language translation not supported");
		}
		setLanguage(languageTranslator, newCompilerSpecID, forceRedisassembly, monitor);
	}

	/**
	 * Translate language
	 * @param translator language translator, if null only re-disassembly will occur.
	 * @param newCompilerSpecID new compiler specification which corresponds to new language, may be null.
	 * @param forceRedisassembly if true a redisassembly will be forced even if not required
	 * @param monitor task monitor
	 * @throws LockException if exclusive access is missing 
	 */
	public void setLanguage(LanguageTranslator translator, CompilerSpecID newCompilerSpecID,
			boolean forceRedisassembly, TaskMonitor monitor) throws LockException {

		checkExclusiveAccess();

		lock.acquire();
		try {
			setEventsEnabled(false);
			try {
				boolean redisassemblyRequired = true;
				int oldLanguageVersion = languageVersion;
				int oldLanguageMinorVersion = languageMinorVersion;
				if (translator != null) {
					language = translator.getNewLanguage();
					languageID = language.getLanguageID();
					if (newCompilerSpecID == null) {
						newCompilerSpecID = translator.getNewCompilerSpecID(compilerSpecID);
					}
					Msg.info(this, "Setting language for Program " + getName() + ": " + translator);
					Msg.info(this, "Setting compiler spec for Program " + getName() + ": " +
						compilerSpecID + " -> " + newCompilerSpecID);
				}
				else if (!forceRedisassembly && language.getVersion() == languageVersion &&
					language.getMinorVersion() == languageMinorVersion) {
					redisassemblyRequired = false; // compiler spec change only
					Msg.info(this, "Setting compiler spec for Program " + getName() + ": " +
						compilerSpecID + " -> " + newCompilerSpecID);
				}
				else {
					Msg.info(this,
						"Updating language version for Program " + getName() + ": " +
							language.getLanguageDescription() + " (Version " +
							language.getVersion() + "." + language.getMinorVersion());
				}

				if (newCompilerSpecID != null) {
					compilerSpec = ProgramCompilerSpec.getProgramCompilerSpec(this,
						language.getCompilerSpecByID(newCompilerSpecID));
				}
				compilerSpecID = compilerSpec.getCompilerSpecID();
				languageVersion = language.getVersion();
				languageMinorVersion = language.getMinorVersion();

				if (translator != null) {
					addressFactory = new ProgramAddressFactory(language, compilerSpec);

					addrMap.setLanguage(language, addressFactory, translator);
					overlaySpaceAdapter.setLanguage(language, addressFactory, translator);

					memoryManager.setLanguage(language);
					addrMap.memoryMapChanged(memoryManager);

					monitor.setMessage("Updating symbols...");
					((SymbolManager) getSymbolTable()).setLanguage(translator, monitor);
					((ExternalManagerDB) getExternalManager()).setLanguage(translator, monitor);
					((FunctionManagerDB) getFunctionManager()).setLanguage(translator, monitor);
				}

				clearCache(true);

				monitor.setMessage("Updating language...");
				monitor.setProgress(0);
				ProgramRegisterContextDB contextMgr =
					(ProgramRegisterContextDB) getProgramContext();

				if (redisassemblyRequired) {
					contextMgr.setLanguage(translator, compilerSpec, memoryManager, monitor);
					repairContext(oldLanguageVersion, oldLanguageMinorVersion, translator, monitor);
					getCodeManager().reDisassembleAllInstructions(monitor);
				}
				else {
					contextMgr.initializeDefaultValues(language, compilerSpec);
				}

				// Force function manager to reconcile calling conventions
				managers[FUNCTION_MGR].setProgram(this);
				managers[FUNCTION_MGR].programReady(UPDATE, getStoredVersion(), monitor);

				if (translator != null) {
					// allow complex language upgrades to transform instructions/context
					translator.fixupInstructions(this, translator.getOldLanguage(), monitor);
				}

				DBRecord record = SCHEMA.createRecord(new StringField(LANGUAGE_ID));
				record.setString(0, languageID.getIdAsString());
				table.putRecord(record);
				record = SCHEMA.createRecord(new StringField(COMPILER_SPEC_ID));
				record.setString(0, compilerSpecID.getIdAsString());
				table.putRecord(record);
				record = SCHEMA.createRecord(new StringField(LANGUAGE_VERSION));
				record.setString(0, languageVersion + "." + languageMinorVersion);
				table.putRecord(record);
				setChanged(true);
				clearCache(true);
				invalidate();
			}
			catch (Throwable t) {
				throw new IllegalStateException(
					"Set language aborted - program object is now in an unusable state!", t);
			}
			finally {
				setEventsEnabled(true);
			}
			fireEvent(new DomainObjectChangeRecord(ChangeManager.DOCR_LANGUAGE_CHANGED));
		}
		finally {
			lock.release();
		}
	}

	/*
	 * Repair damaged context prior to language upgrade.  It is assumed that the context has 
	 * already been upgrade and that the original prototypes and instructions are still intact.
	 */
	private void repairContext(int oldLanguageVersion, int oldLanguageMinorVersion,
			LanguageTranslator translator, TaskMonitor monitor) throws CancelledException {
		String processorName = language.getProcessor().toString();
		if ("ARM".equalsIgnoreCase(processorName)) {
			repairARMContext(oldLanguageVersion, oldLanguageMinorVersion, translator, monitor);
		}
	}

	/*
	 * Repair damaged ARM/THUMB context prior to language upgrade.  With the release of Ghidra 5.2 
	 * (which corresponds to the ARM language version of 1.6) the stored context register 
	 * value is write-protected where instructions exist.
	 * It is assumed that the context has already been upgrade and that the original 
	 * prototypes and instructions are still intact.
	 */
	private void repairARMContext(int oldLanguageVersion, int oldLanguageMinorVersion,
			LanguageTranslator translator, TaskMonitor monitor) throws CancelledException {
		if (!(language instanceof SleighLanguage)) {
			return;
		}
		if (oldLanguageVersion != 1 || oldLanguageMinorVersion >= 6) {
			return;
		}
		monitor.setMessage("Checking ARM Context...");
		CodeManager codeManager = getCodeManager();
		monitor.setMaximum(codeManager.getNumInstructions());
		monitor.setProgress(0);
		int cnt = 0;
		int repairCnt = 0;

		ProgramContext context = getProgramContext();
		Register contextReg = context.getBaseContextRegister();
		if (contextReg == Register.NO_CONTEXT) {
			return;
		}
		Register thumbBitReg = context.getRegister("TMode");
		if (thumbBitReg == null) {
			return; // assume thumb mode not supported
		}
		Register oldContextReg = contextReg;
		if (translator != null) {
			oldContextReg = translator.getOldContextRegister();
		}

		AddressRange contextRange = null;
		BigInteger lastStoredTMode = null;

		InstructionIterator instructions =
			codeManager.getInstructions(memoryManager.getLoadedAndInitializedAddressSet(), true);
		while (instructions.hasNext()) {
			monitor.checkCanceled();
			if (++cnt % 100 == 0) {
				monitor.setProgress(cnt);
			}
			InstructionDB instr = (InstructionDB) instructions.next();
			RegisterValue protoContextValue = instr.getOriginalPrototypeContext(oldContextReg);
			if (translator != null) {
				protoContextValue = translator.getNewRegisterValue(protoContextValue);
			}
			RegisterValue protoTModeValue = protoContextValue.getRegisterValue(thumbBitReg);
			BigInteger protoTMode = protoTModeValue.getUnsignedValue();

			Address addr = instr.getMinAddress();
			if (contextRange == null || !contextRange.contains(addr)) {
				// get tmode context for current range
				contextRange = context.getRegisterValueRangeContaining(contextReg, addr);
				RegisterValue storedValue =
					context.getNonDefaultValue(contextReg, instr.getMinAddress());
				if (storedValue == null) {
					// tmode default assumed always to be 0 (ARM mmode)
					lastStoredTMode = BigInteger.valueOf(0);
				}
				else {
					RegisterValue storedTModeValue = storedValue.getRegisterValue(thumbBitReg);
					lastStoredTMode = storedTModeValue.getUnsignedValueIgnoreMask();
				}
			}

			// verify context
			if (!protoTMode.equals(lastStoredTMode)) {
				try {
					// repair damaged tmode context value
					context.setRegisterValue(addr, addr.add(instr.getLength() - 1),
						protoTModeValue);
					++repairCnt;
				}
				catch (ContextChangeException e) {
					Msg.error(this, "Unexpected Error", e);
				}
				catch (AddressOutOfBoundsException e) {
					Msg.error(this,
						"Unexpected instruction memory error at " + instr.getMaxAddress(), e);
				}
			}
		}
		if (repairCnt != 0) {
			Msg.warn(this, "Repaired ARM Tmode context at " + repairCnt + " locations");
		}

		clearCache(true);
	}

	@Override
	public AddressSetPropertyMap createAddressSetPropertyMap(String mapName)
			throws DuplicateNameException {
		lock.acquire();
		try {
			AddressSetPropertyMapDB map =
				AddressSetPropertyMapDB.createPropertyMap(this, mapName, this, addrMap, lock);
			addrSetPropertyMap.put(mapName, map);
			setChanged(DOCR_ADDRESS_SET_PROPERTY_MAP_ADDED, null, mapName);
			return map;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public AddressSetPropertyMap getAddressSetPropertyMap(String mapName) {
		lock.acquire();
		try {
			AddressSetPropertyMapDB map = addrSetPropertyMap.get(mapName);
			if (map != null) {
				return map;
			}
			map = AddressSetPropertyMapDB.getPropertyMap(this, mapName, this, addrMap, lock);

			if (map != null) {
				addrSetPropertyMap.put(mapName, map);
			}
			return map;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void deleteAddressSetPropertyMap(String mapName) {
		lock.acquire();
		try {
			AddressSetPropertyMapDB pm = addrSetPropertyMap.remove(mapName);
			if (pm == null) {
				pm = AddressSetPropertyMapDB.getPropertyMap(this, mapName, this, addrMap, lock);
			}
			if (pm != null) {
				pm.delete();
				setChanged(DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED, null, mapName);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public IntRangeMapDB createIntRangeMap(String mapName) throws DuplicateNameException {
		lock.acquire();
		try {
			IntRangeMapDB map = IntRangeMapDB.createPropertyMap(this, mapName, this, addrMap, lock);
			intRangePropertyMap.put(mapName, map);
			setChanged(DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED, null, mapName);
			return map;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public IntRangeMap getIntRangeMap(String mapName) {
		lock.acquire();
		try {
			IntRangeMapDB rangeMap = intRangePropertyMap.get(mapName);
			if (rangeMap != null) {
				return rangeMap;
			}

			rangeMap = IntRangeMapDB.getPropertyMap(this, mapName, this, addrMap, lock);
			if (rangeMap != null) {
				intRangePropertyMap.put(mapName, rangeMap);
			}
			return rangeMap;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void deleteIntRangeMap(String mapName) {
		lock.acquire();
		try {
			IntRangeMapDB rangeMap = intRangePropertyMap.remove(mapName);
			if (rangeMap == null) {
				rangeMap = IntRangeMapDB.getPropertyMap(this, mapName, this, addrMap, lock);
			}

			if (rangeMap != null) {
				rangeMap.delete();
				setChanged(DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED, null, mapName);
			}
		}
		finally {
			lock.release();
		}

	}

	@Override
	protected void close() {
		super.close();
		intRangePropertyMap.clear();
		addrSetPropertyMap.clear();
		for (ManagerDB manager : managers) {
			// have to check for null in case we are closing after a failed open. This happens during
			// testing where we first try to open a program and if it fails, we upgrade and re-open.
			if (manager != null) {
				manager.dispose();
			}
		}
	}

	@Override
	public Map<String, String> getMetadata() {
		metadata.clear();
		metadata.put("Program Name", getName());
		metadata.put("Language ID",
			languageID + " (" + languageVersion + "." + languageMinorVersion + ")");
		metadata.put("Compiler ID", compilerSpecID.getIdAsString());
		metadata.put("Processor", language.getProcessor().toString());
		metadata.put("Endian", memoryManager.isBigEndian() ? "Big" : "Little");
		metadata.put("Address Size", "" + addressFactory.getDefaultAddressSpace().getSize());
		metadata.put("Minimum Address", getString(getMinAddress()));
		metadata.put("Maximum Address", getString(getMaxAddress()));
		metadata.put("# of Bytes", "" + getNumberOfBytes());
		metadata.put("# of Memory Blocks", "" + memoryManager.getBlocks().length);
		metadata.put("# of Instructions", "" + listing.getNumInstructions());
		metadata.put("# of Defined Data", "" + listing.getNumDefinedData());
		metadata.put("# of Functions", "" + getFunctionManager().getFunctionCount());
		metadata.put("# of Symbols", "" + getSymbolTable().getNumSymbols());
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

	private static String getString(Object obj) {
		if (obj != null) {
			return obj.toString();
		}
		return null;
	}

	private String getNumberOfBytes() {
		long size = 0;
		MemoryBlock[] blocks = memoryManager.getBlocks();
		for (MemoryBlock block : blocks) {
			size += block.getSize();
		}
		return "" + size;
	}

	@Override
	protected void updateMetadata() throws IOException {
		getMetadata(); // updates metadata map
		super.updateMetadata();
	}

	@Override
	public boolean lock(String reason) {
		if (super.lock(reason)) {
			if (programUserData == null || programUserData.lock(reason)) {
				return true;
			}
			super.unlock();
		}
		return false;
	}

	@Override
	public void forceLock(boolean rollback, String reason) {
		super.forceLock(rollback, reason);
		if (programUserData != null) {
			programUserData.forceLock(rollback, reason);
		}
	}

	@Override
	public void unlock() {
		super.unlock();
		if (programUserData != null) {
			programUserData.unlock();
		}
	}

	@Override
	public long getUniqueProgramID() {
		return dbh.getDatabaseId();
	}

	@Override
	public void invalidateWriteCache() {
		ProgramRegisterContextDB contextMgr = (ProgramRegisterContextDB) getProgramContext();
		contextMgr.invalidateProcessorContextWriteCache();
		super.invalidateWriteCache();
	}

	@Override
	public void flushWriteCache() {
		ProgramRegisterContextDB contextMgr = (ProgramRegisterContextDB) getProgramContext();
		contextMgr.flushProcessorContextWriteCache();
		super.flushWriteCache();
	}

	/**
	 * Install updated compiler spec extension options.
	 * See {@link SpecExtension}.
	 */
	protected void installExtensions() {
		if (!(compilerSpec instanceof ProgramCompilerSpec)) {
			return;
		}
		lock.acquire();
		try {
			((ProgramCompilerSpec) compilerSpec).installExtensions();
		}
		finally {
			lock.release();
		}
	}

	private void registerCompilerSpecOptions() {
		if (!(compilerSpec instanceof ProgramCompilerSpec)) {
			throw new AssertException(
				"unsupported compilerSpec: " + compilerSpec.getClass().getName());
		}
		((ProgramCompilerSpec) compilerSpec).registerProgramOptions();
	}
}
