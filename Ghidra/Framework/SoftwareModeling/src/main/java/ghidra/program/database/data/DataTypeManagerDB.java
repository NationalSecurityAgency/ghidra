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

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.help.UnsupportedOperationException;

import db.*;
import db.util.ErrorHandler;
import generic.jar.ResourceFile;
import generic.stl.Pair;
import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.docking.settings.*;
import ghidra.framework.Application;
import ghidra.framework.data.OpenMode;
import ghidra.framework.model.RuntimeIOException;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.graph.*;
import ghidra.graph.algo.GraphNavigator;
import ghidra.program.database.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.database.symbol.VariableStorageManager;
import ghidra.program.database.util.DBRecordAdapter;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.*;
import ghidra.util.*;
import ghidra.util.classfinder.ClassTranslator;
import ghidra.util.datastruct.FixedSizeHashMap;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/**
 * Base class for DB-backed data type managers. <br>
 * Important Notes:
 * <ul>
 * <li>When invoking {@link DataType#isEquivalent(DataType)} involving
 * DataTypeDB objects it is important to invoke the method on DataTypeDB. This
 * will ensure that the internal optimization mechanisms are used.</li>
 * <li>It is important that the use of {@link DataType#clone(DataTypeManager)}
 * and {@link DataType#copy(DataTypeManager)} be avoided when possible to ensure
 * full benefit of the {@link #equivalenceCache} and {@link #resolveCache}.</li>
 * </ul>
 */
abstract public class DataTypeManagerDB implements DataTypeManager {

	/**
	 * DB_VERSION should be incremented any time a change is made to the overall
	 * database schema associated with any of the managers or the nature of the 
	 * stored data has changed preventing compatibility with older GHIDRA versions.  
	 * 
	 * Due to the frequent use of read-only mode for certain archives, read-only 
	 * mode must always be allowed when opening older versions.
	 *             - version  1 - Legacy prior to overall DTM versioning (not stored)
	 * 12-Jan-2022 - version  2 - Introduced DataTypeManager data map table and overall DTM version.
	 *                            Also added typedef flags and auto-naming support.
	 */
	static final int DB_VERSION = 2;

	static long ROOT_CATEGORY_ID = 0;

	static final int BUILT_IN = 0;
	static final int COMPOSITE = 1;
	static final int COMPONENT = 2;
	static final int ARRAY = 3;
	static final int POINTER = 4;
	static final int TYPEDEF = 5;
	static final int FUNCTION_DEF = 6;
	static final int PARAMETER = 7;
	static final int ENUM = 8;
	static final int BITFIELD = 9; // see BitFieldDataType - used for encoding only (no table)

	static final int DATA_TYPE_KIND_SHIFT = 56;

	private static final String MAP_TABLE_NAME = "DataTypeManager";

	// Data map keys
	private static final String DTM_DB_VERSION_KEY = "DB Version";
	private static final String DTM_GHIDRA_VERSION_KEY = "GHIDRA Version";

	private static final String SETTINGS_TABLE_NAME = "Default Settings";

	public static final byte UNKNOWN_CALLING_CONVENTION_ID =
		CallingConventionDBAdapter.UNKNOWN_CALLING_CONVENTION_ID;
	public static final byte DEFAULT_CALLING_CONVENTION_ID =
		CallingConventionDBAdapter.DEFAULT_CALLING_CONVENTION_ID;

	private BuiltinDBAdapter builtinAdapter;
	private ComponentDBAdapter componentAdapter;
	private CompositeDBAdapter compositeAdapter;
	private ArrayDBAdapter arrayAdapter;
	private PointerDBAdapter pointerAdapter;
	private TypedefDBAdapter typedefAdapter;
	private SettingsDBAdapter settingsAdapter;
	private CategoryDBAdapter categoryAdapter;
	private FunctionDefinitionDBAdapter functionDefAdapter;
	private FunctionParameterAdapter paramAdapter;
	private EnumDBAdapter enumAdapter;
	private EnumValueDBAdapter enumValueAdapter;
	private ParentChildAdapter parentChildAdapter;
	protected SourceArchiveAdapter sourceArchiveAdapter;

	private CallingConventionDBAdapter callingConventionAdapter;
	private TreeSet<String> knownCallingConventions;
	private TreeSet<String> definedCallingConventions;

	protected final boolean readOnlyMode;
	protected final DBHandle dbHandle;
	protected final String tablePrefix;
	protected final ErrorHandler errHandler;

	private DataTypeConflictHandler currentHandler;

	private CategoryDB root;
	private DBObjectCache<DataTypeDB> dtCache;
	private DBObjectCache<SourceArchiveDB> sourceArchiveDBCache;
	private HashMap<Long, DataType> builtInMap = new HashMap<>();
	private HashMap<DataType, Long> builtIn2IdMap = new HashMap<>();
	private DBObjectCache<CategoryDB> catCache = new DBObjectCache<>(50);
	private SettingsCache<Long> settingsCache = new SettingsCache<>(200);
	private List<DataType> sortedDataTypes;
	private Map<Long, Set<String>> enumValueMap;
	private Map<String, Set<String>> previouslyUsedSettingsValuesMap = new HashMap<>();

	private List<InvalidatedListener> invalidatedListeners = new ArrayList<>();
	protected DataTypeManagerChangeListenerHandler defaultListener =
		new DataTypeManagerChangeListenerHandler();
	private Comparator<DataType> nameComparator = DataTypeComparator.INSTANCE;
	private int creatingDataType = 0;
	protected UniversalID universalID;

	private Map<UniversalID, SourceArchive> sourceArchiveMap;
	private LinkedList<Long> idsToDelete = new LinkedList<>();
	private LinkedList<Pair<DataType, DataType>> typesToReplace = new LinkedList<>();
	private List<DataType> favoritesList = new ArrayList<>();

	// TODO: idsToDataTypeMap may have issue since there could be a one to many mapping
	// (e.g., type with same UniversalID could be in multiple categories unless specifically 
	// prevented during resolve)
	private IdsToDataTypeMap idsToDataTypeMap = new IdsToDataTypeMap();

	private ThreadLocal<EquivalenceCache> equivalenceCache = new ThreadLocal<>();

	private IdentityHashMap<DataType, DataType> resolveCache;
	private TreeSet<ResolvePair> resolveQueue; // TODO: is TreeSet really needed?
	private LinkedList<DataType> conflictQueue = new LinkedList<>();

	private boolean isBulkRemoving;

	protected AddressMap addrMap;

	private DataOrganization dataOrganization;
	private ProgramArchitecture programArchitecture;
	private VariableStorageManager variableStorageMgr;

	protected final Lock lock;

	private static class ResolvePair implements Comparable<ResolvePair> {

		private final DataTypeDB resolvedDt;
		private final DataType definitionDt;

		ResolvePair(DataTypeDB resolvedDt, DataType definitionDt) {
			this.resolvedDt = resolvedDt;
			this.definitionDt = definitionDt;
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof ResolvePair)) {
				return false;
			}
			return resolvedDt.getKey() == ((ResolvePair) obj).resolvedDt.getKey();
		}

		@Override
		public int hashCode() {
			long value = resolvedDt.getKey();
			return (int) (value ^ (value >>> 32));
		}

		@Override
		public int compareTo(ResolvePair o) {
			long r = resolvedDt.getKey() - o.resolvedDt.getKey();
			if (r == 0) {
				return 0;
			}
			if (r < 0) {
				return -1;
			}
			return 1;
		}
	}

	/**
	 * Construct a new temporary data-type manager. Note that this manager does not
	 * support the save or saveAs operation.  No Language is associated with instance.
	 * 
	 * @param dataOrganization applicable data organization
	 * @throws RuntimeIOException if database error occurs during creation
	 */
	protected DataTypeManagerDB(DataOrganization dataOrganization) throws RuntimeIOException {
		this.lock = new Lock("DataTypeManagerDB");
		this.errHandler = new DbErrorHandler();
		this.dataOrganization = dataOrganization;
		this.tablePrefix = "";

		try {
			dbHandle = new DBHandle();
			readOnlyMode = false;
			long txId = dbHandle.startTransaction();
			try {
				init(OpenMode.CREATE, TaskMonitor.DUMMY);
			}
			catch (VersionException | CancelledException e) {
				throw new AssertException(e); // unexpected
			}
			finally {
				dbHandle.endTransaction(txId, true);
			}
		}
		catch (IOException e) {
			throw new RuntimeIOException(e);
		}
	}

	/**
	 * Constructor for a data-type manager backed by a packed database file. When
	 * opening for UPDATE an automatic upgrade will be performed if required.
	 * NOTE: Default DataOrganization will be used for new archive.
	 * 
	 * @param packedDBfile packed datatype archive file (i.e., *.gdt resource).
	 * @param openMode     open mode CREATE, READ_ONLY or UPDATE 
	 * @param monitor task monitor
	 * @throws IOException a low-level IO error. This exception may also be thrown
	 *                     when a version error occurs (cause is VersionException).
	 * @throws CancelledException if task cancelled
	 */
	protected DataTypeManagerDB(ResourceFile packedDBfile, OpenMode openMode, TaskMonitor monitor)
			throws IOException, CancelledException {

		this.errHandler = new DbErrorHandler();
		this.lock = new Lock("DataTypeManagerDB");
		this.tablePrefix = "";
		this.readOnlyMode = (openMode == OpenMode.IMMUTABLE);

		File file = packedDBfile.getFile(false);
		if (file == null && openMode != OpenMode.IMMUTABLE) {
			throw new IOException("Unsupported mode (" + openMode +
				") for read-only Datatype Archive: " + packedDBfile.getAbsolutePath());
		}

		// Open packed database archive
		boolean openSuccess = false;
		PackedDatabase pdb = null;
		try {
			if (openMode == OpenMode.CREATE) {
				dbHandle = new PackedDBHandle(
					DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE);
			}
			else {
				pdb = PackedDatabase.getPackedDatabase(packedDBfile, false, monitor);

				if (openMode == OpenMode.IMMUTABLE) {
					dbHandle = pdb.open(monitor);
				}
				else { // UPDATE mode (allows upgrade use)
					dbHandle = pdb.openForUpdate(monitor);
				}
			}
			openSuccess = true;
		}
		finally {
			if (!openSuccess && pdb != null) {
				pdb.dispose(); // dispose on error
			}
		}

		// Initialize datatype manager and save new archive on CREATE
		boolean initSuccess = false;
		try {
			initPackedDatabase(packedDBfile, openMode, monitor); // performs upgrade if needed
			if (openMode == OpenMode.CREATE) {
				// preserve UniversalID if it has been established
				Long uid = universalID != null ? universalID.getValue() : null;
				((PackedDBHandle) dbHandle).saveAs("Archive", file.getParentFile(),
					packedDBfile.getName(), uid, monitor);
			}
			initSuccess = true;
		}
		finally {
			if (!initSuccess) {
				dbHandle.close(); // close on error (packed database will also be disposed)
			}
		}
	}

	private void initPackedDatabase(ResourceFile packedDBfile, OpenMode openMode,
			TaskMonitor monitor) throws CancelledException, IOException {
		Long txId = dbHandle.startTransaction();
		try {
			init(openMode, monitor);

			if (openMode != OpenMode.CREATE && hasDataOrganizationChange(true)) {
				// check for data organization change with possible upgrade
				handleDataOrganizationChange(openMode, monitor);
			}

			if (openMode == OpenMode.UPGRADE) {
				migrateOldFlexArrayComponentsIfRequired(monitor);

				Msg.showInfo(this, null, "Archive Upgraded",
					"Data type archive has been upgraded: " + packedDBfile.getName());
			}
		}
		catch (VersionException e) {
			if (openMode == OpenMode.UPDATE && e.isUpgradable()) {
				// Try again with UPGRADE mode
				dbHandle.endTransaction(txId, true);
				txId = null;
				initPackedDatabase(packedDBfile, OpenMode.UPGRADE, monitor);
			}
			else {
				// Unable to handle required upgrade
				throw new IOException(e);
			}
		}
		finally {
			if (txId != null) {
				dbHandle.endTransaction(txId, true);
			}
		}
	}

	/**
	 * Constructor for a database-backed <code>DataTypeManagerDB</code> extension.
	 * NOTE: This does not check for and handle data organization changes which must be
	 * handled later (use {@link #hasDataOrganizationChange(boolean)} and 
	 * {@link #compilerSpecChanged(TaskMonitor)} to check for and initiate response to changes).
	 * 
	 * @param handle     database handle
	 * @param addrMap    address map (may be null)
	 * @param openMode   open mode CREATE, READ_ONLY, UPDATE, UPGRADE.
	 * @param tablePrefix DB table prefix to be applied to all associated table names.  This 
	 *                    need only be specified when using multiple instances with the same
	 *                    DB handle (null or empty string for no-prefix).
	 * @param errHandler the error handler
	 * @param lock       database lock
	 * @param monitor    the current task monitor
	 * @throws CancelledException if an upgrade is cancelled
	 * @throws IOException if there is a problem reading the database
	 * @throws VersionException if any database handle's version doesn't match the expected version.
	 *                   This exception will never be thrown in READ_ONLY mode.
	 */
	protected DataTypeManagerDB(DBHandle handle, AddressMap addrMap, OpenMode openMode,
			String tablePrefix, ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		this.tablePrefix = tablePrefix != null ? tablePrefix : "";
		this.dbHandle = handle;
		this.readOnlyMode = (openMode == OpenMode.IMMUTABLE);
		this.addrMap = addrMap;
		this.errHandler = errHandler;
		this.lock = lock;
		init(openMode, monitor);
	}

	private void init(OpenMode openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		updateID();
		initializeAdapters(openMode, monitor);
		if (checkForSourceArchiveUpdatesNeeded(openMode, monitor)) {
			doSourceArchiveUpdates(monitor);
		}
		dtCache = new DBObjectCache<>(10);
		sourceArchiveDBCache = new DBObjectCache<>(10);
		builtInMap = new HashMap<>();
		builtIn2IdMap = new HashMap<>();
		root = new CategoryDB(this, catCache);
		if (parentChildAdapter.needsInitializing()) {
			initializedParentChildTable();
		}
	}

	private void initializeAdapters(OpenMode openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {

		//
		// IMPORTANT! All adapter versions must retain read-only capability to permit
		// opening older archives without requiring an upgrade. Failure to do so may
		// present severe usability issues when the ability to open for update is not 
		// possible.
		//

		checkManagerVersion(openMode);

		VersionException versionExc = null;
		try {
			callingConventionAdapter =
				CallingConventionDBAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			builtinAdapter = BuiltinDBAdapter.getAdapter(dbHandle, openMode, tablePrefix);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			categoryAdapter = CategoryDBAdapter.getAdapter(dbHandle, openMode, tablePrefix);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			arrayAdapter = ArrayDBAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			typedefAdapter = TypedefDBAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			compositeAdapter =
				CompositeDBAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			componentAdapter = ComponentDBAdapter.getAdapter(dbHandle, openMode, tablePrefix);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			functionDefAdapter = FunctionDefinitionDBAdapter.getAdapter(dbHandle, openMode,
				tablePrefix, callingConventionAdapter, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			paramAdapter =
				FunctionParameterAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			settingsAdapter = SettingsDBAdapter.getAdapter(tablePrefix + SETTINGS_TABLE_NAME,
				dbHandle, openMode, null, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			pointerAdapter = PointerDBAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			enumAdapter = EnumDBAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			enumValueAdapter =
				EnumValueDBAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			parentChildAdapter = ParentChildAdapter.getAdapter(dbHandle, openMode, tablePrefix);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			sourceArchiveAdapter =
				SourceArchiveAdapter.getAdapter(dbHandle, openMode, tablePrefix, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}

		try {
			initializeOtherAdapters(openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}

		if (versionExc != null) {
			throw versionExc;
		}

		updateManagerAndAppVersion(openMode);
	}

	/**
	 * Initialize other DB adapters after base implementation adapters has been
	 * initialized.
	 * @param openMode the DB open mode
	 * @param monitor the progress monitor
	 * @throws CancelledException if the user cancels an upgrade
	 * @throws VersionException if the database does not match the expected version.
	 * @throws IOException if a database IO error occurs.
	 */
	protected void initializeOtherAdapters(OpenMode openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		// do nothing
	}

	protected void handleDataOrganizationChange(OpenMode openMode, TaskMonitor monitor)
			throws IOException, LanguageVersionException, CancelledException {
		if (openMode == OpenMode.UPDATE) {
			throw new LanguageVersionException("Data organization change detected", true);
		}
		if (openMode == OpenMode.UPGRADE) {
			compilerSpecChanged(monitor);
		}
		// NOTE: No change for READ_ONLY mode
	}

	/**
	 * Build Parent/Child table for tracking dataType usage by other dataTypes
	 * (e.g., arrays, pointers, etc.). Only used to populate the ParentChildAdapter
	 * table following an upgrade because it did not previously exist. This could
	 * not be accomplished by the adapter during instantiation because we must be
	 * able to instantiate all dataTypes to accomplish this.
	 */
	private void initializedParentChildTable() {
		buildSortedDataTypeList();
		for (DataType dt : sortedDataTypes) {
			if (dt instanceof Array) {
				((Array) dt).getDataType().addParent(dt);
			}
			else if (dt instanceof Pointer) {
				DataType pdt = ((Pointer) dt).getDataType();
				if (pdt != null) {
					pdt.addParent(dt);
				}
			}
			else if (dt instanceof TypeDef) {
				((TypeDef) dt).getDataType().addParent(dt);
			}
			else if (dt instanceof Composite) {
				DataTypeComponent[] comps = ((Composite) dt).getDefinedComponents();
				for (DataTypeComponent comp : comps) {
					comp.getDataType().addParent(dt);
				}
			}
			else if (dt instanceof FunctionDefinition) {
				FunctionDefinition funDef = (FunctionDefinition) dt;
				DataType retType = funDef.getReturnType();
				if (retType != null) {
					retType.addParent(dt);
				}
				ParameterDefinition[] vars = funDef.getArguments();
				for (ParameterDefinition var : vars) {
					var.getDataType().addParent(dt);
				}
			}
		}
	}

	/**
	 * Check data map for overall manager version for compatibility.
	 * @throws VersionException if database is a newer unsupported version
	 * @throws IOException if an IO error occurs
	 */
	private void checkManagerVersion(OpenMode openMode) throws IOException, VersionException {

		if (openMode == OpenMode.CREATE) {
			return;
		}

		// Check data map for overall manager version for compatibility.
		DBStringMapAdapter dataMap = getDataMap(openMode == OpenMode.UPGRADE);
		if (dataMap != null) {
			// verify that we are compatible with stored data
			int dbVersion = dataMap.getInt(DTM_DB_VERSION_KEY, 1);
			if (dbVersion > DB_VERSION) {
				throw new VersionException(false);
			}
			if (dbVersion < DB_VERSION && openMode == OpenMode.UPDATE) {
				// Force upgrade if open for update
				throw new VersionException(true);
			}
		}
		else if (openMode == OpenMode.UPDATE) {
			// missing data map
			throw new VersionException(true);
		}
	}

	private void updateManagerAndAppVersion(OpenMode openMode) throws IOException {
		if (openMode == OpenMode.CREATE || openMode == OpenMode.UPGRADE) {
			DBStringMapAdapter dataMap = getDataMap(true);
			dataMap.put(DTM_DB_VERSION_KEY, Integer.toString(DB_VERSION));
			dataMap.put(DTM_GHIDRA_VERSION_KEY, Application.getApplicationVersion());
		}
	}

	/**
	 * Get the manager string data map.
	 * @param createIfNeeded if true map will be created if it does not exist
	 * @return manager string data map or null
	 * @throws IOException if an IO error occurs
	 */
	protected DBStringMapAdapter getDataMap(boolean createIfNeeded) throws IOException {
		DBStringMapAdapter dataMap = null;
		boolean exists = (dbHandle.getTable(MAP_TABLE_NAME) != null);
		if (exists) {
			dataMap = new DBStringMapAdapter(dbHandle, MAP_TABLE_NAME, false);
		}
		else if (createIfNeeded) {
			dataMap = new DBStringMapAdapter(dbHandle, MAP_TABLE_NAME, true);
		}
		return dataMap;
	}

	boolean clearSetting(long dataTypeId, String name) {
		lock.acquire();
		try {
			settingsCache.remove(dataTypeId, name);
			return settingsAdapter.removeSettingsRecord(dataTypeId, name);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	boolean clearAllSettings(long dataTypeId) {
		lock.acquire();
		try {
			boolean changed = false;
			Field[] keys = settingsAdapter.getSettingsKeys(dataTypeId);
			for (Field key : keys) {
				long settingsId = key.getLongValue();
				DBRecord rec = settingsAdapter.getSettingsRecord(settingsId);
				String name = settingsAdapter.getSettingName(rec);
				settingsAdapter.removeSettingsRecord(settingsId);
				settingsCache.remove(dataTypeId, name);
				changed = true;
			}
			return changed;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	String[] getSettingsNames(long dataTypeId) {
		lock.acquire();
		try {
			return settingsAdapter.getSettingsNames(dataTypeId);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return new String[0];
	}

	SettingDB getSetting(long dataTypeId, String name) {
		lock.acquire();
		try {
			SettingDB setting = settingsCache.get(dataTypeId, name);
			if (setting != null) {
				return setting;
			}
			DBRecord rec = settingsAdapter.getSettingsRecord(dataTypeId, name);
			if (rec != null) {
				setting = new SettingDB(rec, settingsAdapter.getSettingName(rec));
				settingsCache.put(dataTypeId, name, setting);
				return setting;
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	boolean updateSettingsRecord(long dataTypeId, String name, String strValue, long longValue) {
		lock.acquire();
		try {
			DBRecord rec =
				settingsAdapter.updateSettingsRecord(dataTypeId, name, strValue, longValue);
			if (rec != null) {
				SettingDB setting = new SettingDB(rec, settingsAdapter.getSettingName(rec));
				settingsCache.put(dataTypeId, name, setting);
				if (strValue != null) {
					Set<String> suggestions = previouslyUsedSettingsValuesMap.get(name);
					if (suggestions != null) {
						// only cache suggestion if suggestions previously requested
						suggestions.add(strValue);
					}
				}
				return true;
			}
			return false;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return false;
	}

	private Set<String> generateSuggestions(StringSettingsDefinition settingsDefinition) {
		Set<String> set = new TreeSet<>();
		try {
			settingsAdapter.addAllValues(settingsDefinition.getStorageKey(), set);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return set;
	}

	/**
	 * Get suggested setting values for a specified settingsDefinition
	 * @param settingsDefinition string settings definition
	 * @return suggested values or empty array if none
	 */
	String[] getSuggestedValues(StringSettingsDefinition settingsDefinition) {
		if (!settingsDefinition.supportsSuggestedValues()) {
			return Settings.EMPTY_STRING_ARRAY;
		}
		lock.acquire();
		try {
			Set<String> previouslyUsedSet = previouslyUsedSettingsValuesMap.computeIfAbsent(
				settingsDefinition.getStorageKey(), n -> generateSuggestions(settingsDefinition));
			// Last-minute additions are not cached since suggested values may change
			Set<String> set = new TreeSet<>(previouslyUsedSet); // copy before updating
			settingsDefinition.addPreferredValues(this, set);
			if (set.isEmpty()) {
				return Settings.EMPTY_STRING_ARRAY;
			}
			return set.toArray(new String[set.size()]);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Set the architecture-specific details associated with this datatype manager.
	 * The data organization will be obtained from the compiler spec specified by
	 * the program architecture.  Fixup of all composites will be performed, if store is
	 * true, to reflect any changes in the data organization.
	 * The caller is resposible for ensuring that this setting is done consistent 
	 * with the {@link #addrMap} setting used during construction if applicable.
	 * <br>
	 * If not storing caller may need to check for data organization change to communicate
	 * change or to facilitate an upgrade situation.
	 * 
	 * @param programArchitecture program architecture details (may be null) in which case
	 * default data organization will be used.
	 * @param variableStorageMgr variable storage manager (within same database) or null
	 * to disable variable storage support.  Ignored if programArchitecture is null;
	 * @param store if true database update will occur and datatypes will be updated if
	 * any change to the data organization is detected (a stored copy may be used to
	 * detect this condition).  This should never be passed as true if opened read-only.
	 * This should be false during create mode where only the state is affected without 
	 * changing the Database or existing datatypes.
	 * @param monitor task monitor
	 * @throws IOException if IO error occurs
	 * @throws CancelledException if processing cancelled - data types may not properly reflect
	 * updated compiler specification
	 * @throws UnsupportedOperationException if language was previously set
	 */
	protected void setProgramArchitecture(ProgramArchitecture programArchitecture,
			VariableStorageManager variableStorageMgr, boolean store, TaskMonitor monitor)
			throws IOException, CancelledException {

		this.programArchitecture = programArchitecture;
		this.variableStorageMgr = programArchitecture != null ? variableStorageMgr : null;

		dataOrganization = programArchitecture != null
				? programArchitecture.getCompilerSpec().getDataOrganization()
				: DataOrganizationImpl.getDefaultOrganization();

		if (store) {
			try {
				compilerSpecChanged(monitor);
				updateLastChangeTime();
			}
			finally {
				invalidateCache();
			}
		}
	}

	/**
	 * Perform updates related to a compiler spec change, including:
	 * <ul>
	 * <li>data organization changes which may impact datatype components and packing</li>
	 * </ul>
	 * NOTE: this manager must be open for update.
	 * @param monitor task monitor
	 * @throws ReadOnlyException if this manager has not been open for update
	 * @throws IOException if an IO error occurs while performing updates
	 * @throws CancelledException if processing cancelled - data types may not properly reflect
	 * updated compiler specification
	 */
	protected void compilerSpecChanged(TaskMonitor monitor) throws IOException, CancelledException {

		if (readOnlyMode) {
			throw new ReadOnlyException();
		}

		boolean hasDataOrgChange = hasDataOrganizationChange(false);

		saveDataOrganization();

		if (hasDataOrgChange) {
			doCompositeFixup(monitor);
		}

		// FUTURE: may need to handle calling convention and data organization change impact
		// on function definitions
	}

	/**
	 * Check if the active {@link #getDataOrganization()} differs from the stored data organization.
	 * False will be returned when {@code ifPreviouslyStored} is true and data organization has never 
	 * beeen saved.
	 * @param ifPreviouslyStored if true and data organization has never been saved false will be returned
	 * @return true if a data organization change has occured
	 * @throws IOException if an IO error occurs
	 */
	protected final boolean hasDataOrganizationChange(boolean ifPreviouslyStored)
			throws IOException {
		// compare DB-stored data organization with the one in affect
		DataOrganization storedDataOrg = readDataOrganization();
		if (ifPreviouslyStored && storedDataOrg == null) {
			return false;
		}
		return !Objects.equals(readDataOrganization(), getDataOrganization());
	}

	/**
	 * Save the current data organization to facilitate future change detection and 
	 * upgrades.
	 * @throws IOException if failure occured while saving data organization.
	 */
	protected void saveDataOrganization() throws IOException {
		DataOrganizationImpl.save(getDataOrganization(), getDataMap(true), "dataOrg.");
	}

	/**
	 * Read the DB-serialized data organization.  If one has not been stored a suitable
	 * default will be returned.
	 * @return stored data organization or suitable default.
	 * @throws IOException if DB error orccurs
	 */
	protected DataOrganization readDataOrganization() throws IOException {
		DBStringMapAdapter dataMap = getDataMap(false);
		if (dataMap == null) {
			return null;
		}

		DataOrganization dataOrg = DataOrganizationImpl.restore(dataMap, "dataOrg.");
		if (dataOrg == null) {
			ProgramArchitecture arch = getProgramArchitecture();
			return DataOrganizationImpl
					.getDefaultOrganization(arch != null ? arch.getLanguage() : null);
		}
		return dataOrg;
	}

	@Override
	public ProgramArchitecture getProgramArchitecture() {
		return programArchitecture;
	}

	protected static String getProgramArchitectureSummary(LanguageID languageId,
			int languageVersion, CompilerSpecID compilerSpecId) {
		StringBuilder buf = new StringBuilder();
		buf.append(languageId.getIdAsString());
		buf.append(" / ");
		buf.append(compilerSpecId.getIdAsString());
		return buf.toString();
	}

	@Override
	public String getProgramArchitectureSummary() {
		if (programArchitecture != null) {
			return getProgramArchitectureSummary(programArchitecture.getLanguage().getLanguageID(),
				programArchitecture.getLanguage().getVersion(),
				programArchitecture.getCompilerSpec().getCompilerSpecID());
		}
		return null;
	}

	/**
	 * Get the variable storage manager if it has been established.
	 * @return variable storage manager or null if no associated architecture.
	 */
	protected VariableStorageManager getVariableStorageManager() {
		return variableStorageMgr;
	}

	/**
	 * Determine if transaction is active.  With proper lock established
	 * this method may be useful for determining if a lazy record update
	 * may be performed.
	 * @return true if database transaction if active, else false
	 */
	protected final boolean isTransactionActive() {
		return dbHandle.isTransactionActive();
	}

	/**
	 * This method should be invoked following an undo/redo or a transaction rollback situation.
	 * This will notify {@link DataTypeManagerChangeListenerHandler} and its listeners that this 
	 * manager has just been restored (e.g., undo/redo/rollback).
	 */
	public void notifyRestored() {
		defaultListener.restored(this);
	}

	abstract protected String getDomainFileID();

	abstract protected String getPath();

	private void buildSortedDataTypeList() {
		if (sortedDataTypes != null) {
			return;
		}
		List<DataType> list = new ArrayList<>();
		popuplateDataTypeList(list, root);
		Collections.sort(list, nameComparator);
		sortedDataTypes = list;
	}

	private void buildEnumValueMap() {
		if (enumValueMap != null) {
			return;
		}
		Map<Long, Set<String>> map = new HashMap<>();
		populateEnumValueMap(map, root);
		enumValueMap = map;
	}

	private void removeDataTypeFromSortedList(DataTypePath dataTypePath) {
		if (sortedDataTypes == null) {
			return;
		}
		// find and remove exact match from sortedDataTypes list
		String name = dataTypePath.getDataTypeName();
		DataType compareDataType =
			new TypedefDataType(dataTypePath.getCategoryPath(), name, DataType.DEFAULT, this);
		int index = Collections.binarySearch(sortedDataTypes, compareDataType, nameComparator);
		if (index >= 0) {
			sortedDataTypes.remove(index);
		}
	}

	private void insertDataTypeIntoSortedList(DataType dataType) {
		if (sortedDataTypes == null) {
			return;
		}
		int index = Collections.binarySearch(sortedDataTypes, dataType, nameComparator);
		if (index < 0) {
			index = -index - 1;
			sortedDataTypes.add(index, dataType);
		}
		else {
			// NOTE: ideally, this should never happen and may indicate presence of duplicate
			sortedDataTypes.set(index, dataType);
		}
	}

	private void popuplateDataTypeList(List<DataType> list, Category category) {
		for (Category childCategory : category.getCategories()) {
			popuplateDataTypeList(list, childCategory);
		}
		list.addAll(Arrays.asList(category.getDataTypes()));
	}

	private void populateEnumValueMap(Map<Long, Set<String>> map, Category category) {
		for (Category childCategory : category.getCategories()) {
			populateEnumValueMap(map, childCategory);
		}
		DataType[] dataTypeCollection = category.getDataTypes();
		for (DataType type : dataTypeCollection) {
			if (type instanceof Enum) {
				Enum enumDt = (Enum) type;
				long[] values = enumDt.getValues();
				for (long value : values) {
					Set<String> namesForValue = map.get(value);
					if (namesForValue == null) {
						namesForValue = new HashSet<>();
						map.put(value, namesForValue);
					}
					namesForValue.add(enumDt.getName(value));
				}
			}
		}
	}

	@Override
	public UniversalID getUniversalID() {
		return universalID;
	}

	public void updateID() {
		long databaseID = dbHandle.getDatabaseId();
		// if the databaseID == 0, we have a non-upgraded file archive, leave
		// universalID null so we can tell.
		universalID = databaseID == 0 ? null : new UniversalID(databaseID);
		invalidateSourceArchiveCache();
	}

	@Override
	public List<DataType> getFavorites() {
		lock.acquire();
		try {
			return new ArrayList<>(favoritesList);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public boolean isFavorite(DataType dataType) {
		lock.acquire();
		try {
			return favoritesList.contains(dataType);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void setFavorite(DataType dataType, boolean isFavorite) {
		if (dataType.getDataTypeManager() != this) {
			throw new IllegalArgumentException(
				"Datatype does not belong to this datatype manager.");
		}
		lock.acquire();
		try {
			boolean isInFavorites = favoritesList.contains(dataType);
			if (isInFavorites == isFavorite) {
				return; // no change
			}
			if (isFavorite) {
				favoritesList.add(dataType);
			}
			else {
				favoritesList.remove(dataType);
			}
			favoritesChanged(dataType, isFavorite);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public String getUniqueName(CategoryPath path, String baseName) {
		int pos = baseName.lastIndexOf('_');
		int oneUpNumber = 0;
		String name = baseName;
		if (pos > 0) {
			String numString = baseName.substring(pos + 1);
			try {
				oneUpNumber = Integer.parseInt(numString);
				name = baseName;
				baseName = baseName.substring(0, pos);
			}
			catch (NumberFormatException e) {
				// the number will get updated below
			}
		}
		while (getDataType(path, name) != null) {
			++oneUpNumber;
			name = baseName + "_" + oneUpNumber;
		}
		return name;
	}

	String getTemporaryUniqueName(CategoryPath newCategoryPath, CategoryPath currentCategoryPath,
			String baseName) {
		int pos = baseName.lastIndexOf('_');
		int oneUpNumber = 0;
		String name = baseName;
		if (pos > 0) {
			String numString = baseName.substring(pos + 1);
			try {
				oneUpNumber = Integer.parseInt(numString);
				name = baseName;
				baseName = baseName.substring(0, pos);
			}
			catch (NumberFormatException e) {
				// the number will get updated below
			}
		}
		while (getDataType(newCategoryPath, name) != null ||
			getDataType(currentCategoryPath, name) != null) {
			++oneUpNumber;
			name = baseName + "_" + oneUpNumber;
		}
		return name;
	}

	@Override
	public Category getCategory(CategoryPath path) {
		if (path == null) {
			return null;
		}
		if (path.equals(CategoryPath.ROOT)) {
			return root;
		}
		Category parent = getCategory(path.getParent());
		if (parent == null) {
			return null;
		}
		return parent.getCategory(path.getName());
	}

	CategoryDB getCategoryDB(long id) throws IOException {
		if (id == DataTypeManagerDB.ROOT_CATEGORY_ID) {
			return root;
		}
		CategoryDB cat = catCache.get(id);
		if (cat == null) {
			DBRecord rec = categoryAdapter.getRecord(id);
			if (rec != null) {
				long parentID = rec.getLongValue(CategoryDBAdapter.CATEGORY_PARENT_COL);
				CategoryDB parent = getCategoryDB(parentID);
				String name = rec.getString(CategoryDBAdapter.CATEGORY_NAME_COL);
				cat = new CategoryDB(this, catCache, id, parent, name);
			}
		}
		return cat;
	}

	CategoryDB createCategoryDB(CategoryDB parent, String categoryName) throws IOException {
		CategoryDB c = parent.getCategory(categoryName);
		if (c != null) {
			return c;
		}
		DBRecord rec = categoryAdapter.createCategory(categoryName, parent.getKey());
		String name = rec.getString(CategoryDBAdapter.CATEGORY_NAME_COL);
		CategoryDB cat = new CategoryDB(this, catCache, rec.getKey(), parent, name);
		parent.categoryAdded(cat);// must be before the event notification below
		categoryCreated(cat);
		return cat;
	}

	/**
	 * Get the category for the given ID.
	 * 
	 * @return null if no category exists with the given ID.
	 */
	@Override
	public Category getCategory(long id) {
		lock.acquire();
		try {
			return getCategoryDB(id);
		}
		catch (IOException e) {
			dbError(e);
			return null;
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType resolve(DataType dataType, DataTypeConflictHandler handler) {

		if (dataType == DataType.DEFAULT) {
			return dataType;
		}

		if (dataType instanceof BitFieldDataType) {
			return resolveBitFieldDataType((BitFieldDataType) dataType, handler);
		}

		lock.acquire();
		DataTypeConflictHandler originalHandler = null;
		boolean isEquivalenceCacheOwner = activateEquivalenceCache();
		boolean isResolveCacheOwner = activateResolveCache();
		DataType resolvedDataType = null;
		try {
			originalHandler = currentHandler;

			if (contains(dataType)) {
				return dataType;
			}

			if (handler != null) {
				currentHandler = handler;
			}
			else if (currentHandler == null) {
				currentHandler = DataTypeConflictHandler.DEFAULT_HANDLER;
			}
			else {
				currentHandler = currentHandler.getSubsequentHandler();
			}

			resolvedDataType = getCachedResolve(dataType);
			if (resolvedDataType == null) {
				SourceArchive sourceArchive = dataType.getSourceArchive();
				if (sourceArchive != null &&
					sourceArchive.getArchiveType() == ArchiveType.BUILT_IN) {
					resolvedDataType = resolveBuiltIn(dataType);
				}
				else if (sourceArchive == null || dataType.getUniversalID() == null) {
					// if the dataType has no source or it has no ID (datatypes with no ID are
					// always local i.e. pointers)
					resolvedDataType = resolveDataTypeNoSource(dataType);
				}
				else if (!sourceArchive.getSourceArchiveID().equals(getUniversalID()) &&
					(sourceArchive.getArchiveType() == ArchiveType.PROGRAM ||
						sourceArchive.getArchiveType() == ArchiveType.TEMPORARY)) {
					// dataTypes from a program or temporary archive don't carry over their identity
					resolvedDataType = resolveDataTypeNoSource(dataType);
				}
				else {
					resolvedDataType = resolveDataTypeWithSource(dataType);
				}
				cacheResolvedDataType(dataType, resolvedDataType);
				if (resolvedDataType instanceof DataTypeDB) {
					setCachedEquivalence((DataTypeDB) resolvedDataType, dataType);
				}
			}
		}
		finally {
			try {
				if (isResolveCacheOwner) {
					// Process resolve queue and allowed resolvedDataType to be replaced
					// during conflict processing
					resolvedDataType = processResolveQueue(true, resolvedDataType);
				}
			}
			finally {
				if (isEquivalenceCacheOwner) {
					clearEquivalenceCache();
				}
				currentHandler = originalHandler;
				lock.release();
			}
		}
		return resolvedDataType;
	}

	private DataType resolveBuiltIn(DataType dataType) {

		if (dataType instanceof Pointer) {
			// treat built-in pointers like other datatypes without a source
			return resolveDataTypeNoSource(dataType);
		}

		// can't do this check now because Pointers from the BuiltinDataTypeManager are
		// not instances of BuiltInDataType because the BuiltInDataTypeManger converts
		// pointers from BuiltIns to PointerDBs (Probably shouldn't, but the 
		// BuiltinManger actually uses a DataTypeManagerDB as a base class.

		DataType existingDataType = getDataType(dataType.getCategoryPath(), dataType.getName());
		if (existingDataType != null) {
			if (existingDataType.isEquivalent(dataType)) {
				return existingDataType;
			}
			// oops a non-builtin dataType exists with the same name. Only option is to rename existing
			String dtName = getUnusedConflictName(dataType);
			try {
				existingDataType.setName(dtName);
			}
			catch (Exception e) {
				throw new AssertException(
					"Failed to rename conflicting datatype: " + existingDataType.getPathName(), e);
			}
		}
		return createDataType(dataType, dataType.getName(), BuiltInSourceArchive.INSTANCE,
			currentHandler);
	}

	private DataType resolveBitFieldDataType(BitFieldDataType bitFieldDataType,
			DataTypeConflictHandler handler) {

		// NOTE: When a bit-field is getting added it will get resolved more than once.
		// The first time we will ensure that the base data type, which may be a
		// TypeDef, gets resolved. If the bit-offset is too large it will be set to 0
		// with the expectation that it will get corrected during subsequent packing.
		DataType baseDt = bitFieldDataType.getBaseDataType();
		DataType resolvedBaseDt = resolve(baseDt, handler);
		int baseLength = resolvedBaseDt.getLength();
		int baseLengthBits = 8 * baseLength;
		int bitSize = bitFieldDataType.getDeclaredBitSize();
		int bitOffset = bitFieldDataType.getBitOffset();
		int storageSize = bitFieldDataType.getStorageSize();
		int storageSizeBits = 8 * storageSize;
		if ((bitOffset + bitSize) > storageSizeBits) {
			// should get recomputed during packing when used within structure with packing enabled
			int effectiveBitSize = Math.min(bitSize, baseLengthBits);
			bitOffset = getDataOrganization().isBigEndian() ? baseLengthBits - effectiveBitSize : 0;
			storageSize = baseLength;
		}
		try {
			return new BitFieldDBDataType(resolvedBaseDt, bitSize, bitOffset);
		}
		catch (InvalidDataTypeException e) {
			throw new AssertException("unexpected", e);
		}
	}

	private void renameToUnusedConflictName(DataType dataType) {
		String name = getUnusedConflictName(dataType);
		try {
			dataType.setName(name);
		}
		catch (InvalidNameException e) {
			throw new AssertException(
				"This should not occur here, all we did is tack more on the end", e);
		}
		catch (DuplicateNameException e) {
			throw new AssertException(
				"This should not occur here, we already looked to see if it existed", e);
		}
	}

	/**
	 * When performing a replacement during conflict resolution, this method handles
	 * an update approach for structure and union replacement.
	 * 
	 * @param existingDataType existing datatype
	 * @param dataType         new datatype
	 * @param sourceArchive source archive associated with new type (may be null).
	 * If not null the existingDataType will be updated with source info.
	 * @return true if replacement approach was successful, else false
	 * @throws DataTypeDependencyException if datatype contains dependency issues
	 *                                     during resolve process
	 */
	private boolean updateExistingDataType(DataType existingDataType, DataType dataType,
			SourceArchive sourceArchive) throws DataTypeDependencyException {

		try {
			if (existingDataType instanceof StructureDB existingStruct) {
				if (!(dataType instanceof StructureInternal replacementStruct)) {
					return false;
				}
				existingStruct.doReplaceWith(replacementStruct, true);
			}
			else if (existingDataType instanceof UnionDB existingUnion) {
				if (!(dataType instanceof UnionInternal replacementUnion)) {
					return false;
				}
				existingUnion.doReplaceWith(replacementUnion, true);
			}
			else if (existingDataType instanceof FunctionDefinitionDB existingFuncDef) {
				if (!(dataType instanceof FunctionDefinition replacementFuncDef)) {
					return false;
				}
				existingFuncDef.doReplaceWith(replacementFuncDef, true);
			}
			else if (existingDataType instanceof EnumDB) {
				if (!(dataType instanceof Enum)) {
					return false;
				}
				// TODO: implement doReplaceWith
				existingDataType.replaceWith(dataType);
			}
			else if (existingDataType instanceof TypedefDB) {
				if (!(dataType instanceof TypeDef)) {
					return false;
				}
				// TODO: implement doReplaceWith
				existingDataType.replaceWith(dataType);
			}
			else {
				return false;
			}

			if (sourceArchive != null) {
				existingDataType.setSourceArchive(sourceArchive);
				((DataTypeDB) existingDataType).setUniversalID(dataType.getUniversalID());
				long lastChangeTime = dataType.getLastChangeTime();
				existingDataType.setLastChangeTime(lastChangeTime);
				existingDataType.setLastChangeTimeInSourceArchive(lastChangeTime);
			}
			return true;
		}
		catch (IOException e) {
			dbError(e);
		}
		return false;
	}

	/**
	 * This method gets a ".conflict" name that is not currently used by any data
	 * types in the datatype's category within this data type manager.  If the baseName without
	 * conflict suffix is not used that name will be returned.
	 * <br>
	 * NOTE: The original datatype name will be returned unchanged for pointers and arrays since 
	 * they cannot be renamed.
	 * 
	 * @param dt datatype who name is used to establish non-conflict base name
	 * @return the unused conflict name or original name for datatypes whose name is automatic
	 */
	public String getUnusedConflictName(DataType dt) {
		return getUnusedConflictName(dt.getCategoryPath(), dt);
	}

	/**
	 * This method gets a ".conflict" name that is not currently used by any data
	 * types in the indicated category within this data type manager.  If the baseName without
	 * conflict suffix is not used that name will be returned.
	 * <br>
	 * NOTE: The original datatype name will be returned unchanged for pointers and arrays since 
	 * they cannot be renamed.
	 * <br>
	 * NOTE: Otherwise, if category does not exist the non-conflict name will be returned.
	 * 
	 * @param path the category path of the category where the new data type live in
	 *             the data type manager.
	 * @param dt datatype who name is used to establish non-conflict base name
	 * @return the unused conflict name
	 */
	public String getUnusedConflictName(CategoryPath path, DataType dt) {
		if ((dt instanceof Array) || (dt instanceof Pointer) || (dt instanceof BuiltInDataType)) {
			// name not used - anything will do
			return dt.getName();
		}
		return getUnusedConflictName(getCategory(path), dt);
	}

	/**
	 * This method gets a ".conflict" name that is not currently used by any data
	 * types in the indicated category within this data type manager.  If the baseName without
	 * conflict suffix is not used that name will be returned.
	 * <br>
	 * NOTE: The original datatype name will be returned unchanged for pointers and arrays since 
	 * they cannot be renamed.
	 * <br>
	 * NOTE: Otherwise, if category does not exist the non-conflict name will be returned.
	 * 
	 * @param cat the existing category to check.
	 * @param dt datatype who name is used to establish non-conflict base name
	 * @return the unused conflict name
	 */
	private String getUnusedConflictName(Category cat, DataType dt) {
		if ((dt instanceof Array) || (dt instanceof Pointer) || (dt instanceof BuiltInDataType)) {
			// name not used - anything will do
			return dt.getName();
		}
		String baseName = DataTypeUtilities.getNameWithoutConflict(dt);
		if (cat == null) {
			return baseName;
		}
		String testName = baseName;
		int count = 0;
		while (cat.getDataType(testName) != null) {
			testName = baseName + DataType.CONFLICT_SUFFIX;
			if (count > 0) {
				testName += Integer.toString(count);
			}
			++count;
		}
		return testName;
	}

	private List<DataType> findDataTypesSameLocation(DataType dataType) {

		Category category = getCategory(dataType.getCategoryPath());
		if (category == null) {
			return List.of();
		}

		if (!(dataType instanceof Pointer) && !(dataType instanceof Array)) {
			return category.getDataTypesByBaseName(dataType.getName());
		}

		DataType existingDataType = category.getDataType(dataType.getName());

		DataType baseDataType = DataTypeUtilities.getBaseDataType(dataType);
		if (baseDataType == null) {
			return existingDataType != null ? List.of(existingDataType) : List.of();
		}

		SourceArchive sourceArchive = baseDataType.getSourceArchive();
		if (sourceArchive != null && sourceArchive.getArchiveType() == ArchiveType.BUILT_IN) {
			return existingDataType != null ? List.of(existingDataType) : List.of();
		}

		String baseTypeName = baseDataType.getName();
		String decorations = dataType.getName().substring(baseTypeName.length());

		List<DataType> list = new ArrayList<>();
		for (DataType existingBaseDt : category.getDataTypesByBaseName(baseTypeName)) {
			String name = existingBaseDt.getName() + decorations;
			DataType dt = category.getDataType(name);
			if (dt != null) {
				list.add(dt);
			}
		}
		return list;
	}

	/**
	 * Finds an datatype in this manager that is equivalent and has the same
	 * categoryPath and has either the same name or a conflict variation of that
	 * name.
	 * 
	 * @param dataType the dataType for which to find an equivalent existing dataType
	 */
	private DataType findEquivalentDataTypeSameLocation(DataType dataType) {

		// Check exact name match
		DataType existingDataType = getDataType(dataType.getCategoryPath(), dataType.getName());

		// If the existing Data type is currently being resolved, its isEquivalent
		// method is short circuited such that it will return true. So it is important 
		// to call the isEquivalent on the existing datatype and not the dataType.
		if (existingDataType != null &&
			DataTypeDB.isEquivalent(existingDataType, dataType, currentHandler)) {
			return existingDataType;
		}

		List<DataType> relatedByName = findDataTypesSameLocation(dataType);
		for (DataType candidate : relatedByName) {
			if (candidate != existingDataType &&
				DataTypeDB.isEquivalent(candidate, dataType, currentHandler)) {
				return candidate;
			}
		}
		return null;
	}

	private DataType findDataTypeSameLocation(DataType dataType) {

		// Check exact name match which is similar
		DataType existingDataType = getDataType(dataType.getCategoryPath(), dataType.getName());
		if (existingDataType != null &&
			DataTypeUtilities.isSameKindDataType(dataType, existingDataType)) {
			return existingDataType;
		}

		// check all conflict types
		List<DataType> relatedByName = findDataTypesSameLocation(dataType);
		for (DataType candidate : relatedByName) {
			if (existingDataType == null) {
				existingDataType = candidate;
			}
			if (DataTypeUtilities.isSameKindDataType(dataType, candidate)) {
				return candidate;
			}
		}

		return existingDataType;
	}

	/**
	 * Either finds an equivalent dataType with the same categoryPath and name (or
	 * conflict name) to the given dataType. Otherwise, it creates a new dataType in
	 * this archive equivalent to the given dataType. If a dataType exists with same
	 * path and name but is not equivalent, the handler will resolve the problem in
	 * one of 3 ways. 1) A new dataType will be created, but with a .conflict name
	 * 2) The existing dataType will be replaced by a resolved copy of the given
	 * dataType. 3) The existing dataType will be returned instead of a resolved
	 * version of the given dataType.
	 * 
	 * @param dataType the dataType for which to return an equivalent dataType in
	 *                 this manager
	 * @return resolved datatype
	 */
	private DataType resolveDataTypeNoSource(DataType dataType) {

		DataType existingDataType = findEquivalentDataTypeSameLocation(dataType);
		if (existingDataType != null) {
			return existingDataType;
		}

		return resolveNoEquivalentFound(dataType, null);
	}

	/**
	 * Perform datatype resolution for types originating from a source archive (excludes
	 * programs and built-in datatypes).
	 * 
	 * @param dataType the dataType for which to return an equivalent dataType in
	 *                 this manager
	 * @return resolved datatype
	 */
	private DataType resolveDataTypeWithSource(DataType dataType) {

		SourceArchive sourceArchive = dataType.getSourceArchive();

		// Do we have that dataType already resolved and associated with the source archive?
		DataType existingDataType = getDataType(sourceArchive, dataType.getUniversalID());
		if (existingDataType != null) {
			if (!DataTypeDB.isEquivalent(existingDataType, dataType, currentHandler) &&
				currentHandler.shouldUpdate(dataType, existingDataType)) {
				existingDataType.replaceWith(dataType);
				existingDataType.setLastChangeTime(dataType.getLastChangeTime());
			}
			return existingDataType;
		}

		if (sourceArchive.getSourceArchiveID().equals(getUniversalID())) {
			// Avoid conflict handling for types with a source which matches
			// this archive, although a conflict name may still be used.  
			// This can occur when a semi-mirrored archive instance is used
			// such as the CompositeViewerDataTypeManager or Program Merge 
			// which uses the same Archive UniversalID.
			return createConflictDataType(dataType, sourceArchive);
		}

		// If we have the same path name and the existing data type is a local data type
		// and is equivalent to this one, then associate it with the source archive
		existingDataType = findEquivalentDataTypeSameLocation(dataType);
		if (existingDataType != null) {
			if (isLocalSource(existingDataType)) {
				// If we have an equivalent local data type associate it with the source archive
				replaceEquivalentLocalWithSourceDataType(dataType, sourceArchive, existingDataType);
			}
			return existingDataType;
		}

		return resolveNoEquivalentFound(dataType, sourceArchive);
	}

	/**
	 * Complete datatype resolution after having attempted to find an existing equivalent type. 
	 * An attempt is made to identify a conflicting datatype and determine a conflict resolution
	 * using the specified conflict handler.
	 * @param dataType datatype being resolved
	 * @param sourceArchive source archive associated with new type (may be null)
	 * @return resolved datatype (may be existing or newly added datatype)
	 */
	private DataType resolveNoEquivalentFound(DataType dataType, SourceArchive sourceArchive) {

		if (sourceArchive != null && sourceArchive.getArchiveType() == ArchiveType.PROGRAM) {
			sourceArchive = null; // do not preserve program as a source archive
		}

		// If not found, do we have the same named data type in the same category already?
		// (preference is given to similar kind of datatype when checking existing conflict types)
		DataType existingDataType = findDataTypeSameLocation(dataType);
		if (existingDataType == null) {
			// create non-existing datatype - keep original name unless it is already used
			String name = dataType.getName();
			if (getDataType(dataType.getCategoryPath(), name) != null) {
				name = getUnusedConflictName(dataType);
			}
			return createDataType(dataType, name, sourceArchive, currentHandler);
		}

		// So we have a dataType with the same path and name, but not equivalent, so use
		// the conflictHandler to decide what to do.
		ConflictResult conflictResult = currentHandler.resolveConflict(dataType, existingDataType);
		switch (conflictResult) {

			case REPLACE_EXISTING: // new type replaces old conflicted type
				try {
					if (updateExistingDataType(existingDataType, dataType, sourceArchive)) {
						return existingDataType;
					}
					renameToUnusedConflictName(existingDataType);
					DataType newDataType =
						createDataType(dataType, dataType.getName(), sourceArchive, currentHandler);
					try {
						replace(existingDataType, newDataType);
					}
					catch (DataTypeDependencyException e) {
						throw new IllegalArgumentException(
							"Invalid datatype replacement: " + newDataType.getName(), e);
					}
					return newDataType;
				}
				catch (DataTypeDependencyException e) {
					// new type refers to old type - fallthrough to RENAME_AND_ADD
					// TODO: alternatively we could throw an exception
				}

			case RENAME_AND_ADD: // default handler behavior
				return createConflictDataType(dataType, sourceArchive);

			default:  // USE_EXISTING - new type is discarded and old conflicted type is returned
				return existingDataType;
		}
	}

	private DataType createConflictDataType(DataType dataType, SourceArchive sourceArchive) {
		String dtName = getUnusedConflictName(dataType);
		DataType newDataType = createDataType(dataType, dtName, sourceArchive, currentHandler);

		// NOTE: queue conflict datatype for delayed check for equivalent type.
		// This is not needed for Pointer or Array which will update if/when
		// referenced type gets replaced.
		if (!(newDataType instanceof Pointer) && !(newDataType instanceof Array)) {
			conflictQueue.add(newDataType);
		}
		return newDataType;
	}

	private void replaceEquivalentLocalWithSourceDataType(DataType dataType,
			SourceArchive sourceArchive, DataType existingDataType) {
		// Since it's equivalent, set its source, ID, and replace its components.
		// TODO: Need a better way to do this.
		existingDataType.setSourceArchive(sourceArchive);
		((DataTypeDB) existingDataType).setUniversalID(dataType.getUniversalID());
		existingDataType.replaceWith(dataType);
		long lastChangeTime = dataType.getLastChangeTime();
		existingDataType.setLastChangeTime(lastChangeTime);
		existingDataType.setLastChangeTimeInSourceArchive(lastChangeTime);
		dataTypeChanged(existingDataType, false);
	}

	private boolean isLocalSource(DataType dataType) {
		SourceArchive sourceArchive = dataType.getSourceArchive();
		return (sourceArchive.equals(getLocalSourceArchive()));
	}

	@Override
	public DataType addDataType(DataType originalDataType, DataTypeConflictHandler handler) {
		return resolve(originalDataType, handler);
	}

	@Override
	public void addDataTypes(Collection<DataType> dataTypes, DataTypeConflictHandler handler,
			TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		boolean isEquivalenceCacheOwner = activateEquivalenceCache();
		boolean isResolveCacheOwner = activateResolveCache();
		// TODO: extended hold time on lock may cause the GUI to become
		// unresponsive.  Consider releasing lock between resolves, although
		// this exposes risk of having active resolve queue/cache without lock
		try {
			monitor.setMessage("Adding datatypes...");
			monitor.setMaximum(dataTypes.size());
			monitor.setProgress(0);
			int i = 0;
			for (DataType dt : dataTypes) {
				monitor.checkCancelled();
				resolve(dt, handler);
				if (isResolveCacheOwner) {
					processResolveQueue(false);
				}
				monitor.setProgress(++i);
			}
		}
		finally {
			if (isResolveCacheOwner) {
				processResolveQueue(true);
			}
			if (isEquivalenceCacheOwner) {
				clearEquivalenceCache();
			}
			lock.release();
		}

	}

	@Override
	public SourceArchive resolveSourceArchive(SourceArchive sourceArchive) {
		if (sourceArchive == null) {
			return null;
		}
		lock.acquire();
		try {
			SourceArchive existingArchive = getSourceArchive(sourceArchive.getSourceArchiveID());
			if (existingArchive != null) {
				return existingArchive;  // already have it
			}
			DBRecord record = sourceArchiveAdapter.createRecord(sourceArchive);
			SourceArchive newSourceArchive = getSourceArchiveDB(record);
			invalidateSourceArchiveCache();
			sourceArchiveAdded(newSourceArchive.getSourceArchiveID());
			return newSourceArchive;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public void removeSourceArchive(SourceArchive sourceArchive) {
		lock.acquire();
		try {
			UniversalID sourceArchiveID = sourceArchive.getSourceArchiveID();
			if (sourceArchiveID.equals(universalID) ||
				sourceArchiveID.equals(LOCAL_ARCHIVE_UNIVERSAL_ID)) {
				// can't delete the local archive
				throw new IllegalArgumentException("Attempted to delete the local archive!");
			}
			disassociateAllDataTypes(sourceArchiveID);
			sourceArchiveAdapter.deleteRecord(sourceArchiveID);
			sourceArchiveChanged(sourceArchiveID); // must occur before invalidateSourceArchiveCache 
			invalidateSourceArchiveCache();
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private void disassociateAllDataTypes(UniversalID sourceArchiveID) {
		List<DataType> dataTypes = new ArrayList<>();
		getAllDataTypes(dataTypes);
		for (DataType dataType : dataTypes) {
			SourceArchive sourceArchive = dataType.getSourceArchive();
			if (sourceArchive != null &&
				sourceArchive.getSourceArchiveID().equals(sourceArchiveID)) {
				disassociate(dataType);
			}
		}
	}

	@Override
	public DataType replaceDataType(DataType existingDt, DataType replacementDt,
			boolean updateCategoryPath) throws DataTypeDependencyException {
		// TODO: we should probably disallow replacementDt to be an instanceof
		// Dynamic or FactoryDataType
		lock.acquire();
		try {
			// Don't support replacement with Factory or Dynamic datatype
			if (replacementDt instanceof Dynamic || replacementDt instanceof FactoryDataType) {
				throw new IllegalArgumentException(
					"Datatype replacment with dynamic or factory type not permitted.");
			}
			if (getID(existingDt) < 0) {
				throw new IllegalArgumentException(
					"Datatype to replace is not contained in this datatype manager.");
			}
			boolean fixupName = false;
			if (!contains(replacementDt)) {
				replacementDt = replacementDt.clone(this);
				try {
					replacementDt.setCategoryPath(existingDt.getCategoryPath());
				}
				catch (DuplicateNameException e) {
					throw new AssertException();
				}

				if (replacementDt.getName().equals(existingDt.getName())) {
					// will get a .conflict when we do the resolve
					fixupName = true;
				}
				replacementDt = resolve(replacementDt, null);
			}

			if (existingDt == replacementDt) {
				// replacement was exact match
				return existingDt;
			}

			replace(existingDt, replacementDt);

			if (fixupName) {
				try {
					long lastChangeTime = replacementDt.getLastChangeTime();
					replacementDt.setName(existingDt.getName());
					replacementDt.setLastChangeTime(lastChangeTime);
				}
				catch (Exception e) {
					Msg.error(this, "Unable to set the name to " + existingDt.getName() + "on " +
						replacementDt + " while replacing the original datatype", e);
				}
			}
			CategoryPath path = existingDt.getCategoryPath();

			if (updateCategoryPath && !replacementDt.getCategoryPath().equals(path)) {
				try {
					replacementDt.setCategoryPath(path);
				}
				catch (Exception e) {
					// not sure what to do here
					Msg.error(this, "Unable to set the CatagoryPath to " + path + "on " +
						replacementDt + " while replacing the original datatype", e);
				}
			}
			return replacementDt;
		}
		finally {
			lock.release();
		}
	}

	private void replace(DataType existingDt, DataType replacementDt)
			throws DataTypeDependencyException {

		if (!contains(existingDt)) {
			return;
		}

		if (replacementDt.dependsOn(existingDt)) {
			throw new DataTypeDependencyException("Replace failed: " +
				replacementDt.getDisplayName() + " depends on " + existingDt.getDisplayName());
		}

		addDataTypeToReplace(existingDt, replacementDt);
		replaceQueuedDataTypes();
	}

	private void replaceQueuedDataTypes() {

		// Collect all datatypes to be replaced and notify children which may also get queued
		// for removal.
		Map<Long, Long> dataTypeReplacementMap = new HashMap<>();
		List<Pair<DataType, DataType>> dataTypeReplacements = new LinkedList<>();
		while (!typesToReplace.isEmpty()) {
			Pair<DataType, DataType> dataTypeReplacement = typesToReplace.removeFirst();
			DataType replacedDt = dataTypeReplacement.first;
			DataType replacementDt = dataTypeReplacement.second;

			long replacedId = getID(replacedDt);
			if (replacedId <= 0) {
				Msg.error(this, "Unexpected ID for replaced datatype (" + replacedId + "): " +
					replacedDt.getPathName());
				continue; // ignore attempt to replace special type
			}
			long replacementId = getID(dataTypeReplacement.second);
			if (replacementId < 0) {
				Msg.error(this, "Unexpected ID for replacement datatype (" + replacementId + "): " +
					replacementDt.getPathName());
			}

			replaceUsesInOtherDataTypes(replacedDt, replacementDt);

			dataTypeReplacements.add(dataTypeReplacement);
			dataTypeReplacementMap.put(replacedId, replacementId);
		}

		// perform any neccessary external use replacements
		replaceDataTypesUsed(dataTypeReplacementMap);

		// perform actual database updates (e.g., record updates, change notifications, etc.)
		for (Pair<DataType, DataType> dataTypeReplacement : dataTypeReplacements) {
			replaceDataType(dataTypeReplacement.first, dataTypeReplacement.second);
		}
	}

	/**
	 * Allow extensions to perform any neccessary fixups to address all datatype replacements.
	 * @param dataTypeReplacementMap map of datatype replacements (oldID maps to replacementID).
	 */
	abstract protected void replaceDataTypesUsed(Map<Long, Long> dataTypeReplacementMap);

	private void replaceDataType(DataType replacedDt, DataType replacementDt) {

		DataTypePath replacedDtPath = replacedDt.getDataTypePath();
		long replacedId = getID(replacedDt);

		UniversalID id = replacedDt.getUniversalID();
		idsToDataTypeMap.removeDataType(replacedDt.getSourceArchive(), id);

		try {
			parentChildAdapter.removeAllRecordsForParent(replacedId);
		}
		catch (IOException e) {
			dbError(e);
		}
		deleteDataTypeRecord(replacedId);
		dtCache.delete(replacedId);

		dataTypeReplaced(replacedId, replacedDtPath, replacementDt);
	}

	private void replaceUsesInOtherDataTypes(DataType existingDt, DataType newDt) {
		if (existingDt instanceof DataTypeDB) {
			// Notify parents that a dependency has been replaced.  For pointers and arrays
			// it may require their subsequent category change or removal to avoid duplication.
			for (DataType dt : existingDt.getParents()) {
				dt.dataTypeReplaced(existingDt, newDt);
			}
		}
		else {
			// Since we do not track parents of non-DB types we must assume that all data types
			// must be modified.  Use of the sortedDataTypes list is the simplest way to do this. 
			// A copy of the list must be used since it will changed if other types get removed
			// in the process.
			buildSortedDataTypeList();
			List<DataType> sortedDataTypesCopy = new ArrayList<>(sortedDataTypes);
			for (DataType dt : sortedDataTypesCopy) {
				dt.dataTypeReplaced(existingDt, newDt);
			}
		}
	}

	/**
	 * Replace one source archive (oldDTM) with another (newDTM). Any data types
	 * whose source was the oldDTM will be changed to have a source that is the
	 * newDTM. The oldDTM will no longer be referenced as a source by this data type
	 * manager.
	 * 
	 * @param oldSourceArchive data type manager for the old source archive
	 * @param newSourceArchive data type manager for the new source archive
	 * @throws IllegalArgumentException if the oldDTM isn't currently a source
	 *                                  archive for this data type manager or if the
	 *                                  old and new source archives already have the
	 *                                  same unique ID.
	 */
	public void replaceSourceArchive(SourceArchive oldSourceArchive,
			SourceArchive newSourceArchive) {
		UniversalID oldSourceArchiveID = oldSourceArchive.getSourceArchiveID();
		UniversalID newSourceArchiveID = newSourceArchive.getSourceArchiveID();
		if (oldSourceArchiveID.equals(newSourceArchiveID)) {
			throw new IllegalArgumentException(
				"Cannot replace source archive \"" + oldSourceArchive.getName() + "\" with \"" +
					newSourceArchive.getName() + "\" in data type archive \"" + getName() +
					"\" since they have the same ID (" + oldSourceArchiveID.getValue() + ").");
		}
		if (getSourceArchive(oldSourceArchiveID) == null) {
			throw new IllegalArgumentException("The source archive \"" +
				oldSourceArchive.getName() + "\" with ID (" + oldSourceArchiveID.getValue() +
				") isn't used in data type archive \"" + getName() + "\".");
		}

		// Add new Source Archive
		resolveSourceArchive(newSourceArchive);

		// Change all data type's with old source archive ID to now have new Source Archive
		Iterator<DataType> allDataTypes = getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dt = allDataTypes.next();
			SourceArchive sourceArchive = dt.getSourceArchive();
			if (sourceArchive != null &&
				oldSourceArchiveID.equals(sourceArchive.getSourceArchiveID())) {
				dt.setSourceArchive(newSourceArchive);
			}
		}

		// Remove old Source Archive
		removeSourceArchive(oldSourceArchive);

		// Want to indicate we are out of sync.
		SourceArchive sourceArchive = getSourceArchive(newSourceArchiveID);
		sourceArchive.setLastSyncTime(0);
	}

	@Override
	public void findDataTypes(String name, List<DataType> list) {
		if (name == null || name.length() == 0) {
			return;
		}
		if (name.equals(DataType.DEFAULT.getName())) {
			list.add(DataType.DEFAULT);
			return;
		}
		// ignore .conflict in both name and result matches
		lock.acquire();
		try {
			buildSortedDataTypeList();
			// Use exemplar datatype in root category without .conflict to position at start
			// of possible matches
			name = DataTypeUtilities.getNameWithoutConflict(name);
			DataType compareDataType =
				new TypedefDataType(CategoryPath.ROOT, name, DataType.DEFAULT, this);
			int index = Collections.binarySearch(sortedDataTypes, compareDataType, nameComparator);
			if (index < 0) {
				index = -index - 1;
			}
			// add all matches to list
			while (index < sortedDataTypes.size()) {
				DataType dt = sortedDataTypes.get(index);
				if (!name.equals(DataTypeUtilities.getNameWithoutConflict(dt, false))) {
					break;
				}
				list.add(dt);
				++index;
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void findDataTypes(String name, List<DataType> list, boolean caseSensitive,
			TaskMonitor monitor) {
		if (name == null || name.length() == 0) {
			return;
		}
		if (name.equals(DataType.DEFAULT.getName())) {
			list.add(DataType.DEFAULT);
			return;
		}
		if (monitor == null) {
			monitor = TaskMonitor.DUMMY;
		}
		Pattern regexp = UserSearchUtils.createSearchPattern(name, caseSensitive);
		lock.acquire();
		try {
			buildSortedDataTypeList();
			for (DataType dt : sortedDataTypes) {
				if (monitor.isCancelled()) {
					return;
				}
				Matcher matcher = regexp.matcher(dt.getName());
				if (matcher.matches()) {
					list.add(dt);
				}
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType getDataType(DataTypePath dataTypePath) {
		Category cat = getCategory(dataTypePath.getCategoryPath());
		if (cat != null) {
			return cat.getDataType(dataTypePath.getDataTypeName());
		}
		return null;

	}

	@Override
	public DataType getDataType(String dataTypePath) {
		// Category path now has sourceID followed by ":" followed by path under that source.
		String name = getName();
		int nameLen = name.length();
		if (dataTypePath.length() > nameLen && dataTypePath.charAt(nameLen) == '/' &&
			dataTypePath.startsWith(name)) {
			dataTypePath = dataTypePath.substring(nameLen);
		}
		else if (!dataTypePath.startsWith("/")) {
			return null;
		}

		// Use a category path to parse the datatype path because it knows how to deal with
		// escaped forward slashes.
		CategoryPath parsedPath = new CategoryPath(dataTypePath);
		CategoryPath categoryPath = parsedPath.getParent();
		String dataTypeName = parsedPath.getName();
		Category category = getCategory(categoryPath);

		if (category == null) {
			return null;
		}
		return category.getDataType(dataTypeName);
	}

	@Override
	public DataType findDataType(String dataTypePath) {
		return getDataType(dataTypePath);
	}

	@Override
	public void findEnumValueNames(long value, Set<String> enumValueNames) {
		buildEnumValueMap();
		Set<String> names = enumValueMap.get(value);
		if (names != null) {
			enumValueNames.addAll(names);
		}
	}

	@Override
	public long getResolvedID(DataType dt) {
		if (dt == null) {
			return NULL_DATATYPE_ID;
		}
		if (dt == DataType.DEFAULT) {
			return DEFAULT_DATATYPE_ID;
		}
		if (dt instanceof BadDataType) {
			return BAD_DATATYPE_ID;
		}
		dt = resolve(dt, currentHandler);
		return getID(dt);
	}

	/**
	 * Get the datatype conflict handler to be used when resolving
	 * datatype dependencies
	 * 
	 * @return dependency datatype conflict handler
	 */
	DataTypeConflictHandler getDependencyConflictHandler() {
		if (currentHandler == null) {
			return DataTypeConflictHandler.DEFAULT_HANDLER;
		}
		return currentHandler.getSubsequentHandler();
	}

	@Override
	public long getID(DataType dt) {
		if (dt == null) {
			return NULL_DATATYPE_ID;
		}
		if (dt == DataType.DEFAULT) {
			return DEFAULT_DATATYPE_ID;
		}
		if (dt instanceof BadDataType) {
			return BAD_DATATYPE_ID;
		}
		if (dt instanceof BitFieldDataType) {
			return createKey(BITFIELD, BitFieldDBDataType.getId((BitFieldDataType) dt));
		}
		if (dt instanceof DataTypeDB) {
			// NOTE: Implementation DOES NOT check or guarantee that datatype or its returned ID 
			// correspond to this datatype manager instance. This seems incorrect although it's 
			// possible that uses depend on this behavior.
			DataTypeDB dtDb = (DataTypeDB) dt;
			if (dtDb.isDeleted()) {
				return BAD_DATATYPE_ID;
			}
			return dtDb.getKey();
		}

		Long l = builtIn2IdMap.get(dt);
		if (l == null) {
			return NULL_DATATYPE_ID;
		}
		return l.longValue();
	}

	@Override
	public DataType getDataType(long dataTypeID) {
		if (dataTypeID == NULL_DATATYPE_ID) {
			return null;
		}
		if (dataTypeID == DEFAULT_DATATYPE_ID) {
			return DataType.DEFAULT;
		}
		if (dataTypeID == BAD_DATATYPE_ID) {
			return BadDataType.dataType;
		}
		return getDataType(dataTypeID, null);
	}

	@Override
	public void addInvalidatedListener(InvalidatedListener listener) {
		invalidatedListeners.add(listener);
	}

	@Override
	public void removeInvalidatedListener(InvalidatedListener listener) {
		invalidatedListeners.remove(listener);
	}

	private void fireInvalidated() {
		for (InvalidatedListener listener : invalidatedListeners) {
			listener.dataTypeManagerInvalidated(this);
		}
	}

	/**
	 * Remove the given datatype from this manager (assumes the lock has already been acquired).
	 * 
	 * @param dataType the dataType to be removed
	 * @return true if datatype removal was successful, else false
	 */
	private boolean removeInternal(DataType dataType) {
		if (!contains(dataType)) {
			return false;
		}

		long id = getID(dataType);
		if (id <= 0) { // removal of certain special types not permitted
			return false;
		}
		idsToDelete.add(id);
		removeQueuedDataTypes();
		return true;
	}

	private void removeQueuedDataTypes() {

		// collect all datatype to be removed and notify children which may also get queued
		// for removal.
		Set<Long> deletedIds = new HashSet<>();
		while (!idsToDelete.isEmpty()) {
			long id = idsToDelete.removeFirst();
			removeUseOfDataType(id);
			deletedIds.add(id);
		}

		// perform any neccessary external use removals
		deleteDataTypesUsed(deletedIds);

		// perform actual database updates (e.g., record removal, change notifications, etc.)
		for (long id : deletedIds) {
			deleteDataType(id);
		}
	}

	/**
	 * Allow extensions to perform any neccessary fixups for all datatype removals listed.
	 * @param deletedIds list of IDs for all datatypes which are getting removed.
	 */
	protected abstract void deleteDataTypesUsed(Set<Long> deletedIds);

	private void removeUseOfDataType(long id) {

		if (isBulkRemoving) {
			throw new IllegalStateException(
				"Cannot remove data types with a bulk remove operation in place");
		}

		isBulkRemoving = true;
		try {
			notifyDeleted(id);
		}
		finally {
			isBulkRemoving = false;
		}

		removeAllParentChildRecordsForChild(id);
	}

	@Override
	public boolean remove(DataType dataType, TaskMonitor monitor) {
		lock.acquire();
		try {
			if (contains(dataType)) {
				return removeInternal(dataType);
			}
		}
		finally {
			lock.release();
		}
		return false;
	}

	@Override
	public void associateDataTypeWithArchive(DataType datatype, SourceArchive archive) {
		if (!contains(datatype)) {
			throw new IllegalArgumentException(
				"The given datatype must exist in this DataTypeManager");
		}
		SourceArchive currentSource = datatype.getSourceArchive();
		if (!currentSource.equals(getLocalSourceArchive()) && !currentSource.equals(archive)) {
			return;
		}
		resolveSourceArchive(archive);
		Collection<DataType> datatypes = DataTypeUtilities.getContainedDataTypes(datatype);
		datatypes = filterOutNonSourceSettableDataTypes(datatypes);
		for (DataType dt : datatypes) {
			dt.setSourceArchive(archive);
			long timeNow = System.currentTimeMillis();
			dt.setLastChangeTime(timeNow);
			dt.setLastChangeTimeInSourceArchive(timeNow);
		}

	}

	@Override
	public void disassociate(DataType dataType) {

		lock.acquire();
		try {
			UniversalID oldDtID = dataType.getUniversalID();
			SourceArchive sourceArchive = dataType.getSourceArchive();
			sourceArchive = resolveSourceArchive(sourceArchive);
			UniversalID id = sourceArchive == null ? DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID
					: sourceArchive.getSourceArchiveID();
			if (id.equals(getUniversalID())) {
				id = DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID;
			}
			if (id == DataTypeManager.LOCAL_ARCHIVE_UNIVERSAL_ID) {
				// Already local data type so no source archive associated.
				return;
			}

			// Set the source archive to null indicating no associated archive.
			dataType.setSourceArchive(null);

			// Set the datatype's universal ID to a newly generated universal ID,
			// since we no longer want the source archive data type's universal ID.
			if (dataType instanceof DataTypeDB dt) {
				dt.setUniversalID(UniversalIdGenerator.nextID());
			}

			if (oldDtID != null) {
				idsToDataTypeMap.removeDataType(sourceArchive, oldDtID);
			}

			dataTypeChanged(dataType, false);
		}
		finally {
			lock.release();
		}
	}

	private Collection<DataType> filterOutNonSourceSettableDataTypes(
			Collection<DataType> datatypes) {

		List<DataType> filteredList = new ArrayList<>();
		for (DataType dataType : datatypes) {
			if (isSourceSettable(dataType)) {
				filteredList.add(dataType);
			}
		}
		return filteredList;
	}

	private boolean isSourceSettable(DataType dataType) {
		if (!(dataType instanceof DataTypeDB)) {
			return false;
		}
		SourceArchive sourceArchive = dataType.getSourceArchive();
		DataTypeManager dtm = dataType.getDataTypeManager();
		if (sourceArchive == null || dtm == null) {
			return false;
		}
		return (sourceArchive.equals(dtm.getLocalSourceArchive()));
	}

	/**
	 * Queue a datatype to deleted in response to another datatype being deleted.
	 * @param id datatype ID to be removed
	 */
	protected void addDataTypeToDelete(long id) {
		idsToDelete.add(Long.valueOf(id));
	}

	/**
	 * Queue a datatype to be replaced by another datatype in response to its referenced 
	 * datatype being replaced.
	 * @param oldDataType datatype to be replaced
	 * @param replacementDataType datatype which is the replacement
	 */
	protected void addDataTypeToReplace(DataType oldDataType, DataType replacementDataType) {
		Objects.requireNonNull(oldDataType);
		Objects.requireNonNull(replacementDataType);
		if (oldDataType == replacementDataType) {
			throw new AssertionError("Invalid datatype replacement pair");
		}
		typesToReplace.add(new Pair<>(oldDataType, replacementDataType));
	}

	private void notifyDeleted(long dataTypeID) {
		DataType dataType = getDataType(dataTypeID);
		if (dataType == null) {
			return;
		}
		if (dataType instanceof DataTypeDB dt) {
			// Notify datatype that it has been deleted which in-turn will notify all of its
			// parents.  Parent datatype which are no longer valid (i.e., pointers, arrays)
			// may invoke addDataTypeToDelete method to schedule their subsequent removal.
			dt.notifyDeleted();
		}
		else {
			// Since we do not track parents of non-DB types we must assume that all data types
			// must be modified.  Use of the sortedDataTypes list is the simplest way to do this. 
			// A copy of the list must be used since it will changed if other types get removed
			// in the process.
			buildSortedDataTypeList();
			List<DataType> sortedDataTypesCopy = new ArrayList<>(sortedDataTypes);
			for (DataType dt : sortedDataTypesCopy) {
				dt.dataTypeDeleted(dataType);
			}
		}

	}

	private void deleteDataType(long dataTypeID) {

		DataType dataType = getDataType(dataTypeID);
		if (dataType == null) {
			return;
		}
		UniversalID id = dataType.getUniversalID();
		if (id != null) {
			idsToDataTypeMap.removeDataType(dataType.getSourceArchive(), id);
		}

		deleteDataTypeRecord(dataTypeID);
		try {
			parentChildAdapter.removeAllRecordsForParent(dataTypeID);
		}
		catch (IOException e) {
			dbError(e);
		}
		dtCache.delete(dataTypeID);
		favoritesList.remove(dataType);
		// DT Should delete data type update the sync time or last change time?
//		updateLastSyncTime((new Date()).getTime()); // Update my Last Sync Time in the Archive ID table.
		DataTypePath deletedDtPath = dataType.getDataTypePath();
		dataTypeDeleted(dataTypeID, deletedDtPath);
	}

	private void deleteDataTypeRecord(long dataTypeID) {
		int tableID = getTableID(dataTypeID);

		try {
			DataType dt = null;
			switch (tableID) {
				case BUILT_IN:
					boolean status = builtinAdapter.removeRecord(dataTypeID);
					if (status) {
						dt = builtInMap.remove(dataTypeID);
						builtIn2IdMap.remove(dt);
					}
					break;
				case COMPOSITE:
					removeComponents(dataTypeID);
					status = compositeAdapter.removeRecord(dataTypeID);
					break;
				case COMPONENT:
					status = componentAdapter.removeRecord(dataTypeID);
					break;
				case TYPEDEF:
					status = typedefAdapter.removeRecord(dataTypeID);
					break;
				case ARRAY:
					status = arrayAdapter.removeRecord(dataTypeID);
					break;
				case POINTER:
					status = pointerAdapter.removeRecord(dataTypeID);
					break;
				case FUNCTION_DEF:
					removeParameters(dataTypeID);
					status = functionDefAdapter.removeRecord(dataTypeID);
					break;
				case PARAMETER:
					status = paramAdapter.removeRecord(dataTypeID);
					break;
				case ENUM:
					status = enumAdapter.removeRecord(dataTypeID);
					break;
			}
			settingsAdapter.removeAllSettingsRecords(dataTypeID);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
	}

	/**
	 * Remove all function signature parameters from the data base that have the
	 * indicated parent.
	 * 
	 * @param parentID the parentData type's ID
	 */
	private void removeParameters(long parentID) throws IOException {
		Field[] paramIDs = paramAdapter.getParameterIdsInFunctionDef(parentID);
		for (Field paramID : paramIDs) {
			deleteDataTypeRecord(paramID.getLongValue());
		}
	}

	/**
	 * Remove all components from the data base that have the indicated parent.
	 * 
	 * @param parentID the parentData type's ID
	 */
	private void removeComponents(long parentID) throws IOException {
		Field[] componentIDs = componentAdapter.getComponentIdsInComposite(parentID);
		for (Field componentID : componentIDs) {
			deleteDataTypeRecord(componentID.getLongValue());
		}
	}

	@Override
	public boolean contains(DataType dataType) {
		if (dataType == null) {
			return false;
		}
		if (dataType.getDataTypeManager() != this) {
			return false;
		}
		// otherwise, it probably belongs to this dataTypeManager, but it could a
		// leftover after an undo. So make sure it really is there.
		if (dataType instanceof DataTypeDB dtDb) {
			return dtCache.get(dtDb.getKey()) == dataType && !dtDb.isDeleted();
		}
		return builtIn2IdMap.containsKey(dataType);
	}

	@Override
	public boolean containsCategory(CategoryPath path) {
		return getCategory(path) != null;
	}

	@Override
	public Category createCategory(CategoryPath path) {
		lock.acquire();
		try {
			Category cat = getCategory(path);
			if (cat != null) {
				return cat;
			}

			CategoryPath parentPath = path.getParent();
			Category parentCat = getCategory(parentPath);
			if (parentCat == null) {
				parentCat = createCategory(parentPath);
			}
			return parentCat.createCategory(path.getName());
		}
		catch (InvalidNameException e) {
			// since the name was already validated by the CategoryPath object, should not
			// get exception here
			throw new AssertException("Got invalid name exception here, but should be impossible.");
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Category getRootCategory() {
		return root;
	}

	/**
	 * Gets the datatypes in the given category path
	 * 
	 * @param path the category path in which to look for datatypes
	 * @return array of datatypes contained with specified category
	 */
	public DataType[] getDataTypes(CategoryPath path) {
		Category cat = getCategory(path);
		if (cat != null) {
			return cat.getDataTypes();
		}
		return new DataType[0];
	}

	@Override
	public DataType getDataType(CategoryPath path, String name) {
		if (CategoryPath.ROOT.equals(path) && name.equals(DataType.DEFAULT.getName())) {
			return DataType.DEFAULT;
		}
		Category category = getCategory(path);
		if (category != null) {
			return category.getDataType(name);
		}
		return null;
	}

	List<DataType> getDataTypesInCategory(long categoryID) {
		lock.acquire();
		ArrayList<DataType> list = new ArrayList<>();
		try {
			Field[] ids = builtinAdapter.getRecordIdsInCategory(categoryID);
			getDataTypes(ids, list);

			ids = typedefAdapter.getRecordIdsInCategory(categoryID);
			getDataTypes(ids, list);

			ids = compositeAdapter.getRecordIdsInCategory(categoryID);
			getDataTypes(ids, list);

			ids = functionDefAdapter.getRecordIdsInCategory(categoryID);
			getDataTypes(ids, list);

			ids = enumAdapter.getRecordIdsInCategory(categoryID);
			getDataTypes(ids, list);

			ids = pointerAdapter.getRecordIdsInCategory(categoryID);
			getDataTypes(ids, list);

			ids = arrayAdapter.getRecordIdsInCategory(categoryID);
			getDataTypes(ids, list);

		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return list;
	}

	@Override
	public int getCategoryCount() {
		return categoryAdapter.getRecordCount() + 1;
	}

	@Override
	public int getDataTypeCount(boolean includePointersAndArrays) {
		lock.acquire();
		try {
			buildSortedDataTypeList();
			int count = sortedDataTypes.size();
			if (includePointersAndArrays) {
				return count;
			}
			for (DataType dt : sortedDataTypes) {
				if ((dt instanceof Pointer) || (dt instanceof Array)) {
					--count;
				}
			}
			return count;
		}
		finally {
			lock.release();
		}
	}

	private void getDataTypes(Field[] ids, ArrayList<DataType> list) {
		for (Field id : ids) {
			DataType dt = getDataType(id.getLongValue());
			if (dt == null) {
				throw new AssertException("Could not find data type id: " + id);
			}
			list.add(dt);
		}
	}

	static int getTableID(long dataID) {
		return (int) (dataID >> DATA_TYPE_KIND_SHIFT);
	}

	private DataType getDataType(long dataTypeID, DBRecord record) {
		int tableId = getTableID(dataTypeID);
		DataType dt = null;
		switch (tableId) {
			case BUILT_IN:
				dt = getBuiltInDataType(dataTypeID, record);
				break;
			case COMPOSITE:
				dt = getCompositeDataType(dataTypeID, record);
				break;
			case ARRAY:
				dt = getArrayDataType(dataTypeID, record);
				break;
			case POINTER:
				dt = getPointerDataType(dataTypeID, record);
				break;
			case TYPEDEF:
				dt = getTypedefDataType(dataTypeID, record);
				break;
			case FUNCTION_DEF:
				dt = getFunctionDefDataType(dataTypeID, record);
				break;
			case ENUM:
				dt = getEnumDataType(dataTypeID, record);
				break;
			case BITFIELD:
				dt = BitFieldDBDataType.getBitFieldDataType(dataTypeID, this);
				break;
			default:
				return null;
		}
		return dt;
	}

	private DataType getBuiltInDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			DataType dt = builtInMap.get(dataTypeID);
			if (dt != null) {
				return dt;
			}

			if (record == null) {
				record = builtinAdapter.getRecord(dataTypeID);
				if (record == null) {
					return null;
				}
			}

			long catID = record.getLongValue(BuiltinDBAdapter.BUILT_IN_CAT_COL);
			CategoryDB catDB = getCategoryDB(catID);
			CategoryPath catPath = catDB.getCategoryPath();
			String classPath = record.getString(BuiltinDBAdapter.BUILT_IN_CLASSNAME_COL);
			String name = record.getString(BuiltinDBAdapter.BUILT_IN_NAME_COL);
			try { // TODO: !! Can we look for alternate constructor which takes DTM argument
				Class<?> c;
				try {
					c = Class.forName(classPath);
				}
				catch (ClassNotFoundException | NoClassDefFoundError e) {
					// Check the classNameMap.
					String newClassPath = ClassTranslator.get(classPath);
					if (newClassPath == null) {
						throw e;
					}
					try {
						c = Class.forName(newClassPath);
					}
					catch (ClassNotFoundException e1) {
						throw e1;
					}
				}

				BuiltInDataType bdt = (BuiltInDataType) c.getDeclaredConstructor().newInstance();
				bdt.setName(name);
				bdt.setCategoryPath(catPath);

				final BuiltInDataType builtInDt = (BuiltInDataType) bdt.clone(this);

				// check for prior instantiation with different id
				Long id = builtIn2IdMap.get(builtInDt);
				if (id != null) {
					DataType datatype = builtInMap.get(id);
					if (datatype != null) {
						builtInMap.put(dataTypeID, datatype);
						return datatype;
					}
				}

				if (allowsDefaultBuiltInSettings() &&
					builtInDt.getSettingsDefinitions().length != 0) {
					DataTypeSettingsDB settings =
						new DataTypeSettingsDB(this, builtInDt, dataTypeID);
					if (builtInDt instanceof TypeDef) {
						// Copy default immutable builtin typedef settings
						Settings typedefSettings = builtInDt.getDefaultSettings();
						for (String n : typedefSettings.getNames()) {
							settings.setValue(n, typedefSettings.getValue(n));
						}
					}
					settings.setAllowedSettingPredicate(n -> isBuiltInSettingAllowed(builtInDt, n));
					builtInDt.setDefaultSettings(settings);
				}
				dt = builtInDt;
			}
			catch (Exception e) {
				Msg.error(this, e);
				dt = new MissingBuiltInDataType(catPath, name, classPath, this);
			}
			builtInMap.put(dataTypeID, dt);
			builtIn2IdMap.put(dt, dataTypeID);
			return dt;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	private boolean isBuiltInSettingAllowed(BuiltInDataType bdt, String settingName) {
		SettingsDefinition def = null;
		for (SettingsDefinition sd : bdt.getSettingsDefinitions()) {
			if (sd.getStorageKey().equals(settingName)) {
				def = sd;
				break;
			}
		}
		// restrict to non-TypeDefSettingsDefinitions which are defined for the datatype
		return def != null && !(def instanceof TypeDefSettingsDefinition);
	}

	private Enum getEnumDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			EnumDB enu = (EnumDB) dtCache.get(dataTypeID);
			if (enu == null) {
				if (record == null) {
					record = enumAdapter.getRecord(dataTypeID);
				}
				if (record != null) {
					enu = new EnumDB(this, dtCache, enumAdapter, enumValueAdapter, record);
				}
			}
			return enu;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	private Composite getCompositeDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			CompositeDB comp = (CompositeDB) dtCache.get(dataTypeID);
			if (comp == null) {
				if (record == null) {
					record = compositeAdapter.getRecord(dataTypeID);
				}
				if (record != null) {
					if (record.getBooleanValue(CompositeDBAdapter.COMPOSITE_IS_UNION_COL)) {
						comp =
							new UnionDB(this, dtCache, compositeAdapter, componentAdapter, record);
					}
					else {
						comp = new StructureDB(this, dtCache, compositeAdapter, componentAdapter,
							record);
					}
				}
			}
			return comp;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	private TypeDef getTypedefDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			TypedefDB typeDB = (TypedefDB) dtCache.get(dataTypeID);
			if (typeDB == null) {
				if (record == null) {
					record = typedefAdapter.getRecord(dataTypeID);
				}
				if (record != null) {
					typeDB = new TypedefDB(this, dtCache, typedefAdapter, record);
				}
			}
			return typeDB;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	private Array getArrayDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			ArrayDB arrayDB = (ArrayDB) dtCache.get(dataTypeID);
			if (arrayDB == null) {
				if (record == null) {
					record = arrayAdapter.getRecord(dataTypeID);
				}
				if (record != null) {
					arrayDB = new ArrayDB(this, dtCache, arrayAdapter, record);
				}
			}
			return arrayDB;
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
		return null;
	}

	private Pointer getPointerDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			PointerDB ptrDB = (PointerDB) dtCache.get(dataTypeID);
			if (ptrDB == null) {
				if (record == null) {
					record = pointerAdapter.getRecord(dataTypeID);
				}
				if (record != null) {
					ptrDB = new PointerDB(this, dtCache, pointerAdapter, record);
				}
			}
			return ptrDB;
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
		return null;
	}

	private FunctionDefinition getFunctionDefDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			FunctionDefinitionDB funDef = (FunctionDefinitionDB) dtCache.get(dataTypeID);
			if (funDef == null) {
				if (record == null) {
					record = functionDefAdapter.getRecord(dataTypeID);
				}
				if (record != null) {
					funDef = new FunctionDefinitionDB(this, dtCache, functionDefAdapter,
						paramAdapter, record);
				}
			}
			return funDef;
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
		return null;
	}

	private DataType createDataType(DataType dt, String name, SourceArchive sourceArchive,
			DataTypeConflictHandler handler) {

		try {
			resolveSourceArchive(sourceArchive);
			CategoryPath cp = dt.getCategoryPath();
			CategoryDB cat = (CategoryDB) createCategory(cp);
			UniversalID id = dt.getUniversalID();

			// assume this dataType is local for now. If not it will be changed below.
			long sourceArchiveIdValue = DataTypeManager.LOCAL_ARCHIVE_KEY;

			if (sourceArchive == null) {
				// this is a new non-associated dataType, assign it a new universalID
				id = UniversalIdGenerator.nextID();
			}
			else if (!sourceArchive.getSourceArchiveID().equals(getUniversalID())) {
				// if its not me, use its sourceArchiveID. Otherwise it is local.
				sourceArchiveIdValue = sourceArchive.getSourceArchiveID().getValue();
			}

			DataType newDataType = null;
			if (dt instanceof Array array) {
				newDataType = createArray(array.getDataType(), array.getNumElements(),
					array.getElementLength(), cat, handler);
			}
			else if (dt instanceof Pointer ptr) {
				int len = ptr.hasLanguageDependantLength() ? -1 : ptr.getLength();
				newDataType = createPointer(ptr.getDataType(), cat, (byte) len, handler);
			}
			else if (dt instanceof BuiltInDataType builtInDataType) {
				newDataType = createBuiltIn(builtInDataType, cat);
			}
			else if (dt instanceof StructureInternal structure) {
				newDataType =
					createStructure(structure, name, cat, sourceArchiveIdValue, id.getValue());
			}
			else if (dt instanceof TypeDef typedef) {
				newDataType =
					createTypeDef(typedef, name, cat, sourceArchiveIdValue, id.getValue());
			}
			else if (dt instanceof UnionInternal union) {
				newDataType = createUnion(union, name, cat, sourceArchiveIdValue, id.getValue());
			}
			else if (dt instanceof Enum enumm) {
				newDataType = createEnum(enumm, name, cat, sourceArchiveIdValue, id.getValue());
			}
			else if (dt instanceof FunctionDefinition funDef) {
				newDataType = createFunctionDefinition(funDef, name, cat, sourceArchiveIdValue,
					id.getValue());
			}
			else if (dt instanceof MissingBuiltInDataType missingBuiltInDataType) {
				newDataType = createMissingBuiltIn(missingBuiltInDataType, cat);
			}
			else {
				throw new AssertException("Unknown data Type:" + dt.getDisplayName());
			}

			dataTypeAdded(newDataType, dt);
			return newDataType;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
	}

	private Structure createStructure(StructureInternal struct, String name, CategoryDB category,
			long sourceArchiveIdValue, long universalIdValue) throws IOException {
		try {
			if (name == null || name.length() == 0) {
				throw new IllegalArgumentException("Data type must have a valid name");
			}
			creatingDataType++;
			int len = struct.getLength();
			if (struct.isZeroLength() || struct.isPackingEnabled()) {
				len = 0;
			}
			DBRecord record = compositeAdapter.createRecord(name, struct.getDescription(), false,
				category.getID(), len, -1, sourceArchiveIdValue, universalIdValue,
				struct.getLastChangeTime(), struct.getStoredPackingValue(),
				struct.getStoredMinimumAlignment());

			StructureDB structDB =
				new StructureDB(this, dtCache, compositeAdapter, componentAdapter, record);

			// Make sure category knows about structure before replace is performed
			category.dataTypeAdded(structDB);

			structDB.doReplaceWith(struct, false);

			// doReplaceWith may have updated the last change time so set it back to what we want
			// without triggering change notification
			structDB.doSetLastChangeTime(struct.getLastChangeTime());

			return structDB;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException("Invalid structure: " + struct.getName(), e);
		}
		finally {
			creatingDataType--;
		}
	}

	public boolean isChanged() {
		return dbHandle.isChanged();
	}

	private TypeDef createTypeDef(TypeDef typedef, String name, Category cat,
			long sourceArchiveIdValue, long universalIdValue) throws IOException {
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Data type must have a valid name");
		}

		DataType dataType = resolve(typedef.getDataType(), getDependencyConflictHandler());
		boolean isAutoNamed = typedef.isAutoNamed();
		short flags = 0;
		if (isAutoNamed) {
			flags = (short) TypedefDBAdapter.TYPEDEF_FLAG_AUTONAME;
			cat = getCategory(dataType.getCategoryPath()); // force category
		}
		else if (cat.getDataType(name) != null) {
			// force use of conflict name if needed
			name = getUnusedConflictName(cat, typedef);
		}
		DBRecord record = typedefAdapter.createRecord(getID(dataType), name, flags, cat.getID(),
			sourceArchiveIdValue, universalIdValue, typedef.getLastChangeTime());
		TypedefDB typedefDB = new TypedefDB(this, dtCache, typedefAdapter, record);

		// Copy TypeDef settings from original
		DataTypeSettingsDB settings = (DataTypeSettingsDB) typedefDB.getDefaultSettings();
		boolean wasLocked = settings.setLock(false);
		TypedefDataType.copyTypeDefSettings(typedef, typedefDB, false);
		settings.setLock(wasLocked);

		typedefDB.updateAutoName(false);

		dataType.addParent(typedefDB);
		return typedefDB;
	}

	private Union createUnion(UnionInternal union, String name, CategoryDB category,
			long sourceArchiveIdValue, long universalIdValue) throws IOException {
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Data type must have a valid name");
		}
		try {
			creatingDataType++;
			DBRecord record = compositeAdapter.createRecord(name, null, true, category.getID(), 0,
				-1, sourceArchiveIdValue, universalIdValue, union.getLastChangeTime(),
				union.getStoredPackingValue(), union.getStoredMinimumAlignment());
			UnionDB unionDB =
				new UnionDB(this, dtCache, compositeAdapter, componentAdapter, record);

			// Make sure category knows about union before replace is performed
			category.dataTypeAdded(unionDB);

			unionDB.doReplaceWith(union, false);

			// doReplaceWith may have updated the last change time so set it back to what we want
			// without triggering change notification
			unionDB.doSetLastChangeTime(union.getLastChangeTime());

			return unionDB;
		}
		catch (DataTypeDependencyException e) {
			throw new IllegalArgumentException("Invalid union: " + union.getName(), e);
		}
		finally {
			creatingDataType--;
		}
	}

	private Enum createEnum(Enum enumm, String name, Category cat, long sourceArchiveIdValue,
			long universalIdValue) throws IOException {
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Data type must have a valid name");
		}
		DBRecord record = enumAdapter.createRecord(name, enumm.getDescription(), cat.getID(),
			(byte) enumm.getLength(), sourceArchiveIdValue, universalIdValue,
			enumm.getLastChangeTime());
		long enumID = record.getKey();
		String[] enumNames = enumm.getNames();
		for (String enumName : enumNames) {
			enumValueAdapter.createRecord(enumID, enumName, enumm.getValue(enumName),
				enumm.getComment(enumName));
		}
		EnumDB enumDB = new EnumDB(this, dtCache, enumAdapter, enumValueAdapter, record);
		return enumDB;
	}

	private Pointer createPointer(DataType dt, Category cat, byte length,
			DataTypeConflictHandler handler) throws IOException {

		if (dt != null) {
			dt = resolve(dt, handler);
		}
		long dataTypeID = getResolvedID(dt);

		DBRecord record = pointerAdapter.createRecord(dataTypeID, cat.getID(), length);
		PointerDB ptrDB = new PointerDB(this, dtCache, pointerAdapter, record);
		if (dt != null) {
			dt.addParent(ptrDB);
		}
		return ptrDB;
	}

	private Array createArray(DataType dt, int numElements, int elementLength, Category cat,
			DataTypeConflictHandler handler) throws IOException {
		dt = resolve(dt, handler);
		long dataTypeID = getResolvedID(dt);
		if (!(dt instanceof Dynamic)) {
			elementLength = -1;
		}

		// defer to ArrayDataType for checks
		new ArrayDataType(dt, numElements, elementLength, this);

		DBRecord record =
			arrayAdapter.createRecord(dataTypeID, numElements, elementLength, cat.getID());
		addParentChildRecord(record.getKey(), dataTypeID);
		ArrayDB arrayDB = new ArrayDB(this, dtCache, arrayAdapter, record);
		dt.addParent(arrayDB);
		return arrayDB;
	}

	protected void updateLastChangeTime() {
		SourceArchive mySourceArchive = getSourceArchive(getUniversalID());
		if (mySourceArchive == null) {
			return;
		}
		mySourceArchive.setLastSyncTime(System.currentTimeMillis());
	}

	private void setDirtyFlag(DataType dt) {
		SourceArchive sourceArchive = dt.getSourceArchive();
		if (sourceArchive == null) {
			return;
		}
		sourceArchive.setDirtyFlag(true);
	}

	@Override
	public List<SourceArchive> getSourceArchives() {
		Collection<SourceArchive> values = getSourceArchivesFromCache();
		List<SourceArchive> sourceArchives = new ArrayList<>();
		for (SourceArchive sourceArchive : values) {
			if (isOtherAndNotBuiltIn(sourceArchive)) {
				sourceArchives.add(sourceArchive);
			}
		}
		return sourceArchives;
	}

	private boolean isOtherAndNotBuiltIn(SourceArchive sourceArchive) {
		if (sourceArchive.getSourceArchiveID() == LOCAL_ARCHIVE_UNIVERSAL_ID) {
			return false;
		}
		if (sourceArchive.getSourceArchiveID() == universalID) {
			return false;
		}
		if (sourceArchive.getSourceArchiveID() == BUILT_IN_ARCHIVE_UNIVERSAL_ID) {
			return false;
		}
		return true;
	}

	public SourceArchive getSourceArchive(String fileID) {
		for (SourceArchive archive : getSourceArchivesFromCache()) {
			if (fileID.equals(archive.getDomainFileID())) {
				return archive;
			}
		}
		return null;
	}

	@Override
	public SourceArchive getSourceArchive(UniversalID sourceID) {
		if (!LOCAL_ARCHIVE_UNIVERSAL_ID.equals(sourceID)) {
			return getSourceArchiveFromCache(sourceID);
		}

		// special case - non-upgraded archives have a null universalID. return no sourceArchive
		if (universalID == null) {
			return null;
		}

		// Otherwise, return the sourceArchive for this dataTypeManager since it is local to this
		return getSourceArchiveFromCache(universalID);
	}

	@Override
	public SourceArchive getLocalSourceArchive() {
		return getSourceArchive(getUniversalID());
	}

	private synchronized SourceArchive getSourceArchiveFromCache(UniversalID sourceID) {
		populateSourceArchiveCache();
		return sourceArchiveMap.get(sourceID);
	}

	private synchronized void invalidateSourceArchiveCache() {
		sourceArchiveMap = null;
	}

	private synchronized Collection<SourceArchive> getSourceArchivesFromCache() {
		populateSourceArchiveCache();
		return new ArrayList<>(sourceArchiveMap.values());
	}

	private synchronized void populateSourceArchiveCache() {
		if (sourceArchiveMap != null) {
			return;
		}
		Map<UniversalID, SourceArchive> archiveMap = new HashMap<>();
		archiveMap.put(BUILT_IN_ARCHIVE_UNIVERSAL_ID, BuiltInSourceArchive.INSTANCE);
		try {
			List<DBRecord> records = sourceArchiveAdapter.getRecords();
			for (DBRecord record : records) {
				SourceArchive sourceArchive = getSourceArchiveDB(record);
				archiveMap.put(sourceArchive.getSourceArchiveID(), sourceArchive);
			}

		}
		catch (IOException e) {
			dbError(e);
		}
		sourceArchiveMap = archiveMap;
	}

	private SourceArchiveDB getSourceArchiveDB(DBRecord record) {
		SourceArchiveDB archive = sourceArchiveDBCache.get(record.getKey());
		if (archive == null) {
			archive = new SourceArchiveDB(this, sourceArchiveDBCache, sourceArchiveAdapter, record);
		}
		return archive;
	}

	@Override
	public boolean updateSourceArchiveName(String archiveFileID, String name) {
		SourceArchive sourceArchive = getSourceArchive(archiveFileID);
		if (sourceArchive != null && !sourceArchive.getName().equals(name)) {
			sourceArchive.setName(name);
			return true;
		}
		return false;
	}

	@Override
	public boolean updateSourceArchiveName(UniversalID sourceID, String name) {
		SourceArchive sourceArchive = getSourceArchive(sourceID);
		if (sourceArchive != null && !sourceArchive.getName().equals(name)) {
			sourceArchive.setName(name);
			return true;
		}
		return false;
	}

	@Override
	public List<DataType> getDataTypes(SourceArchive sourceArchive) {
		List<DataType> sourceDataTypes = new ArrayList<>();
		Iterator<DataType> allDataTypes = getAllDataTypes();
		while (allDataTypes.hasNext()) {
			DataType dt = allDataTypes.next();
			if (sourceArchive.equals(dt.getSourceArchive())) {
				sourceDataTypes.add(dt);
			}
		}
		return sourceDataTypes;
	}

	private DataType createMissingBuiltIn(MissingBuiltInDataType dt, Category category)
			throws IOException {

		DBRecord record = builtinAdapter.createRecord(dt.getMissingBuiltInName(),
			dt.getMissingBuiltInClassPath(), category.getID());
		return getBuiltInDataType(record.getKey(), record);
	}

	private DataType createBuiltIn(BuiltInDataType dt, Category category) throws IOException {

		DBRecord record =
			builtinAdapter.createRecord(dt.getName(), dt.getClass().getName(), category.getID());
		return getBuiltInDataType(record.getKey(), record);
	}

	private FunctionDefinition createFunctionDefinition(FunctionDefinition funDef, String name,
			CategoryDB cat, long sourceArchiveIdValue, long universalIdValue) throws IOException {
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Data type must have a valid name");
		}
		try {
			creatingDataType++;
			byte callingConventionId = callingConventionAdapter.getCallingConventionId(
				funDef.getCallingConventionName(), cc -> callingConventionNameAdded(cc));
			DBRecord record = functionDefAdapter.createRecord(name, funDef.getComment(),
				cat.getID(), DEFAULT_DATATYPE_ID, funDef.hasNoReturn(), funDef.hasVarArgs(),
				callingConventionId, sourceArchiveIdValue, universalIdValue,
				funDef.getLastChangeTime());
			FunctionDefinitionDB funDefDb =
				new FunctionDefinitionDB(this, dtCache, functionDefAdapter, paramAdapter, record);

			// Make sure category knows about function definition before args/return resolved
			cat.dataTypeAdded(funDefDb);

			funDefDb.doReplaceWith(funDef, false);

			// setArguments updated the last change time so set it back to what we want.
			funDefDb.setLastChangeTime(funDef.getLastChangeTime());

			return funDefDb;
		}
		finally {
			creatingDataType--;
		}
	}

	class DataTypeIterator<T extends DataType> implements Iterator<T> {
		private RecordIterator it;
		private T nextDataType;
		private Predicate<DataType> predicate;

		DataTypeIterator(DBRecordAdapter adapter, Predicate<DataType> predicate)
				throws IOException {
			it = adapter.getRecords();
			this.predicate = predicate;
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException("Remove not supported");
		}

		@Override
		public boolean hasNext() {
			if (nextDataType == null) {
				getNextDataType();
			}
			return nextDataType != null;
		}

		@Override
		public T next() {
			if (hasNext()) {
				T dt = nextDataType;
				nextDataType = null;
				return dt;
			}
			return null;
		}

		@SuppressWarnings("unchecked")
		private void getNextDataType() {
			try {
				while (it.hasNext()) {
					DBRecord rec = it.next();
					DataType dt = getDataType(rec.getKey(), rec);
					if (predicate.test(dt)) {
						nextDataType = (T) dt;
						return;
					}
				}
			}
			catch (IOException e) {
				Msg.error(this, "Unexpected exception iterating structures", e);
			}
		}
	}

	/**
	 * Handles IOExceptions
	 * 
	 * @param e the exception to handle
	 */
	public void dbError(IOException e) {
		errHandler.dbError(e);
	}

	SettingsDBAdapter getSettingsAdapter() {
		return settingsAdapter;
	}

	/**
	 * Notifies the category path changed
	 * 
	 * @param dt       the datatype whose path changed
	 * @param oldPath  the old category
	 * @param oldCatId the old category's record id
	 */
	void dataTypeCategoryPathChanged(DataTypeDB dt, CategoryPath oldPath, long oldCatId) {

		try {
			if (!(dt instanceof Array) && !(dt instanceof Pointer)) {
				for (Field arrayId : arrayAdapter.getRecordIdsInCategory(oldCatId)) {
					long id = arrayId.getLongValue();
					DBRecord rec = arrayAdapter.getRecord(id);
					ArrayDB array = (ArrayDB) getDataType(id, rec);
					array.updatePath(dt);
				}
				for (Field ptrId : pointerAdapter.getRecordIdsInCategory(oldCatId)) {
					long id = ptrId.getLongValue();
					DBRecord rec = pointerAdapter.getRecord(id);
					PointerDB ptr = (PointerDB) getDataType(id, rec);
					ptr.updatePath(dt);
				}
			}

			// only affects those with auto-naming which must follow category change
			for (Field ptrId : typedefAdapter.getRecordIdsInCategory(oldCatId)) {
				long id = ptrId.getLongValue();
				DBRecord rec = typedefAdapter.getRecord(id);
				TypedefDB td = (TypedefDB) getDataType(id, rec);
				td.updatePath(dt);
			}
		}
		catch (IOException e) {
			dbError(e);
		}

		dataTypeMoved(dt, new DataTypePath(oldPath, dt.getName()), dt.getDataTypePath());
	}

	@Override
	public Iterator<DataType> getAllDataTypes() {
		lock.acquire();
		try {
			buildSortedDataTypeList();
			return new ArrayList<>(sortedDataTypes).iterator();
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void getAllDataTypes(List<DataType> list) {
		lock.acquire();
		try {
			buildSortedDataTypeList();
			list.addAll(sortedDataTypes);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public Iterator<FunctionDefinition> getAllFunctionDefinitions() {
		try {
			return new DataTypeIterator<FunctionDefinition>(functionDefAdapter, dt -> true);
		}
		catch (IOException e) {
			dbError(e);
		}
		List<FunctionDefinition> emptyList = List.of();
		return emptyList.iterator();
	}

	@Override
	public Iterator<Structure> getAllStructures() {
		try {
			return new DataTypeIterator<Structure>(compositeAdapter,
				dt -> (dt instanceof Structure));
		}
		catch (IOException e) {
			dbError(e);
		}
		return (new ArrayList<Structure>()).iterator();
	}

	@Override
	public Iterator<Composite> getAllComposites() {
		try {
			return new DataTypeIterator<Composite>(compositeAdapter, dt -> true);
		}
		catch (IOException e) {
			dbError(e);
		}
		return (new ArrayList<Composite>()).iterator();
	}

	public void dispose() {
		sortedDataTypes = null;
		enumValueMap = null;
	}

	@Override
	public void close() {
		dispose();
	}

	/**
	 * Invalidates the cache.
	 */
	public void invalidateCache() {
		lock.acquire();
		try {
			callingConventionAdapter.invalidateCache();
			knownCallingConventions = null;
			definedCallingConventions = null;
			dtCache.invalidate();
			sourceArchiveDBCache.invalidate();
			invalidateSourceArchiveCache();
			builtInMap.clear();
			builtIn2IdMap.clear();
			root.setInvalid();
			catCache.invalidate();
			settingsCache.clear();
			settingsAdapter.invalidateNameCache();
			sortedDataTypes = null;
			enumValueMap = null;
			fireInvalidated();
			updateFavorites();
			idsToDataTypeMap.clear();
		}
		finally {
			lock.release();
		}
	}

	private void updateFavorites() {
		Iterator<DataType> it = favoritesList.iterator();
		while (it.hasNext()) {
			DataType dt = it.next();
			if (!contains(dt)) {
				it.remove();
				favoritesChanged(dt, false);
			}
		}
	}

	@Override
	public boolean isUpdatable() {
		return dbHandle.canUpdate();
	}

	@Override
	public boolean allowsDefaultBuiltInSettings() {
		return false;
	}

	@Override
	public final boolean allowsDefaultComponentSettings() {
		// default component settings support follows the same rules as BuiltIn settings
		return allowsDefaultBuiltInSettings();
	}

	/**
	 * Create a key from the table ID and the key obtained from the database table;
	 * the upper 8 bits indicates which data type table should be accessed.
	 * 
	 * @param tableID  table ID
	 * @param tableKey key obtained from the table
	 * @return long that has the upper 8 bits as the table ID, the rest of the bits
	 *         are from the tableKey.
	 */
	static long createKey(int tableID, long tableKey) {
		long key = (long) tableID << DATA_TYPE_KIND_SHIFT;
		return key |= tableKey;
	}

	void addParentChildRecord(long parentID, long childID) {
		try {
			parentChildAdapter.createRecord(parentID, childID);
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	private void removeAllParentChildRecordsForChild(long childID) {
		try {
			parentChildAdapter.removeAllRecordsForChild(childID);
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	protected void removeParentChildRecord(long parentID, long childID) {

		if (isBulkRemoving) {
			// we are in the process of bulk removing the given child; no need to call
			// remove here
			return;
		}

		try {
			parentChildAdapter.removeRecord(parentID, childID);
		}
		catch (IOException e) {
			dbError(e);
		}
	}

	protected Set<Long> getChildIds(long parentID) {
		try {
			return parentChildAdapter.getChildIds(parentID);
		}
		catch (IOException e) {
			dbError(e);
		}
		return Set.of();
	}

	protected boolean hasParent(long childID) {
		try {
			return parentChildAdapter.hasParent(childID);
		}
		catch (IOException e) {
			dbError(e);
		}
		return false;
	}

	List<DataType> getParentDataTypes(long dataTypeId) {
		lock.acquire();
		try {
			Set<Long> parentIds = parentChildAdapter.getParentIds(dataTypeId);
			// NOTE: Use of Set for containing datatypes is avoided due to the excessive
			// overhead of DataType.equals
			List<DataType> dts = new ArrayList<>();
			for (long id : parentIds) {
				DataType dt = getDataType(id);
				if (dt == null) {
					// cleanup invalid records for missing parent
					attemptRecordRemovalForParent(id);
				}
				else {
					dts.add(dt);
				}
			}
			return dts;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * NOTE: method use should be avoided since use of a Set for containing
	 * datatypes can cause use of DataType.equals method which should
	 * be avoided for performance reasons.
	 * @param dataTypeId id of datatype whose parents should be found
	 * @return set of known parent datatypes
	 */
	@Deprecated
	Set<DataType> getParentDataTypeSet(long dataTypeId) {
		lock.acquire();
		try {
			Set<Long> parentIds = parentChildAdapter.getParentIds(dataTypeId);
			Set<DataType> dts = new HashSet<>();
			for (long id : parentIds) {
				DataType dt = getDataType(id);
				if (dt == null) {
					// cleanup invalid records for missing parent
					attemptRecordRemovalForParent(id);
				}
				else {
					dts.add(dt);
				}
			}
			return dts;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	@Override
	public Set<DataType> getDataTypesContaining(DataType dataType) {
		if (dataType instanceof DataTypeDB dataTypeDb) {
			if (dataTypeDb.getDataTypeManager() != this) {
				return Set.of();
			}
			return getParentDataTypeSet(dataTypeDb.getKey());
		}
		return Set.of();
	}

	private void attemptRecordRemovalForParent(long parentKey) throws IOException {
		lock.acquire();
		try {
			if (dbHandle.isTransactionActive()) {
				parentChildAdapter.removeAllRecordsForParent(parentKey);
			}
		}
		finally {
			lock.release();
		}
	}

	@Override
	public final Pointer getPointer(DataType dt) {
		return new PointerDataType(dt, this);
	}

	@Override
	public final Pointer getPointer(DataType dt, int size) {
		return new PointerDataType(dt, size, this);
	}

	@Override
	public void addDataTypeManagerListener(DataTypeManagerChangeListener l) {
		defaultListener.addDataTypeManagerListener(l);
	}

	@Override
	public void removeDataTypeManagerListener(DataTypeManagerChangeListener l) {
		defaultListener.removeDataTypeManagerListener(l);
	}

	/**
	 * @return true if manager is in the process of adding/creating a new type
	 */
	protected boolean isCreatingDataType() {
		return creatingDataType != 0;
	}

	/**
	 * Notification when data type is changed.
	 * @param dt data type that is changed
	 * @param isAutoChange true if change was an automatic change in response to
	 * another datatype's change (e.g., size, alignment).
	 */
	public void dataTypeChanged(DataType dt, boolean isAutoChange) {
		if (dt instanceof Enum) {
			enumValueMap = null;
		}
		if (!isAutoChange && creatingDataType == 0) {
			// auto-changes should not be synced
			updateLastChangeTime();
			setDirtyFlag(dt);
		}
		defaultListener.dataTypeChanged(this, dt.getDataTypePath());
	}

	/**
	 * Notification when data type settings have changed.
	 * @param dt data type that is changed
	 */
	public void dataTypeSettingsChanged(DataType dt) {
		if (dt instanceof TypedefDB) {
			TypedefDB td = (TypedefDB) dt;
			td.updateAutoName(true);
			if (creatingDataType == 0) {
				td.setLastChangeTime(System.currentTimeMillis());
				setDirtyFlag(dt);
			}
		}
		defaultListener.dataTypeChanged(this, dt.getDataTypePath());
	}

	protected void dataTypeAdded(DataType newDt, DataType originalDataType) {
		CategoryDB category = (CategoryDB) getCategory(newDt.getCategoryPath());
		category.dataTypeAdded(newDt);
		insertDataTypeIntoSortedList(newDt);
		if (newDt instanceof Enum) {
			enumValueMap = null;
		}
		updateLastChangeTime();
		defaultListener.dataTypeAdded(this, newDt.getDataTypePath());
	}

	protected void dataTypeReplaced(long existingDtID, DataTypePath replacedDataTypePath,
			DataType replacementDt) {
		CategoryDB category = (CategoryDB) getCategory(replacedDataTypePath.getCategoryPath());
		category.dataTypeRemoved(replacedDataTypePath.getDataTypeName());
		removeDataTypeFromSortedList(replacedDataTypePath);
		enumValueMap = null;
		updateLastChangeTime();
		defaultListener.dataTypeReplaced(this, replacedDataTypePath,
			replacementDt.getDataTypePath(), replacementDt);
	}

	protected void dataTypeDeleted(long deletedID, DataTypePath deletedDataTypePath) {
		CategoryDB category = (CategoryDB) getCategory(deletedDataTypePath.getCategoryPath());
		category.dataTypeRemoved(deletedDataTypePath.getDataTypeName());
		removeDataTypeFromSortedList(deletedDataTypePath);
		enumValueMap = null;
		updateLastChangeTime();
		defaultListener.dataTypeRemoved(this, deletedDataTypePath);
	}

	protected void dataTypeMoved(DataType dt, DataTypePath oldDataTypePath,
			DataTypePath newDataTypePath) {
		CategoryDB category = (CategoryDB) getCategory(oldDataTypePath.getCategoryPath());
		category.dataTypeRemoved(oldDataTypePath.getDataTypeName());
		removeDataTypeFromSortedList(oldDataTypePath);
		category = (CategoryDB) getCategory(newDataTypePath.getCategoryPath());
		category.dataTypeAdded(dt);
		insertDataTypeIntoSortedList(dt);
		updateLastChangeTime();
		defaultListener.dataTypeMoved(this, oldDataTypePath, newDataTypePath);
	}

	protected void dataTypeNameChanged(DataType dt, String oldName) {
		CategoryDB category = (CategoryDB) getCategory(dt.getCategoryPath());
		category.dataTypeRenamed(dt, oldName);
		if (sortedDataTypes != null) {
			Collections.sort(sortedDataTypes, nameComparator);
		}
		updateLastChangeTime();
		setDirtyFlag(dt);
		defaultListener.dataTypeRenamed(this, new DataTypePath(dt.getCategoryPath(), oldName),
			dt.getDataTypePath());
	}

	protected void categoryCreated(Category cat) {
		updateLastChangeTime();
		defaultListener.categoryAdded(this, cat.getCategoryPath());
	}

	protected void categoryRenamed(CategoryPath oldPath, Category category) {
		catCache.invalidate();
		updateLastChangeTime();
		defaultListener.categoryRenamed(this, oldPath, category.getCategoryPath());
	}

	protected void categoryRemoved(Category parent, String name, long categoryID) {
		catCache.delete(categoryID);
		updateLastChangeTime();
		defaultListener.categoryRemoved(this, new CategoryPath(parent.getCategoryPath(), name));
	}

	protected void categoryMoved(CategoryPath oldPath, Category category) {
		catCache.invalidate();
		updateLastChangeTime();
		defaultListener.categoryMoved(this, oldPath, category.getCategoryPath());
	}

	protected void favoritesChanged(DataType dataType, boolean isFavorite) {
		defaultListener.favoritesChanged(this, dataType.getDataTypePath(), isFavorite);
	}

	public void sourceArchiveChanged(UniversalID sourceArchiveID) {
		SourceArchive sourceArchive = getSourceArchive(sourceArchiveID);
		defaultListener.sourceArchiveChanged(this, sourceArchive);
	}

	protected void sourceArchiveAdded(UniversalID sourceArchiveID) {
		SourceArchive sourceArchive = getSourceArchive(sourceArchiveID);
		defaultListener.sourceArchiveAdded(this, sourceArchive);
	}

	CategoryDBAdapter getCategoryDBAdapter() {
		return categoryAdapter;
	}

	@Override
	public long getLastChangeTimeForMyManager() {
		SourceArchive archive = getSourceArchive(getUniversalID());
		if (archive != null) {
			return archive.getLastSyncTime();
		}
		return DataType.NO_LAST_CHANGE_TIME;
	}

	@Override
	public DataType getDataType(SourceArchive sourceArchive, UniversalID datatypeID) {
		UniversalID sourceID = sourceArchive == null ? null : sourceArchive.getSourceArchiveID();
		lock.acquire();
		try {
			return idsToDataTypeMap.getDataType(sourceID, datatypeID);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public DataType findDataTypeForID(UniversalID datatypeID) {
		SourceArchive localSA = getLocalSourceArchive();
		DataType dt = getDataType(localSA, datatypeID);
		if (dt != null) {
			return dt;
		}
		for (SourceArchive sa : getSourceArchives()) {
			if (sa != localSA) {
				dt = getDataType(sa, datatypeID);
				if (dt != null) {
					return dt;
				}
			}
		}
		return null;
	}

	private DataType findDataTypeForIDs(UniversalID sourceID, UniversalID datatypeID) {
		lock.acquire();
		DBRecord record = null;
		try {
			record = typedefAdapter.getRecordWithIDs(sourceID, datatypeID);
			if (record == null) {
				record = compositeAdapter.getRecordWithIDs(sourceID, datatypeID);
			}
			if (record == null) {
				record = functionDefAdapter.getRecordWithIDs(sourceID, datatypeID);
			}
			if (record == null) {
				record = enumAdapter.getRecordWithIDs(sourceID, datatypeID);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		if (record != null) {
			return getDataType(record.getKey(), record);
		}
		return null;
	}

	@Override
	public AddressMap getAddressMap() {
		return addrMap;
	}

	@Override
	public final DataOrganization getDataOrganization() {
		if (dataOrganization == null) {
			try {
				// Initialization of dataOrganization may never have been established
				// if either an architecture has never been specified or a language
				// error occured during initializtion.  In such cases the stored
				// data organization should be used if available.
				dataOrganization = readDataOrganization();
			}
			catch (IOException e) {
				dbError(e);
			}
			if (dataOrganization == null) {
				dataOrganization = DataOrganizationImpl.getDefaultOrganization();
			}
		}
		return dataOrganization;
	}

	/**
	 * Get calling convention name corresponding to existing specified id.
	 * @param id calling convention ID
	 * @return calling convention name if found else unknown
	 */
	public String getCallingConventionName(byte id) {
		lock.acquire();
		try {
			String callingConvention = callingConventionAdapter.getCallingConventionName(id);
			return callingConvention != null ? callingConvention
					: CompilerSpec.CALLING_CONVENTION_unknown;
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Get (and assign if needed thus requiring open transaction) the ID associated with the 
	 * specified calling convention name.  If name is a new convention and the number of stored
	 * convention names exceeds 127 the returned ID will correspond to the unknown calling 
	 * convention.
	 * @param name calling convention name
	 * @param restrictive if true an error will be thrown if name is not defined by 
	 * {@link GenericCallingConvention} or the associated compiler specification if 
	 * datatype manager has an associated program architecture.
	 * @return calling convention ID
	 * @throws IOException if database IO error occurs
	 * @throws InvalidInputException if restrictive is true and name is not defined by 
	 * {@link GenericCallingConvention} or the associated compiler specification if 
	 * datatype manager has an associated program architecture.
	 */
	public byte getCallingConventionID(String name, boolean restrictive)
			throws InvalidInputException, IOException {

		if (CompilerSpec.isUnknownCallingConvention(name)) {
			return UNKNOWN_CALLING_CONVENTION_ID;
		}
		if (CompilerSpec.CALLING_CONVENTION_default.equals(name)) {
			return DEFAULT_CALLING_CONVENTION_ID;
		}

		lock.acquire();
		try {
			// If restrictive only permit a name which is known
			if (restrictive &&
				GenericCallingConvention
						.getGenericCallingConvention(name) == GenericCallingConvention.unknown &&
				!getKnownCallingConventionNames().contains(name) &&
				getCallingConvention(name) == null) {

				throw new InvalidInputException("Invalid calling convention name: " + name);
			}

			return callingConventionAdapter.getCallingConventionId(name,
				cc -> callingConventionNameAdded(cc));
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
		return UNKNOWN_CALLING_CONVENTION_ID;
	}

	private void callingConventionNameAdded(String name) {
		getKnownCallingConventionSet().add(name);
	}

	private Set<String> getDefinedCallingConventionSet() {
		if (definedCallingConventions == null) {
			definedCallingConventions = buildDefinedCallingConventionSet();
		}
		return definedCallingConventions;
	}

	private TreeSet<String> buildDefinedCallingConventionSet() {

		// Include all calling conventions defined by associated architecure compiler spec
		TreeSet<String> nameSet = new TreeSet<>();
		ProgramArchitecture arch = getProgramArchitecture();
		if (arch != null) {
			CompilerSpec compilerSpec = arch.getCompilerSpec();
			PrototypeModel[] namedCallingConventions = compilerSpec.getCallingConventions();
			for (PrototypeModel model : namedCallingConventions) {
				nameSet.add(model.getName());
			}
		}

		// Include all generic calling convention names without cspec
		else {
			for (GenericCallingConvention conv : GenericCallingConvention.values()) {
				if (conv == GenericCallingConvention.unknown) {
					continue; // added below
				}
				nameSet.add(conv.getDeclarationName());
			}
		}

		return nameSet;
	}

	@Override
	public Collection<String> getDefinedCallingConventionNames() {
		lock.acquire();
		try {
			return new ArrayList<>(getDefinedCallingConventionSet());
		}
		finally {
			lock.release();
		}
	}

	private Set<String> getKnownCallingConventionSet() {
		if (knownCallingConventions == null) {
			knownCallingConventions = buildKnownCallingConventionSet();
		}
		return knownCallingConventions;
	}

	private TreeSet<String> buildKnownCallingConventionSet() {
		TreeSet<String> nameSet = new TreeSet<>();
		try {
			// Include defined call convention names
			nameSet.addAll(getDefinedCallingConventionSet());

			// Include all calling convention names previously added to DB
			for (String name : callingConventionAdapter.getCallingConventionNames()) {
				nameSet.add(name);
			}
		}
		catch (IOException e) {
			dbError(e);
		}

		return nameSet;
	}

	@Override
	public Collection<String> getKnownCallingConventionNames() {
		lock.acquire();
		try {
			return new ArrayList<>(getKnownCallingConventionSet());
		}
		finally {
			lock.release();
		}
	}

	@Override
	public PrototypeModel getDefaultCallingConvention() {
		ProgramArchitecture arch = getProgramArchitecture();
		if (arch != null) {
			CompilerSpec compilerSpec = arch.getCompilerSpec();
			return compilerSpec.getDefaultCallingConvention();
		}
		return null;
	}

	@Override
	public PrototypeModel getCallingConvention(String name) {
		ProgramArchitecture arch = getProgramArchitecture();
		if (arch != null) {
			CompilerSpec compilerSpec = arch.getCompilerSpec();
			return compilerSpec.getCallingConvention(name);
		}
		return null;
	}

	private boolean checkForSourceArchiveUpdatesNeeded(OpenMode openMode, TaskMonitor monitor)
			throws IOException, CancelledException {
		if (openMode == OpenMode.CREATE || openMode == OpenMode.IMMUTABLE) {
			return false;
		}
		List<DBRecord> records = sourceArchiveAdapter.getRecords();
		for (DBRecord record : records) {
			monitor.checkCancelled();
			if (SourceArchiveUpgradeMap.isReplacedSourceArchive(record.getKey())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * During any UPGRADE instantiation this method should be invoked with an open transaction 
	 * once the associated DomainObject is ready.  This late stage upgrade is required since
	 * it may entail resolving new array datatypes which requires this manager to be in a
	 * fully functional state.
	 * @param monitor task monitor
	 * @throws IOException if an IO error occurs on database
	 * @throws CancelledException if monitor is cancelled
	 */
	protected void migrateOldFlexArrayComponentsIfRequired(TaskMonitor monitor)
			throws IOException, CancelledException {

		if (!compositeAdapter.isFlexArrayMigrationRequired()) {
			return;
		}

		RecordIterator records = compositeAdapter.getRecords();
		while (records.hasNext()) {
			monitor.checkCancelled();
			DBRecord rec = records.next();
			if (!rec.getBooleanValue(CompositeDBAdapter.COMPOSITE_IS_UNION_COL)) {
				// StructureDB instantiation will perform an automatic flex-array
				// record migration if needed.
				new StructureDB(this, dtCache, compositeAdapter, componentAdapter, rec);
			}
		}

	}

	/**
	 * This method is only invoked during an upgrade.
	 * 
	 * @param monitor      task monitor
	 * @throws CancelledException if task cancelled
	 */
	protected void doSourceArchiveUpdates(TaskMonitor monitor) throws CancelledException {
		SourceArchiveUpgradeMap upgradeMap = new SourceArchiveUpgradeMap();
		for (SourceArchive sourceArchive : getSourceArchives()) {
			SourceArchive mappedSourceArchive = upgradeMap.getMappedSourceArchive(sourceArchive);
			if (mappedSourceArchive != null) {
				replaceSourceArchive(sourceArchive, mappedSourceArchive);
			}
		}
		BuiltInDataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
		for (String name : SourceArchiveUpgradeMap.getTypedefReplacements()) {
			monitor.checkCancelled();
			DataType dataType = getDataType(CategoryPath.ROOT, name);
			if (dataType instanceof TypeDef) {
				DataType builtIn = builtInDTM.getDataType(CategoryPath.ROOT, name);
				if (builtIn != null) {
					try {
						replace(dataType, resolve(builtIn, null));
					}
					catch (DataTypeDependencyException e) {
						throw new AssertException("Got DataTypeDependencyException on built in", e);
					}
				}
			}
		}
	}

	/**
	 * Fixup all composites and thier components which may be affected by a data organization
	 * change include primitive type size changes and alignment changes.  It is highly recommended
	 * that this program be open with exclusive access before invoking this method to avoid 
	 * excessive merge conflicts with other users.
	 * @param monitor task monitor
	 * @throws CancelledException if processing cancelled - data types may not properly reflect
	 * updated compiler specification
	 */
	public void fixupComposites(TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			doCompositeFixup(monitor);
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
		}
	}

	private void doCompositeFixup(TaskMonitor monitor) throws CancelledException, IOException {

		// NOTE: Any composite could be indirectly affected by a component size change
		// based upon type relationships.  In addition, an architecture change could
		// alter the size and alignment of any datatype.

		// NOTE: Composites brought in from archive may have incorrect component size
		// if packing disabled and should not be used to guage a primitive size change

		// Unfortunately parent table does not track use of primitives so a brute
		// force search is required.  Since all composites must be checked, this 
		// is combined with the composite graph generation to get ordered list
		// of composites for subsequent size change operation.

		List<CompositeDB> orderedComposites = getAllCompositesInPostDependencyOrder(monitor);

		monitor.setProgress(0);
		monitor.setMaximum(orderedComposites.size());
		monitor.setMessage("Updating Datatype Sizes...");

		int count = 0;
		for (CompositeDB c : orderedComposites) {
			monitor.checkCancelled();
			if (c.isPackingEnabled()) {
				c.repack(true, false);
			}
			else {
				c.fixupComponents();
			}
			monitor.setProgress(++count);
		}
	}

	/**
	 * Get composite base type which corresponds to a specified datatype.
	 * Pointers to composites are ignored.  This method is intended to be
	 * used by the {@link #getAllCompositesInPostDependencyOrder} method only.
	 * @param dt datatype
	 * @return base datatype if dt corresponds to a composite or array of composites, 
	 * otherwise null is returned
	 */
	private CompositeDB getCompositeBaseType(DataType dt) {
		while ((dt instanceof Array) || (dt instanceof TypeDef)) {
			if (dt instanceof Array) {
				dt = ((Array) dt).getDataType();
			}
			else {
				dt = ((TypeDef) dt).getBaseDataType();
			}
		}
		return (dt instanceof CompositeDB) ? (CompositeDB) dt : null;
	}

	/*
	 * Graph all composites return an ordered list with leaves returned first and detect
	 * primitve size changes based upon specified primitiveTypeIds.  It is assumed TypeDef
	 * use of primitives have already be handled elsewhere.
	 * All pointers are ignored and not followed during graph generation.
	 * This method is intended to facilitate datatype size change propogation in an 
	 * orderly fashion to reduce size change propogation.
	
	 * @param monitor task monitor
	 * @return order list of composites
	 * @throws CancelledException if task cancelled
	 */
	private List<CompositeDB> getAllCompositesInPostDependencyOrder(TaskMonitor monitor)
			throws CancelledException {

		GDirectedGraph<CompositeDB, GEdge<CompositeDB>> graph = GraphFactory.createDirectedGraph();
		Iterator<Composite> allComposites = getAllComposites();
		while (allComposites.hasNext()) {
			monitor.checkCancelled();
			CompositeDB c = (CompositeDB) allComposites.next();
			graph.addVertex(c);
			for (DataTypeComponent m : c.getDefinedComponents()) {
				CompositeDB refC = getCompositeBaseType(m.getDataType());
				if (refC != null) {
					graph.addEdge(new DefaultGEdge<>(c, refC));
				}
			}
		}
		return GraphAlgorithms.getVerticesInPostOrder(graph, GraphNavigator.topDownNavigator());
	}

	/**
	 * De-duplicate equivalent conflict datatypes which share a common base data type name and
	 * are found to be equivalent.
	 * 
	 * @param dataType data type whose related conflict types should be de-duplicated
	 * @return true if one or more datatypes were de-duplicted or dde-conflicted, else false
	 */
	public boolean dedupeConflicts(DataType dataType) {
		if (!(dataType instanceof DataTypeDB)) {
			return false;
		}

		lock.acquire();
		try {
			if (dataType instanceof Pointer || dataType instanceof Array) {
				dataType = DataTypeUtilities.getBaseDataType(dataType);
			}
			if (dataType == null || !contains(dataType)) {
				return false;
			}
			List<DataType> relatedByName = findDataTypesSameLocation(dataType);
			if (relatedByName.size() < 2) {
				return false;
			}
			Collections.sort(relatedByName, DataTypeComparator.INSTANCE);

			boolean success = false;
			for (int n = relatedByName.size() - 1; n != 0; n--) {
				DataType targetDt = relatedByName.get(n);

				for (int m = 0; m < n; m++) {
					DataType candidate = relatedByName.get(m);
					if (candidate.isEquivalent(targetDt)) {
						try {
							replace(targetDt, candidate);
							success = true;
							break;
						}
						catch (DataTypeDependencyException e) {
							throw new AssertionError("Unexpected condition", e);
						}
					}
				}
			}
			return success;
		}
		finally {
			lock.release();
		}
	}

	private record DedupedConflicts(int processCnt, int replaceCnt) {
	}

	private DedupedConflicts doDedupeConflicts(DataType dataType) {

		List<DataType> relatedByName = findDataTypesSameLocation(dataType);
		if (relatedByName.size() < 2) {
			return new DedupedConflicts(1, 0);
		}
		Collections.sort(relatedByName, DataTypeComparator.INSTANCE);

		int replaceCnt = 0;
		for (int n = relatedByName.size() - 1; n != 0; n--) {
			DataType targetDt = relatedByName.get(n);

			for (int m = 0; m < n; m++) {
				DataType candidate = relatedByName.get(m);
				if (candidate.isEquivalent(targetDt)) {
					try {
						replace(targetDt, candidate);
						++replaceCnt;
						break;
					}
					catch (DataTypeDependencyException e) {
						throw new AssertionError("Unexpected condition", e);
					}
				}
			}
		}
		return new DedupedConflicts(relatedByName.size(), replaceCnt);

	}

	/**
	 * De-duplicate equivalent conflict datatypes which share a common base data type name and
	 * are found to be equivalent.
	 * 
	 * @param monitor task monitor
	 * @throws CancelledException if task is cancelled
	 */
	public void dedupeAllConflicts(TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {
			List<DataType> conflictList = new ArrayList<>();
			int total = popuplateConflictList(conflictList, getRootCategory());
			monitor.initialize(total);
			int processed = 0;
			int replacements = 0;
			for (DataType conflictDt : conflictList) {
				monitor.checkCancelled();
				DedupedConflicts result = doDedupeConflicts(conflictDt);
				processed += result.processCnt;
				replacements += result.replaceCnt;
				monitor.setProgress(processed);
			}
			Msg.info(this, "Evaluated " + processed + " conflict types, replaced " + replacements +
				" base type conflicts");
		}
		finally {
			lock.release();
		}
	}

	private int popuplateConflictList(List<DataType> conflictList, Category category) {

		int count = 0;
		for (Category childCategory : category.getCategories()) {
			count += popuplateConflictList(conflictList, childCategory);
		}

		DataType[] dataTypes = category.getDataTypes();
		Arrays.sort(dataTypes, DataTypeComparator.INSTANCE);

		String lastBaseName = null;
		boolean lastHadConflict = false;

		for (DataType dt : dataTypes) {
			if (dt instanceof Pointer || dt instanceof Array) {
				continue;
			}
			boolean isConflict = DataTypeUtilities.isConflictDataType(dt);
			String name = DataTypeUtilities.getNameWithoutConflict(dt, false);
			if (!name.equals(lastBaseName)) {
				// base name changed
				lastBaseName = name;
				lastHadConflict = false;
				if (isConflict) {
					// non-conflict type is not present
					conflictList.add(dt);
					lastHadConflict = true;
					++count;
				}
			}
			else if (isConflict) {
				if (!lastHadConflict) {
					// account for non-conflict type in count
					conflictList.add(dt);
					lastHadConflict = true;
					++count;
				}
				++count;
			}
		}
		return count;
	}

	/**
	 * Process the conflict queue of newly created conflict datatypes.  Processing performs one
	 * last attempt at locating an equivalent datatype 
	 * 
	 * @param dataType final resolved data type.
	 * If a newly created conflict type and this method and is able to replace with an equivalent 
	 * data type the replacement datatype will be returned, otherwise the specified {@code dataType}
	 * instance will be returned.
	 * @return final resolved data type
	 */
	private DataType processConflictQueue(DataType dataType) {

		while (!conflictQueue.isEmpty()) {

			// Process last conflict first (LIFO) to ensure conflicts with larger
			// numbers are discarded first if applicable - although unlikely to occur
			// during the same resolve-cycle.
			DataType dt = conflictQueue.removeLast();

			List<DataType> relatedByName = findDataTypesSameLocation(dt);
			for (DataType candidate : relatedByName) {
				if (candidate != dt && DataTypeDB.isEquivalent(candidate, dt,
					DataTypeConflictHandler.DEFAULT_HANDLER)) {
					try {
						replace(dt, candidate);
						if (dt == dataType) {
							// switch final type
							dataType = candidate;
						}
						break;
					}
					catch (DataTypeDependencyException e) {
						// ignore - try next if available
					}
				}
			}

		}
		return dataType;
	}

	/**
	 * Activate resolveCache and associated resolveQueue if not already active. If
	 * this method returns true caller is responsible for flushing resolveQueue and
	 * invoking {@link #processResolveQueue(boolean)} when resolve complete. 
	 * For each completed resolve {@link #cacheResolvedDataType(DataType, DataType)} 
	 * should be invoked.
	 * 
	 * @return true if resolveCache activated else false if already active.
	 */
	boolean activateResolveCache() {
		if (resolveCache != null) {
			return false;
		}
		resolveCache = new IdentityHashMap<>();
		return true;
	}

	/**
	 * Queue partially resolved datatype for delayed pointer resolution
	 * 
	 * @param resolvedDt   partially resolved datatype
	 * @param definitionDt original definition datatype
	 */
	void queuePostResolve(DataTypeDB resolvedDt, DataType definitionDt) {
		resolvedDt.resolving = true;
		if (resolveQueue == null) {
			resolveQueue = new TreeSet<>();
		}
		resolveQueue.add(new ResolvePair(resolvedDt, definitionDt));
	}

	/**
	 * Process resolve queue, which  includes:
	 * <ul>
	 * <li>Process any deferred pointer resolves in {@code resolveQueue}</li>
	 * <li>If deactivating cache {@code deactivateCache==true} the conflict queue will be 
	 * processed</li>
	 * <li>If deactivating cache {@code deactivateCache==true} the {@code resolveCache} will be
	 * disposed.</li>
	 * </ul>
	 * @param deactivateCache true if caller is {@code resolveCache} owner as determined by call 
	 * to {@link #activateResolveCache()}) at start of resolve cycle, else false.
	 */
	void processResolveQueue(boolean deactivateCache) {
		processResolveQueue(deactivateCache, null);
	}

	/**
	 * Process resolve queue, which  includes:
	 * <ul>
	 * <li>Process any deferred pointer resolves in {@code resolveQueue}</li>
	 * <li>If deactivating cache {@code deactivateCache==true} the conflict queue will be 
	 * processed</li>
	 * <li>If deactivating cache {@code deactivateCache==true} the {@code resolveCache} will be
	 * disposed.</li>
	 * </ul>
	 * 
	 * @param deactivateCache true if caller is {@code resolveCache} owner as determined by call 
	 * to {@link #activateResolveCache()}) at start of resolve cycle, else false.
	 * @param dataType final resolved data type.  If {@code deactivateCache==true} and this type
	 * is a newly created conflict type and this method and is able to replace with an equivalent 
	 * data type the replacement datatype will be returned, otherwise the specified {@code dataType}
	 * instance will be returned.
	 * @return final resolved data type
	 */
	private DataType processResolveQueue(boolean deactivateCache, DataType dataType) {

		try {
			if (resolveQueue != null) {
				DataTypeConflictHandler handler = getDependencyConflictHandler();
				while (!resolveQueue.isEmpty()) {
					ResolvePair resolvePair = resolveQueue.pollFirst();
					DataTypeDB resolvedDt = resolvePair.resolvedDt;
					try {
						if (!resolvedDt.isDeleted()) {
							resolvedDt.postPointerResolve(resolvePair.definitionDt, handler);
						}
					}
					// TODO: catch exceptions if needed
					finally {
						resolvedDt.resolving = false;
						resolvedDt.pointerPostResolveRequired = false;
					}
				}
			}
			if (deactivateCache) {
				return processConflictQueue(dataType);
			}
		}
		finally {
			resolveQueue = null;
			if (deactivateCache) {
				resolveCache = null;
			}
		}
		return dataType;
	}

	private DataType getCachedResolve(DataType dt) {
		if (resolveCache != null) {
			return resolveCache.get(dt);
		}
		return null;
	}

	private void cacheResolvedDataType(DataType dt, DataType resolvedDt) {
		if (resolveCache == null) {
			throw new AssertException("resolve cache inactive - unexpected condition");
		}
		resolveCache.put(dt, resolvedDt);
	}

	/**
	 * Check for cached equivalence of a type contained within this datatype manager
	 * against another datatype. Every call to this method when {@code null} is
	 * returned must be following by an invocation of
	 * {@link #putCachedEquivalence(DataTypeDB, DataType, boolean)} once an
	 * equivalence determination has been made. The number of outstanding calls to
	 * this method will be tracked. When the outstanding call count returns to zero
	 * the cache will be cleared. <br>
	 * A repeated call for the same datatype pair, while the equivalence is unknown,
	 * will return a simplified equivalence check based upon
	 * {@link DataType#getUniversalID()} or path alone.
	 * 
	 * @param dataTypeDB datatype associated with this datatype manager
	 * @param dataType   other datatype instance
	 * @return true, false or {@code null} if unknown. A {@code null} value mandates
	 *         that the caller make a determination and put the result into the
	 *         cache when known (see
	 *         {@link #putCachedEquivalence(DataTypeDB, DataType, boolean)}.
	 */
	Boolean getCachedEquivalence(DataTypeDB dataTypeDB, DataType dataType) {
		EquivalenceCache cache = equivalenceCache.get();
		if (cache == null) {
			cache = new EquivalenceCache();
			equivalenceCache.set(cache);
		}
		long key = getEquivalenceKey(dataTypeDB, dataType);
		Boolean value = cache.getValue(key);
		if (value == null) {
			// null value indicates isEquivalent in progress between the two
			// datatypes - perform simplified equivalence check
			if (cache.contains(key)) {
				if (dataType.getUniversalID().equals(getUniversalID())) {
					return true;
				}
				return DataTypeUtilities.equalsIgnoreConflict(dataTypeDB.getPathName(),
					dataType.getPathName());
			}
			cache.putValue(key, null); // indicates isEquivalent in progress
		}
		return value;
	}

	/**
	 * Set two datatypes as equivalent within the EquivalenceCache following a
	 * datatype resolution.
	 * 
	 * @param dataTypeDB datatype associated with this datatype manager
	 * @param dataType   other datatype instance
	 */
	private void setCachedEquivalence(DataTypeDB dataTypeDB, DataType dataType) {
		EquivalenceCache cache = equivalenceCache.get();
		if (cache == null) {
			throw new IllegalStateException("equivalence cache not active - unexpected condition");
		}
		long key = getEquivalenceKey(dataTypeDB, dataType);
		cache.setValue(key);
	}

	/**
	 * Cache the result of {@link DataTypeDB#isEquivalent(DataType)} for select
	 * implementations (e.g., {@link StructureDB}, {@link UnionDB}, and
	 * {@link FunctionDefinitionDB}). The call to this method must be properly
	 * matched up with a preceding invocation of
	 * {@link #getCachedEquivalence(DataTypeDB, DataType)} which returned
	 * {@code null}.
	 * 
	 * @param dataTypeDB   datatype associated with this datatype manager
	 * @param dataType     other datatype instance
	 * @param isEquivalent true or false result from
	 *                     {@link DataTypeDB#isEquivalent(DataType)}.
	 */
	void putCachedEquivalence(DataTypeDB dataTypeDB, DataType dataType, boolean isEquivalent) {
		EquivalenceCache cache = equivalenceCache.get();
		if (cache == null) {
			throw new IllegalStateException("equivalence cache not active - unexpected condition");
		}
		long key = getEquivalenceKey(dataTypeDB, dataType);
		cache.putValue(key, isEquivalent);
		if (!cache.isCacheActive()) {
			clearEquivalenceCache();
		}
	}

	/**
	 * Perform forced activation of equivalence cache if not already active. If true
	 * is returned, cache will remain active until {@link #clearEquivalenceCache()}
	 * is invoked.
	 * 
	 * @return true if successful, false if already active
	 */
	private boolean activateEquivalenceCache() {
		EquivalenceCache cache = equivalenceCache.get();
		if (cache == null) {
			cache = new EquivalenceCache();
			equivalenceCache.set(cache);
			cache.putValue(0, null); // keep cache active until cleared
			return true;
		}
		return false;
	}

	private void clearEquivalenceCache() {
		equivalenceCache.set(null);
	}

	private static long getEquivalenceKey(DataTypeDB dataTypeDB, DataType dataType) {
		return ((long) System.identityHashCode(dataTypeDB) << 32) +
			(System.identityHashCode(dataType) & 0x0ffffffffL);
	}

	/**
	 * {@code EquivalenceCache} - DataTypeDB equivalence cache
	 */
	private static class EquivalenceCache {

		private Map<Long, Boolean> cacheMap = new HashMap<>();
		int outstandingRequestCount;

		/**
		 * Get the cached datatype pair equivalence
		 * 
		 * @param key datatype identity pair (see
		 *            {@link DataTypeManagerDB#getEquivalenceKey(DataTypeDB, DataType)}
		 * @return boolean equivalence or null if unknown or determination is
		 *         in-progress
		 */
		Boolean getValue(long key) {
			return cacheMap.get(key);
		}

		/**
		 * Determine if cache contains datatype pair equivalence entry
		 * 
		 * @param key datatype identity pair (see
		 *            {@link DataTypeManagerDB#getEquivalenceKey(DataTypeDB, DataType)}
		 * @return true if cache contains specified datatype identify pair
		 */
		boolean contains(long key) {
			return cacheMap.containsKey(key);
		}

		/**
		 * Replace or put datatype pair equivalence state into cache without impacting
		 * its internal activity counter.
		 * 
		 * @param key datatype identity pair (see
		 *            {@link DataTypeManagerDB#getEquivalenceKey(DataTypeDB, DataType)}
		 */
		void setValue(long key) {
			cacheMap.put(key, true);
		}

		/**
		 * Put datatype pair equivalence state into cache. A null value is used to
		 * indicate an equivalence check will be determined and another call made to
		 * this method to update the cache with the equivalence state.
		 * 
		 * @param key   datatype identity pair (see
		 *              {@link DataTypeManagerDB#getEquivalenceKey(DataTypeDB, DataType)}
		 * @param value equivalence state (specify {@code null} to indicate equivalence
		 *              determination is in-progress)
		 */
		void putValue(long key, Boolean value) {
			cacheMap.put(key, value);
			if (value != null) {
				--outstandingRequestCount;
			}
			else {
				++outstandingRequestCount;
			}
		}

		/**
		 * Determine if one or more equivalence determinations are in-progress
		 * 
		 * @return true if one or more equivalence determinations are in-progress
		 */
		boolean isCacheActive() {
			return outstandingRequestCount > 0;
		}

	}

	/**
	 * {@code IdsToDataTypeMap} - DataType resolve cache map
	 */
	private class IdsToDataTypeMap {

		private Map<UniversalID, Map<UniversalID, DataType>> map = new ConcurrentHashMap<>();

		DataType getDataType(UniversalID sourceID, UniversalID dataTypeID) {
			if (sourceID == null || sourceID.equals(universalID)) {
				sourceID = LOCAL_ARCHIVE_UNIVERSAL_ID;
			}

			Map<UniversalID, DataType> idMap =
				map.computeIfAbsent(sourceID, k -> new ConcurrentHashMap<>());
			UniversalID sourceArchiveID = sourceID;

			// note: this call is atomic and has a lock on the 'idMap'.  It may call to a method
			//       that requires a db lock.  As such, the call to computeIfAbsent() must be 
			//       made while holding the db lock.
			return idMap.computeIfAbsent(dataTypeID,
				k -> findDataTypeForIDs(sourceArchiveID, dataTypeID));
		}

		void clear() {
			map.clear();
		}

		void removeDataType(SourceArchive sourceArchive, UniversalID dataTypeID) {
			if (dataTypeID == null) {
				return;
			}
			UniversalID sourceID;
			if (sourceArchive == null || sourceArchive.getSourceArchiveID().equals(universalID)) {
				sourceID = LOCAL_ARCHIVE_UNIVERSAL_ID;
			}
			else {
				sourceID = sourceArchive.getSourceArchiveID();
			}
			Map<UniversalID, DataType> idMap = map.get(sourceID);
			if (idMap != null) {
				idMap.remove(dataTypeID);
			}
		}
	}

	private class DbErrorHandler implements ErrorHandler {

		@Override
		public void dbError(IOException e) throws RuntimeIOException {

			String message = e.getMessage();
			if (e instanceof ClosedException) {
				message = "Data type archive is closed: " + getName();
				Msg.showError(this, null, "IO ERROR", message, e);
			}

			throw new RuntimeIOException(e);
		}
	}

	/**
	 * Diagnostic method to determine actual number of datatype records which exist.  This
	 * may differ from the total number of datatypes reported via {@link DataTypeManager#getAllDataTypes()}
	 * due to the manner in which datatypes are held in-memory (i.e., name-based indexed) if
	 * duplicate datatype names exist within a category.
	 * @return total number of datatype records.
	 */
	int getDataTypeRecordCount() {
		lock.acquire();
		try {
			return builtinAdapter.getRecordCount() + compositeAdapter.getRecordCount() +
				arrayAdapter.getRecordCount() + pointerAdapter.getRecordCount() +
				typedefAdapter.getRecordCount() + functionDefAdapter.getRecordCount() +
				enumAdapter.getRecordCount();
		}
		finally {
			lock.release();
		}
	}

}

class CategoryCache extends FixedSizeHashMap<String, Category> {
	private static final int CACHE_SIZE = 100;

	CategoryCache() {
		super(CACHE_SIZE, CACHE_SIZE);
	}
}
