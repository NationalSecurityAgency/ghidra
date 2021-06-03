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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import db.*;
import db.util.ErrorHandler;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.datamgr.archive.BuiltInSourceArchive;
import ghidra.framework.store.db.PackedDBHandle;
import ghidra.framework.store.db.PackedDatabase;
import ghidra.graph.*;
import ghidra.graph.algo.GraphNavigator;
import ghidra.program.database.*;
import ghidra.program.database.map.AddressMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.KeyRange;
import ghidra.program.model.data.*;
import ghidra.program.model.data.DataTypeConflictHandler.ConflictResult;
import ghidra.program.model.data.Enum;
import ghidra.program.model.lang.CompilerSpec;
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

	private BuiltinDBAdapter builtinAdapter;
	private ComponentDBAdapter componentAdapter;
	private CompositeDBAdapter compositeAdapter;
	private ArrayDBAdapter arrayAdapter;
	private PointerDBAdapter pointerAdapter;
	private TypedefDBAdapter typedefAdapter;
	private SettingsDBAdapter settingsAdapter;
	private InstanceSettingsDBAdapter instanceSettingsAdapter;
	private CategoryDBAdapter categoryAdapter;
	private FunctionDefinitionDBAdapter functionDefAdapter;
	private FunctionParameterAdapter paramAdapter;
	private EnumDBAdapter enumAdapter;
	private EnumValueDBAdapter enumValueAdapter;
	private ParentChildAdapter parentChildAdapter;
	protected SourceArchiveAdapter sourceArchiveAdapter;

	protected DBHandle dbHandle;
	private AddressMap addrMap;
	private ErrorHandler errHandler = new DbErrorHandler();
	private DataTypeConflictHandler currentHandler;

	private CategoryDB root;
	private DBObjectCache<DataTypeDB> dtCache;
	private DBObjectCache<SourceArchiveDB> sourceArchiveDBCache;
	private HashMap<Long, DataType> builtInMap = new HashMap<>();
	private HashMap<DataType, Long> builtIn2IdMap = new HashMap<>();
	private DBObjectCache<CategoryDB> catCache = new DBObjectCache<>(50);
	private SettingsCache settingsCache = new SettingsCache();
	private List<DataType> sortedDataTypes;
	private Map<Long, Set<String>> enumValueMap;

	private List<InvalidatedListener> invalidatedListeners = new ArrayList<>();
	protected DataTypeManagerChangeListenerHandler defaultListener =
		new DataTypeManagerChangeListenerHandler();
	private NameComparator nameComparator = new NameComparator();
	private int creatingDataType = 0;
	protected UniversalID universalID;

	private Map<UniversalID, SourceArchive> sourceArchiveMap;
	private LinkedList<Long> idsToDelete = new LinkedList<>();
	private List<DataType> favoritesList = new ArrayList<>();
	private IdsToDataTypeMap idsToDataTypeMap = new IdsToDataTypeMap();

	private ThreadLocal<EquivalenceCache> equivalenceCache = new ThreadLocal<>();

	private IdentityHashMap<DataType, DataType> resolveCache;
	private TreeSet<ResolvePair> resolveQueue;

	private boolean isBulkRemoving;

	Lock lock;

	protected DataOrganization dataOrganization;

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
	 * Construct a temporary data-type manager. Note that this manager does not
	 * support the save or saveAs operation.
	 */
	protected DataTypeManagerDB() {
		this.lock = new Lock("DataTypeManagerDB");

		try {
			dbHandle = new DBHandle();
			int id = startTransaction("");

			try {
				init(DBConstants.CREATE, TaskMonitor.DUMMY);
			}
			catch (VersionException | CancelledException e) {
				throw new AssertException(e); // unexpected
			}
			finally {
				endTransaction(id, true);
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
	}

	/**
	 * Constructor for a data-type manager backed by a packed database file. When
	 * opening for UPDATE an automatic upgrade will be performed if required.
	 * 
	 * @param packedDBfile packed datatype archive file (i.e., *.gdt resource).
	 * @param openMode     open mode CREATE, READ_ONLY or UPDATE (see
	 *                     {@link DBConstants})
	 * @throws IOException a low-level IO error. This exception may also be thrown
	 *                     when a version error occurs (cause is VersionException).
	 */
	protected DataTypeManagerDB(ResourceFile packedDBfile, int openMode) throws IOException {

		lock = new Lock("DataTypeManagerDB");

		File file = packedDBfile.getFile(false);
		if (file == null && openMode != DBConstants.READ_ONLY) {
			throw new IOException("Unsupported mode (" + openMode +
				") for read-only Datatype Archive: " + packedDBfile.getAbsolutePath());
		}

		// Open packed database archive
		boolean openSuccess = false;
		PackedDatabase pdb = null;
		try {
			if (openMode == DBConstants.CREATE) {
				dbHandle = new PackedDBHandle(
					DataTypeArchiveContentHandler.DATA_TYPE_ARCHIVE_CONTENT_TYPE);
			}
			else {
				pdb = PackedDatabase.getPackedDatabase(packedDBfile, false, TaskMonitor.DUMMY);
				if (openMode == DBConstants.UPDATE) {
					dbHandle = pdb.openForUpdate(TaskMonitor.DUMMY);
				}
				else {
					dbHandle = pdb.open(TaskMonitor.DUMMY);
				}
			}
			openSuccess = true;
		}
		catch (CancelledException e1) {
			throw new AssertException(e1); // can't happen--dummy monitor
		}
		finally {
			if (!openSuccess && pdb != null) {
				pdb.dispose(); // dispose on error
			}
		}

		// Initialize datatype manager and save new archive on CREATE
		boolean initSuccess = false;
		try {
			initPackedDatabase(packedDBfile, openMode);

			if (openMode == DBConstants.CREATE) {
				// preserve UniversalID if it has been established
				Long uid = universalID != null ? universalID.getValue() : null;
				((PackedDBHandle) dbHandle).saveAs("Archive", file.getParentFile(),
					packedDBfile.getName(), uid, TaskMonitor.DUMMY);
			}

			initSuccess = true;
		}
		catch (CancelledException e) {
			throw new AssertException(e); // can't happen--dummy monitor
		}
		finally {
			if (!initSuccess) {
				dbHandle.close(); // close on error (packed database will also be disposed)
			}
		}
	}

	private void initPackedDatabase(ResourceFile packedDBfile, int openMode)
			throws CancelledException, IOException {
		int id = startTransaction("");
		try {
			init(openMode, TaskMonitor.DUMMY);
		}
		catch (VersionException e) {
			if (openMode == DBConstants.UPDATE && e.isUpgradable()) {
				try {
					Msg.info(this,
						"Performing datatype archive schema upgrade: " + packedDBfile.getName());
					init(DBConstants.UPGRADE, TaskMonitor.DUMMY);
				}
				catch (VersionException ve) {
					throw new IOException(e); // unexpected
				}
			}
			else {
				throw new IOException(e);
			}
		}
		finally {
			endTransaction(id, true);
		}
	}

	/**
	 * Constructor
	 * 
	 * @param handle     database handle
	 * @param addrMap    map to convert addresses to longs and longs to addresses
	 * @param openMode   mode to open the DataTypeManager in
	 * @param errHandler the error handler
	 * @param lock       database lock
	 * @param monitor    the current task monitor
	 * @throws CancelledException if an upgrade is cancelled
	 * @throws IOException if there is a problem reading the database
	 * @throws VersionException if any database handle's version doesn't match the expected version
	 */
	protected DataTypeManagerDB(DBHandle handle, AddressMap addrMap, int openMode,
			ErrorHandler errHandler, Lock lock, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {

		this.dbHandle = handle;
		this.addrMap = addrMap;
		this.errHandler = errHandler;
		this.lock = lock;
		init(openMode, monitor);
	}

	private void init(int openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {
		updateID();
		initializeAdapters(openMode, monitor);
		if (checkForSourceArchiveUpdatesNeeded(openMode, monitor)) {
			doSourceArchiveUpdates(null, TaskMonitor.DUMMY);
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

	private void initializeAdapters(int openMode, TaskMonitor monitor)
			throws CancelledException, IOException, VersionException {

		//
		// IMPORTANT! All adapter version must retain read-only capability to permit
		// opening older archives without requiring an upgrade. Failure to do so may
		// present severe usability issues when the ability to open for update is not 
		// possible.
		//

		VersionException versionExc = null;
		try {
			builtinAdapter = BuiltinDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			categoryAdapter = CategoryDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			arrayAdapter = ArrayDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			typedefAdapter = TypedefDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			compositeAdapter = CompositeDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			componentAdapter = ComponentDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			functionDefAdapter =
				FunctionDefinitionDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			paramAdapter = FunctionParameterAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			settingsAdapter = SettingsDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		if (addrMap != null) {
			try {
				instanceSettingsAdapter =
					InstanceSettingsDBAdapter.getAdapter(dbHandle, openMode, addrMap, monitor);
			}
			catch (VersionException e) {
				versionExc = e.combine(versionExc);
			}
		}
		try {
			pointerAdapter = PointerDBAdapter.getAdapter(dbHandle, openMode, monitor, addrMap);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			enumAdapter = EnumDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			enumValueAdapter = EnumValueDBAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			parentChildAdapter = ParentChildAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}
		try {
			sourceArchiveAdapter = SourceArchiveAdapter.getAdapter(dbHandle, openMode, monitor);
		}
		catch (VersionException e) {
			versionExc = e.combine(versionExc);
		}

		if (versionExc != null) {
			throw versionExc;
		}
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
		Iterator<DataType> it = sortedDataTypes.iterator();
		while (it.hasNext()) {
			DataType dt = it.next();
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
				if (dt instanceof Structure) {
					Structure struct = (Structure) dt;
					if (struct.hasFlexibleArrayComponent()) {
						struct.getFlexibleArrayComponent().getDataType().addParent(dt);
					}
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
	 * Determine if transaction is active.  With proper lock established
	 * this method may be useful for determining if a lazy record update
	 * may be performed.
	 * @return true if database transaction if active, else false
	 */
	protected final boolean isTransactionActive() {
		return dbHandle.isTransactionActive();
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
		String name = dataTypePath.getDataTypeName();
		DataType compareDataType = new TypedefDataType(name, DefaultDataType.dataType);
		try {
			compareDataType.setCategoryPath(dataTypePath.getCategoryPath());
		}
		catch (DuplicateNameException e) {
			// will not happen - compareDataType not in dataTypeManager
		}
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

	ConflictResult resolveConflict(DataTypeConflictHandler handler, DataType addedDataType,
			DataType existingDataType) {
		return handler.resolveConflict(addedDataType, existingDataType);
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

	public String getUniqueName(CategoryPath path1, CategoryPath path2, String baseName) {
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
		while (getDataType(path1, name) != null || getDataType(path2, name) != null) {
			++oneUpNumber;
			name = baseName + "_" + oneUpNumber;
		}
		return name;
	}

	@Override
	public Category getCategory(CategoryPath path) {
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
			if (resolvedDataType != null) {
				return resolvedDataType;
			}

			SourceArchive sourceArchive = dataType.getSourceArchive();
			if (sourceArchive != null && sourceArchive.getArchiveType() == ArchiveType.BUILT_IN) {
				resolvedDataType = resolveBuiltIn(dataType, currentHandler);
			}
			else if (sourceArchive == null || dataType.getUniversalID() == null) {
				// if the dataType has no source or it has no ID (datatypes with no ID are
				// always local i.e. pointers)
				resolvedDataType = resolveNoSourceDataType(dataType, currentHandler);
			}
			else if (!sourceArchive.getSourceArchiveID().equals(getUniversalID()) &&
				sourceArchive.getArchiveType() == ArchiveType.PROGRAM) {
				// dataTypes from a different program don't carry over their identity.
				resolvedDataType = resolveNoSourceDataType(dataType, currentHandler);
			}
			else {
				resolvedDataType =
					resolveDataTypeWithSource(dataType, sourceArchive, currentHandler);
			}
			cacheResolvedDataType(dataType, resolvedDataType);
			if (resolvedDataType instanceof DataTypeDB) {
				setCachedEquivalence((DataTypeDB) resolvedDataType, dataType);
			}
			return resolvedDataType;
		}
		finally {
			try {
				if (isResolveCacheOwner) {
					flushResolveQueue(true); // may throw exception - incomplete resolve
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
	}

	private DataType resolveBuiltIn(DataType dataType, DataTypeConflictHandler handler) {
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
			String dtName = getUnusedConflictName(dataType.getCategoryPath(), dataType.getName());
			try {
				existingDataType.setName(dtName);
			}
			catch (Exception e) {
				throw new AssertException(
					"Failed to rename conflicting datatype: " + existingDataType.getPathName(), e);
			}
		}
		return createDataType(dataType, dataType.getName(), BuiltInSourceArchive.INSTANCE, handler);
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
			// should get recomputed during packing when used within aligned structure
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
	 * @param handler  Used to handle collisions with dataTypes with same path and
	 *                 name that is
	 * @return resolved datatype
	 */
	private DataType resolveNoSourceDataType(DataType dataType, DataTypeConflictHandler handler) {

		DataType existingDataType = findEquivalentDataTypeSameLocation(dataType, handler);
		if (existingDataType != null) {
			return existingDataType;
		}
		existingDataType = getDataType(dataType.getCategoryPath(), dataType.getName());
		if (existingDataType == null) {
			return createDataType(dataType, dataType.getName(), null, handler);
		}

		// So we have a dataType with the same path and name, but not equivalent, so use
		// the conflictHandler to decide what to do.
		ConflictResult result = resolveConflict(handler, dataType, existingDataType);
		switch (result) {

			case REPLACE_EXISTING: // new type replaces old conflicted type
				try {
					if (updateExistingDataType(existingDataType, dataType)) {
						return existingDataType;
					}
					renameToUnusedConflictName(existingDataType);
					DataType newDataType =
						createDataType(dataType, dataType.getName(), null, handler);
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
				String dtName =
					getUnusedConflictName(dataType.getCategoryPath(), dataType.getName());
				DataType newDataType = createDataType(dataType, dtName, null, handler);

				// resolving child data types could result in another copy of dataType in the
				// manager depending upon the conflict handler - check again
				existingDataType = findEquivalentDataTypeSameLocation(dataType, handler);
				// If there is an equivalent datatype, remove the added type and return the existing
				if (existingDataType != null && existingDataType != newDataType) {
					removeInternal(newDataType, TaskMonitor.DUMMY);
					return existingDataType;
				}
				return newDataType;

			case USE_EXISTING: // new type is discarded and old conflicted type is returned
				return existingDataType;
		}
		return null;
	}

	private void renameToUnusedConflictName(DataType dataType) {
		String dtName = dataType.getName();
		String name = getUnusedConflictName(dataType.getCategoryPath(), dtName);
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
	 * @return true if replacement approach was successful, else false
	 * @throws DataTypeDependencyException if datatype contains dependency issues
	 *                                     during resolve process
	 */
	private boolean updateExistingDataType(DataType existingDataType, DataType dataType)
			throws DataTypeDependencyException {

		// TODO: this approach could be added to other DB datatypes to avoid
		// unnecessary creation and removal.

		try {
			if (existingDataType instanceof StructureDB) {
				if (!(dataType instanceof StructureInternal)) {
					return false;
				}
				StructureDB existingStruct = (StructureDB) existingDataType;
				existingStruct.doReplaceWith((StructureInternal) dataType, true);
				return true;
			}
			else if (existingDataType instanceof UnionDB) {
				if (!(dataType instanceof UnionInternal)) {
					return false;
				}
				UnionDB existingUnion = (UnionDB) existingDataType;
				existingUnion.doReplaceWith((UnionInternal) dataType, true);
				return true;
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		return false;
	}

	/**
	 * This method gets a ".conflict" name that is not currently used by any data
	 * types in the indicated category of the data type manager.
	 * 
	 * @param path the category path of the category where the new data type live in
	 *             the data type manager.
	 * @param name The name of the data type. This name may or may not contain
	 *             ".conflict" as part of it. If the name contains ".conflict", only
	 *             the part of the name that comes prior to the ".conflict" will be
	 *             used to determine a new unused conflict name.
	 * @return the unused conflict name
	 */
	public String getUnusedConflictName(CategoryPath path, String name) {
		int index = name.indexOf(DataType.CONFLICT_SUFFIX);
		if (index > 0) {
			name = name.substring(0, index);
		}
		String baseName = name + DataType.CONFLICT_SUFFIX;
		String testName = baseName;
		int count = 0;
		while (getDataType(path, testName) != null) {
			count++;
			testName = baseName + count;
		}
		return testName;
	}

	private boolean isEquivalentDataType(DataType addedDataType, DataType existingDataType,
			DataTypeConflictHandler handler) {
		return existingDataType.isEquivalent(addedDataType) ||
			handler.resolveConflict(addedDataType, existingDataType) == ConflictResult.USE_EXISTING;
	}

	/**
	 * Finds an datatype in this manager that is equivalent and has the same
	 * categoryPath and has either the same name or a conflict variation of that
	 * name.
	 * 
	 * @param dataType the dataType for which to find an equivalent existing
	 *                 dataType
	 */
	private DataType findEquivalentDataTypeSameLocation(DataType dataType,
			DataTypeConflictHandler handler) {

		// first see if an exact match exists
		String dtName = dataType.getName();

		DataType existingDataType = getDataType(dataType.getCategoryPath(), dtName);

		// If the existing Data type is currently being resolved, its isEquivalent
		// method is short circuited such that it will return true. So it is important 
		// to call the isEquivalent on the existing datatype and not the dataType.
		if (existingDataType != null && isEquivalentDataType(dataType, existingDataType, handler)) {
			return existingDataType;
		}

		Category category = getCategory(dataType.getCategoryPath());
		if (category == null) {
			return null;
		}
		List<DataType> relatedByName = category.getDataTypesByBaseName(dtName);

		for (DataType candidate : relatedByName) {
			if (candidate != existingDataType &&
				isEquivalentDataType(dataType, candidate, handler)) {
				return candidate;
			}
		}
		return null;
	}

	private DataType resolveDataTypeWithSource(DataType dataType, SourceArchive sourceArchive,
			DataTypeConflictHandler handler) {
		// Do we have that dataType already resolved and associated with the source archive?
		DataType existingDataType = getDataType(sourceArchive, dataType.getUniversalID());
		if (existingDataType != null) {
			if (!existingDataType.isEquivalent(dataType)) {
				if (handler.shouldUpdate(dataType, existingDataType)) {
					existingDataType.replaceWith(dataType);
					existingDataType.setLastChangeTime(dataType.getLastChangeTime());
				}
			}
			return existingDataType;
		}

		// Do we have the same named data type in the same category already?
		existingDataType = getDataType(dataType.getCategoryPath(), dataType.getName());
		if (existingDataType == null) {
			// Don't have a data type with this path name, so can create it.
			return createDataType(dataType, dataType.getName(), sourceArchive, handler);
		}

		// If we have the same path name and the existing data type is a local data type
		// and is equivalent to this one, then associate it with the source archive
		if (isLocalSource(existingDataType) &&
			isEquivalentDataType(dataType, existingDataType, handler)) {
			return replaceEquivalentLocalWithSourceDataType(dataType, sourceArchive,
				existingDataType);
		}

		// Otherwise, we need to create a new Data type associated with the archive
		// and it will possibly have a conflict name.
		String dtName = getUnusedConflictName(dataType.getCategoryPath(), dataType.getName());
		return createDataType(dataType, dtName, sourceArchive, handler);
	}

	private DataType replaceEquivalentLocalWithSourceDataType(DataType dataType,
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
		return existingDataType;
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
				monitor.checkCanceled();
				resolve(dt, handler);
				if (isResolveCacheOwner) {
					flushResolveQueue(false);
				}
				monitor.setProgress(++i);
			}
		}
		finally {
			if (isResolveCacheOwner) {
				flushResolveQueue(true);
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
		if (getSourceArchive(sourceArchive.getSourceArchiveID()) != null) {
			// already have it
			return getSourceArchive(sourceArchive.getSourceArchiveID());
		}
		try {
			DBRecord record = sourceArchiveAdapter.createRecord(sourceArchive);
			SourceArchive newSourceArchive = getSourceArchiveDB(record);
			invalidateSourceArchiveCache();
			sourceArchiveAdded(newSourceArchive.getSourceArchiveID());
			return newSourceArchive;
		}
		catch (IOException e) {
			dbError(e);
			return null;
		}
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
			try {
				sourceArchiveAdapter.deleteRecord(sourceArchiveID);
			}
			catch (IOException e) {
				dbError(e);
			}
			sourceArchiveChanged(sourceArchiveID);
			invalidateSourceArchiveCache();
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
			if (getID(existingDt) < 0) {
				throw new IllegalArgumentException(
					"datatype to replace is not contained in this datatype manager.");
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
					Msg.error(this, "Unable to set the name to " + existingDt.getName() +
						"on " + replacementDt + " while replacing the original datatype", e);
				}
			}
			CategoryPath path = existingDt.getCategoryPath();

			if (updateCategoryPath && !replacementDt.getCategoryPath().equals(path)) {
				try {
					replacementDt.setCategoryPath(path);
				}
				catch (Exception e) {
					// not sure what to do here
					Msg.error(this, "Unable to set the CatagoryPath to " + path +
						"on " + replacementDt + " while replacing the original datatype", e);
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
		if (existingDt == replacementDt) {
			return;
		}
		DataTypePath replacedDtPath = existingDt.getDataTypePath();
		long replacedId = getID(existingDt);

		UniversalID id = existingDt.getUniversalID();
		idsToDataTypeMap.removeDataType(existingDt.getSourceArchive(), id);

		if (replacementDt.dependsOn(existingDt)) {
			throw new DataTypeDependencyException("Replace failed: " +
				replacementDt.getDisplayName() + " depends on " + existingDt.getDisplayName());
		}

		replaceUsesInOtherDataTypes(existingDt, replacementDt);

		try {
			replaceDataTypeIDs(replacedId, getID(replacementDt));
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
			DataType[] dts = existingDt.getParents();
			for (DataType dt : dts) {
				dt.dataTypeReplaced(existingDt, newDt);
			}
		}
		else {
			buildSortedDataTypeList();
			// make copy of sortedDataTypes list before iterating as dt.dataTypeReplaced may
			// call back into this class and cause a modification to the sortedDataTypes list.
			Iterator<DataType> it = new ArrayList<>(sortedDataTypes).iterator();
			while (it.hasNext()) {
				DataType dt = it.next();
				dt.dataTypeReplaced(existingDt, newDt);
			}
		}
	}

	abstract protected void replaceDataTypeIDs(long oldID, long newID);

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
		if (name.equals(DefaultDataType.dataType.getName())) {
			list.add(DefaultDataType.dataType);
			return;
		}
		lock.acquire();
		try {
			buildSortedDataTypeList();
			DataType compareDataType = new TypedefDataType(name, DefaultDataType.dataType);
			int index = Collections.binarySearch(sortedDataTypes, compareDataType, nameComparator);
			if (index < 0) {
				index = -index - 1;
			}
			while (index < sortedDataTypes.size()) {
				DataType dt = sortedDataTypes.get(index);
				if (!name.equals(dt.getName())) {
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
		if (name.equals(DefaultDataType.dataType.getName())) {
			list.add(DefaultDataType.dataType);
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
		if (dt instanceof BitFieldDataType) {
			return createKey(BITFIELD, BitFieldDBDataType.getId((BitFieldDataType) dt));
		}
		if (dt instanceof BadDataType) {
			return BAD_DATATYPE_ID;
		}
		if (dt instanceof DatabaseObject) {
			// NOTE: Implementation DOES NOT check or guarantee that datatype or its returned ID 
			// correspond to this datatype manager instance. This seems incorrect although it's 
			// possible that uses depend on this behavior.
			return ((DatabaseObject) dt).getKey();
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
	 * @param monitor  the task monitor
	 */
	private boolean removeInternal(DataType dataType, TaskMonitor monitor) {
		if (!contains(dataType)) {
			return false;
		}

		LinkedList<Long> deletedIds = new LinkedList<>();

		long id = getID(dataType);

		if (id < 0) {
			return false;
		}

		idsToDelete.add(Long.valueOf(id));

		while (!idsToDelete.isEmpty()) {
			Long l = idsToDelete.removeFirst();
			id = l.longValue();
			removeUseOfDataType(id);

			deletedIds.addFirst(l);
		}

		Iterator<Long> it = deletedIds.iterator();
		while (it.hasNext()) {
			Long l = it.next();
			deleteDataType(l.longValue());
		}

		try {
			deleteDataTypeIDs(deletedIds, monitor);
		}
		catch (CancelledException e) {
			return false;
		}

		return true;
	}

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
			return removeInternal(dataType, monitor);
		}
		finally {
			lock.release();
		}
	}

	@Override
	public void associateDataTypeWithArchive(DataType datatype, SourceArchive archive) {
		if (!contains(datatype)) {
			throw new IllegalArgumentException(
				"The given datatype must exist in this DataTypeManager");
		}
		if (!datatype.getSourceArchive().equals(getLocalSourceArchive())) {
			return;
		}
		if (datatype.getSourceArchive().equals(archive)) {
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
			if (dataType instanceof DataTypeDB) {
				DataTypeDB dt = (DataTypeDB) dataType;
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

	protected void addDataTypeToDelete(long id) {
		idsToDelete.add(Long.valueOf(id));
	}

	abstract protected void deleteDataTypeIDs(LinkedList<Long> deletedIds, TaskMonitor monitor)
			throws CancelledException;

	private void notifyDeleted(long dataTypeID) {
		DataType dataType = getDataType(dataTypeID);
		if (dataType == null) {
			return;
		}
		if (dataType instanceof DataTypeDB) {
			((DataTypeDB) dataType).notifyDeleted();
		}
		else {
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

	private void deleteDataTypeRecord(long dataID) {
		int tableID = getTableID(dataID);

		try {
			DataType dt = null;
			switch (tableID) {
				case BUILT_IN:
					boolean status = builtinAdapter.removeRecord(dataID);
					if (status) {
						dt = builtInMap.remove(dataID);
						builtIn2IdMap.remove(dt);
					}
					break;
				case COMPOSITE:
					removeComponents(dataID);
					status = compositeAdapter.removeRecord(dataID);
					break;
				case COMPONENT:
					status = componentAdapter.removeRecord(dataID);
					break;
				case TYPEDEF:
					status = typedefAdapter.removeRecord(dataID);
					break;
				case ARRAY:
					status = arrayAdapter.removeRecord(dataID);
					break;
				case POINTER:
					status = pointerAdapter.removeRecord(dataID);
					break;
				case FUNCTION_DEF:
					removeParameters(dataID);
					status = functionDefAdapter.removeRecord(dataID);
					break;
				case PARAMETER:
					status = paramAdapter.removeRecord(dataID);
					break;
				case ENUM:
					status = enumAdapter.removeRecord(dataID);
					break;
			}
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
		if (dataType instanceof DataTypeDB) {
			long id = ((DataTypeDB) dataType).getKey();
//	NOTE: Does not seem to help following an undo/redo		
//			DataTypeDB existingDt = dtCache.get(id);
//			return existingDt == dataType && existingDt.validate(lock);
//			
			return dtCache.get(id) != null;
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
		if (path.equals(DataType.DEFAULT.getCategoryPath()) &&
			name.equals(DataType.DEFAULT.getName())) {
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
		switch (tableId) {
			case BUILT_IN:
				return getBuiltInDataType(dataTypeID, record);
			case COMPOSITE:
				return getCompositeDataType(dataTypeID, record);
			case ARRAY:
				return getArrayDataType(dataTypeID, record);
			case POINTER:
				return getPointerDataType(dataTypeID, record);
			case TYPEDEF:
				return getTypedefDataType(dataTypeID, record);
			case FUNCTION_DEF:
				return getFunctionDefDataType(dataTypeID, record);
			case ENUM:
				return getEnumDataType(dataTypeID, record);
			case BITFIELD:
				return BitFieldDBDataType.getBitFieldDataType(dataTypeID, this);
			default:
				return null;
		}
	}

	private DataType getBuiltInDataType(long dataTypeID, DBRecord record) {
		lock.acquire();
		try {
			Long key = dataTypeID;
			DataType dt = builtInMap.get(key);

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

				dt = (BuiltInDataType) c.getDeclaredConstructor().newInstance();
				dt.setName(name);
				dt.setCategoryPath(catPath);
				dt = dt.clone(this);
				dt.setDefaultSettings(new SettingsDBManager(this, dt, dataTypeID));
			}
			catch (Exception e) {
				dt = new MissingBuiltInDataType(catPath, name, classPath, this);
			}
			builtInMap.put(key, dt);
			builtIn2IdMap.put(dt, key);
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
			if (dt instanceof Array) {
				Array array = (Array) dt;
				newDataType = createArray(array.getDataType(), array.getNumElements(),
					array.getElementLength(), cat, handler);
			}
			else if (dt instanceof Pointer) {
				Pointer ptr = (Pointer) dt;
				int len = ptr.hasLanguageDependantLength() ? -1 : ptr.getLength();
				newDataType = createPointer(ptr.getDataType(), cat, (byte) len, handler);
			}
			else if (dt instanceof StructureInternal) {
				StructureInternal structure = (StructureInternal) dt;
				newDataType = createStructure(structure, name, cat, sourceArchiveIdValue,
					id.getValue());
			}
			else if (dt instanceof TypeDef) {
				TypeDef typedef = (TypeDef) dt;
				newDataType =
					createTypeDef(typedef, name, cat, sourceArchiveIdValue, id.getValue());
			}
			else if (dt instanceof UnionInternal) {
				UnionInternal union = (UnionInternal) dt;
				newDataType =
					createUnion(union, name, cat, sourceArchiveIdValue, id.getValue());
			}
			else if (dt instanceof Enum) {
				Enum enumm = (Enum) dt;
				newDataType = createEnum(enumm, name, cat, sourceArchiveIdValue, id.getValue());
			}
			else if (dt instanceof FunctionDefinition) {
				FunctionDefinition funDef = (FunctionDefinition) dt;
				newDataType = createFunctionDefinition(funDef, name, cat, sourceArchiveIdValue,
					id.getValue());
			}
			else if (dt instanceof BuiltInDataType) {
				BuiltInDataType builtInDataType = (BuiltInDataType) dt;
				newDataType = createBuiltIn(builtInDataType, cat);
			}
			else if (dt instanceof MissingBuiltInDataType) {
				MissingBuiltInDataType missingBuiltInDataType = (MissingBuiltInDataType) dt;
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
			long sourceArchiveIdValue, long universalIdValue)
			throws IOException {
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
				category.getID(), len, -1, sourceArchiveIdValue,
				universalIdValue, struct.getLastChangeTime(),
				struct.getStoredPackingValue(), struct.getStoredMinimumAlignment());

			StructureDB structDB =
				new StructureDB(this, dtCache, compositeAdapter, componentAdapter, record);

			// Make sure category knows about structure before replace is performed
			category.dataTypeAdded(structDB);

			structDB.doReplaceWith(struct, false);
			structDB.setDescription(struct.getDescription());
//			structDB.notifySizeChanged();
			// doReplaceWith may have updated the last change time so set it back to what we want.
			structDB.setLastChangeTime(struct.getLastChangeTime());

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

//	private int getExternalAlignment(Composite struct) {
//		if (struct.isDefaultAligned()) {
//			return CompositeDB.DEFAULT_ALIGNED;
//		}
//		else if (struct.isMachineAligned()) {
//			return CompositeDB.MACHINE_ALIGNED;
//		}
//		else {
//			int alignment = struct.getAlignment();
//			if (alignment <= 0) {
//				return CompositeDB.DEFAULT_ALIGNED;
//			}
//			return alignment;
//		}
//	}

//	private int getInternalAlignment(Composite struct) {
//		if (struct.isPackingEnabled()) {
//			int packingValue = struct.getPackingValue();
//			if (packingValue == 0) {
//				return CompositeDB.ALIGNED_NO_PACKING;
//			}
//			return packingValue;
//		}
//		return CompositeDB.UNALIGNED;
//	}

	private TypeDef createTypeDef(TypeDef typedef, String name, Category cat,
			long sourceArchiveIdValue, long universalIdValue)
			throws IOException {
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Data type must have a valid name");
		}
		DataType dataType = resolve(typedef.getDataType(), getDependencyConflictHandler());
		DBRecord record = typedefAdapter.createRecord(getID(dataType), name, cat.getID(),
			sourceArchiveIdValue, universalIdValue, typedef.getLastChangeTime());
		TypedefDB typedefDB = new TypedefDB(this, dtCache, typedefAdapter, record);
		dataType.addParent(typedefDB);

		return typedefDB;
	}

	private Union createUnion(UnionInternal union, String name, CategoryDB category,
			long sourceArchiveIdValue, long universalIdValue)
			throws IOException {
		if (name == null || name.length() == 0) {
			throw new IllegalArgumentException("Data type must have a valid name");
		}
		try {
			creatingDataType++;
			DBRecord record = compositeAdapter.createRecord(name, null, true, category.getID(), 0,
				-1, sourceArchiveIdValue, universalIdValue,
				union.getLastChangeTime(), union.getStoredPackingValue(), union.getStoredMinimumAlignment());
			UnionDB unionDB =
				new UnionDB(this, dtCache, compositeAdapter, componentAdapter, record);

			// Make sure category knows about union before replace is performed
			category.dataTypeAdded(unionDB);

			unionDB.doReplaceWith(union, false);
			unionDB.setDescription(union.getDescription());
//			unionDB.notifySizeChanged();
			// doReplaceWith updated the last change time so set it back to what we want.
			unionDB.setLastChangeTime(union.getLastChangeTime());

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
			enumValueAdapter.createRecord(enumID, enumName, enumm.getValue(enumName));
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
		if (dt instanceof FactoryDataType) {
			throw new IllegalArgumentException(
				"Array data-type may not be a Factory data-type: " + dt.getName());
		}
		if (dt instanceof Dynamic && !((Dynamic) dt).canSpecifyLength()) {
			throw new IllegalArgumentException(
				"Array data-type may not be a non-sizable Dynamic data-type: " + dt.getName());
		}
		if (elementLength <= 0) {
			throw new IllegalArgumentException("Array data-type must be Fixed length");
		}
		if (numElements <= 0) {
			throw new IllegalArgumentException(
				"number of array elements must be positive, not " + numElements);
		}
		dt = resolve(dt, handler);
		long dataTypeID = getResolvedID(dt);
		if (!(dt instanceof Dynamic)) {
			elementLength = -1;
		}

		DBRecord record =
			arrayAdapter.createRecord(dataTypeID, numElements, elementLength, cat.getID());
		addParentChildRecord(record.getKey(), dataTypeID);
		ArrayDB arrayDB = new ArrayDB(this, dtCache, arrayAdapter, record);
		dt.addParent(arrayDB);
		return arrayDB;
	}

	private void updateLastChangeTime() {
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
			DBRecord record =
				functionDefAdapter.createRecord(name, funDef.getComment(), cat.getID(),
					DEFAULT_DATATYPE_ID, funDef.hasVarArgs(), funDef.getGenericCallingConvention(),
					sourceArchiveIdValue, universalIdValue, funDef.getLastChangeTime());
			FunctionDefinitionDB funDefDb =
				new FunctionDefinitionDB(this, dtCache, functionDefAdapter, paramAdapter, record);

			// Make sure category knows about function definition before args/return resolved
			cat.dataTypeAdded(funDefDb);

			funDefDb.setArguments(funDef.getArguments());
			funDefDb.setReturnType(funDef.getReturnType());

			// setArguments updated the last change time so set it back to what we want.
			funDefDb.setLastChangeTime(funDef.getLastChangeTime());

			return funDefDb;
		}
		finally {
			creatingDataType--;
		}
	}

	class StructureIterator implements Iterator<Structure> {
		private RecordIterator it;
		private StructureDB nextStruct;

		StructureIterator() throws IOException {
			it = compositeAdapter.getRecords();
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException("Remove not supported");
		}

		@Override
		public boolean hasNext() {
			if (nextStruct == null) {
				getNextStruct();
			}
			return nextStruct != null;
		}

		@Override
		public StructureDB next() {
			if (hasNext()) {
				StructureDB s = nextStruct;
				nextStruct = null;
				return s;
			}
			return null;
		}

		private void getNextStruct() {
			try {
				while (it.hasNext()) {
					DBRecord rec = it.next();
					DataType dt = getDataType(rec.getKey(), rec);
					if (dt instanceof Structure) {
						nextStruct = (StructureDB) dt;
						return;
					}
				}
			}
			catch (IOException e) {
				Msg.error(this, "Unexpected exception iterating structures", e);
			}
		}
	}

	class CompositeIterator implements Iterator<Composite> {
		private RecordIterator it;
		private CompositeDB nextComposite;

		CompositeIterator() throws IOException {
			it = compositeAdapter.getRecords();
		}

		@Override
		public void remove() {
			throw new UnsupportedOperationException("Remove not supported");
		}

		@Override
		public boolean hasNext() {
			if (nextComposite == null) {
				getNextComposite();
			}
			return nextComposite != null;
		}

		@Override
		public CompositeDB next() {
			if (hasNext()) {
				CompositeDB c = nextComposite;
				nextComposite = null;
				return c;
			}
			return null;
		}

		private void getNextComposite() {
			try {
				if (it.hasNext()) {
					DBRecord rec = it.next();
					nextComposite = (CompositeDB) getDataType(rec.getKey(), rec);
				}
			}
			catch (IOException e) {
				Msg.error(this, "Unexpected exception iterating composites", e);
			}
		}
	}

	private class NameComparator implements Comparator<DataType> {
		/**
		 * Compares its two arguments for order. Returns a negative integer, zero, or a
		 * positive integer as the first argument is less than, equal to, or greater
		 * than the second.
		 * <p>
		 *
		 * @param d1 the first datatype to be compared
		 * @param d2 the second datatype to be compared
		 * @return a negative integer, zero, or a positive integer as the first argument
		 *         is less than, equal to, or greater than the second
		 * @throws ClassCastException if the arguments' types prevent them from being
		 *                            compared by this Comparator
		 */
		@Override
		public int compare(DataType d1, DataType d2) {
			int c = d1.getName().compareTo(d2.getName());
			if (c == 0) {
				return d1.getCategoryPath().compareTo(d2.getCategoryPath());
			}
			return c;
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
		if (!(dt instanceof Array) && !(dt instanceof Pointer)) {
			try {
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
			catch (IOException e) {
				dbError(e);
			}
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
	public Iterator<Structure> getAllStructures() {
		try {
			return new StructureIterator();
		}
		catch (IOException e) {
			dbError(e);
		}
		return (new ArrayList<Structure>()).iterator();
	}

	@Override
	public Iterator<Composite> getAllComposites() {
		try {
			return new CompositeIterator();
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
			dtCache.invalidate();
			sourceArchiveDBCache.invalidate();
			invalidateSourceArchiveCache();
			builtInMap.clear();
			builtIn2IdMap.clear();
			root.setInvalid();
			catCache.invalidate();
			settingsCache.clear();
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

	/**
	 * Set the long value for instance settings.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @param value    value of setting
	 * @return true if the settings actually changed
	 */

	public boolean setLongSettingsValue(Address dataAddr, String name, long value) {

		return updateInstanceSettings(dataAddr, name, null, value, null);
	}

	/**
	 * Set the string value for instance settings.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @param value    value of setting
	 * @return true if the settings actually changed
	 */
	public boolean setStringSettingsValue(Address dataAddr, String name, String value) {
		return updateInstanceSettings(dataAddr, name, value, -1, null);
	}

	/**
	 * Set the byte array value for instance settings.
	 * 
	 * @param dataAddr  min address of data ata
	 * @param name      settings name
	 * @param byteValue byte array value of setting
	 * @return true if the settings actually changed
	 */
	public boolean setByteSettingsValue(Address dataAddr, String name, byte[] byteValue) {
		return updateInstanceSettings(dataAddr, name, null, -1, byteValue);
	}

	/**
	 * Set the Object settings.
	 * 
	 * @param dataAddr min address of data
	 * @param name     the name of the settings
	 * @param value    the value for the settings, must be either a String, byte[]
	 *                 or Long
	 * @return true if the settings were updated
	 */
	public boolean setSettings(Address dataAddr, String name, Object value) {
		if (value instanceof String) {
			return updateInstanceSettings(dataAddr, name, (String) value, -1, null);
		}
		else if (value instanceof byte[]) {
			return updateInstanceSettings(dataAddr, name, null, -1, (byte[]) value);
		}
		else if (isAllowedNumberType(value)) {
			return updateInstanceSettings(dataAddr, name, null, ((Number) value).longValue(), null);
		}
		throw new IllegalArgumentException(
			"Unsupportd Settings Value: " + (value == null ? "null" : value.getClass().getName()));
	}

	private boolean isAllowedNumberType(Object value) {
		if (value instanceof Long) {
			return true;
		}
		if (value instanceof Integer) {
			return true;
		}
		if (value instanceof Short) {
			return true;
		}
		if (value instanceof Byte) {
			return true;
		}
		return false;
	}

	/**
	 * Get the long value for an instance setting.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @return null if the named setting was not found
	 */
	public Long getLongSettingsValue(Address dataAddr, String name) {
		InstanceSettingsDB settings = getInstanceSettingsDB(dataAddr, name);
		if (settings != null) {
			return settings.getLongValue();
		}
		return null;
	}

	/**
	 * Get the String value for an instance setting.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @return null if the named setting was not found
	 */
	public String getStringSettingsValue(Address dataAddr, String name) {
		InstanceSettingsDB settings = getInstanceSettingsDB(dataAddr, name);
		if (settings != null) {
			return settings.getStringValue();
		}
		return null;
	}

	/**
	 * Get the byte array value for an instance setting.
	 * 
	 * @param dataAddr min address of data
	 * @param name     settings name
	 * @return null if the named setting was not found
	 */
	public byte[] getByteSettingsValue(Address dataAddr, String name) {

		InstanceSettingsDB settings = getInstanceSettingsDB(dataAddr, name);
		if (settings != null) {
			return settings.getByteValue();
		}
		return null;
	}

	/**
	 * Gets the value of a settings as an object (either String, byte[], or Long).
	 * 
	 * @param dataAddr the address of the data for this settings
	 * @param name     the name of settings.
	 * @return the settings object
	 */
	public Object getSettings(Address dataAddr, String name) {
		Object obj = getStringSettingsValue(dataAddr, name);
		if (obj != null) {
			return obj;
		}
		obj = getByteSettingsValue(dataAddr, name);
		if (obj != null) {
			return obj;
		}
		return getLongSettingsValue(dataAddr, name);
	}

	/**
	 * Clear the setting
	 * 
	 * @param dataAddr min address of data
	 * @param name settings name
	 * @return true if the settings were cleared
	 */
	public boolean clearSetting(Address dataAddr, String name) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			InstanceSettingsDB settings = getInstanceSettingsDB(dataAddr, name);
			if (settings != null) {
				long key = settings.getKey();
				settingsCache.remove(dataAddr, name);
				instanceSettingsAdapter.removeInstanceRecord(key);
				return true;
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
		return false;
	}

	/**
	 * Clear all settings at the given address.
	 * 
	 * @param dataAddr the address for this settings.
	 */
	public void clearAllSettings(Address dataAddr) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			settingsCache.clear();
			Field[] keys = instanceSettingsAdapter.getInstanceKeys(addrMap.getKey(dataAddr, false));
			for (Field key : keys) {
				instanceSettingsAdapter.removeInstanceRecord(key.getLongValue());
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);

		}
		finally {
			lock.release();
		}
	}

	/**
	 * Clears all settings in the given address range.
	 * 
	 * @param start   the first address of the range to clear
	 * @param end     the last address of the range to clear.
	 * @param monitor the progress monitor for this operation.
	 * @throws CancelledException if the user cancels the operation.
	 */
	public void clearSettings(Address start, Address end, TaskMonitor monitor)
			throws CancelledException {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			settingsCache.clear();
			List<KeyRange> keyRanges = addrMap.getKeyRanges(start, end, false);
			for (KeyRange range : keyRanges) {
				RecordIterator iter =
					instanceSettingsAdapter.getRecords(range.minKey, range.maxKey);
				while (iter.hasNext()) {
					if (monitor.isCancelled()) {
						throw new CancelledException();
					}
					iter.next();
					iter.delete();
				}
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
	}

	/**
	 * Move the settings in the range to the new start address
	 * 
	 * @param fromAddr start address from where to move
	 * @param toAddr   new Address to move to
	 * @param length   number of addresses to move
	 * @param monitor  progress monitor
	 * @throws CancelledException if the operation was cancelled
	 */
	public void moveAddressRange(Address fromAddr, Address toAddr, long length, TaskMonitor monitor)
			throws CancelledException {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}

		DBHandle scratchPad = null;
		lock.acquire();
		try {
			settingsCache.clear();
			scratchPad = dbHandle.getScratchPad();
			Table tmpTable = scratchPad.createTable(InstanceSettingsDBAdapter.INSTANCE_TABLE_NAME,
				InstanceSettingsDBAdapterV0.V0_INSTANCE_SCHEMA);

			List<KeyRange> keyRanges =
				addrMap.getKeyRanges(fromAddr, fromAddr.add(length - 1), false);
			for (KeyRange range : keyRanges) {
				RecordIterator iter =
					instanceSettingsAdapter.getRecords(range.minKey, range.maxKey);
				while (iter.hasNext()) {
					monitor.checkCanceled();
					DBRecord rec = iter.next();
					tmpTable.putRecord(rec);
					iter.delete();
				}
			}

			RecordIterator iter = tmpTable.iterator();
			while (iter.hasNext()) {
				monitor.checkCanceled();
				DBRecord rec = iter.next();
				// update address column and re-introduce into table
				Address addr = addrMap.decodeAddress(
					rec.getLongValue(InstanceSettingsDBAdapter.INST_ADDR_COL));
				long offset = addr.subtract(fromAddr);
				addr = toAddr.add(offset);
				rec.setLongValue(InstanceSettingsDBAdapter.INST_ADDR_COL,
					addrMap.getKey(addr, true));
				instanceSettingsAdapter.updateInstanceRecord(rec);
			}

		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			if (scratchPad != null) {
				try {
					scratchPad.deleteTable(InstanceSettingsDBAdapter.INSTANCE_TABLE_NAME);
				}
				catch (IOException e) {
					// ignore
				}
			}
			lock.release();
		}
	}

	@Override
	public boolean isUpdatable() {
		return dbHandle.canUpdate();
	}

	/**
	 * Returns all the Settings names for the given address
	 * 
	 * @param dataAddr the address
	 * @return the names
	 */
	public String[] getNames(Address dataAddr) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			Field[] keys = instanceSettingsAdapter.getInstanceKeys(addrMap.getKey(dataAddr, false));
			ArrayList<String> list = new ArrayList<>();
			for (Field key : keys) {
				DBRecord rec = instanceSettingsAdapter.getInstanceRecord(key.getLongValue());
				list.add(rec.getString(InstanceSettingsDBAdapter.INST_NAME_COL));
			}
			String[] names = new String[list.size()];
			return list.toArray(names);
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}
		return null;
	}

	/**
	 * Returns true if no settings are set for the given address
	 * 
	 * @param dataAddr the address to test
	 * @return true if not settings
	 */
	public boolean isEmptySetting(Address dataAddr) {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		try {
			return instanceSettingsAdapter.getInstanceKeys(
				addrMap.getKey(dataAddr, false)).length == 0;
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return true;
	}

	private boolean updateInstanceSettings(Address dataAddr, String name, String strValue,
			long longValue, byte[] byteValue) {

		boolean wasChanged = false;

		lock.acquire();
		try {
			if (instanceSettingsAdapter == null) {
				throw new UnsupportedOperationException();
			}

			InstanceSettingsDB settings = getInstanceSettingsDB(dataAddr, name);
			if (settings == null) {
				wasChanged = true;
				// create new record

				DBRecord rec = instanceSettingsAdapter.createInstanceRecord(
					addrMap.getKey(dataAddr, true), name, strValue, longValue, byteValue);
				settings = new InstanceSettingsDB(rec);
				settingsCache.put(dataAddr, name, settings);
			}
			else {
				DBRecord rec = settings.getRecord();
				String recStrValue = rec.getString(SettingsDBAdapter.SETTINGS_STRING_VALUE_COL);
				byte[] recByteValue = rec.getBinaryData(SettingsDBAdapter.SETTINGS_BYTE_VALUE_COL);
				long recLongValue = rec.getLongValue(SettingsDBAdapter.SETTINGS_LONG_VALUE_COL);
				wasChanged = SettingsDBManager.valuesChanged(recStrValue, strValue, byteValue,
					recByteValue, recLongValue, longValue);
				if (wasChanged) {
					rec.setString(InstanceSettingsDBAdapter.INST_STRING_VALUE_COL, strValue);
					rec.setLongValue(InstanceSettingsDBAdapter.INST_LONG_VALUE_COL, longValue);
					rec.setBinaryData(InstanceSettingsDBAdapter.INST_BYTE_VALUE_COL, byteValue);
					instanceSettingsAdapter.updateInstanceRecord(rec);
				}
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		finally {
			lock.release();
		}

		return wasChanged;
	}

	private InstanceSettingsDB getInstanceSettingsDB(Address dataAddr, String name) {
		lock.acquire();
		try {
			if (instanceSettingsAdapter == null) {
				throw new UnsupportedOperationException();
			}
			InstanceSettingsDB settings = settingsCache.getInstanceSettings(dataAddr, name);
			if (settings != null) {
				return settings;
			}
			long addr = addrMap.getKey(dataAddr, false);
			DBRecord rec = getInstanceRecord(addr, name);
			if (rec != null) {
				settings = new InstanceSettingsDB(rec);
				settingsCache.put(dataAddr, name, settings);
				return settings;
			}
			return null;
		}
		finally {
			lock.release();
		}
	}

	private DBRecord getInstanceRecord(long addr, String name) {
		try {
			Field[] keys = instanceSettingsAdapter.getInstanceKeys(addr);
			for (Field key : keys) {
				DBRecord rec = instanceSettingsAdapter.getInstanceRecord(key.getLongValue());
				if (rec.getString(InstanceSettingsDBAdapter.INST_NAME_COL).equals(name)) {
					return rec;
				}
			}
		}
		catch (IOException e) {
			errHandler.dbError(e);
		}
		return null;
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

	void removeParentChildRecord(long parentID, long childID) {

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

	List<DataType> getParentDataTypes(long childID) {
		lock.acquire();
		try {
			long[] ids = parentChildAdapter.getParentIds(childID);
			List<DataType> dts = new ArrayList<>();
			for (long id : ids) {
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
	public Set<DataType> getDataTypesContaining(DataType dataType) {
		Set<DataType> set = new HashSet<>();
		if (dataType instanceof DataTypeDB) {
			long dataTypeID = ((DataTypeDB) dataType).getKey();
			try {
				long[] ids = parentChildAdapter.getParentIds(dataTypeID);
				for (long id : ids) {
					set.add(getDataType(id));
				}
			}
			catch (IOException e) {
				dbError(e);
			}
		}
		return set;
	}

	@Override
	public Pointer getPointer(DataType dt) {
		return new PointerDataType(dt, -1, this);
	}

	@Override
	public Pointer getPointer(DataType dt, int size) {
		return new PointerDataType(dt, size, this);
	}

	/**
	 * Removes all settings in the range
	 * 
	 * @param startAddr the first address in the range.
	 * @param endAddr   the last address in the range.
	 * @param monitor   the progress monitor
	 * @throws CancelledException if the user cancelled the operation.
	 */
	public void deleteAddressRange(Address startAddr, Address endAddr, TaskMonitor monitor)
			throws CancelledException {
		if (instanceSettingsAdapter == null) {
			throw new UnsupportedOperationException();
		}
		lock.acquire();
		try {
			List<?> addrKeyRanges = addrMap.getKeyRanges(startAddr, endAddr, false);
			int cnt = addrKeyRanges.size();
			for (int i = 0; i < cnt; i++) {
				KeyRange kr = (KeyRange) addrKeyRanges.get(i);
				instanceSettingsAdapter.delete(kr.minKey, kr.maxKey, monitor);
			}
		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			settingsCache.clear();
			lock.release();
		}
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

	@Override
	public void dataTypeChanged(DataType dt, boolean isAutoChange) {
		if (dt instanceof Enum) {
			enumValueMap = null;
		}
		if (creatingDataType == 0) {
			updateLastChangeTime();
			setDirtyFlag(dt);
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
	public DataOrganization getDataOrganization() {
		if (dataOrganization == null) {
			dataOrganization = DataOrganizationImpl.getDefaultOrganization();
		}
		return dataOrganization;
	}

	private boolean checkForSourceArchiveUpdatesNeeded(int openMode, TaskMonitor monitor)
			throws IOException {
		if (openMode == DBConstants.CREATE || openMode == DBConstants.READ_ONLY) {
			return false;
		}
		List<DBRecord> records = sourceArchiveAdapter.getRecords();
		for (DBRecord record : records) {
			if (SourceArchiveUpgradeMap.isReplacedSourceArchive(record.getKey())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * This method is only invoked during an upgrade.
	 * 
	 * @param compilerSpec compiler spec
	 * @param monitor      task monitor
	 * @throws CancelledException if task cacn
	 */
	protected void doSourceArchiveUpdates(CompilerSpec compilerSpec, TaskMonitor monitor)
			throws CancelledException {
		SourceArchiveUpgradeMap upgradeMap = new SourceArchiveUpgradeMap();
		for (SourceArchive sourceArchive : getSourceArchives()) {
			SourceArchive mappedSourceArchive =
				upgradeMap.getMappedSourceArchive(sourceArchive, compilerSpec);
			if (mappedSourceArchive != null) {
				replaceSourceArchive(sourceArchive, mappedSourceArchive);
			}
		}
		BuiltInDataTypeManager builtInDTM = BuiltInDataTypeManager.getDataTypeManager();
		for (String name : SourceArchiveUpgradeMap.getTypedefReplacements()) {
			monitor.checkCanceled();
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
	 * @throws CancelledException if operation is cancelled
	 */
	public void fixupComposites(TaskMonitor monitor) throws CancelledException {
		lock.acquire();
		try {

			// NOTE: Any composite could be indirectly affected by a component size change
			// based upon type relationships

			// NOTE: Composites brought in from archive may have incorrect component size
			// if not aligned and should not be used to guage a primitive size change

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
				monitor.checkCanceled();
				c.fixupComponents();
				monitor.setProgress(++count);
			}

		}
		catch (IOException e) {
			dbError(e);
		}
		finally {
			lock.release();
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
			monitor.checkCanceled();
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
	 * Activate resolveCache and associated resolveQueue if not already active. If
	 * this method returns true caller is responsible for flushing resolveQueue and
	 * invoking {@link #flushResolveQueue(boolean)} when resolve complete. 
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

	void flushResolveQueue(boolean deactivateCache) {
		try {
			if (resolveQueue != null) {
				DataTypeConflictHandler handler = getDependencyConflictHandler();
				while (!resolveQueue.isEmpty()) {
					ResolvePair resolvePair = resolveQueue.pollFirst();
					DataTypeDB resolvedDt = resolvePair.resolvedDt;
					try {
						resolvedDt.postPointerResolve(resolvePair.definitionDt, handler);
					}
					// TODO: catch exceptions if needed
					finally {
						resolvedDt.resolving = false;
						resolvedDt.pointerPostResolveRequired = false;
					}
				}
			}
		}
		finally {
			resolveQueue = null;
			if (deactivateCache) {
				resolveCache = null;
			}
		}
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
		public void dbError(IOException e) {

			String message = e.getMessage();
			if (e instanceof ClosedException) {
				message = "Data type archive is closed: " + getName();
			}

			Msg.showError(this, null, "IO ERROR", message, e);
		}
	}
}

/**
 * Cached object for the instance settings.
 */
class InstanceSettingsDB {

	private DBRecord record;

	InstanceSettingsDB(DBRecord record) {
		this.record = record;
	}

	public long getKey() {
		return record.getKey();
	}

	byte[] getByteValue() {
		return record.getBinaryData(InstanceSettingsDBAdapter.INST_BYTE_VALUE_COL);
	}

	String getStringValue() {
		return record.getString(InstanceSettingsDBAdapter.INST_STRING_VALUE_COL);
	}

	Long getLongValue() {
		return record.getLongValue(InstanceSettingsDBAdapter.INST_LONG_VALUE_COL);
	}

	DBRecord getRecord() {
		return record;
	}

	protected boolean refresh() {
		return false;
	}
}

class CategoryCache extends FixedSizeHashMap<String, Category> {
	private static final int CACHE_SIZE = 100;

	CategoryCache() {
		super(CACHE_SIZE, CACHE_SIZE);
	}
}
