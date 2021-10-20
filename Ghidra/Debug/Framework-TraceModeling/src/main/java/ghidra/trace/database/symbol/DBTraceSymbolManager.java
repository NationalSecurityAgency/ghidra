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
package ghidra.trace.database.symbol;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;

import com.google.common.collect.*;

import db.*;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.data.DBTraceDataTypeManager;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.DBTraceSpaceKey;
import ghidra.trace.database.thread.DBTraceThread;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceFunctionTagChangeType;
import ghidra.trace.model.Trace.TraceSymbolChangeType;
import ghidra.trace.model.symbol.*;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.annot.*;
import ghidra.util.exception.*;
import ghidra.util.task.TaskMonitor;

/*
 * TODO: A place to store and track dynamic symbols. It looks like dynamic symbols are always
 * labels, and they exist at addresses where there exist references to, but there is no
 * user-defined label or function.
 * 
 * TODO: See if CALL-type references produce dynamic labels or functions.
 */
public class DBTraceSymbolManager implements TraceSymbolManager, DBTraceManager {
	protected static final byte DEFAULT_CALLING_CONVENTION_ID = -1;
	protected static final byte UNKNOWN_CALLING_CONVENTION_ID = -2;

	protected static final String DEFAULT_CALLING_CONVENTION_NAME = "default";
	protected static final String UNKNOWN_CALLING_CONVENTION_NAME = "unknown";

	private static final long TYPE_MASK = 0xFF;
	private static final int TYPE_SHIFT = 64 - 8;

	private static final long KEY_MASK = 0x00FF_FFFF_FFFF_FFFFL;
	private static final int KEY_SHIFT = 0;

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceSymbolIDEntry
			extends AbstractDBTraceAddressSnapRangePropertyMapData<Long> {
		static final String ID_COLUMN_NAME = "ID";

		@DBAnnotatedColumn(ID_COLUMN_NAME)
		static DBObjectColumn ID_COLUMN;

		@DBAnnotatedField(column = ID_COLUMN_NAME, indexed = true)
		long symbolID;

		public DBTraceSymbolIDEntry(DBTraceAddressSnapRangePropertyMapTree<Long, ?> tree,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(tree, store, record);
		}

		@Override
		protected void setRecordValue(Long symbolID) {
			assert symbolID != null;
			this.symbolID = symbolID;
			update(ID_COLUMN);
		}

		@Override
		protected Long getRecordValue() {
			return symbolID;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceCallingConventionEntry extends DBAnnotatedObject {
		static final String TABLE_NAME = "CallingConventions";

		static final String NAME_COLUMN_NAME = "Name";

		@DBAnnotatedColumn(NAME_COLUMN_NAME)
		static DBObjectColumn NAME_COLUMN;

		@DBAnnotatedField(column = NAME_COLUMN_NAME)
		String name;

		public DBTraceCallingConventionEntry(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		public void setName(String name) {
			this.name = name;
			update(NAME_COLUMN);
		}

		public String getName() {
			return name;
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceFunctionTag extends DBAnnotatedObject implements FunctionTag {

		static final String TABLE_NAME = "FunctionTags";

		static final String NAME_COLUMN_NAME = "Name";
		static final String COMMENT_COLUMN_NAME = "Comment";

		@DBAnnotatedColumn(NAME_COLUMN_NAME)
		static DBObjectColumn NAME_COLUMN;
		@DBAnnotatedColumn(COMMENT_COLUMN_NAME)
		static DBObjectColumn COMMENT_COLUMN;

		@DBAnnotatedField(column = NAME_COLUMN_NAME, indexed = true)
		String name;
		@DBAnnotatedField(column = COMMENT_COLUMN_NAME)
		String comment;

		protected final DBTraceSymbolManager manager;

		public DBTraceFunctionTag(DBTraceSymbolManager manager, DBCachedObjectStore<?> store,
				DBRecord record) {
			super(store, record);
			this.manager = manager;
		}

		protected void set(String name, String comment) {
			this.name = name;
			this.comment = comment;
			update(NAME_COLUMN, COMMENT_COLUMN);
		}

		@Override
		public int hashCode() {
			return Long.hashCode(key);
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof FunctionTag)) {
				return false;
			}
			if (obj == this) {
				return true;
			}
			FunctionTag that = (FunctionTag) obj;
			if (!Objects.equals(this.getName(), that.getName())) {
				return false;
			}
			if (!Objects.equals(this.getComment(), that.getComment())) {
				return false;
			}
			return true;
		}

		@Override
		public int compareTo(FunctionTag o) {
			int result;
			result = this.getName().compareToIgnoreCase(o.getName());
			if (result != 0) {
				return result;
			}
			result = this.getComment().compareToIgnoreCase(o.getComment());
			if (result != 0) {
				return result;
			}
			return 0;
		}

		@Override
		public long getId() {
			return key;
		}

		@Override
		public String getName() {
			try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
				return name;
			}
		}

		@Override
		public String getComment() {
			try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
				return comment;
			}
		}

		@Override
		public void setName(String name) {
			try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
				this.name = name;
				update(NAME_COLUMN);
			}
			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceFunctionTagChangeType.CHANGED, null, this));
		}

		@Override
		public void setComment(String comment) {
			try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
				this.comment = comment;
				update(COMMENT_COLUMN);
			}
			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceFunctionTagChangeType.CHANGED, null, this));
		}

		@Override
		public void delete() {
			try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
				for (DBTraceFunctionTagMapping mapping : manager.tagMappingsByTag.get(key)) {
					manager.tagMappingStore.delete(mapping);
				}
				manager.tagStore.delete(this);
			}
			manager.trace.setChanged(
				new TraceChangeRecord<>(TraceFunctionTagChangeType.DELETED, null, this));
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceFunctionTagMapping extends DBAnnotatedObject {

		static final String TABLE_NAME = "FunctionTagMappings";

		static final String FUNCTION_COLUMN_NAME = "Function";
		static final String TAG_COLUMN_NAME = "Tag";

		@DBAnnotatedColumn(FUNCTION_COLUMN_NAME)
		static DBObjectColumn FUNCTION_COLUMN;
		@DBAnnotatedColumn(TAG_COLUMN_NAME)
		static DBObjectColumn TAG_COLUMN;

		@DBAnnotatedField(column = FUNCTION_COLUMN_NAME, indexed = true)
		private long functionKey;
		@DBAnnotatedField(column = TAG_COLUMN_NAME, indexed = true)
		private long tagKey;

		public DBTraceFunctionTagMapping(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		protected void set(DBTraceFunctionSymbol function, DBTraceFunctionTag tag) {
			this.functionKey = function.getKey();
			this.tagKey = tag.getKey();
			update(FUNCTION_COLUMN, TAG_COLUMN);
		}

		public long getFunctionKey() {
			return functionKey;
		}

		public long getTagKey() {
			return tagKey;
		}
	}

	public static class VariableStorageDBFieldCodec extends
			AbstractDBFieldCodec<VariableStorage, DBTraceVariableStorageEntry, StringField> {

		public VariableStorageDBFieldCodec(Class<DBTraceVariableStorageEntry> objectType,
				Field field, int column) {
			super(VariableStorage.class, objectType, StringField.class, field, column);
		}

		@Override
		public void store(VariableStorage value, StringField f) {
			f.setString(value == null ? null : value.getSerializationString());
		}

		@Override
		protected void doStore(DBTraceVariableStorageEntry obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			VariableStorage value = getValue(obj);
			record.setString(column, value == null ? null : value.getSerializationString());
		}

		@Override
		protected void doLoad(DBTraceVariableStorageEntry obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			String serial = record.getString(column);
			try {
				setValue(obj,
					serial == null ? null : VariableStorage.deserialize(obj.getProgram(), serial));
			}
			catch (InvalidInputException e) {
				throw new AssertionError("Database corruption", e); // TODO: A better exception
			}
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	public static class DBTraceVariableStorageEntry extends DBAnnotatedObject {

		static final String TABLE_NAME = "VariableStorage";

		static final String STORAGE_COLUMN_NAME = "Storage";

		@DBAnnotatedColumn(STORAGE_COLUMN_NAME)
		static DBObjectColumn STORAGE_COLUMN;

		@DBAnnotatedField(
			column = STORAGE_COLUMN_NAME,
			indexed = true,
			codec = VariableStorageDBFieldCodec.class)
		private VariableStorage storage;

		protected final DBTraceSymbolManager manager;

		public DBTraceVariableStorageEntry(DBTraceSymbolManager manager,
				DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
			this.manager = manager;
		}

		void set(VariableStorage storage) {
			this.storage = storage;
			update(STORAGE_COLUMN);
		}

		public Program getProgram() {
			return manager.trace.getProgramView();
		}

		public VariableStorage getStorage() {
			return storage;
		}
	}

	public static enum MySymbolTypes {
		LABEL {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return true;
			}
		},
		NO_LIBRARY {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return false;
			}
		},
		NO_NULL {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return false;
			}
		},
		NAMESPACE {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return true;
			}
		},
		CLASS {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return isNoFunctionAncestor(parent);
			}
		},
		FUNCTION {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return isNoFunctionAncestor(parent);
			}
		},
		PARAMETER {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return parent instanceof Function;
			}
		},
		LOCAL_VAR {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return parent instanceof Function;
			}
		},
		GLOBAL_VAR {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return parent.getSymbolType() == SymbolType.GLOBAL;
			}
		};

		abstract boolean isValidParent(DBTraceNamespaceSymbol parent);

		boolean isNoFunctionAncestor(DBTraceNamespaceSymbol parent) {
			for (DBTraceNamespaceSymbol p = parent; p != null; p = p.parent) {
				if (p instanceof Function) {
					return false;
				}
			}
			return true;
		}
	}

	protected final DBTrace trace;
	protected final ReadWriteLock lock;
	protected final DBTraceThreadManager threadManager;
	protected final DBTraceDataTypeManager dataTypeManager;
	protected final DBTraceOverlaySpaceAdapter overlayAdapter;

	protected final DBTraceAddressSnapRangePropertyMap<Long, DBTraceSymbolIDEntry> idMap;

	protected final DBCachedObjectStore<DBTraceCallingConventionEntry> callingConventionStore;
	protected final BiMap<String, Byte> callingConventionMap = HashBiMap.create();

	protected final DBCachedObjectStore<DBTraceFunctionTag> tagStore;
	protected final DBCachedObjectIndex<String, DBTraceFunctionTag> tagsByName;

	protected final DBCachedObjectStore<DBTraceFunctionTagMapping> tagMappingStore;
	protected final DBCachedObjectIndex<Long, DBTraceFunctionTagMapping> tagMappingsByFunc;
	protected final DBCachedObjectIndex<Long, DBTraceFunctionTagMapping> tagMappingsByTag;

	protected final DBCachedObjectStore<DBTraceVariableStorageEntry> storageStore;
	protected final DBCachedObjectIndex<VariableStorage, DBTraceVariableStorageEntry> storageByStorage;

	protected final DBCachedObjectStore<DBTraceLabelSymbol> labelStore;
	protected final DBCachedObjectStore<DBTraceNamespaceSymbol> namespaceStore;
	protected final DBCachedObjectStore<DBTraceClassSymbol> classStore;
	protected final DBCachedObjectStore<DBTraceFunctionSymbol> functionStore;
	protected final DBCachedObjectIndex<Long, DBTraceFunctionSymbol> functionsByThunked;
	protected final DBCachedObjectStore<DBTraceParameterSymbol> parameterStore;
	protected final DBCachedObjectStore<DBTraceLocalVariableSymbol> localVarStore;
	// Seems only for "global register" variables
	protected final DBCachedObjectStore<DBTraceGlobalVariableSymbol> globalVarStore;
	protected final DBTraceNamespaceSymbol globalNamespace;

	protected final DBTraceLabelSymbolView labels;
	protected final DBTraceNamespaceSymbolView namespaces;
	protected final DBTraceClassSymbolView classes;
	protected final DBTraceFunctionSymbolView functions;
	protected final DBTraceParameterSymbolView parameters;
	protected final DBTraceLocalVariableSymbolView localVars;
	protected final DBTraceGlobalVariableSymbolView globalVars;

	protected final DBTraceSymbolMultipleTypesView<? extends DBTraceNamespaceSymbol> allNamespaces;
	protected final DBTraceSymbolMultipleTypesNoDuplicatesView<? extends DBTraceNamespaceSymbol> uniqueNamespaces;
	protected final DBTraceSymbolMultipleTypesWithAddressNoDuplicatesView<? extends AbstractDBTraceVariableSymbol> allLocals;
	protected final DBTraceSymbolMultipleTypesWithAddressNoDuplicatesView<?> allVariables;
	protected final DBTraceSymbolMultipleTypesWithLocationView<?> labelsAndFunctions;
	protected final DBTraceSymbolMultipleTypesNoDuplicatesView<?> notLabelsNorFunctions;
	protected final DBTraceSymbolMultipleTypesView<?> allSymbols;

	protected final Map<Byte, AbstractDBTraceSymbolSingleTypeView<?>> symbolViews = new HashMap<>();

	public DBTraceSymbolManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager, DBTraceDataTypeManager dataTypeManager,
			DBTraceOverlaySpaceAdapter overlayAdapter)
			throws VersionException, IOException {
		this.trace = trace;
		this.lock = lock;
		this.threadManager = threadManager;
		this.dataTypeManager = dataTypeManager;
		this.overlayAdapter = overlayAdapter;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		idMap = new DBTraceAddressSnapRangePropertyMap<>("SymbolIDs", dbh, openMode, lock, monitor,
			baseLanguage, trace, threadManager, DBTraceSymbolIDEntry.class,
			DBTraceSymbolIDEntry::new);

		callingConventionStore =
			factory.getOrCreateCachedStore(DBTraceCallingConventionEntry.TABLE_NAME,
				DBTraceCallingConventionEntry.class, DBTraceCallingConventionEntry::new, true);
		loadCallingConventions();

		tagStore = factory.getOrCreateCachedStore(DBTraceFunctionTag.TABLE_NAME,
			DBTraceFunctionTag.class, (s, r) -> new DBTraceFunctionTag(this, s, r), true);
		tagsByName = tagStore.getIndex(String.class, DBTraceFunctionTag.NAME_COLUMN);

		tagMappingStore = factory.getOrCreateCachedStore(DBTraceFunctionTagMapping.TABLE_NAME,
			DBTraceFunctionTagMapping.class, DBTraceFunctionTagMapping::new, true);
		tagMappingsByFunc =
			tagMappingStore.getIndex(long.class, DBTraceFunctionTagMapping.FUNCTION_COLUMN);
		tagMappingsByTag =
			tagMappingStore.getIndex(long.class, DBTraceFunctionTagMapping.TAG_COLUMN);

		storageStore = factory.getOrCreateCachedStore(DBTraceVariableStorageEntry.TABLE_NAME,
			DBTraceVariableStorageEntry.class,
			(s, r) -> new DBTraceVariableStorageEntry(this, s, r), true);
		storageByStorage = storageStore.getIndex(VariableStorage.class,
			DBTraceVariableStorageEntry.STORAGE_COLUMN);

		labelStore = factory.getOrCreateCachedStore(DBTraceLabelSymbol.TABLE_NAME,
			DBTraceLabelSymbol.class, (s, r) -> new DBTraceLabelSymbol(this, s, r), true);
		namespaceStore = factory.getOrCreateCachedStore(DBTraceNamespaceSymbol.TABLE_NAME,
			DBTraceNamespaceSymbol.class, (s, r) -> new DBTraceNamespaceSymbol(this, s, r), true);
		classStore = factory.getOrCreateCachedStore(DBTraceClassSymbol.TABLE_NAME,
			DBTraceClassSymbol.class, (s, r) -> new DBTraceClassSymbol(this, s, r), true);
		functionStore = factory.getOrCreateCachedStore(DBTraceFunctionSymbol.TABLE_NAME,
			DBTraceFunctionSymbol.class, (s, r) -> new DBTraceFunctionSymbol(this, s, r), true);
		functionsByThunked =
			functionStore.getIndex(long.class, DBTraceFunctionSymbol.THUNKED_COLUMN);
		parameterStore = factory.getOrCreateCachedStore(DBTraceParameterSymbol.TABLE_NAME,
			DBTraceParameterSymbol.class, (s, r) -> new DBTraceParameterSymbol(this, s, r), true);
		localVarStore = factory.getOrCreateCachedStore(DBTraceLocalVariableSymbol.TABLE_NAME,
			DBTraceLocalVariableSymbol.class, (s, r) -> new DBTraceLocalVariableSymbol(this, s, r),
			true);
		globalVarStore = factory.getOrCreateCachedStore(DBTraceGlobalVariableSymbol.TABLE_NAME,
			DBTraceGlobalVariableSymbol.class,
			(s, r) -> new DBTraceGlobalVariableSymbol(this, s, r), true);

		globalNamespace = getOrCreateGlobalNamespace();

		// TODO: Use createLabelSymbolView, etc., etc. for extensibility?
		labels = putInMap(new DBTraceLabelSymbolView(this));
		namespaces = putInMap(new DBTraceNamespaceSymbolView(this));
		classes = putInMap(new DBTraceClassSymbolView(this));
		functions = putInMap(new DBTraceFunctionSymbolView(this));
		parameters = putInMap(new DBTraceParameterSymbolView(this));
		localVars = putInMap(new DBTraceLocalVariableSymbolView(this));
		globalVars = putInMap(new DBTraceGlobalVariableSymbolView(this));

		allNamespaces = new DBTraceSymbolMultipleTypesView<>(this, namespaces, classes, functions);
		uniqueNamespaces =
			new DBTraceSymbolMultipleTypesNoDuplicatesView<>(this, namespaces, classes);
		allLocals = new DBTraceSymbolMultipleTypesWithAddressNoDuplicatesView<>(this, parameters,
			localVars);
		allVariables = new DBTraceSymbolMultipleTypesWithAddressNoDuplicatesView<>(this, parameters,
			localVars, globalVars);
		labelsAndFunctions = new DBTraceSymbolMultipleTypesWithLocationView<AbstractDBTraceSymbol>(
			this, labels, functions);
		notLabelsNorFunctions = new DBTraceSymbolMultipleTypesNoDuplicatesView<>(this, namespaces,
			classes, parameters, localVars, globalVars);
		allSymbols = new DBTraceSymbolMultipleTypesView<>(this, labels, namespaces, classes,
			functions, parameters, localVars, globalVars);

	}

	protected DataType checkIndirection(VariableStorage s, DataType formal) {
		if (!s.isForcedIndirect()) {
			return formal;
		}
		int ptrSize = s.size();
		if (ptrSize != dataTypeManager.getDataOrganization().getPointerSize()) {
			return dataTypeManager.getPointer(formal, ptrSize);
		}
		else {
			return dataTypeManager.getPointer(formal);
		}
	}

	protected <T extends AbstractDBTraceSymbolSingleTypeView<?>> T putInMap(T view) {
		symbolViews.put(view.typeID, view);
		return view;
	}

	protected DBTraceNamespaceSymbol getOrCreateGlobalNamespace() {
		DBTraceNamespaceSymbol global =
			namespaceStore.getObjectAt(GlobalNamespace.GLOBAL_NAMESPACE_ID);
		if (global != null) {
			assert global.parentID == -1;
			assert GlobalNamespace.GLOBAL_NAMESPACE_NAME.equals(global.name);
			return global;
		}
		global = namespaceStore.create(0);
		global.rawSet(GlobalNamespace.GLOBAL_NAMESPACE_NAME, -1);
		return global;
	}

	protected static long packID(byte typeID, long key) {
		assert typeID + 1 <= TYPE_MASK;
		assert key <= KEY_MASK;
		// NOTE: Add one to typeID so that GLOBAL == 0, and LABEL != 0
		return ((typeID + 1) & TYPE_MASK) << TYPE_SHIFT | (key & KEY_MASK) << KEY_SHIFT;
	}

	protected static byte unpackTypeID(long symbolID) {
		return (byte) (((symbolID >> TYPE_SHIFT) & TYPE_MASK) - 1);
	}

	protected static long unpackKey(long symbolID) {
		return (symbolID >> KEY_SHIFT) & KEY_MASK;
	}

	protected void loadCallingConventions() {
		// NOTE: Should already own write lock
		for (DBTraceCallingConventionEntry ent : callingConventionStore.asMap().values()) {
			// NOTE: No need to check. Only called on new or invalidate.
			callingConventionMap.put(ent.name, (byte) ent.getKey());
		}
	}

	protected byte doRecordCallingConvention(String name) {
		DBTraceCallingConventionEntry ent = callingConventionStore.create();
		ent.setName(name);
		return (byte) ent.getKey();
	}

	protected byte findOrRecordCallingConvention(String name) {
		// NOTE: Must already have write lock
		return callingConventionMap.computeIfAbsent(name, this::doRecordCallingConvention);
	}

	protected int findOrRecordVariableStorage(VariableStorage storage) {
		DBTraceVariableStorageEntry entry = storageByStorage.getOne(storage);
		if (entry == null) {
			entry = storageStore.create();
			entry.set(storage);
		}
		return (int) entry.getKey();
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		try (LockHold hold = LockHold.lock(lock.writeLock())) {
			idMap.invalidateCache(all);
			callingConventionStore.invalidateCache();
			callingConventionMap.clear();
			loadCallingConventions();

			for (AbstractDBTraceSymbolSingleTypeView<?> view : symbolViews.values()) {
				view.invalidateCache();
			}

			if (globalNamespace.isDeleted()) {
				throw new AssertionError();
			}
		}
	}

	// Internal
	public void replaceDataTypes(long oldID, long newID) {
		// TODO Auto-generated method stub
		// DataTypes of Function returns, params, locals, globalRegs
	}

	protected void assertValidThreadAddress(DBTraceThread thread, Address address) {
		if (thread != null && address.isMemoryAddress()) {
			throw new IllegalArgumentException(
				"Memory addresses cannot be associated with a thread");
		}
		if (thread == null && address.getAddressSpace().isRegisterSpace()) {
			throw new IllegalArgumentException(
				"Register addresses must be associated with a thread");
		}
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	@Override
	public AbstractDBTraceSymbol getSymbolByID(long symbolID) {
		if (symbolID == GlobalNamespace.GLOBAL_NAMESPACE_ID) {
			return globalNamespace;
		}
		byte typeID = unpackTypeID(symbolID);
		AbstractDBTraceSymbolSingleTypeView<?> view = symbolViews.get(typeID);
		if (view == null) {
			return null;
		}
		return view.store.getObjectAt(unpackKey(symbolID));
	}

	@Override
	public DBTraceNamespaceSymbol getGlobalNamespace() {
		return globalNamespace;
	}

	@Override
	public DBTraceLabelSymbolView labels() {
		return labels;
	}

	@Override
	public DBTraceNamespaceSymbolView namespaces() {
		return namespaces;
	}

	@Override
	public DBTraceClassSymbolView classes() {
		return classes;
	}

	@Override
	public DBTraceFunctionSymbolView functions() {
		return functions;
	}

	@Override
	public DBTraceParameterSymbolView parameters() {
		return parameters;
	}

	@Override
	public DBTraceLocalVariableSymbolView localVariables() {
		return localVars;
	}

	@Override
	public DBTraceGlobalVariableSymbolView globalVariables() {
		return globalVars;
	}

	@Override
	public TraceSymbolView<? extends DBTraceNamespaceSymbol> allNamespaces() {
		return allNamespaces;
	}

	public TraceSymbolNoDuplicatesView<? extends DBTraceNamespaceSymbol> uniqueNamespaces() {
		return uniqueNamespaces;
	}

	@Override
	public TraceSymbolWithAddressNoDuplicatesView<? extends AbstractDBTraceVariableSymbol> allLocals() {
		return allLocals;
	}

	@Override
	public TraceSymbolWithAddressNoDuplicatesView<? extends AbstractDBTraceSymbol> allVariables() {
		return allVariables;
	}

	@Override
	public TraceSymbolWithLocationView<? extends AbstractDBTraceSymbol> labelsAndFunctions() {
		return labelsAndFunctions;
	}

	@Override
	public TraceSymbolNoDuplicatesView<? extends AbstractDBTraceSymbol> notLabelsNorFunctions() {
		return notLabelsNorFunctions;
	}

	@Override
	public TraceSymbolView<? extends AbstractDBTraceSymbol> allSymbols() {
		return allSymbols;
	}

	// Internal
	public DBTraceNamespaceSymbol checkIsMine(Namespace ns) {
		if (!(ns instanceof DBTraceNamespaceSymbol)) {
			return null;
		}
		DBTraceNamespaceSymbol dbns = (DBTraceNamespaceSymbol) ns;
		if (dbns.manager != this) {
			return null;
		}
		if (dbns.isDeleted()) {
			return null;
		}
		if (namespaceStore.contains(dbns)) {
			return dbns;
		}
		if (dbns instanceof DBTraceClassSymbol) {
			if (classStore.contains((DBTraceClassSymbol) dbns)) {
				return dbns;
			}
		}
		if (dbns instanceof DBTraceFunctionSymbol) {
			if (functionStore.contains((DBTraceFunctionSymbol) dbns)) {
				return dbns;
			}
		}
		return null;
	}

	// Internal
	public AbstractDBTraceSymbol checkIsMine(Symbol symbol) {
		if (!(symbol instanceof AbstractDBTraceSymbol)) {
			return null;
		}
		AbstractDBTraceSymbol dbSym = (AbstractDBTraceSymbol) symbol;
		if (dbSym.manager != this) {
			return null;
		}
		if (dbSym.isDeleted()) {
			return null;
		}
		long symbolID = dbSym.getID();
		byte tid = unpackTypeID(symbolID);
		AbstractDBTraceSymbolSingleTypeView<?> view = symbolViews.get(tid);
		if (view == null) {
			return null;
		}
		if (!view.store.containsKey(unpackKey(symbolID))) {
			return null;
		}
		return dbSym;
	}

	// Internal
	public DBTraceFunctionSymbol checkIsMine(Function function) {
		if (!(function instanceof DBTraceFunctionSymbol)) {
			return null;
		}
		DBTraceFunctionSymbol dbFunc = (DBTraceFunctionSymbol) function;
		if (dbFunc.manager != this) {
			return null;
		}
		if (dbFunc.isDeleted()) {
			return null;
		}
		if (functionStore.contains(dbFunc)) {
			return dbFunc;
		}
		return null;
	}

	// Internal
	public DBTraceNamespaceSymbol assertIsMine(Namespace ns) {
		DBTraceNamespaceSymbol dbns = checkIsMine(ns);
		if (dbns == null) {
			throw new IllegalArgumentException("Given namespace is not in this trace");
		}
		return dbns;
	}

	// Internal
	public AbstractDBTraceSymbol assertIsMine(Symbol symbol) {
		AbstractDBTraceSymbol dbSym = checkIsMine(symbol);
		if (dbSym == null) {
			throw new IllegalArgumentException("Given symbol is not in this trace");
		}
		return dbSym;
	}

	// Internal
	public DBTraceFunctionSymbol assertIsMine(Function function) {
		DBTraceFunctionSymbol dbFunc = checkIsMine(function);
		if (dbFunc == null) {
			throw new IllegalArgumentException("Given function is not in this trace");
		}
		return dbFunc;
	}

	protected static void assertValidName(String name) throws InvalidInputException {
		if (name == null || name.length() == 0 || !name.matches("\\p{Graph}+")) {
			throw new InvalidInputException(name);
		}
	}

	/**
	 * Checks for duplicate names, allowing {@link SymbolType#LABEL} and
	 * {@link SymbolType#FUNCTION}.
	 * 
	 * @param name the proposed name
	 * @param parent the parent namespace
	 * @throws DuplicateNameException if the name is a duplicate
	 */
	protected void assertUniqueName(String name, DBTraceNamespaceSymbol parent)
			throws DuplicateNameException {
		for (AbstractDBTraceSymbol symbol : notLabelsNorFunctions.getChildren(parent)) {
			if (name.equals(symbol.name)) {
				throw new DuplicateNameException(name);
			}
		}
	}

	protected boolean doDeleteSymbol(AbstractDBTraceSymbol symbol) {
		byte typeID = symbol.getSymbolType().getID();
		DBTraceThread thread = symbol.getThread();
		AbstractDBTraceSymbol deleted = symbolViews.get(typeID).store.deleteKey(symbol.getKey());
		if (deleted == null) {
			return false;
		}
		if (symbol.getAddress().isMemoryAddress()) {
			delID(thread, symbol.getAddress().getAddressSpace(), symbol.getID());
		}
		// TODO: Remove from other space maps, once implemented.
		trace.setChanged(
			new TraceChangeRecord<>(TraceSymbolChangeType.DELETED, symbol.getSpace(), symbol, null,
				null));
		return true;
	}

	protected void putID(Range<Long> lifespan, DBTraceThread thread, Address address, long id) {
		idMap.get(DBTraceSpaceKey.create(address.getAddressSpace(), thread, 0), true)
				.put(address, lifespan, id);
		// TODO: Add to ancestors' too?
		// NOTE: Might be hard to remove because of overlaps
	}

	protected void putID(Range<Long> lifespan, DBTraceThread thread, AddressRange rng, long id) {
		idMap.get(DBTraceSpaceKey.create(rng.getAddressSpace(), thread, 0), true)
				.put(rng, lifespan, id);
		// TODO: Add to ancestors' too?
		// NOTE: Might be hard to remove because of overlaps
	}

	protected void delID(DBTraceThread thread, AddressSpace addressSpace, long id) {
		DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> space =
			idMap.get(DBTraceSpaceKey.create(addressSpace, thread, 0), false);
		if (space == null) {
			return;
		}
		DBCachedObjectIndex<Long, DBTraceSymbolIDEntry> byID =
			space.getUserIndex(long.class, DBTraceSymbolIDEntry.ID_COLUMN);
		for (DBTraceSymbolIDEntry entry : byID.get(id)) {
			space.deleteData(entry);
		}
	}

	protected void assertNotDuplicate(AbstractDBTraceSymbol exclude, Range<Long> lifespan,
			DBTraceThread thread, Address address, String name, DBTraceNamespaceSymbol parent)
			throws DuplicateNameException {
		if (address.isMemoryAddress()) {
			for (AbstractDBTraceSymbol duplicate : labelsAndFunctions.getIntersecting(lifespan,
				thread, new AddressRangeImpl(address, address), false, true)) {
				if (duplicate == exclude) {
					continue;
				}
				if (duplicate.getParentNamespace() != parent) {
					continue;
				}
				if (!name.contentEquals(duplicate.getName())) {
					continue;
				}
				throw new DuplicateNameException(name);
			}
		}
		assertNotDuplicate(exclude, name, parent);
	}

	protected void assertNotDuplicate(AbstractDBTraceSymbol exclude, String name,
			DBTraceNamespaceSymbol parent) throws DuplicateNameException {
		for (AbstractDBTraceSymbol duplicate : notLabelsNorFunctions.getChildrenNamed(name,
			parent)) {
			if (duplicate == exclude) {
				continue;
			}
			throw new DuplicateNameException(name);
		}
	}

	@Override
	public Collection<Long> getIDsAdded(long from, long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Collection<Long> result = new ArrayList<>();
		for (DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> space : idMap
				.getActiveMemorySpaces()) {
			result.addAll(space
					.reduce(TraceAddressSnapRangeQuery.added(from, to, space.getAddressSpace()))
					.values());
		}
		return result;
	}

	@Override
	public Collection<Long> getIDsRemoved(long from, long to) {
		if (from == to) {
			return Collections.emptySet();
		}
		Collection<Long> result = new ArrayList<>();
		for (DBTraceAddressSnapRangePropertyMapSpace<Long, DBTraceSymbolIDEntry> space : idMap
				.getActiveMemorySpaces()) {
			result.addAll(space
					.reduce(TraceAddressSnapRangeQuery.removed(from, to, space.getAddressSpace()))
					.values());
		}
		return result;
	}
}
