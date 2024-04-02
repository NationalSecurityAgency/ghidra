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

import db.*;
import ghidra.framework.data.OpenMode;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.address.DBTraceOverlaySpaceAdapter;
import ghidra.trace.database.data.DBTraceDataTypeManager;
import ghidra.trace.database.map.*;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.AbstractDBTraceAddressSnapRangePropertyMapData;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.space.DBTraceSpaceKey;
import ghidra.trace.database.thread.DBTraceThreadManager;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.symbol.*;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
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

		@DBAnnotatedField(column = STORAGE_COLUMN_NAME, indexed = true, codec = VariableStorageDBFieldCodec.class)
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
				return true;
			}
		},
		GLOBAL_VAR {
			@Override
			boolean isValidParent(DBTraceNamespaceSymbol parent) {
				return parent.getSymbolType() == SymbolType.GLOBAL;
			}
		};

		public static final List<MySymbolTypes> VALUES = List.of(values());

		abstract boolean isValidParent(DBTraceNamespaceSymbol parent);
	}

	protected final DBTrace trace;
	protected final ReadWriteLock lock;
	protected final DBTraceThreadManager threadManager;
	protected final DBTraceDataTypeManager dataTypeManager;
	protected final DBTraceOverlaySpaceAdapter overlayAdapter;

	protected final DBTraceAddressSnapRangePropertyMap<Long, DBTraceSymbolIDEntry> idMap;

	// NB. This is unused since the purging of trace function symbols
	// In theory, may get used by global variables.
	protected final DBCachedObjectStore<DBTraceVariableStorageEntry> storageStore;
	protected final DBCachedObjectIndex<VariableStorage, DBTraceVariableStorageEntry> storageByStorage;

	protected final DBCachedObjectStore<DBTraceLabelSymbol> labelStore;
	protected final DBCachedObjectStore<DBTraceNamespaceSymbol> namespaceStore;
	protected final DBCachedObjectStore<DBTraceClassSymbol> classStore;
	protected final DBTraceNamespaceSymbol globalNamespace;

	protected final DBTraceLabelSymbolView labels;
	protected final DBTraceNamespaceSymbolView namespaces;
	protected final DBTraceClassSymbolView classes;

	protected final DBTraceSymbolMultipleTypesView<? extends DBTraceNamespaceSymbol> allNamespaces;
	protected final DBTraceSymbolMultipleTypesNoDuplicatesView<? extends DBTraceNamespaceSymbol> uniqueNamespaces;
	protected final DBTraceSymbolMultipleTypesNoDuplicatesView<?> notLabels;
	protected final DBTraceSymbolMultipleTypesView<?> allSymbols;

	protected final Map<Byte, AbstractDBTraceSymbolSingleTypeView<?>> symbolViews = new HashMap<>();

	public DBTraceSymbolManager(DBHandle dbh, OpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace,
			DBTraceThreadManager threadManager, DBTraceDataTypeManager dataTypeManager,
			DBTraceOverlaySpaceAdapter overlayAdapter) throws VersionException, IOException {
		this.trace = trace;
		this.lock = lock;
		this.threadManager = threadManager;
		this.dataTypeManager = dataTypeManager;
		this.overlayAdapter = overlayAdapter;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();

		idMap = new DBTraceAddressSnapRangePropertyMap<>("SymbolIDs", dbh, openMode, lock, monitor,
			baseLanguage, trace, threadManager, DBTraceSymbolIDEntry.class,
			DBTraceSymbolIDEntry::new);

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

		globalNamespace = getOrCreateGlobalNamespace();

		// TODO: Use createLabelSymbolView, etc., etc. for extensibility?
		labels = putInMap(new DBTraceLabelSymbolView(this));
		namespaces = putInMap(new DBTraceNamespaceSymbolView(this));
		classes = putInMap(new DBTraceClassSymbolView(this));

		allNamespaces = new DBTraceSymbolMultipleTypesView<>(this, namespaces, classes);
		uniqueNamespaces =
			new DBTraceSymbolMultipleTypesNoDuplicatesView<>(this, namespaces, classes);
		notLabels = new DBTraceSymbolMultipleTypesNoDuplicatesView<>(this, namespaces, classes);
		allSymbols = new DBTraceSymbolMultipleTypesView<>(this, labels, namespaces, classes);
	}

	protected DataType checkIndirection(VariableStorage s, DataType formal) {
		if (!s.isForcedIndirect()) {
			return formal;
		}
		int ptrSize = s.size();
		if (ptrSize != dataTypeManager.getDataOrganization().getPointerSize()) {
			return dataTypeManager.getPointer(formal, ptrSize);
		}
		return dataTypeManager.getPointer(formal);
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

			for (AbstractDBTraceSymbolSingleTypeView<?> view : symbolViews.values()) {
				view.invalidateCache();
			}

			if (globalNamespace.isDeleted()) {
				throw new AssertionError();
			}
		}
	}

	// Internal
	public void replaceDataTypes(Map<Long, Long> dataTypeReplacementMap) {
		// Would apply to functions and variables, but those are not supported.
	}

	protected void assertValidThreadAddress(TraceThread thread, Address address) {
		if (thread != null && address.isMemoryAddress()) {
			throw new IllegalArgumentException(
				"Memory addresses cannot be associated with a thread");
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
	public TraceSymbolView<? extends DBTraceNamespaceSymbol> allNamespaces() {
		return allNamespaces;
	}

	public TraceSymbolNoDuplicatesView<? extends DBTraceNamespaceSymbol> uniqueNamespaces() {
		return uniqueNamespaces;
	}

	@Override
	public TraceSymbolNoDuplicatesView<? extends AbstractDBTraceSymbol> notLabels() {
		return notLabels;
	}

	@Override
	public TraceSymbolView<? extends AbstractDBTraceSymbol> allSymbols() {
		return allSymbols;
	}

	// Internal
	public DBTraceNamespaceSymbol checkIsMine(Namespace ns) {
		if (!(ns instanceof DBTraceNamespaceSymbol dbns)) {
			return null;
		}
		if (dbns.manager != this) {
			return null;
		}
		if (dbns.isDeleted()) {
			return null;
		}
		if (namespaceStore.contains(dbns)) {
			return dbns;
		}
		if (dbns instanceof DBTraceClassSymbol dbcs) {
			if (classStore.contains(dbcs)) {
				return dbns;
			}
		}
		return null;
	}

	// Internal
	public AbstractDBTraceSymbol checkIsMine(Symbol symbol) {
		if (!(symbol instanceof AbstractDBTraceSymbol dbSym)) {
			return null;
		}
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

	@Internal
	public DBTraceNamespaceSymbol assertIsMine(Namespace ns) {
		DBTraceNamespaceSymbol dbns = checkIsMine(ns);
		if (dbns == null) {
			throw new IllegalArgumentException("Given namespace is not in this trace");
		}
		return dbns;
	}

	@Internal
	public AbstractDBTraceSymbol assertIsMine(Symbol symbol) {
		AbstractDBTraceSymbol dbSym = checkIsMine(symbol);
		if (dbSym == null) {
			throw new IllegalArgumentException("Given symbol is not in this trace");
		}
		return dbSym;
	}

	protected static void assertValidName(String name) throws InvalidInputException {
		if (name == null || name.length() == 0 || !name.matches("\\p{Graph}+")) {
			throw new InvalidInputException(name);
		}
	}

	/**
	 * Checks for duplicate names, allowing {@link SymbolType#LABEL}
	 * 
	 * @param name the proposed name
	 * @param parent the parent namespace
	 * @throws DuplicateNameException if the name is a duplicate
	 */
	protected void assertUniqueName(String name, DBTraceNamespaceSymbol parent)
			throws DuplicateNameException {
		for (AbstractDBTraceSymbol symbol : notLabels.getChildren(parent)) {
			if (name.equals(symbol.name)) {
				throw new DuplicateNameException(name);
			}
		}
	}

	protected boolean doDeleteSymbol(AbstractDBTraceSymbol symbol) {
		byte typeID = symbol.getSymbolType().getID();
		TraceThread thread = symbol.getThread();
		AbstractDBTraceSymbol deleted = symbolViews.get(typeID).store.deleteKey(symbol.getKey());
		if (deleted == null) {
			return false;
		}
		if (symbol.getAddress().isMemoryAddress()) {
			delID(thread, symbol.getAddress().getAddressSpace(), symbol.getID());
		}
		// TODO: Remove from other space maps, once implemented.
		trace.setChanged(new TraceChangeRecord<>(TraceEvents.SYMBOL_DELETED, symbol.getSpace(),
			symbol, null, null));
		return true;
	}

	protected void putID(Lifespan lifespan, TraceThread thread, Address address, long id) {
		idMap.get(DBTraceSpaceKey.create(address.getAddressSpace(), thread, 0), true)
				.put(address, lifespan, id);
		// TODO: Add to ancestors' too?
		// NOTE: Might be hard to remove because of overlaps
	}

	protected void putID(Lifespan lifespan, TraceThread thread, AddressRange rng, long id) {
		idMap.get(DBTraceSpaceKey.create(rng.getAddressSpace(), thread, 0), true)
				.put(rng, lifespan, id);
		// TODO: Add to ancestors' too?
		// NOTE: Might be hard to remove because of overlaps
	}

	protected void delID(TraceThread thread, AddressSpace addressSpace, long id) {
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

	protected void assertNotDuplicate(AbstractDBTraceSymbol exclude, Lifespan lifespan,
			TraceThread thread, Address address, String name, DBTraceNamespaceSymbol parent)
			throws DuplicateNameException {
		if (address.isMemoryAddress()) {
			for (AbstractDBTraceSymbol duplicate : labels.getIntersecting(lifespan, thread,
				new AddressRangeImpl(address, address), false, true)) {
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
		for (AbstractDBTraceSymbol duplicate : notLabels.getChildrenNamed(name, parent)) {
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
			result.addAll(
				space.reduce(TraceAddressSnapRangeQuery.added(from, to, space.getAddressSpace()))
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
			result.addAll(
				space.reduce(TraceAddressSnapRangeQuery.removed(from, to, space.getAddressSpace()))
						.values());
		}
		return result;
	}
}
