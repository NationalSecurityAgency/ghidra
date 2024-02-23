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
package ghidra.trace.database.target;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.*;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.jdom.JDOMException;

import db.*;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.util.*;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.breakpoint.DBTraceObjectBreakpointLocation;
import ghidra.trace.database.module.TraceObjectSection;
import ghidra.trace.database.target.DBTraceObjectValueRStarTree.DBTraceObjectValueMap;
import ghidra.trace.database.target.ValueSpace.EntryKeyDimension;
import ghidra.trace.database.target.visitors.SuccessorsRelativeVisitor;
import ghidra.trace.database.thread.DBTraceObjectThread;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.breakpoint.*;
import ghidra.trace.model.memory.*;
import ghidra.trace.model.modules.TraceObjectModule;
import ghidra.trace.model.stack.TraceObjectStack;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.DuplicateKeyException;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.model.thread.TraceThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.DBCachedObjectStoreFactory.PrimitiveCodec;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceObjectManager implements TraceObjectManager, DBTraceManager {
	private static final int OBJECTS_CONTAINING_CACHE_SIZE = 100;

	public static class DBTraceObjectSchemaDBFieldCodec extends
			AbstractDBFieldCodec<SchemaContext, DBTraceObjectSchemaEntry, StringField> {
		public DBTraceObjectSchemaDBFieldCodec(Class<DBTraceObjectSchemaEntry> objectType,
				Field field, int column) {
			super(SchemaContext.class, objectType, StringField.class, field, column);
		}

		protected String encode(SchemaContext value) {
			return value == null ? null : XmlSchemaContext.serialize(value);
		}

		protected SchemaContext decode(String xml) {
			try {
				return xml == null ? null : XmlSchemaContext.deserialize(xml);
			}
			catch (JDOMException e) {
				throw new IllegalArgumentException("Invalid XML-encoded schema context");
			}
		}

		@Override
		public void store(SchemaContext value, StringField f) {
			f.setString(encode(value));
		}

		@Override
		protected void doStore(DBTraceObjectSchemaEntry obj, DBRecord record)
				throws IllegalAccessException {
			record.setString(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(DBTraceObjectSchemaEntry obj, DBRecord record)
				throws IllegalAccessException {
			setValue(obj, decode(record.getString(column)));
		}
	}

	@DBAnnotatedObjectInfo(version = 0)
	protected static final class DBTraceObjectSchemaEntry extends DBAnnotatedObject {
		public static final String TABLE_NAME = "ObjectSchema";

		static final String CONTEXT_COLUMN_NAME = "Context";
		static final String SCHEMA_COLUMN_NAME = "Schema";

		@DBAnnotatedColumn(CONTEXT_COLUMN_NAME)
		static DBObjectColumn CONTEXT_COLUMN;
		@DBAnnotatedColumn(SCHEMA_COLUMN_NAME)
		static DBObjectColumn SCHEMA_COLUMN;

		@DBAnnotatedField(
			column = CONTEXT_COLUMN_NAME,
			codec = DBTraceObjectSchemaDBFieldCodec.class)
		private SchemaContext context;
		@DBAnnotatedField(column = SCHEMA_COLUMN_NAME)
		private String schemaName;

		private TargetObjectSchema schema;

		public DBTraceObjectSchemaEntry(DBCachedObjectStore<?> store, DBRecord record) {
			super(store, record);
		}

		@Override
		protected void fresh(boolean created) throws IOException {
			if (created) {
				return;
			}
			schema = context.getSchema(new SchemaName(schemaName));
		}

		protected void set(TargetObjectSchema schema) {
			context = schema.getContext();
			schemaName = schema.getName().toString();
			update(CONTEXT_COLUMN, SCHEMA_COLUMN);
		}
	}

	record ObjectsContainingKey(long snap, Address address, String key,
			Class<? extends TraceObjectInterface> iface) {
	}

	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBCachedObjectStore<DBTraceObjectSchemaEntry> schemaStore;
	protected final DBCachedObjectStore<DBTraceObject> objectStore;
	protected final DBTraceObjectValueRStarTree valueTree;
	protected final DBTraceObjectValueMap valueMap;
	protected final DBTraceObjectValueWriteBehindCache valueWbCache;

	protected final DBCachedObjectIndex<TraceObjectKeyPath, DBTraceObject> objectsByPath;

	protected final Collection<TraceObject> objectsView;

	protected TargetObjectSchema rootSchema;

	protected final Map<ObjectsContainingKey, Collection<?>> objectsContainingCache =
		new LinkedHashMap<>() {
			protected boolean removeEldestEntry(
					Map.Entry<ObjectsContainingKey, Collection<?>> eldest) {
				return size() > OBJECTS_CONTAINING_CACHE_SIZE;
			}
		};
	protected final Map<Class<? extends TraceObjectInterface>, Set<TargetObjectSchema>> //
	schemasByInterface = new HashMap<>();

	public DBTraceObjectManager(DBHandle dbh, DBOpenMode openMode, ReadWriteLock lock,
			TaskMonitor monitor, Language baseLanguage, DBTrace trace)
			throws IOException, VersionException {
		this.lock = lock;
		this.trace = trace;

		DBCachedObjectStoreFactory factory = trace.getStoreFactory();
		schemaStore = factory.getOrCreateCachedStore(DBTraceObjectSchemaEntry.TABLE_NAME,
			DBTraceObjectSchemaEntry.class, DBTraceObjectSchemaEntry::new, true);
		loadRootSchema();
		objectStore = factory.getOrCreateCachedStore(DBTraceObject.TABLE_NAME,
			DBTraceObject.class, (s, r) -> new DBTraceObject(this, s, r), true);

		valueTree = new DBTraceObjectValueRStarTree(this, factory,
			DBTraceObjectValueData.TABLE_NAME, ValueSpace.INSTANCE, DBTraceObjectValueData.class,
			DBTraceObjectValueNode.class, false, 50);
		valueMap = valueTree.asSpatialMap();

		objectsByPath =
			objectStore.getIndex(TraceObjectKeyPath.class, DBTraceObject.PATH_COLUMN);

		valueWbCache = new DBTraceObjectValueWriteBehindCache(this);

		objectsView = Collections.unmodifiableCollection(objectStore.asMap().values());
	}

	protected void loadRootSchema() {
		if (schemaStore.asMap().isEmpty()) {
			rootSchema = null;
			return;
		}
		assert schemaStore.asMap().size() == 1;
		DBTraceObjectSchemaEntry schemaEntry = schemaStore.getObjectAt(0);
		rootSchema = schemaEntry.schema;
	}

	@Override
	public void dbError(IOException e) {
		trace.dbError(e);
	}

	@Override
	public void invalidateCache(boolean all) {
		objectStore.invalidateCache();
		valueTree.invalidateCache();
		schemaStore.invalidateCache();
		loadRootSchema();
		objectsContainingCache.clear();
		// Though rare, the root schema could change
		schemasByInterface.clear();
	}

	protected boolean checkMyObject(DBTraceObject object) {
		if (object.manager != this) {
			return false;
		}
		if (!objectStore.asMap().values().contains(object)) {
			return false;
		}
		return true;
	}

	protected DBTraceObject assertIsMine(TraceObject object) {
		if (!(object instanceof DBTraceObject dbObject)) {
			throw new IllegalArgumentException("Object " + object + " is not part of this trace");
		}
		if (!checkMyObject(dbObject)) {
			throw new IllegalArgumentException("Object " + object + " is not part of this trace");
		}
		return dbObject;
	}

	protected Object validatePrimitive(Object value) {
		try {
			PrimitiveCodec.getCodec(value.getClass());
		}
		catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Cannot encode " + value, e);
		}
		return value;
	}

	protected Object validateValue(Object value) {
		if (value instanceof TraceObject | value instanceof Address |
			value instanceof AddressRange) {
			return value;
		}
		return validatePrimitive(value);
	}

	@Override
	public Trace getTrace() {
		return trace;
	}

	protected void setSchema(TargetObjectSchema schema) {
		if (rootSchema != null) {
			throw new IllegalStateException("There is already a root object");
		}
		DBTraceObjectSchemaEntry schemaEntry = schemaStore.create(0);
		schemaEntry.set(schema);
		rootSchema = schema;
	}

	protected void emitValueCreated(DBTraceObject parent, DBTraceObjectValue entry) {
		if (parent == null) {
			// Don't need event for root value created
			return;
		}
		parent.emitEvents(new TraceChangeRecord<>(TraceEvents.VALUE_CREATED, null, entry));
	}

	protected DBTraceObjectValueData doCreateValueData(Lifespan lifespan, DBTraceObject parent,
			String key, Object value) {
		DBTraceObjectValueData entry =
			valueMap.put(new ImmutableValueShape(parent, value, key, lifespan), null);
		if (!(value instanceof DBTraceObject)) {
			entry.doSetPrimitive(value);
		}
		return entry;
	}

	protected DBTraceObjectValue doCreateValue(Lifespan lifespan,
			DBTraceObject parent, String key, Object value) {
		// Root is never in write-behind cache
		DBTraceObjectValue entry = parent == null
				? doCreateValueData(lifespan, parent, key, value).getWrapper()
				: valueWbCache.doCreateValue(lifespan, parent, key, value).getWrapper();
		if (parent != null) {
			parent.notifyValueCreated(entry);
		}
		if (value instanceof DBTraceObject child) {
			child.notifyParentValueCreated(entry);
		}
		// TODO: Perhaps a little drastic
		invalidateObjectsContainingCache();
		emitValueCreated(parent, entry);
		return entry;
	}

	protected DBTraceObject doCreateObject(TraceObjectKeyPath path) {
		DBTraceObject obj = objectsByPath.getOne(path);
		if (obj != null) {
			return obj;
		}
		obj = objectStore.create();
		obj.set(path);
		obj.emitEvents(new TraceChangeRecord<>(TraceEvents.OBJECT_CREATED, null, obj));
		return obj;
	}

	protected DBTraceObject doGetObject(TraceObjectKeyPath path) {
		return objectsByPath.getOne(path);
	}

	@Override
	public DBTraceObject createObject(TraceObjectKeyPath path) {
		if (path.isRoot()) {
			throw new IllegalArgumentException("Cannot create non-root object with root path");
		}
		try (LockHold hold = trace.lockWrite()) {
			if (rootSchema == null) {
				throw new IllegalStateException("No schema! Create the root object, first.");
			}
			return doCreateObject(path);
		}
	}

	@Override
	public DBTraceObjectValue createRootObject(TargetObjectSchema schema) {
		try (LockHold hold = trace.lockWrite()) {
			setSchema(schema);
			DBTraceObject root = doCreateObject(TraceObjectKeyPath.of());
			assert root.getKey() == 0;
			DBTraceObjectValue val = doCreateValue(Lifespan.ALL, null, "", root);
			assert val.getWrapped() instanceof DBTraceObjectValueData data && data.getKey() == 0;
			return val;
		}
	}

	@Override
	public TargetObjectSchema getRootSchema() {
		try (LockHold hold = trace.lockRead()) {
			return rootSchema;
		}
	}

	public DBTraceObjectValue getRootValue() {
		try (LockHold hold = trace.lockRead()) {
			DBTraceObjectValueData data = valueTree.getDataStore().getObjectAt(0);
			return data == null ? null : data.getWrapper();
		}
	}

	@Override
	public DBTraceObject getRootObject() {
		return getObjectById(0);
	}

	@Override
	public DBTraceObject getObjectById(long key) {
		try (LockHold hold = trace.lockRead()) {
			return objectStore.getObjectAt(key);
		}
	}

	@Override
	public DBTraceObject getObjectByCanonicalPath(TraceObjectKeyPath path) {
		return objectsByPath.getOne(path);
	}

	@Override
	public Stream<? extends DBTraceObject> getObjectsByPath(Lifespan span,
			TraceObjectKeyPath path) {
		DBTraceObject root = getRootObject();
		return getValuePaths(span, new PathPattern(path.getKeyList()))
				.map(p -> p.getDestinationValue(root))
				.filter(DBTraceObject.class::isInstance)
				.map(DBTraceObject.class::cast);
	}

	@Override
	public Stream<? extends TraceObjectValPath> getValuePaths(Lifespan span,
			PathPredicates predicates) {
		try (LockHold hold = trace.lockRead()) {
			DBTraceObjectValue rootVal = getRootValue();
			if (rootVal == null) {
				return Stream.of();
			}
			return rootVal.doStreamVisitor(span, new SuccessorsRelativeVisitor(predicates));
		}
	}

	@Override
	public Stream<DBTraceObject> getAllObjects() {
		return objectStore.asMap().values().stream();
	}

	@Override
	public int getObjectCount() {
		return objectStore.getRecordCount();
	}

	@Override
	public Stream<DBTraceObjectValue> getAllValues() {
		return Stream.concat(
			valueMap.values().stream().map(v -> v.getWrapper()),
			StreamUtils.lock(lock.readLock(),
				valueWbCache.streamAllValues().map(v -> v.getWrapper())));
	}

	protected Stream<DBTraceObjectValueData> streamValuesIntersectingData(Lifespan span,
			AddressRange range, String entryKey) {
		return valueMap.reduce(TraceObjectValueQuery.intersecting(
			entryKey != null ? entryKey : EntryKeyDimension.INSTANCE.absoluteMin(),
			entryKey != null ? entryKey : EntryKeyDimension.INSTANCE.absoluteMax(),
			span, range)).values().stream();
	}

	protected Stream<DBTraceObjectValueBehind> streamValuesIntersectingBehind(Lifespan span,
			AddressRange range, String entryKey) {
		return valueWbCache.streamValuesIntersecting(span, range, entryKey);
	}

	@Override
	public Collection<? extends TraceObjectValue> getValuesIntersecting(Lifespan span,
			AddressRange range, String entryKey) {
		return Stream.concat(
			streamValuesIntersectingData(span, range, entryKey).map(v -> v.getWrapper()),
			streamValuesIntersectingBehind(span, range, entryKey).map(v -> v.getWrapper()))
				.toList();
	}

	protected Stream<DBTraceObjectValueData> streamValuesAtData(long snap, Address address,
			String entryKey) {
		return valueMap.reduce(TraceObjectValueQuery.at(entryKey, snap, address)).values().stream();
	}

	protected Stream<DBTraceObjectValueBehind> streamValuesAtBehind(long snap, Address address,
			String entryKey) {
		return valueWbCache.streamValuesAt(snap, address, entryKey);
	}

	public Collection<? extends TraceObjectValue> getValuesAt(long snap, Address address,
			String entryKey) {
		return Stream.concat(
			streamValuesAtData(snap, address, entryKey).map(v -> v.getWrapper()),
			streamValuesAtBehind(snap, address, entryKey).map(v -> v.getWrapper()))
				.toList();
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryAllInterface(Lifespan span,
			Class<I> ifClass) {
		if (rootSchema == null) {
			throw new IllegalStateException("There is no schema. Create a root object.");
		}
		Class<? extends TargetObject> targetIf = TraceObjectInterfaceUtils.toTargetIf(ifClass);
		PathMatcher matcher = rootSchema.searchFor(targetIf, true);
		return getValuePaths(span, matcher)
				.filter(p -> {
					TraceObject object = p.getDestination(getRootObject());
					if (object == null) {
						Msg.error(this, "NULL VALUE! " + p.getLastEntry());
						return false;
					}
					return true;
				})
				.map(p -> p.getDestination(getRootObject()).queryInterface(ifClass));
	}

	@Override
	public void cullDisconnectedObjects() {
		try (LockHold hold = trace.lockWrite()) {
			for (DBTraceObject obj : objectStore.asMap().values()) {
				if (!obj.doIsConnected()) {
					obj.delete();
				}
			}
		}
	}

	@Override
	public void clear() {
		try (LockHold hold = trace.lockWrite()) {
			valueMap.clear();
			valueWbCache.clear();
			objectStore.deleteAll();
			schemaStore.deleteAll();
			rootSchema = null;
			objectsContainingCache.clear();
			schemasByInterface.clear();
		}
	}

	protected void doDeleteObject(DBTraceObject object) {
		objectStore.delete(object);
		object.emitEvents(new TraceChangeRecord<>(TraceEvents.OBJECT_DELETED, null, object));
	}

	protected void doDeleteValue(DBTraceObjectValueData value) {
		valueTree.doDeleteEntry(value);

		// TODO: Perhaps a little drastic....
		/**
		 * NB. An object in one of these queries had to have an edge. Deleting that object will also
		 * delete referring edges, so the cache will get invalidated. No need to repeat in
		 * doDeleteObject.
		 */
		invalidateObjectsContainingCache();
	}

	protected void doDeleteCachedValue(DBTraceObjectValueBehind value) {
		valueWbCache.remove(value);
		// Ditto NB from doDeleteValue
		invalidateObjectsContainingCache();
	}

	public boolean hasSchema() {
		return rootSchema != null;
	}

	protected <I extends TraceObjectInterface> I doAddWithInterface(List<String> keyList,
			Class<I> iface) {
		Class<? extends TargetObject> targetIf = TraceObjectInterfaceUtils.toTargetIf(iface);
		TargetObjectSchema schema = rootSchema.getSuccessorSchema(keyList);
		if (!schema.getInterfaces().contains(targetIf)) {
			throw new IllegalStateException(
				"Schema " + schema + " at " + PathUtils.toString(keyList) +
					" does not provide interface " + iface.getSimpleName());
		}
		DBTraceObject obj = createObject(TraceObjectKeyPath.of(keyList));
		return obj.queryInterface(iface);
	}

	protected <I extends TraceObjectInterface> I doAddWithInterface(String path, Class<I> iface) {
		return doAddWithInterface(PathUtils.parse(path), iface);
	}

	public <I extends TraceObjectInterface> Collection<I> getAllObjects(Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return queryAllInterface(Lifespan.ALL, iface).collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> Collection<I> getObjectsByPath(String path,
			Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return getObjectsByPath(Lifespan.ALL, TraceObjectKeyPath.parse(path))
					.map(o -> o.queryInterface(iface))
					.filter(i -> i != null)
					.collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> I getObjectByPath(long snap, String path,
			Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return getObjectsByPath(Lifespan.at(snap), TraceObjectKeyPath.parse(path)).findAny()
					.map(o -> o.queryInterface(iface))
					.orElse(null);
		}
	}

	protected void invalidateObjectsContainingCache() {
		synchronized (objectsContainingCache) {
			objectsContainingCache.clear();
		}
	}

	protected Collection<? extends TraceObjectInterface> doGetObjectsContaining(
			ObjectsContainingKey key) {
		return getObjectsIntersecting(Lifespan.at(key.snap),
			new AddressRangeImpl(key.address, key.address), key.key, key.iface);
	}

	@SuppressWarnings("unchecked")
	public <I extends TraceObjectInterface> Collection<I> getObjectsContaining(long snap,
			Address address, String key, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			synchronized (objectsContainingCache) {
				return (Collection<I>) objectsContainingCache.computeIfAbsent(
					new ObjectsContainingKey(snap, address, key, iface),
					this::doGetObjectsContaining);
			}
		}
	}

	public <I extends TraceObjectInterface> I getObjectContaining(long snap, Address address,
			String key, Class<I> iface) {
		Collection<I> col = getObjectsContaining(snap, address, key, iface);
		if (col.isEmpty()) {
			return null;
		}
		return col.iterator().next();
	}

	protected Set<TargetObjectSchema> collectSchemasForInterface(
			Class<? extends TraceObjectInterface> iface) {
		if (rootSchema == null) {
			return Set.of();
		}
		Class<? extends TargetObject> targetIf = TraceObjectInterfaceUtils.toTargetIf(iface);
		Set<TargetObjectSchema> result = new HashSet<>();
		for (TargetObjectSchema schema : rootSchema.getContext().getAllSchemas()) {
			if (schema.getInterfaces().contains(targetIf)) {
				result.add(schema);
			}
		}
		return Set.copyOf(result);
	}

	public <I extends TraceObjectInterface> Collection<I> getObjectsIntersecting(
			Lifespan lifespan, AddressRange range, String key, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			Set<TargetObjectSchema> schemas;
			synchronized (schemasByInterface) {
				schemas =
					schemasByInterface.computeIfAbsent(iface, this::collectSchemasForInterface);
			}
			Map<String, List<TargetObjectSchema>> schemasByAliasTo =
				schemas.stream().collect(Collectors.groupingBy(s -> s.checkAliasedAttribute(key)));
			return schemasByAliasTo.entrySet().stream().flatMap(ent -> {
				return getValuesIntersecting(lifespan, range, ent.getKey()).stream()
						.map(v -> v.getParent())
						.filter(o -> ent.getValue().contains(o.getTargetSchema()));
			}).map(o -> o.queryInterface(iface)).collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> Collection<I> getObjectsAtSnap(long snap,
			Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return queryAllInterface(Lifespan.at(snap), iface).collect(Collectors.toSet());
		}
	}

	static <I extends TraceObjectInterface> boolean acceptValue(DBTraceObjectValue value,
			String key, Class<I> ifaceCls, Predicate<? super I> predicate) {
		if (!value.hasEntryKey(key)) {
			return false;
		}
		TraceObject parent = value.getParent();
		I iface = parent.queryInterface(ifaceCls);
		if (iface == null) {
			return false;
		}
		if (!predicate.test(iface)) {
			return false;
		}
		return true;
	}

	public <I extends TraceObjectInterface> AddressSetView getObjectsAddressSet(long snap,
			String key, Class<I> ifaceCls, Predicate<? super I> predicate) {
		return new UnionAddressSetView(
			valueMap.getAddressSetView(Lifespan.at(snap),
				v -> acceptValue(v.getWrapper(), key, ifaceCls, predicate)),
			valueWbCache.getObjectsAddressSet(snap, key, ifaceCls, predicate));
	}

	public <I extends TraceObjectInterface> I getSuccessor(TraceObject seed,
			PathPredicates predicates, long snap, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return seed.getSuccessors(Lifespan.at(snap), predicates)
					.map(p -> p.getDestination(seed).queryInterface(iface))
					.filter(i -> i != null)
					.findAny()
					.orElse(null);
		}
	}

	public <I extends TraceObjectInterface> I getLatestSuccessor(TraceObject seed,
			TraceObjectKeyPath path, long snap, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return seed.getOrderedSuccessors(Lifespan.toNow(snap), path, false)
					.map(p -> p.getDestination(seed).queryInterface(iface))
					.filter(i -> i != null)
					.findAny()
					.orElse(null);
		}
	}

	public TraceObjectBreakpointLocation addBreakpoint(String path, Lifespan lifespan,
			AddressRange range, Collection<TraceThread> threads,
			Collection<TraceBreakpointKind> kinds, boolean enabled, String comment)
			throws DuplicateNameException {
		// First verify that the schema accommodates
		List<String> specPath =
			getRootSchema().searchForAncestor(TargetBreakpointSpec.class, PathUtils.parse(path));
		if (specPath == null) {
			throw new IllegalStateException("The schema does not provide an implicit " +
				"breakpoint specification on the given path.");
		}
		try (LockHold hold = trace.lockWrite()) {
			DBTraceObjectBreakpointLocation loc =
				(DBTraceObjectBreakpointLocation) doAddWithInterface(path,
					TraceObjectBreakpointLocation.class);
			loc.setName(lifespan, path);
			loc.setRange(lifespan, range);
			loc.setEnabled(lifespan, enabled);
			loc.setComment(lifespan, comment);

			TraceObjectBreakpointSpec spec = loc.getOrCreateSpecification();
			// NB. Ignore threads. I'd like to deprecate that field, anyway.
			spec.setKinds(lifespan, kinds);
			loc.getObject().insert(lifespan, ConflictResolution.DENY);
			return loc;
		}
		catch (DuplicateKeyException e) {
			throw new DuplicateNameException(e.getMessage());
		}
	}

	public TraceObjectMemoryRegion addMemoryRegion(String path, Lifespan lifespan,
			AddressRange range, Collection<TraceMemoryFlag> flags)
			throws TraceOverlappedRegionException {
		try (LockHold hold = trace.lockWrite()) {
			TraceObjectMemoryRegion region =
				doAddWithInterface(path, TraceObjectMemoryRegion.class);
			region.setName(lifespan, path);
			region.setRange(lifespan, range);
			region.setFlags(lifespan, flags);
			region.getObject().insert(lifespan, ConflictResolution.TRUNCATE);
			return region;
		}
	}

	public TraceObjectModule addModule(String path, String name, Lifespan lifespan,
			AddressRange range) throws DuplicateNameException {
		try (LockHold hold = trace.lockWrite()) {
			TraceObjectModule module = doAddWithInterface(path, TraceObjectModule.class);
			module.setName(lifespan, name);
			module.setRange(lifespan, range);
			module.getObject().insert(lifespan, ConflictResolution.DENY);
			return module;
		}
		catch (DuplicateKeyException e) {
			throw new DuplicateNameException(e.getMessage());
		}
	}

	public TraceObjectSection addSection(String path, String name, Lifespan lifespan,
			AddressRange range) throws DuplicateNameException {
		try (LockHold hold = trace.lockWrite()) {
			TraceObjectSection section = doAddWithInterface(path, TraceObjectSection.class);
			section.setName(lifespan, name);
			section.setRange(lifespan, range);
			section.getObject().insert(lifespan, ConflictResolution.DENY);
			return section;
		}
		catch (DuplicateKeyException e) {
			throw new DuplicateNameException(e.getMessage());
		}
	}

	public TraceObjectStack addStack(List<String> keyList, long snap) {
		try (LockHold hold = trace.lockWrite()) {
			TraceObjectStack stack = doAddWithInterface(keyList, TraceObjectStack.class);
			stack.getObject().insert(Lifespan.at(snap), ConflictResolution.DENY);
			return stack;
		}
	}

	public TraceObjectStackFrame addStackFrame(List<String> keyList, long snap) {
		try (LockHold hold = trace.lockWrite()) {
			TraceObjectStackFrame frame = doAddWithInterface(keyList, TraceObjectStackFrame.class);
			frame.getObject().insert(Lifespan.at(snap), ConflictResolution.DENY);
			return frame;
		}
	}

	protected void checkDuplicateThread(String path, Lifespan lifespan)
			throws DuplicateNameException {
		// TODO: Change the semantics to just expand the life rather than complain of duplication
		DBTraceObject exists = getObjectByCanonicalPath(TraceObjectKeyPath.parse(path));
		if (exists == null) {
			return;
		}
		if (!exists.getLife().intersects(lifespan)) {
			return;
		}
		throw new DuplicateNameException("A thread having path '" + path +
			"' already exists within an overlapping snap");
	}

	public TraceObjectThread addThread(String path, String display, Lifespan lifespan)
			throws DuplicateNameException {
		try (LockHold hold = trace.lockWrite()) {
			checkDuplicateThread(path, lifespan);
			TraceObjectThread thread = doAddWithInterface(path, TraceObjectThread.class);
			thread.setName(lifespan, display);
			thread.getObject().insert(lifespan, ConflictResolution.DENY);
			return thread;
		}
		catch (DuplicateKeyException e) {
			throw new DuplicateNameException(e.getMessage());
		}
	}

	public TraceThread assertMyThread(TraceThread thread) {
		if (!(thread instanceof DBTraceObjectThread dbThread)) {
			throw new AssertionError("Thread " + thread + " is not an object in this trace");
		}
		if (!checkMyObject(dbThread.getObject())) {
			throw new AssertionError("Thread " + thread + " is not an object in this trace");
		}
		return dbThread;
	}

	public void flushWbCaches() {
		valueWbCache.flush();
	}

	public void waitWbWorkers() {
		valueWbCache.waitWorkers();
	}
}
