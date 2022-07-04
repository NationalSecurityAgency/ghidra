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

import com.google.common.collect.Range;

import db.*;
import ghidra.dbg.target.TargetBreakpointSpec;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.*;
import ghidra.dbg.target.schema.TargetObjectSchema.SchemaName;
import ghidra.dbg.util.*;
import ghidra.lifecycle.Internal;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Language;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceManager;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMap;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.module.TraceObjectSection;
import ghidra.trace.database.target.DBTraceObjectValue.PrimaryTriple;
import ghidra.trace.database.thread.DBTraceObjectThread;
import ghidra.trace.model.ImmutableTraceAddressSnapRange;
import ghidra.trace.model.Trace;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.breakpoint.TraceBreakpointKind;
import ghidra.trace.model.breakpoint.TraceObjectBreakpointLocation;
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
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.DBCachedObjectStoreFactory.PrimitiveCodec;
import ghidra.util.database.annot.*;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TaskMonitor;

public class DBTraceObjectManager implements TraceObjectManager, DBTraceManager {

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

	protected final ReadWriteLock lock;
	protected final DBTrace trace;

	protected final DBCachedObjectStore<DBTraceObjectSchemaEntry> schemaStore;
	protected final DBCachedObjectStore<DBTraceObject> objectStore;
	protected final DBCachedObjectStore<DBTraceObjectValue> valueStore;

	protected final DBTraceAddressSnapRangePropertyMap<DBTraceObjectAddressRangeValue, DBTraceObjectAddressRangeValue> rangeValueMap;

	protected final DBCachedObjectIndex<TraceObjectKeyPath, DBTraceObject> objectsByPath;
	protected final DBCachedObjectIndex<PrimaryTriple, DBTraceObjectValue> valuesByTriple;
	protected final DBCachedObjectIndex<DBTraceObject, DBTraceObjectValue> valuesByChild;

	protected final Collection<TraceObject> objectsView;
	protected final Collection<TraceObjectValue> valuesView;

	protected TargetObjectSchema rootSchema;

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
		valueStore = factory.getOrCreateCachedStore(DBTraceObjectValue.TABLE_NAME,
			DBTraceObjectValue.class, (s, r) -> new DBTraceObjectValue(this, s, r), true);
		rangeValueMap = new DBTraceAddressSnapRangePropertyMap<>(
			DBTraceObjectAddressRangeValue.TABLE_NAME, dbh, openMode, lock, monitor, baseLanguage,
			trace, null, DBTraceObjectAddressRangeValue.class,
			(t, s, r) -> new DBTraceObjectAddressRangeValue(this, t, s, r));

		objectsByPath =
			objectStore.getIndex(TraceObjectKeyPath.class, DBTraceObject.PATH_COLUMN);
		valuesByTriple =
			valueStore.getIndex(PrimaryTriple.class, DBTraceObjectValue.TRIPLE_COLUMN);
		valuesByChild =
			valueStore.getIndex(DBTraceObject.class, DBTraceObjectValue.CHILD_COLUMN);

		objectsView = Collections.unmodifiableCollection(objectStore.asMap().values());
		valuesView = Collections.unmodifiableCollection(valueStore.asMap().values());
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
		valueStore.invalidateCache();
		rangeValueMap.invalidateCache(all);
		schemaStore.invalidateCache();
		loadRootSchema();
	}

	@Internal
	protected DBTraceObject assertIsMine(TraceObject object) {
		if (!(object instanceof DBTraceObject)) {
			throw new IllegalArgumentException("Object " + object + " is not part of this trace");
		}
		DBTraceObject dbObject = (DBTraceObject) object;
		if (dbObject.manager != this) {
			throw new IllegalArgumentException("Object " + object + " is not part of this trace");
		}
		if (!getAllObjects().contains(dbObject)) {
			throw new IllegalArgumentException("Object " + object + " is not part of this trace");
		}
		return dbObject;
	}

	protected Object validatePrimitive(Object child) {
		try {
			PrimitiveCodec.getCodec(child.getClass());
		}
		catch (IllegalArgumentException e) {
			throw new IllegalArgumentException("Cannot encode " + child, e);
		}
		return child;
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

	protected InternalTraceObjectValue doCreateValue(Range<Long> lifespan,
			DBTraceObject parent, String key, Object value) {
		if (value instanceof AddressRange) {
			DBTraceObjectAddressRangeValue entry = rangeValueMap
					.put(new ImmutableTraceAddressSnapRange((AddressRange) value, lifespan), null);
			entry.set(parent, key, false);
			return entry;
		}
		else if (value instanceof Address) {
			Address address = (Address) value;
			AddressRange singleton = new AddressRangeImpl(address, address);
			DBTraceObjectAddressRangeValue entry = rangeValueMap
					.put(new ImmutableTraceAddressSnapRange(singleton, lifespan), null);
			entry.set(parent, key, true);
			return entry;
		}
		DBTraceObjectValue entry = valueStore.create();
		entry.set(lifespan, parent, key, value);
		if (parent != null) {
			// Don't need event for root value created
			parent.emitEvents(
				new TraceChangeRecord<>(TraceObjectChangeType.VALUE_CREATED, null, entry));
		}
		return entry;
	}

	protected DBTraceObject doCreateObject(TraceObjectKeyPath path) {
		DBTraceObject obj = objectsByPath.getOne(path);
		if (obj != null) {
			return obj;
		}
		obj = objectStore.create();
		obj.set(path);
		obj.emitEvents(new TraceChangeRecord<>(TraceObjectChangeType.CREATED, null, obj));
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
	public TraceObjectValue createRootObject(TargetObjectSchema schema) {
		try (LockHold hold = trace.lockWrite()) {
			setSchema(schema);
			DBTraceObject root = doCreateObject(TraceObjectKeyPath.of());
			assert root.getKey() == 0;
			InternalTraceObjectValue val = doCreateValue(Range.all(), null, "", root);
			assert val.getKey() == 0;
			return val;
		}
	}

	@Override
	public TargetObjectSchema getRootSchema() {
		try (LockHold hold = trace.lockRead()) {
			return rootSchema;
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
	public Stream<? extends DBTraceObject> getObjectsByPath(Range<Long> span,
			TraceObjectKeyPath path) {
		DBTraceObject root = getRootObject();
		return getValuePaths(span, new PathPattern(path.getKeyList()))
				.map(p -> p.getDestinationValue(root))
				.filter(DBTraceObject.class::isInstance)
				.map(DBTraceObject.class::cast);
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getValuePaths(Range<Long> span,
			PathPredicates predicates) {
		try (LockHold hold = trace.lockRead()) {
			DBTraceObjectValue rootVal = valueStore.getObjectAt(0);
			if (rootVal == null) {
				return Stream.of();
			}
			return rootVal.doStreamVisitor(span, new InternalSuccessorsRelativeVisitor(predicates));
		}
	}

	@Override
	public Collection<? extends TraceObject> getAllObjects() {
		return objectsView;
	}

	@Override
	public Collection<? extends TraceObjectValue> getAllValues() {
		return valuesView;
	}

	@Override
	public Collection<? extends TraceObjectValue> getValuesIntersecting(Range<Long> span,
			AddressRange range) {
		return Collections.unmodifiableCollection(
			rangeValueMap.reduce(TraceAddressSnapRangeQuery.intersecting(range, span)).values());
	}

	public Collection<? extends TraceObjectValue> getValuesAt(long snap, Address address) {
		return Collections.unmodifiableCollection(
			rangeValueMap.reduce(TraceAddressSnapRangeQuery.at(address, snap)).values());
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryAllInterface(Range<Long> span,
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
			valueStore.deleteAll();
			rangeValueMap.clear();
			objectStore.deleteAll();
			schemaStore.deleteAll();
			rootSchema = null;
		}
	}

	protected void doDeleteObject(DBTraceObject object) {
		objectStore.delete(object);
		object.emitEvents(new TraceChangeRecord<>(TraceObjectChangeType.DELETED, null, object));
	}

	protected void doDeleteEdge(DBTraceObjectValue edge) {
		valueStore.delete(edge);
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
			return queryAllInterface(Range.all(), iface).collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> Collection<I> getObjectsByPath(String path,
			Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return getObjectsByPath(Range.all(), TraceObjectKeyPath.parse(path))
					.map(o -> o.queryInterface(iface))
					.filter(i -> i != null)
					.collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> I getObjectByPath(long snap, String path,
			Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return getObjectsByPath(Range.singleton(snap), TraceObjectKeyPath.parse(path)).findAny()
					.map(o -> o.queryInterface(iface))
					.orElse(null);
		}
	}

	protected <I extends TraceObjectInterface> Stream<I> doParentsWithKeyHaving(
			Stream<? extends TraceObjectValue> values, String key, Class<I> iface) {
		return values.filter(v -> key.equals(v.getEntryKey()))
				.map(v -> v.getParent())
				.map(o -> o.queryInterface(iface))
				.filter(i -> i != null);
	}

	public <I extends TraceObjectInterface> Collection<I> getObjectsContaining(long snap,
			Address address, String key, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return doParentsWithKeyHaving(getValuesAt(snap, address).stream(), key,
				iface).collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> I getObjectContaining(long snap, Address address,
			String key, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return doParentsWithKeyHaving(getValuesAt(snap, address).stream(), key,
				iface).findAny().orElse(null);
		}
	}

	public <I extends TraceObjectInterface> Collection<I> getObjectsIntersecting(
			Range<Long> lifespan, AddressRange range, String key, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return doParentsWithKeyHaving(getValuesIntersecting(lifespan, range).stream(), key,
				iface).collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> Collection<I> getObjectsAtSnap(long snap,
			Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return queryAllInterface(Range.singleton(snap), iface).collect(Collectors.toSet());
		}
	}

	public <I extends TraceObjectInterface> AddressSetView getObjectsAddressSet(long snap,
			String key, Class<I> ifaceCls, Predicate<? super I> predicate) {
		return rangeValueMap.getAddressSetView(Range.singleton(snap), v -> {
			if (!key.equals(v.getEntryKey())) {
				return false;
			}
			TraceObject parent = v.getParent();
			I iface = parent.queryInterface(ifaceCls);
			if (iface == null) {
				return false;
			}
			if (!predicate.test(iface)) {
				return false;
			}
			return true;
		});
	}

	public <I extends TraceObjectInterface> I getSuccessor(TraceObject seed,
			PathPredicates predicates, long snap, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return seed.getSuccessors(Range.singleton(snap), predicates)
					.map(p -> p.getDestination(seed).queryInterface(iface))
					.filter(i -> i != null)
					.findAny()
					.orElse(null);
		}
	}

	public <I extends TraceObjectInterface> I getLatestSuccessor(TraceObject seed,
			TraceObjectKeyPath path, long snap, Class<I> iface) {
		try (LockHold hold = trace.lockRead()) {
			return seed.getOrderedSuccessors(Range.atMost(snap), path, false)
					.map(p -> p.getDestination(seed).queryInterface(iface))
					.filter(i -> i != null)
					.findAny()
					.orElse(null);
		}
	}

	public TraceObjectBreakpointLocation addBreakpoint(String path, Range<Long> lifespan,
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
			TraceObjectBreakpointLocation loc =
				doAddWithInterface(path, TraceObjectBreakpointLocation.class);
			loc.setName(lifespan, path);
			loc.setRange(lifespan, range);
			// NB. Ignore threads. I'd like to deprecate that field, anyway.
			loc.setKinds(lifespan, kinds);
			loc.setEnabled(lifespan, enabled);
			loc.setComment(lifespan, comment);
			loc.getObject().insert(lifespan, ConflictResolution.DENY);
			return loc;
		}
		catch (DuplicateKeyException e) {
			throw new DuplicateNameException(e.getMessage());
		}
	}

	public TraceObjectMemoryRegion addMemoryRegion(String path, Range<Long> lifespan,
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

	public TraceObjectModule addModule(String path, String name, Range<Long> lifespan,
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

	public TraceObjectSection addSection(String path, String name, Range<Long> lifespan,
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
			stack.getObject().insert(Range.singleton(snap), ConflictResolution.DENY);
			return stack;
		}
	}

	public TraceObjectStackFrame addStackFrame(List<String> keyList, long snap) {
		try (LockHold hold = trace.lockWrite()) {
			TraceObjectStackFrame frame = doAddWithInterface(keyList, TraceObjectStackFrame.class);
			frame.getObject().insert(Range.singleton(snap), ConflictResolution.DENY);
			return frame;
		}
	}

	protected void checkDuplicateThread(String path, Range<Long> lifespan)
			throws DuplicateNameException {
		// TODO: Change the semantics to just expand the life rather than complain of duplication
		DBTraceObject exists = getObjectByCanonicalPath(TraceObjectKeyPath.parse(path));
		if (exists == null) {
			return;
		}
		if (exists.getLife().subRangeSet(lifespan).isEmpty()) {
			return;
		}
		throw new DuplicateNameException("A thread having path '" + path +
			"' already exists within an overlapping snap");
	}

	public TraceObjectThread addThread(String path, String display, Range<Long> lifespan)
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

	public boolean checkMyObject(DBTraceObject object) {
		if (object.manager != this) {
			return false;
		}
		if (!getAllObjects().contains(object)) {
			return false;
		}
		return true;
	}

	public TraceThread assertMyThread(TraceThread thread) {
		if (!(thread instanceof DBTraceObjectThread)) {
			throw new AssertionError("Thread " + thread + " is not an object in this trace");
		}
		DBTraceObjectThread dbThread = (DBTraceObjectThread) thread;
		if (!checkMyObject(dbThread.getObject())) {
			throw new AssertionError("Thread " + thread + " is not an object in this trace");
		}
		return dbThread;
	}
}
