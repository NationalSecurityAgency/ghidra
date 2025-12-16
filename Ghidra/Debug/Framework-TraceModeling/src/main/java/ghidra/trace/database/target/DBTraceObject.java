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
import java.util.stream.Collectors;
import java.util.stream.Stream;

import db.DBRecord;
import db.StringField;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.target.CachePerDBTraceObject.Cached;
import ghidra.trace.database.target.DBTraceObjectValue.ValueLifespanSetter;
import ghidra.trace.database.target.ValueSpace.EntryKeyDimension;
import ghidra.trace.database.target.ValueSpace.SnapDimension;
import ghidra.trace.database.target.visitors.*;
import ghidra.trace.database.target.visitors.TreeTraversal.Visitor;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.*;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.iface.TraceObjectInterface;
import ghidra.trace.model.target.info.TraceObjectInterfaceFactory.Constructor;
import ghidra.trace.model.target.info.TraceObjectInterfaceUtils;
import ghidra.trace.model.target.path.KeyPath;
import ghidra.trace.model.target.path.PathFilter;
import ghidra.trace.model.target.schema.TraceObjectSchema;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.*;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceObject extends DBAnnotatedObject implements TraceObject {
	protected static final String TABLE_NAME = "Objects";

	protected static final class ObjectPathDBFieldCodec
			extends AbstractDBFieldCodec<KeyPath, DBAnnotatedObject, StringField> {

		public ObjectPathDBFieldCodec(Class<DBAnnotatedObject> objectType, Field field,
				int column) {
			super(KeyPath.class, objectType, StringField.class, field, column);
		}

		protected String encode(KeyPath value) {
			return value == null ? null : value.toString();
		}

		protected KeyPath decode(String path) {
			return KeyPath.parse(path);
		}

		@Override
		public void store(KeyPath value, StringField f) {
			f.setString(encode(value));
		}

		@Override
		protected void doStore(DBAnnotatedObject obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			record.setString(column, encode(getValue(obj)));
		}

		@Override
		protected void doLoad(DBAnnotatedObject obj, DBRecord record)
				throws IllegalArgumentException, IllegalAccessException {
			setValue(obj, decode(record.getString(column)));
		}
	}

	// Canonical path
	static final String PATH_COLUMN_NAME = "Path";

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;

	@DBAnnotatedField(
		column = PATH_COLUMN_NAME,
		codec = ObjectPathDBFieldCodec.class,
		indexed = true)
	private KeyPath path;

	protected final DBTraceObjectManager manager;

	private TraceObjectSchema schema;
	private Map<Class<? extends TraceObjectInterface>, TraceObjectInterface> ifaces;

	private final CachePerDBTraceObject cache = new CachePerDBTraceObject();
	private volatile MutableLifeSet cachedLife = null;

	public DBTraceObject(DBTraceObjectManager manager, DBCachedObjectStore<?> store,
			DBRecord record) {
		super(store, record);
		this.manager = manager;
	}

	@Override
	protected void fresh(boolean created) throws IOException {
		if (created) {
			return;
		}
		if (path != null) {
			freshIfaces();
		}
	}

	@Override
	public String toString() {
		return "TraceObject: " + getCanonicalPath();
	}

	protected void freshIfaces() {
		if (ifaces != null) {
			return;
		}
		ifaces = TraceObjectInterfaceUtils.streamConstructors(getSchema())
				.collect(Collectors.toUnmodifiableMap(
					Constructor::iface,
					c -> c.ctor().apply(this)));
	}

	protected void set(KeyPath path) {
		this.path = path;
		update(PATH_COLUMN);

		freshIfaces();
	}

	@Override
	public DBTrace getTrace() {
		return manager.trace;
	}

	public DBTraceObjectManager getManager() {
		return manager;
	}

	@Override
	public DBTraceObject getRoot() {
		return manager.getRootObject();
	}

	@Override
	public KeyPath getCanonicalPath() {
		try (LockHold hold = manager.trace.lockRead()) {
			return path;
		}
	}

	protected LifeSet ensureCachedLife() {
		if (cachedLife != null) {
			return cachedLife;
		}
		MutableLifeSet result = new DefaultLifeSet();
		getCanonicalParents(Lifespan.ALL).forEach(v -> result.add(v.getLifespan()));
		cachedLife = result;
		return result;
	}

	@Override
	public LifeSet getLife() {
		try (LockHold hold = manager.trace.lockRead()) {
			LifeSet result = ensureCachedLife();
			synchronized (result) {
				return DefaultLifeSet.copyOf(result);
			}
		}
	}

	@Override
	public boolean isAlive(long snap) {
		try (LockHold hold = manager.trace.lockRead()) {
			LifeSet result = ensureCachedLife();
			synchronized (result) {
				return result.contains(snap);
			}
		}
	}

	@Override
	public boolean isAlive(Lifespan span) {
		try (LockHold hold = manager.trace.lockRead()) {
			LifeSet result = ensureCachedLife();
			synchronized (result) {
				return result.intersects(span);
			}
		}
	}

	protected DBTraceObject doCreateCanonicalParentObject() {
		return manager.doCreateObject(path.parent());
	}

	protected DBTraceObject doGetCanonicalParentObject() {
		return manager.doGetObject(path.parent());
	}

	protected DBTraceObjectValPath doInsert(Lifespan lifespan, ConflictResolution resolution) {
		if (path.isRoot()) {
			return DBTraceObjectValPath.of();
		}
		DBTraceObject parent = doCreateCanonicalParentObject();
		DBTraceObjectValue value = parent.setValue(lifespan, path.key(), this, resolution);
		// TODO: Should I re-order the recursion, so values are inserted from root to this?
		// TODO: Should child lifespans be allowed to exceed the parent's?
		DBTraceObjectValPath path = parent.doInsert(lifespan, resolution);
		return path.append(value);
	}

	@Override
	public DBTraceObjectValPath insert(Lifespan lifespan, ConflictResolution resolution) {
		try (LockHold hold = manager.trace.lockWrite()) {
			return doInsert(lifespan, resolution);
		}
	}

	protected void doRemove(Lifespan span) {
		if (isRoot()) {
			throw new IllegalArgumentException("Cannot remove the root object");
		}
		DBTraceObject parent = doGetCanonicalParentObject();
		parent.setValue(span, path.key(), null);
		// Do not recurse on parent
	}

	@Override
	public void remove(Lifespan span) {
		try (LockHold hold = manager.trace.lockWrite()) {
			doRemove(span);
		}
	}

	protected void doRemoveTree(Lifespan span) {
		for (DBTraceObjectValue parent : getParents(span)) {
			parent.doTruncateOrDeleteAndEmitLifeChange(span);
		}
		for (DBTraceObjectValue value : getValues(span)) {
			value.doTruncateOrDeleteAndEmitLifeChange(span);
			if (value.isCanonical()) {
				value.getChild().doRemoveTree(span);
			}
		}
	}

	@Override
	public void removeTree(Lifespan span) {
		try (LockHold hold = manager.trace.lockWrite()) {
			doRemoveTree(span);
		}
	}

	protected Stream<DBTraceObjectValueData> streamCanonicalParentsData(Lifespan lifespan) {
		return manager.valueMap.reduce(TraceObjectValueQuery.canonicalParents(this, lifespan))
				.values()
				.stream();
	}

	protected Stream<DBTraceObjectValueBehind> streamCanonicalParentsBehind(Lifespan lifespan) {
		return manager.valueWbCache.streamCanonicalParents(this, lifespan);
	}

	protected Stream<DBTraceObjectValue> streamCanonicalParents(Lifespan lifespan) {
		return Stream.concat(
			streamCanonicalParentsData(lifespan).map(v -> v.getWrapper()),
			streamCanonicalParentsBehind(lifespan).map(v -> v.getWrapper()));
	}

	@Override
	public TraceObjectValue getCanonicalParent(long snap) {
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return manager.getRootValue();
			}
			return streamCanonicalParents(Lifespan.at(snap)).findAny().orElse(null);
		}
	}

	@Override
	public Stream<DBTraceObjectValue> getCanonicalParents(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return Stream.of(manager.getRootValue());
			}
			return streamCanonicalParents(lifespan).toList().stream();
		}
	}

	@Override
	public boolean isRoot() {
		try (LockHold hold = manager.trace.lockRead()) {
			return path.isRoot();
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getAllPaths(Lifespan span) {
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return Stream.of(DBTraceObjectValPath.of());
			}
			return doStreamVisitor(span, AllPathsVisitor.INSTANCE);
		}
	}

	@Override
	public Collection<Class<? extends TraceObjectInterface>> getInterfaces() {
		return getSchema().getInterfaces();
	}

	@Override
	public <I extends TraceObjectInterface> I queryInterface(Class<I> ifCls) {
		return ifCls.cast(ifaces.get(ifCls));
	}

	protected Stream<DBTraceObjectValueData> streamParentsData(Lifespan lifespan) {
		return manager.valueMap.reduce(TraceObjectValueQuery.parents(this, lifespan))
				.values()
				.stream();
	}

	protected Stream<DBTraceObjectValueBehind> streamParentsBehind(Lifespan lifespan) {
		return manager.valueWbCache.streamParents(this, lifespan);
	}

	protected Stream<DBTraceObjectValue> streamParents(Lifespan lifespan) {
		return Stream.concat(
			streamParentsData(lifespan).map(v -> v.getWrapper()),
			streamParentsBehind(lifespan).map(v -> v.getWrapper()));
	}

	@Override
	public Collection<DBTraceObjectValue> getParents(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			return streamParents(lifespan).toList();
		}
	}

	protected boolean doHasAnyValues() {
		return streamValuesW(Lifespan.ALL).findAny().isPresent();
	}

	protected Stream<DBTraceObjectValueData> streamValuesData(Lifespan lifespan) {
		return manager.valueMap
				.reduce(TraceObjectValueQuery.values(this, lifespan)
						.starting(EntryKeyDimension.FORWARD))
				.values()
				.stream();
	}

	protected Stream<DBTraceObjectValueBehind> streamValuesBehind(Lifespan lifespan) {
		return manager.valueWbCache.streamValues(this, lifespan);
	}

	protected Stream<DBTraceObjectValue> streamValuesW(Lifespan lifespan) {
		return Stream.concat(
			streamValuesData(lifespan).map(d -> d.getWrapper()),
			streamValuesBehind(lifespan).map(b -> b.getWrapper()));
	}

	protected Stream<DBTraceObjectValue> streamValuesR(Lifespan lifespan) {
		Cached<Stream<DBTraceObjectValue>> cached = cache.streamValues(lifespan);
		if (!cached.isMiss()) {
			return cached.value();
		}
		Lifespan expanded = cache.expandLifespan(lifespan);
		Stream<DBTraceObjectValue> stream = streamValuesW(expanded);
		return cache.offerStreamAnyKey(expanded, stream, lifespan);
	}

	protected boolean doHasAnyParents() {
		return streamParents(Lifespan.ALL).findAny().isPresent();
	}

	protected boolean doIsConnected() {
		return doHasAnyParents() || doHasAnyValues();
	}

	@Override
	public Collection<DBTraceObjectValue> getValues(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			return streamValuesR(lifespan).toList();
		}
	}

	@Override
	public Collection<DBTraceObjectValue> getElements(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			return streamValuesR(lifespan)
					.filter(v -> KeyPath.isIndex(v.getEntryKey()))
					.toList();
		}
	}

	@Override
	public Collection<DBTraceObjectValue> getAttributes(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			return streamValuesR(lifespan)
					.filter(v -> KeyPath.isName(v.getEntryKey()))
					.toList();
		}
	}

	protected void doCheckConflicts(Lifespan span, String key, Object value) {
		for (DBTraceObjectValue val : StreamUtils.iter(streamValuesR(span, key, true))) {
			if (!Objects.equals(value, val.getValue())) {
				throw new DuplicateKeyException(key);
			}
		}
	}

	protected Lifespan doAdjust(Lifespan span, String key, Object value) {
		// Ordered by min, so I only need to consider the first conflict
		// If start is contained in an entry, assume the user means to overwrite it.
		for (DBTraceObjectValue val : StreamUtils.iter(streamValuesR(span, key, true))) {
			if (Objects.equals(value, val.getValue())) {
				continue; // not a conflict
			}
			if (val.getLifespan().contains(span.min())) {
				continue; // user probably wants to overwrite the remainder of this entry
			}
			// Every entry intersects the span, so if we get one, adjust
			return span.withMax(val.getMinSnap() - 1);
		}
		return span;
	}

	protected Stream<DBTraceObjectValueData> streamValuesData(Lifespan span, String key,
			boolean forward) {
		return manager.valueMap
				.reduce(TraceObjectValueQuery.values(this, key, key, span)
						.starting(forward ? SnapDimension.FORWARD : SnapDimension.BACKWARD))
				.orderedValues()
				.stream();
	}

	protected Stream<DBTraceObjectValueBehind> streamValuesBehind(Lifespan span, String key,
			boolean forward) {
		return manager.valueWbCache.streamValues(this, key, span, forward);
	}

	protected Stream<DBTraceObjectValue> streamValuesW(Lifespan span, String key, boolean forward) {
		return StreamUtils.merge(List.of(
			streamValuesData(span, key, forward).map(d -> d.getWrapper()),
			streamValuesBehind(span, key, forward).map(b -> b.getWrapper())),
			Comparator.comparing(forward ? v -> v.getMinSnap() : v -> -v.getMaxSnap()));
	}

	protected Stream<DBTraceObjectValue> streamValuesR(Lifespan span, String key, boolean forward) {
		Cached<Stream<DBTraceObjectValue>> cached = cache.streamValues(span, key, forward);
		if (!cached.isMiss()) {
			return cached.value();
		}
		Lifespan expanded = cache.expandLifespan(span);
		Stream<DBTraceObjectValue> stream = streamValuesW(expanded, key, forward);
		return cache.offerStreamPerKey(expanded, stream, span, key, forward);
	}

	@Override
	public Collection<? extends DBTraceObjectValue> getValues(Lifespan span, String key) {
		try (LockHold hold = manager.trace.lockRead()) {
			String k = getSchema().checkAliasedAttribute(key);
			return streamValuesR(span, k, true).toList();
		}
	}

	protected DBTraceObjectValue getValueW(long snap, String key) {
		DBTraceObjectValueBehind behind = manager.valueWbCache.get(this, key, snap);
		if (behind != null) {
			return behind.getWrapper();
		}
		DBTraceObjectValueData data = manager.valueMap
				.reduce(TraceObjectValueQuery.values(this, key, key, Lifespan.at(snap)))
				.firstValue();
		if (data != null) {
			return data.getWrapper();
		}
		return null;
	}

	protected DBTraceObjectValue getValueR(long snap, String key) {
		Cached<DBTraceObjectValue> cached = cache.getValue(snap, key);
		if (!cached.isMiss()) {
			return cached.value();
		}
		Lifespan expanded = cache.expandLifespan(Lifespan.at(snap));
		Stream<DBTraceObjectValue> stream = streamValuesW(expanded, key, true);
		return cache.offerGetValue(expanded, stream, snap, key);
	}

	@Override
	public DBTraceObjectValue getValue(long snap, String key) {
		try (LockHold hold = manager.trace.lockRead()) {
			String k = getSchema().checkAliasedAttribute(key);
			return getValueR(snap, k);
		}
	}

	@Override
	public Stream<DBTraceObjectValue> getOrderedValues(Lifespan span, String key,
			boolean forward) {
		try (LockHold hold = manager.trace.lockRead()) {
			String k = getSchema().checkAliasedAttribute(key);
			// Locking issue if we stream lazily. Capture to list with lock
			return streamValuesR(span, k, forward).toList().stream();
		}
	}

	@Override
	public DBTraceObjectValue getElement(long snap, String index) {
		return getValue(snap, KeyPath.makeKey(index));
	}

	@Override
	public DBTraceObjectValue getElement(long snap, long index) {
		return getElement(snap, KeyPath.makeIndex(index));
	}

	@Override
	public TraceObjectValue getAttribute(long snap, String name) {
		if (!KeyPath.isName(name)) {
			throw new IllegalArgumentException("name cannot be an index");
		}
		return getValue(snap, name);
	}

	protected Stream<? extends TraceObjectValPath> doStreamVisitor(Lifespan span,
			Visitor visitor) {
		// Capturing to list with lock
		return TreeTraversal.INSTANCE.walkObject(visitor, this, span,
			DBTraceObjectValPath.of()).toList().stream();
	}

	@Override
	public Stream<? extends TraceObjectValPath> getAncestors(Lifespan span,
			PathFilter relativeFilter) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends TraceObjectValPath> ancestors =
				doStreamVisitor(span, new AncestorsRelativeVisitor(relativeFilter));
			if (relativeFilter.matches(KeyPath.ROOT)) {
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), ancestors);
			}
			return ancestors;
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getAncestorsRoot(
			Lifespan span, PathFilter rootFilter) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doStreamVisitor(span, new AncestorsRootVisitor(rootFilter));
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getSuccessors(
			Lifespan span, PathFilter relativeFilter) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends TraceObjectValPath> succcessors =
				doStreamVisitor(span, new SuccessorsRelativeVisitor(relativeFilter));
			if (relativeFilter.matches(KeyPath.ROOT)) {
				// Pre-cat the empty path (not the empty stream)
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), succcessors);
			}
			return succcessors;
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getOrderedSuccessors(Lifespan span,
			KeyPath relativePath, boolean forward) {
		DBTraceObjectValPath empty = DBTraceObjectValPath.of();
		try (LockHold hold = manager.trace.lockRead()) {
			if (relativePath.isRoot()) {
				// Singleton of empty path (not the empty stream)
				return Stream.of(empty);
			}
			return doStreamVisitor(span,
				new OrderedSuccessorsVisitor(relativePath, forward));
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getCanonicalSuccessors(
			PathFilter relativeFilter) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends TraceObjectValPath> successors = doStreamVisitor(Lifespan.ALL,
				new CanonicalSuccessorsRelativeVisitor(relativeFilter));
			if (relativeFilter.matches(KeyPath.ROOT)) {
				// Pre-cat the empty path (not the empty stream)
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), successors);
			}
			return successors;
		}
	}

	protected DBTraceObjectValue doCreateValue(Lifespan lifespan, String key, Object value) {
		return manager.doCreateValue(lifespan, this, key, value);
	}

	@Override
	public DBTraceObjectValue setValue(Lifespan lifespan, String key, Object value,
			ConflictResolution resolution) {
		try (LockHold hold = manager.trace.lockWrite()) {
			if (isDeleted()) {
				throw new IllegalStateException("Cannot set value on deleted object.");
			}
			String k = getSchema().checkAliasedAttribute(key);
			if (resolution == ConflictResolution.DENY) {
				doCheckConflicts(lifespan, k, value);
			}
			else if (resolution == ConflictResolution.ADJUST) {
				lifespan = doAdjust(lifespan, k, value);
			}
			var setter = new ValueLifespanSetter(lifespan, value) {
				DBTraceObject canonicalLifeChanged = null;

				@Override
				protected Iterable<DBTraceObjectValue> getIntersecting(Long lower,
						Long upper) {
					return StreamUtils.iter(streamValuesR(Lifespan.span(lower, upper), k, true));
				}

				@Override
				protected void remove(DBTraceObjectValue entry) {
					if (entry.isCanonical()) {
						canonicalLifeChanged = entry.getChild();
					}
					super.remove(entry);
				}

				@Override
				protected DBTraceObjectValue put(Lifespan range, Object value) {
					DBTraceObjectValue entry = super.put(range, value);
					if (entry != null && entry.isCanonical()) {
						canonicalLifeChanged = entry.getChild();
					}
					return entry;
				}

				@Override
				protected DBTraceObjectValue create(Lifespan range, Object value) {
					return doCreateValue(range, k, value);
				}
			};
			DBTraceObjectValue result = setter.set(lifespan, value);

			DBTraceObject child = setter.canonicalLifeChanged;
			if (child != null) {
				child.emitEvents(
					new TraceChangeRecord<>(TraceEvents.OBJECT_LIFE_CHANGED, null, child));
			}
			return result;
		}
	}

	static AddressSpace spaceForValue(Object value) {
		return switch (value) {
			case Address address -> address.getAddressSpace();
			case AddressRange range -> range.getAddressSpace();
			default -> null;
		};
	}

	@Override
	public TraceObjectValue setValue(Lifespan lifespan, String key, Object value) {
		return setValue(lifespan, key, value, ConflictResolution.TRUNCATE);
	}

	@Override
	public TraceObjectValue setAttribute(Lifespan lifespan, String name, Object value) {
		if (!KeyPath.isName(name)) {
			throw new IllegalArgumentException("Attribute name must not be an index");
		}
		return setValue(lifespan, name, value);
	}

	@Override
	public TraceObjectValue setElement(Lifespan lifespan, String index, Object value) {
		return setValue(lifespan, KeyPath.makeKey(index), value);
	}

	@Override
	public TraceObjectValue setElement(Lifespan lifespan, long index, Object value) {
		return setElement(lifespan, KeyPath.makeIndex(index), value);
	}

	@Override
	public TraceObjectSchema getSchema() {
		// NOTE: No need to synchronize. Schema is immutable.
		if (schema == null) {
			schema = manager.rootSchema.getSuccessorSchema(path);
		}
		return schema;
	}

	@Override
	public Stream<? extends TraceObjectValPath> findAncestorsInterface(Lifespan span,
			Class<? extends TraceObjectInterface> iface) {
		// This is a sort of meet-in-the-middle. The type search must originate from the root
		PathFilter filter = getManager().getRootSchema().searchFor(iface, false);
		return getAncestorsRoot(span, filter);
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryAncestorsInterface(Lifespan span,
			Class<I> iface) {
		return findAncestorsInterface(span, iface)
				.map(p -> p.getSource(this).queryInterface(iface));
	}

	public TraceObject findOrCreateCanonicalAncestorInterface(
			Class<? extends TraceObjectInterface> iface) {
		PathFilter filter = getManager().getRootSchema().searchFor(iface, false);
		return path.streamMatchingAncestry(filter)
				.limit(1)
				.map(kp -> manager.createObject(kp))
				.findAny()
				.orElseThrow();
	}

	public <I extends TraceObjectInterface> I queryOrCreateCanonicalAncestorInterface(
			Class<I> iface) {
		return findOrCreateCanonicalAncestorInterface(iface).queryInterface(iface);
	}

	@Override
	public Stream<? extends TraceObject> findCanonicalAncestorsInterface(
			Class<? extends TraceObjectInterface> iface) {
		// This is a sort of meet-in-the-middle. The type search must originate from the root
		PathFilter filter = getManager().getRootSchema().searchFor(iface, false);
		try (LockHold hold = manager.trace.lockRead()) {
			return path.streamMatchingAncestry(filter)
					.map(kp -> manager.getObjectByCanonicalPath(kp));
		}
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryCanonicalAncestorsInterface(
			Class<I> iface) {
		return findCanonicalAncestorsInterface(iface).map(o -> o.queryInterface(iface));
	}

	// TODO: Post filter until GP-1301
	private boolean isActuallyInterface(TraceObjectValPath path,
			Class<? extends TraceObjectInterface> iface) {
		TraceObjectValue lastEntry = path.getLastEntry();
		if (lastEntry == null) {
			// TODO: This assumes the client will call getDestination(this)
			return this.getSchema().getInterfaces().contains(iface);
		}
		if (!lastEntry.isObject()) {
			return false;
		}
		return lastEntry.getChild().getSchema().getInterfaces().contains(iface);
	}

	@Override
	public Stream<? extends TraceObjectValPath> findSuccessorsInterface(Lifespan span,
			Class<? extends TraceObjectInterface> iface, boolean requireCanonical) {
		PathFilter filter = getSchema().searchFor(iface, requireCanonical);
		return getSuccessors(span, filter).filter(p -> isActuallyInterface(p, iface));
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> querySuccessorsInterface(Lifespan span,
			Class<I> iface, boolean requireCanonical) {
		return findSuccessorsInterface(span, iface, requireCanonical)
				.map(p -> p.getDestination(this).queryInterface(iface));
	}

	protected void doDelete() {
		manager.doDeleteObject(this);
	}

	protected void doDeleteReferringValues() {
		for (DBTraceObjectValue child : getValues(Lifespan.ALL)) {
			child.doDeleteAndEmit();
		}
		for (DBTraceObjectValue parent : getParents(Lifespan.ALL)) {
			parent.doDeleteAndEmit();
		}
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			doDeleteReferringValues();
			doDelete();
		}
	}

	protected void emitEvents(TraceChangeRecord<?, ?> rec) {
		manager.trace.setChanged(rec);
		for (TraceObjectInterface iface : ifaces.values()) {
			DBTraceObjectInterface dbIface = (DBTraceObjectInterface) iface;
			try {
				TraceChangeRecord<?, ?> evt = dbIface.translateEvent(rec);
				if (evt != null) {
					manager.trace.setChanged(evt);
				}
			}
			catch (Throwable t) {
				Msg.error(this,
					"Error while translating event " + rec + " for interface " + iface + ":" + t);
			}
		}
	}

	protected void notifyValueCreated(DBTraceObjectValue value) {
		cache.notifyValueCreated(value);
	}

	protected void notifyValueDeleted(DBTraceObjectValue value) {
		cache.notifyValueDeleted(value);
	}

	protected void notifyParentValueCreated(DBTraceObjectValue parent) {
		Objects.requireNonNull(parent);
		if (cachedLife != null && parent.isCanonical()) {
			synchronized (cachedLife) {
				cachedLife.add(parent.getLifespan());
			}
		}
	}

	protected void notifyParentValueDeleted(DBTraceObjectValue parent) {
		Objects.requireNonNull(parent);
		if (cachedLife != null && parent.isCanonical()) {
			synchronized (cachedLife) {
				cachedLife.remove(parent.getLifespan());
			}
		}
	}
}
