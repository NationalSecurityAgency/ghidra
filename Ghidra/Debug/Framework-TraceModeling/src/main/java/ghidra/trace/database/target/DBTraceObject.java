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
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import db.DBRecord;
import db.StringField;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.breakpoint.DBTraceObjectBreakpointLocation;
import ghidra.trace.database.breakpoint.DBTraceObjectBreakpointSpec;
import ghidra.trace.database.memory.DBTraceObjectMemoryRegion;
import ghidra.trace.database.memory.DBTraceObjectRegister;
import ghidra.trace.database.module.*;
import ghidra.trace.database.stack.DBTraceObjectStack;
import ghidra.trace.database.stack.DBTraceObjectStackFrame;
import ghidra.trace.database.target.InternalTraceObjectValue.ValueLifespanSetter;
import ghidra.trace.database.target.ValueSpace.EntryKeyDimension;
import ghidra.trace.database.target.ValueSpace.SnapDimension;
import ghidra.trace.database.target.visitors.*;
import ghidra.trace.database.target.visitors.TreeTraversal.Visitor;
import ghidra.trace.database.thread.DBTraceObjectThread;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.*;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.breakpoint.TraceObjectBreakpointLocation;
import ghidra.trace.model.breakpoint.TraceObjectBreakpointSpec;
import ghidra.trace.model.memory.TraceObjectMemoryRegion;
import ghidra.trace.model.memory.TraceObjectRegister;
import ghidra.trace.model.modules.TraceObjectModule;
import ghidra.trace.model.stack.TraceObjectStack;
import ghidra.trace.model.stack.TraceObjectStackFrame;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.annot.TraceObjectInterfaceUtils;
import ghidra.trace.model.thread.TraceObjectThread;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;
import ghidra.util.Msg;
import ghidra.util.database.*;
import ghidra.util.database.DBCachedObjectStoreFactory.AbstractDBFieldCodec;
import ghidra.util.database.annot.*;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceObject extends DBAnnotatedObject implements TraceObject {
	protected static final String TABLE_NAME = "Objects";

	private static final int VALUE_CACHE_SIZE = 50;

	protected static <T extends TraceObjectInterface> //
	Map.Entry<Class<? extends T>, Function<DBTraceObject, ? extends T>> safeEntry(
			Class<T> cls, Function<DBTraceObject, ? extends T> ctor) {
		return Map.entry(cls, ctor);
	}

	protected static final Map<Class<? extends TraceObjectInterface>, //
			Function<DBTraceObject, ? extends TraceObjectInterface>> CTORS = Map.ofEntries(
				safeEntry(TraceObjectThread.class, DBTraceObjectThread::new),
				safeEntry(TraceObjectMemoryRegion.class, DBTraceObjectMemoryRegion::new),
				safeEntry(TraceObjectModule.class, DBTraceObjectModule::new),
				safeEntry(TraceObjectSection.class, DBTraceObjectSection::new),
				safeEntry(TraceObjectBreakpointSpec.class, DBTraceObjectBreakpointSpec::new),
				safeEntry(TraceObjectBreakpointLocation.class,
					DBTraceObjectBreakpointLocation::new),
				safeEntry(TraceObjectStack.class, DBTraceObjectStack::new),
				safeEntry(TraceObjectStackFrame.class, DBTraceObjectStackFrame::new),
				safeEntry(TraceObjectRegister.class, DBTraceObjectRegister::new));

	protected static final class ObjectPathDBFieldCodec
			extends AbstractDBFieldCodec<TraceObjectKeyPath, DBAnnotatedObject, StringField> {

		public ObjectPathDBFieldCodec(Class<DBAnnotatedObject> objectType, Field field,
				int column) {
			super(TraceObjectKeyPath.class, objectType, StringField.class, field, column);
		}

		protected String encode(TraceObjectKeyPath value) {
			return value == null ? null : value.toString();
		}

		protected TraceObjectKeyPath decode(String path) {
			return TraceObjectKeyPath.parse(path);
		}

		@Override
		public void store(TraceObjectKeyPath value, StringField f) {
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

	record CachedLifespanValues(Lifespan span, Set<InternalTraceObjectValue> values) {
	}

	// Canonical path
	static final String PATH_COLUMN_NAME = "Path";

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;

	@DBAnnotatedField(
		column = PATH_COLUMN_NAME,
		codec = ObjectPathDBFieldCodec.class,
		indexed = true)
	private TraceObjectKeyPath path;

	protected final DBTraceObjectManager manager;

	private TargetObjectSchema targetSchema;
	private Map<Class<? extends TraceObjectInterface>, TraceObjectInterface> ifaces;

	private final Map<String, InternalTraceObjectValue> valueCache = new LinkedHashMap<>() {
		protected boolean removeEldestEntry(Map.Entry<String, InternalTraceObjectValue> eldest) {
			return size() > VALUE_CACHE_SIZE;
		}
	};
	private final Map<String, Long> nullCache = new LinkedHashMap<>() {
		protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
			return size() > VALUE_CACHE_SIZE;
		}
	};
	private CachedLifespanValues cachedLifespanValues = null;
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
		Set<Class<? extends TargetObject>> targetIfaces = getTargetSchema().getInterfaces();
		ifaces = CTORS.entrySet()
				.stream()
				.filter(
					e -> targetIfaces.contains(TraceObjectInterfaceUtils.toTargetIf(e.getKey())))
				.collect(
					Collectors.toUnmodifiableMap(e -> e.getKey(), e -> e.getValue().apply(this)));
	}

	protected void set(TraceObjectKeyPath path) {
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
	public TraceObjectKeyPath getCanonicalPath() {
		try (LockHold hold = manager.trace.lockRead()) {
			return path;
		}
	}

	@Override
	public LifeSet getLife() {
		try (LockHold hold = manager.trace.lockRead()) {
			if (cachedLife != null) {
				synchronized (cachedLife) {
					return DefaultLifeSet.copyOf(cachedLife);
				}
			}
			MutableLifeSet result = new DefaultLifeSet();
			getCanonicalParents(Lifespan.ALL).forEach(v -> result.add(v.getLifespan()));
			cachedLife = result;
			synchronized (result) {
				return DefaultLifeSet.copyOf(result);
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
		InternalTraceObjectValue value = parent.setValue(lifespan, path.key(), this, resolution);
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
		for (InternalTraceObjectValue parent : getParents(span)) {
			parent.doTruncateOrDeleteAndEmitLifeChange(span);
		}
		for (InternalTraceObjectValue value : getValues(span)) {
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

	@Override
	public TraceObjectValue getCanonicalParent(long snap) {
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return manager.getRootValue();
			}
			return manager.valueMap
					.reduce(TraceObjectValueQuery.canonicalParents(this, Lifespan.at(snap)))
					.firstValue();
		}
	}

	@Override
	public Stream<? extends InternalTraceObjectValue> getCanonicalParents(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return Stream.of(manager.getRootValue());
			}
			List<InternalTraceObjectValue> list = List.copyOf(
				manager.valueMap.reduce(TraceObjectValueQuery.canonicalParents(this, lifespan))
						.values());
			return list.stream();
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
		Set<Class<? extends TargetObject>> targetIfs = getTargetSchema().getInterfaces();
		return CTORS.keySet()
				.stream()
				.filter(iface -> targetIfs.contains(TraceObjectInterfaceUtils.toTargetIf(iface)))
				.collect(Collectors.toSet());
	}

	@Override
	public <I extends TraceObjectInterface> I queryInterface(Class<I> ifCls) {
		return ifCls.cast(ifaces.get(ifCls));
	}

	protected Collection<? extends InternalTraceObjectValue> doGetParents(Lifespan lifespan) {
		return List.copyOf(
			manager.valueMap.reduce(TraceObjectValueQuery.parents(this, lifespan)).values());
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getParents(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetParents(lifespan);
		}
	}

	protected boolean doHasAnyValues() {
		return !manager.valueMap.reduce(TraceObjectValueQuery.values(this, Lifespan.ALL))
				.isEmpty();
	}

	protected Collection<? extends InternalTraceObjectValue> doGetValues(Lifespan lifespan) {
		return manager.valueMap
				.reduce(TraceObjectValueQuery.values(this, lifespan)
						.starting(EntryKeyDimension.FORWARD))
				.values();
	}

	protected Collection<? extends InternalTraceObjectValue> cachedDoGetValues(Lifespan lifespan) {
		if (Long.compareUnsigned(lifespan.lmax() - lifespan.lmin(), 10) > 0) {
			return List.copyOf(doGetValues(lifespan));
		}
		if (cachedLifespanValues == null || !cachedLifespanValues.span.encloses(lifespan)) {
			// Expand the query to take advantage of spatial locality (in the time dimension)
			long min = lifespan.lmin() - 10;
			if (min > lifespan.lmin()) {
				min = Lifespan.ALL.lmin();
			}
			long max = lifespan.lmax() + 10;
			if (max < lifespan.lmax()) {
				max = Lifespan.ALL.lmax();
			}
			Lifespan expanded = Lifespan.span(min, max);
			cachedLifespanValues =
				new CachedLifespanValues(expanded, new HashSet<>(doGetValues(expanded)));
		}
		return cachedLifespanValues.values.stream()
				.filter(v -> v.getLifespan().intersects(lifespan))
				.toList();
	}

	protected boolean doHasAnyParents() {
		return !manager.valueMap.reduce(TraceObjectValueQuery.parents(this, Lifespan.ALL))
				.isEmpty();
	}

	protected boolean doIsConnected() {
		return doHasAnyParents() || doHasAnyValues();
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getValues(Lifespan lifespan) {
		try (LockHold hold = manager.trace.lockRead()) {
			return cachedDoGetValues(lifespan);
		}
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getElements(Lifespan lifespan) {
		return getValues(lifespan).stream()
				.filter(v -> PathUtils.isIndex(v.getEntryKey()))
				.toList();
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getAttributes(Lifespan lifespan) {
		return getValues(lifespan).stream()
				.filter(v -> PathUtils.isName(v.getEntryKey()))
				.toList();
	}

	protected void doCheckConflicts(Lifespan span, String key, Object value) {
		for (InternalTraceObjectValue val : doGetValues(span, key, true)) {
			if (!Objects.equals(value, val.getValue())) {
				throw new DuplicateKeyException(key);
			}
		}
	}

	protected Lifespan doAdjust(Lifespan span, String key, Object value) {
		// Ordered by min, so I only need to consider the first conflict
		// If start is contained in an entry, assume the user means to overwrite it.
		for (InternalTraceObjectValue val : doGetValues(span, key, true)) {
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

	protected Collection<? extends InternalTraceObjectValue> doGetValues(Lifespan span,
			String key, boolean forward) {
		return manager.valueMap
				.reduce(TraceObjectValueQuery.values(this, key, key, span)
						.starting(forward ? SnapDimension.FORWARD : SnapDimension.BACKWARD))
				.orderedValues();
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getValues(Lifespan span, String key) {
		try (LockHold hold = manager.trace.lockRead()) {
			String k = getTargetSchema().checkAliasedAttribute(key);
			return doGetValues(span, k, true);
		}
	}

	@Override
	public InternalTraceObjectValue getValue(long snap, String key) {
		try (LockHold hold = manager.trace.lockRead()) {
			String k = getTargetSchema().checkAliasedAttribute(key);
			InternalTraceObjectValue cached = valueCache.get(k);
			if (cached != null && !cached.isDeleted() && cached.getLifespan().contains(snap)) {
				return cached;
			}
			Long nullSnap = nullCache.get(k);
			if (nullSnap != null && nullSnap.longValue() == snap) {
				return null;
			}
			InternalTraceObjectValue found = manager.valueMap
					.reduce(TraceObjectValueQuery.values(this, k, k, Lifespan.at(snap)))
					.firstValue();
			if (found == null) {
				nullCache.put(k, snap);
			}
			else {
				valueCache.put(k, found);
			}
			return found;
		}
	}

	@Override
	public Stream<? extends InternalTraceObjectValue> getOrderedValues(Lifespan span, String key,
			boolean forward) {
		try (LockHold hold = manager.trace.lockRead()) {
			String k = getTargetSchema().checkAliasedAttribute(key);
			return doGetValues(span, k, forward).stream();
		}
	}

	@Override
	public InternalTraceObjectValue getElement(long snap, String index) {
		return getValue(snap, PathUtils.makeKey(index));
	}

	@Override
	public InternalTraceObjectValue getElement(long snap, long index) {
		return getElement(snap, PathUtils.makeIndex(index));
	}

	@Override
	public TraceObjectValue getAttribute(long snap, String name) {
		if (!PathUtils.isName(name)) {
			throw new IllegalArgumentException("name cannot be an index");
		}
		return getValue(snap, name);
	}

	protected Stream<? extends TraceObjectValPath> doStreamVisitor(Lifespan span,
			Visitor visitor) {
		return TreeTraversal.INSTANCE.walkObject(visitor, this, span,
			DBTraceObjectValPath.of());
	}

	@Override
	public Stream<? extends TraceObjectValPath> getAncestors(Lifespan span,
			PathPredicates relativePredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends TraceObjectValPath> ancestors =
				doStreamVisitor(span, new AncestorsRelativeVisitor(relativePredicates));
			if (relativePredicates.matches(List.of())) {
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), ancestors);
			}
			return ancestors;
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getAncestorsRoot(
			Lifespan span, PathPredicates rootPredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doStreamVisitor(span, new AncestorsRootVisitor(rootPredicates));
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getSuccessors(
			Lifespan span, PathPredicates relativePredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends TraceObjectValPath> succcessors =
				doStreamVisitor(span, new SuccessorsRelativeVisitor(relativePredicates));
			if (relativePredicates.matches(List.of())) {
				// Pre-cat the empty path (not the empty stream)
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), succcessors);
			}
			return succcessors;
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getOrderedSuccessors(Lifespan span,
			TraceObjectKeyPath relativePath, boolean forward) {
		DBTraceObjectValPath empty = DBTraceObjectValPath.of();
		try (LockHold hold = manager.trace.lockRead()) {
			if (relativePath.isRoot()) {
				return Stream.of(empty); // Not the empty stream
			}
			return doStreamVisitor(span,
				new OrderedSuccessorsVisitor(relativePath, forward));
		}
	}

	@Override
	public Stream<? extends TraceObjectValPath> getCanonicalSuccessors(
			PathPredicates relativePredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends TraceObjectValPath> successors = doStreamVisitor(Lifespan.ALL,
				new CanonicalSuccessorsRelativeVisitor(relativePredicates));
			if (relativePredicates.matches(List.of())) {
				// Pre-cat the empty path (not the empty stream)
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), successors);
			}
			return successors;
		}
	}

	protected InternalTraceObjectValue doCreateValue(Lifespan lifespan, String key,
			Object value) {
		Long nullSnap = nullCache.get(key);
		if (nullSnap != null && lifespan.contains(nullSnap)) {
			nullCache.remove(key);
		}
		return manager.doCreateValue(lifespan, this, key, value);
	}

	@Override
	public InternalTraceObjectValue setValue(Lifespan lifespan, String key, Object value,
			ConflictResolution resolution) {
		try (LockHold hold = manager.trace.lockWrite()) {
			if (isDeleted()) {
				throw new IllegalStateException("Cannot set value on deleted object.");
			}
			String k = getTargetSchema().checkAliasedAttribute(key);
			if (resolution == ConflictResolution.DENY) {
				doCheckConflicts(lifespan, k, value);
			}
			else if (resolution == ConflictResolution.ADJUST) {
				lifespan = doAdjust(lifespan, k, value);
			}
			var setter = new ValueLifespanSetter(lifespan, value) {
				DBTraceObject canonicalLifeChanged = null;

				@Override
				protected Iterable<InternalTraceObjectValue> getIntersecting(Long lower,
						Long upper) {
					return Collections.unmodifiableCollection(
						doGetValues(Lifespan.span(lower, upper), k, true));
				}

				@Override
				protected void remove(InternalTraceObjectValue entry) {
					if (entry.isCanonical()) {
						canonicalLifeChanged = entry.getChild();
					}
					super.remove(entry);
				}

				@Override
				protected InternalTraceObjectValue put(Lifespan range, Object value) {
					InternalTraceObjectValue entry = super.put(range, value);
					if (entry != null && entry.isCanonical()) {
						canonicalLifeChanged = entry.getChild();
					}
					return entry;
				}

				@Override
				protected InternalTraceObjectValue create(Lifespan range, Object value) {
					return doCreateValue(range, k, value);
				}
			};
			InternalTraceObjectValue result = setter.set(lifespan, value);

			DBTraceObject child = setter.canonicalLifeChanged;
			if (child != null) {
				child.emitEvents(
					new TraceChangeRecord<>(TraceObjectChangeType.LIFE_CHANGED, null, child));
			}
			return result;
		}
	}

	@Override
	public TraceObjectValue setValue(Lifespan lifespan, String key, Object value) {
		return setValue(lifespan, key, value, ConflictResolution.TRUNCATE);
	}

	@Override
	public TraceObjectValue setAttribute(Lifespan lifespan, String name, Object value) {
		if (!PathUtils.isName(name)) {
			throw new IllegalArgumentException("Attribute name must not be an index");
		}
		return setValue(lifespan, name, value);
	}

	@Override
	public TraceObjectValue setElement(Lifespan lifespan, String index, Object value) {
		return setValue(lifespan, PathUtils.makeKey(index), value);
	}

	@Override
	public TraceObjectValue setElement(Lifespan lifespan, long index, Object value) {
		return setElement(lifespan, PathUtils.makeIndex(index), value);
	}

	@Override
	public TargetObjectSchema getTargetSchema() {
		// NOTE: No need to synchronize. Schema is immutable.
		if (targetSchema == null) {
			targetSchema = manager.rootSchema.getSuccessorSchema(path.getKeyList());
		}
		return targetSchema;
	}

	@Override
	public Stream<? extends TraceObjectValPath> queryAncestorsTargetInterface(Lifespan span,
			Class<? extends TargetObject> targetIf) {
		// This is a sort of meet-in-the-middle. The type search must originate from the root
		PathMatcher matcher = getManager().getRootSchema().searchFor(targetIf, false);
		return getAncestorsRoot(span, matcher);
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryAncestorsInterface(Lifespan span,
			Class<I> ifClass) {
		return queryAncestorsTargetInterface(span, TraceObjectInterfaceUtils.toTargetIf(ifClass))
				.map(p -> p.getSource(this).queryInterface(ifClass));
	}

	public TraceObject queryOrCreateCanonicalAncestorTargetInterface(
			Class<? extends TargetObject> targetIf) {
		PathMatcher matcher = getManager().getRootSchema().searchFor(targetIf, false);
		return path.streamMatchingAncestry(matcher)
				.limit(1)
				.map(kp -> manager.createObject(kp))
				.findAny()
				.orElseThrow();
	}

	public <I extends TraceObjectInterface> I queryOrCreateCanonicalAncestorInterface(
			Class<I> ifClass) {
		return queryOrCreateCanonicalAncestorTargetInterface(
			TraceObjectInterfaceUtils.toTargetIf(ifClass)).queryInterface(ifClass);
	}

	@Override
	public Stream<? extends TraceObject> queryCanonicalAncestorsTargetInterface(
			Class<? extends TargetObject> targetIf) {
		// This is a sort of meet-in-the-middle. The type search must originate from the root
		PathMatcher matcher = getManager().getRootSchema().searchFor(targetIf, false);
		try (LockHold hold = manager.trace.lockRead()) {
			return path.streamMatchingAncestry(matcher)
					.map(kp -> manager.getObjectByCanonicalPath(kp));
		}
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryCanonicalAncestorsInterface(
			Class<I> ifClass) {
		return queryCanonicalAncestorsTargetInterface(TraceObjectInterfaceUtils.toTargetIf(ifClass))
				.map(o -> o.queryInterface(ifClass));
	}

	// TODO: Post filter until GP-1301
	private boolean isActuallyInterface(TraceObjectValPath path,
			Class<? extends TargetObject> targetIf) {
		TraceObjectValue lastEntry = path.getLastEntry();
		if (lastEntry == null) {
			// TODO: This assumes the client will call getDestination(this)
			return this.getTargetSchema().getInterfaces().contains(targetIf);
		}
		if (!lastEntry.isObject()) {
			return false;
		}
		return lastEntry.getChild().getTargetSchema().getInterfaces().contains(targetIf);
	}

	@Override
	public Stream<? extends TraceObjectValPath> querySuccessorsTargetInterface(Lifespan span,
			Class<? extends TargetObject> targetIf, boolean requireCanonical) {
		PathMatcher matcher = getTargetSchema().searchFor(targetIf, requireCanonical);
		return getSuccessors(span, matcher).filter(p -> isActuallyInterface(p, targetIf));
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> querySuccessorsInterface(Lifespan span,
			Class<I> ifClass, boolean requireCanonical) {
		return querySuccessorsTargetInterface(span, TraceObjectInterfaceUtils.toTargetIf(ifClass),
			requireCanonical).map(p -> p.getDestination(this).queryInterface(ifClass));
	}

	protected void doDelete() {
		manager.doDeleteObject(this);
	}

	protected void doDeleteReferringValues() {
		for (InternalTraceObjectValue child : getValues(Lifespan.ALL)) {
			child.doDeleteAndEmit();
		}
		for (InternalTraceObjectValue parent : getParents(Lifespan.ALL)) {
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

	protected void notifyValueCreated(InternalTraceObjectValue value) {
		if (cachedLifespanValues != null) {
			if (cachedLifespanValues.span.intersects(value.getLifespan())) {
				cachedLifespanValues.values.add(value);
			}
		}
	}

	protected void notifyValueDeleted(InternalTraceObjectValue value) {
		if (cachedLifespanValues != null) {
			cachedLifespanValues.values.remove(value);
		}
	}

	protected void notifyParentValueCreated(InternalTraceObjectValue parent) {
		if (cachedLife != null && parent.isCanonical()) {
			synchronized (cachedLife) {
				cachedLife.add(parent.getLifespan());
			}
		}
	}

	protected void notifyParentValueDeleted(InternalTraceObjectValue parent) {
		if (cachedLife != null && parent.isCanonical()) {
			synchronized (cachedLife) {
				cachedLife.remove(parent.getLifespan());
			}
		}
	}
}
