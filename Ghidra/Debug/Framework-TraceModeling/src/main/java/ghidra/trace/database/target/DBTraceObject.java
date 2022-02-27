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
import java.util.stream.*;

import org.apache.commons.collections4.IteratorUtils;

import com.google.common.collect.Iterators;
import com.google.common.collect.Range;

import db.DBRecord;
import db.StringField;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.*;
import ghidra.lifecycle.Experimental;
import ghidra.program.model.address.*;
import ghidra.trace.database.DBTrace;
import ghidra.trace.database.DBTraceUtils;
import ghidra.trace.database.breakpoint.DBTraceObjectBreakpointLocation;
import ghidra.trace.database.breakpoint.DBTraceObjectBreakpointSpec;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapSpace;
import ghidra.trace.database.map.DBTraceAddressSnapRangePropertyMapTree.TraceAddressSnapRangeQuery;
import ghidra.trace.database.memory.DBTraceObjectMemoryRegion;
import ghidra.trace.database.memory.DBTraceObjectRegister;
import ghidra.trace.database.module.*;
import ghidra.trace.database.stack.DBTraceObjectStack;
import ghidra.trace.database.stack.DBTraceObjectStackFrame;
import ghidra.trace.database.target.DBTraceObjectValue.PrimaryTriple;
import ghidra.trace.database.target.InternalTraceObjectValue.ValueLifespanSetter;
import ghidra.trace.database.target.LifespanCorrector.Direction;
import ghidra.trace.database.target.LifespanCorrector.Operation;
import ghidra.trace.database.thread.DBTraceObjectThread;
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
import ghidra.util.database.spatial.rect.Rectangle2DDirection;

@DBAnnotatedObjectInfo(version = 0)
public class DBTraceObject extends DBAnnotatedObject implements TraceObject {
	protected static final String TABLE_NAME = "Objects";

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

	// Canonical path
	static final String PATH_COLUMN_NAME = "Path";
	static final String MIN_SNAP_COLUMN_NAME = "MinSnap";
	static final String MAX_SNAP_COLUMN_NAME = "MaxSnap";

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;
	@DBAnnotatedColumn(MIN_SNAP_COLUMN_NAME)
	static DBObjectColumn MIN_SNAP_COLUMN;
	@DBAnnotatedColumn(MAX_SNAP_COLUMN_NAME)
	static DBObjectColumn MAX_SNAP_COLUMN;

	@DBAnnotatedField(
		column = PATH_COLUMN_NAME,
		codec = ObjectPathDBFieldCodec.class,
		indexed = true)
	private TraceObjectKeyPath path;
	@DBAnnotatedField(column = MIN_SNAP_COLUMN_NAME)
	private long minSnap;
	@DBAnnotatedField(column = MAX_SNAP_COLUMN_NAME)
	private long maxSnap;

	protected final DBTraceObjectManager manager;

	private Range<Long> lifespan;

	private Map<Class<? extends TraceObjectInterface>, TraceObjectInterface> ifaces;

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
		lifespan = DBTraceUtils.toRange(minSnap, maxSnap);
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

	protected void set(TraceObjectKeyPath path, Range<Long> lifespan) {
		this.path = path;
		this.lifespan = lifespan;
		this.doSetLifespan(lifespan);
		update(PATH_COLUMN);

		freshIfaces();
	}

	protected void doSetLifespan(Range<Long> lifespan) {
		this.minSnap = DBTraceUtils.lowerEndpoint(lifespan);
		this.maxSnap = DBTraceUtils.upperEndpoint(lifespan);
		update(MIN_SNAP_COLUMN, MAX_SNAP_COLUMN);
		this.lifespan = DBTraceUtils.toRange(minSnap, maxSnap);
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
	public void insert(ConflictResolution resolution) {
		try (LockHold hold = manager.trace.lockWrite()) {
			for (InternalTraceObjectValue val : getParents()) {
				if (val.isCanonical() && DBTraceUtils.intersect(val.getLifespan(), lifespan)) {
					return;
				}
			}
			TraceObjectKeyPath parentPath = path.parent();
			for (DBTraceObject parent : manager.getObjectsByCanonicalPath(parentPath)) {
				if (DBTraceUtils.intersect(parent.getLifespan(), lifespan)) {
					parent.setValue(lifespan, path.key(), this, resolution);
					return;
				}
			}
			DBTraceObject parent = manager.createObject(parentPath, lifespan);
			parent.setValue(lifespan, path.key(), this, resolution);
			parent.insert(resolution);
		}
	}

	@Override
	public boolean isRoot() {
		try (LockHold hold = manager.trace.lockRead()) {
			return path.isRoot();
		}
	}

	protected Stream<TraceObjectValPath> doGetAllPaths(Range<Long> span,
			DBTraceObjectValPath post) {
		if (isRoot()) {
			return Stream.of(post);
		}
		return getParents().stream()
				.filter(e -> !post.contains(e))
				.flatMap(e -> e.doGetAllPaths(span, post));
	}

	@Override
	public Stream<TraceObjectValPath> getAllPaths(Range<Long> span) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetAllPaths(span, DBTraceObjectValPath.of());
		}
	}

	@Override
	public void setLifespan(Range<Long> lifespan) {
		// TODO: Could derive fixed attributes from schema and set their lifespans, too....
		try (LockHold hold = manager.trace.lockWrite()) {
			Range<Long> oldLifespan = getLifespan();
			doSetLifespan(lifespan);
			emitEvents(new TraceChangeRecord<>(TraceObjectChangeType.LIFESPAN_CHANGED, null, this,
				oldLifespan, lifespan));
		}
	}

	@Experimental
	public void correctLifespans(Direction direction, Operation operation,
			ConflictResolution resolution) {
		new LifespanCorrector(direction, operation, resolution).correctLifespans(this);
	}

	@Override
	public Range<Long> getLifespan() {
		try (LockHold hold = manager.trace.lockRead()) {
			return lifespan;
		}
	}

	@Override
	public void setMinSnap(long minSnap) {
		setLifespan(DBTraceUtils.toRange(minSnap, maxSnap));
	}

	@Override
	public long getMinSnap() {
		try (LockHold hold = manager.trace.lockRead()) {
			return minSnap;
		}
	}

	@Override
	public void setMaxSnap(long maxSnap) {
		setLifespan(DBTraceUtils.toRange(minSnap, maxSnap));
	}

	@Override
	public long getMaxSnap() {
		try (LockHold hold = manager.trace.lockRead()) {
			return maxSnap;
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

	@Override
	public Collection<? extends DBTraceObjectValue> getParents() {
		return manager.valuesByChild.get(this);
	}

	protected void collectNonRangedValues(Collection<? super DBTraceObjectValue> result) {
		for (DBTraceObjectValue val : manager.valuesByTriple
				.tail(new PrimaryTriple(this, "", Long.MIN_VALUE), true)
				.values()) {
			if (val.getParent() != this) {
				break;
			}
			result.add(val);
		}
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getValues() {
		try (LockHold hold = manager.trace.lockRead()) {
			List<InternalTraceObjectValue> result = new ArrayList<>();
			collectNonRangedValues(result);

			for (DBTraceAddressSnapRangePropertyMapSpace<DBTraceObjectAddressRangeValue, //
					?> space : manager.rangeValueMap
							.getActiveMemorySpaces()) {
				for (DBTraceObjectAddressRangeValue val : space.values()) {
					if (val.getParent() != this) {
						continue;
					}
					result.add(val);
				}
			}

			return result;
		}
	}

	protected Collection<? extends DBTraceObjectValue> doGetElements() {
		List<DBTraceObjectValue> result = new ArrayList<>();
		for (DBTraceObjectValue val : manager.valuesByTriple
				.sub(new PrimaryTriple(this, "[", Long.MIN_VALUE), true,
					new PrimaryTriple(this, "\\", Long.MIN_VALUE), false)
				.values()) {
			result.add(val);
		}
		return result;
	}

	@Override
	public Collection<? extends DBTraceObjectValue> getElements() {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetElements();
		}
	}

	protected Collection<? extends DBTraceObjectValue> doGetAttributes() {
		List<DBTraceObjectValue> result = new ArrayList<>();
		for (DBTraceObjectValue val : manager.valuesByTriple
				.sub(new PrimaryTriple(this, "", Long.MIN_VALUE), true,
					new PrimaryTriple(this, "[", Long.MIN_VALUE), false)
				.values()) {
			result.add(val);
		}
		for (DBTraceObjectValue val : manager.valuesByTriple
				.tail(new PrimaryTriple(this, "\\", Long.MIN_VALUE), true)
				.values()) {
			if (val.getParent() != this) {
				break;
			}
			result.add(val);
		}
		return result;
	}

	@Override
	public Collection<? extends DBTraceObjectValue> getAttributes() {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetAttributes();
		}
	}

	protected void doCheckConflicts(Range<Long> span, String key, Object value) {
		for (InternalTraceObjectValue val : doGetValues(span, key)) {
			if (!Objects.equals(value, val.getValue())) {
				throw new DuplicateKeyException(key);
			}
		}
	}

	protected Collection<? extends InternalTraceObjectValue> doGetValues(Range<Long> span,
			String key) {
		return doGetValues(DBTraceUtils.lowerEndpoint(span), DBTraceUtils.upperEndpoint(span), key);
	}

	protected Collection<? extends InternalTraceObjectValue> doGetValues(long lower, long upper,
			String key) {
		try (LockHold hold = manager.trace.lockRead()) {
			// Collect triplet-indexed values
			Set<InternalTraceObjectValue> result = new LinkedHashSet<>();
			PrimaryTriple min = new PrimaryTriple(this, key, lower);
			PrimaryTriple max = new PrimaryTriple(this, key, upper);
			DBTraceObjectValue floor = manager.valuesByTriple.floorValue(min);
			if (floor != null && floor.getParent() == this && key.equals(floor.getEntryKey()) &&
				floor.getLifespan().contains(lower)) {
				result.add(floor);
			}
			for (DBTraceObjectValue val : manager.valuesByTriple.sub(min, true, max, true)
					.values()) {
				result.add(val);
			}

			// Collect R*-Tree-indexed values
			for (DBTraceAddressSnapRangePropertyMapSpace<DBTraceObjectAddressRangeValue, DBTraceObjectAddressRangeValue> space : manager.rangeValueMap
					.getActiveMemorySpaces()) {
				AddressSpace as = space.getAddressSpace();

				for (DBTraceObjectAddressRangeValue val : manager.rangeValueMap
						.reduce(TraceAddressSnapRangeQuery
								.intersecting(as.getMinAddress(), as.getMaxAddress(), lower, upper))
						.values()) {
					if (val.getParent() != this) {
						continue;
					}
					if (!key.equals(val.getEntryKey())) {
						continue;
					}
					result.add(val);
				}
			}

			return result.stream()
					.sorted(Comparator.comparing(v -> v.getMinSnap()))
					.collect(Collectors.toList());
		}
	}

	protected DBTraceObjectValue doGetNonRangedValue(long snap, String key) {
		DBTraceObjectValue floor =
			manager.valuesByTriple.floorValue(new PrimaryTriple(this, key, snap));
		if (floor == null || floor.getParent() != this || !key.equals(floor.getEntryKey()) ||
			!floor.getLifespan().contains(snap)) {
			return null;
		}
		return floor;
	}

	protected Stream<DBTraceObjectValue> doGetNonRangedValues(Range<Long> span, String key,
			boolean forward) {
		DBCachedObjectIndex<PrimaryTriple, DBTraceObjectValue> sub = manager.valuesByTriple.sub(
			new PrimaryTriple(this, key, DBTraceUtils.lowerEndpoint(span)), true,
			new PrimaryTriple(this, key, DBTraceUtils.upperEndpoint(span)), true);
		Spliterator<DBTraceObjectValue> spliterator = (forward ? sub : sub.descending())
				.values()
				.spliterator();
		return StreamSupport.stream(spliterator, false);
	}

	protected DBTraceObjectAddressRangeValue doGetRangedValue(long snap, String key) {
		for (DBTraceAddressSnapRangePropertyMapSpace<DBTraceObjectAddressRangeValue, //
				DBTraceObjectAddressRangeValue> space : manager.rangeValueMap
						.getActiveMemorySpaces()) {
			AddressSpace as = space.getAddressSpace();
			for (DBTraceObjectAddressRangeValue val : space
					.reduce(TraceAddressSnapRangeQuery.atSnap(snap, as))
					.values()) {
				if (val.getParent() == this && key.equals(val.getEntryKey())) {
					return val;
				}
			}
		}
		return null;
	}

	protected Stream<DBTraceObjectAddressRangeValue> doGetRangedValues(Range<Long> span,
			String key, boolean forward) {
		Rectangle2DDirection dir = forward
				? Rectangle2DDirection.BOTTOMMOST
				: Rectangle2DDirection.TOPMOST;
		List<Iterator<DBTraceObjectAddressRangeValue>> iterators = manager.rangeValueMap
				.getActiveMemorySpaces()
				.stream()
				.map(s -> IteratorUtils.filteredIterator(s
						.reduce(TraceAddressSnapRangeQuery.intersecting(span, s.getAddressSpace())
								.starting(dir))
						.orderedValues()
						.iterator(),
					v -> key.equals(v.getEntryKey())))
				.collect(Collectors.toList());
		Comparator<Long> order = forward ? Comparator.naturalOrder() : Comparator.reverseOrder();
		Comparator<DBTraceObjectAddressRangeValue> comparator =
			Comparator.comparing(v -> v.getMinSnap(), order);
		Iterator<DBTraceObjectAddressRangeValue> merged =
			Iterators.mergeSorted(iterators, comparator);
		return StreamSupport
				.stream(Spliterators.spliteratorUnknownSize(merged, Spliterator.ORDERED), false)
				.filter(v -> key.equals(v.getEntryKey()));
	}

	@Override
	public InternalTraceObjectValue getValue(long snap, String key) {
		try (LockHold hold = manager.trace.lockRead()) {
			DBTraceObjectValue nrVal = doGetNonRangedValue(snap, key);
			if (nrVal != null) {
				return nrVal;
			}
			return doGetRangedValue(snap, key);
		}
	}

	protected Stream<InternalTraceObjectValue> doGetOrderedValues(Range<Long> span, String key,
			boolean forward) {
		Stream<DBTraceObjectValue> nrVals = doGetNonRangedValues(span, key, forward);
		Stream<DBTraceObjectAddressRangeValue> rVals = doGetRangedValues(span, key, forward);
		Comparator<Long> order = forward ? Comparator.naturalOrder() : Comparator.reverseOrder();
		Comparator<InternalTraceObjectValue> comparator =
			Comparator.comparing(v -> v.getMinSnap(), order);
		Iterator<InternalTraceObjectValue> merged =
			Iterators.mergeSorted(Arrays.asList(nrVals.iterator(), rVals.iterator()), comparator);
		return StreamSupport
				.stream(Spliterators.spliteratorUnknownSize(merged, Spliterator.ORDERED), false);
	}

	@Override
	public Stream<? extends InternalTraceObjectValue> getOrderedValues(Range<Long> span, String key,
			boolean forward) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetOrderedValues(span, key, forward);
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

	protected Stream<? extends DBTraceObjectValPath> doGetAncestors(Range<Long> span,
			DBTraceObjectValPath post, PathPredicates predicates) {
		if (predicates.matches(getCanonicalPath().getKeyList())) {
			return Stream.of(post);
		}
		if (isRoot()) {
			return Stream.empty();
		}
		return getParents().stream()
				.filter(e -> !post.contains(e))
				.flatMap(e -> e.doGetAncestors(span, post, predicates));
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getAncestors(
			Range<Long> span, PathPredicates rootPredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetAncestors(span, DBTraceObjectValPath.of(), rootPredicates);
		}
	}

	protected Stream<? extends DBTraceObjectValPath> doGetSuccessors(
			Range<Long> span, DBTraceObjectValPath pre, PathPredicates predicates) {
		Set<String> nextKeys = predicates.getNextKeys(pre.getKeyList());
		if (nextKeys.isEmpty()) {
			return Stream.empty();
		}

		Stream<? extends DBTraceObjectValue> attrStream;
		if (nextKeys.contains("")) {
			attrStream = doGetAttributes().stream()
					.filter(v -> DBTraceUtils.intersect(span, v.getLifespan()));
		}
		else {
			attrStream = Stream.empty();
		}

		Stream<? extends DBTraceObjectValue> elemStream;
		if (nextKeys.contains("[]")) {
			elemStream = doGetElements().stream()
					.filter(v -> DBTraceUtils.intersect(span, v.getLifespan()));
		}
		else {
			elemStream = Stream.empty();
		}

		Stream<InternalTraceObjectValue> restStream = nextKeys.stream()
				.filter(k -> !"".equals(k) && !"[]".equals(k))
				.flatMap(k -> doGetValues(span, k).stream());

		return Stream.concat(Stream.concat(attrStream, elemStream), restStream)
				.flatMap(v -> v.doGetSuccessors(span, pre, predicates));
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getSuccessors(
			Range<Long> span, PathPredicates relativePredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetSuccessors(span, DBTraceObjectValPath.of(), relativePredicates);
		}
	}

	protected Stream<? extends DBTraceObjectValPath> doGetOrderedSuccessors(Range<Long> span,
			DBTraceObjectValPath pre, PathPredicates predicates, boolean forward) {
		Set<String> nextKeys = predicates.getNextKeys(pre.getKeyList());
		if (nextKeys.isEmpty()) {
			return null;
		}
		if (nextKeys.size() != 1) {
			throw new IllegalArgumentException("predicates must be a singleton");
		}
		String next = nextKeys.iterator().next();
		if (PathPattern.isWildcard(next)) {
			throw new IllegalArgumentException("predicates must be a singleton");
		}
		return doGetOrderedValues(span, next, forward)
				.flatMap(v -> v.doGetOrderedSuccessors(span, pre, predicates, forward));
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getOrderedSuccessors(Range<Long> span,
			TraceObjectKeyPath relativePath, boolean forward) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetOrderedSuccessors(span, DBTraceObjectValPath.of(),
				new PathPattern(relativePath.getKeyList()), forward);
		}
	}

	protected InternalTraceObjectValue doCreateValue(Range<Long> lifespan, String key,
			Object value) {
		return manager.doCreateValue(lifespan, this, key, value);
	}

	// HACK: Because breakpoint uses address,length instead of range. FIXME!
	protected void applyBreakpointRangeHack(Range<Long> lifespan, String key, Object value,
			ConflictResolution resolution) {
		/**
		 * NOTE: This should only be happening in Target/TraceBreakpointLocation, but I suppose
		 * anything using this scheme should be hacked.
		 */
		Address address;
		int length;
		if (key == TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME &&
			value instanceof Address) {
			address = (Address) value;
			Object lengthObj = getValue(DBTraceUtils.lowerEndpoint(lifespan),
				TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME);
			if (!(lengthObj instanceof Integer)) {
				return;
			}
			length = (Integer) lengthObj;
		}
		else if (key == TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME &&
			value instanceof Integer) {
			length = (Integer) value;
			Object addressObj = getValue(DBTraceUtils.lowerEndpoint(lifespan),
				TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME);
			if (!(addressObj instanceof Address)) {
				return;
			}
			address = (Address) addressObj;
		}
		else {
			return;
		}
		try {
			setValue(lifespan, TraceObjectBreakpointLocation.KEY_RANGE,
				new AddressRangeImpl(address, length), resolution);
		}
		catch (AddressOverflowException e) {
			Msg.warn(this, "Could not set range: " + e);
		}
	}

	@Override
	public InternalTraceObjectValue setValue(Range<Long> lifespan, String key, Object value,
			ConflictResolution resolution) {
		try (LockHold hold = manager.trace.lockWrite()) {
			if (isDeleted()) {
				throw new IllegalStateException("Cannot set value on deleted object.");
			}
			InternalTraceObjectValue oldEntry = getValue(DBTraceUtils.lowerEndpoint(lifespan), key);
			Object oldVal = null;
			if (oldEntry != null && oldEntry.getLifespan().encloses(lifespan)) {
				oldVal = oldEntry.getValue();
			}
			if (resolution == ConflictResolution.DENY) {
				doCheckConflicts(lifespan, key, value);
			}
			InternalTraceObjectValue result = new ValueLifespanSetter(lifespan, value) {
				@Override
				protected Iterable<InternalTraceObjectValue> getIntersecting(Long lower,
						Long upper) {
					return Collections.unmodifiableCollection(doGetValues(lower, upper, key));
				}

				@Override
				protected InternalTraceObjectValue create(Range<Long> range, Object value) {
					return doCreateValue(range, key, value);
				}
			}.set(lifespan, value);
			if (result == null && oldEntry == null) {
				return null;
			}
			emitEvents(new TraceChangeRecord<>(TraceObjectChangeType.VALUE_CHANGED,
				null, result != null ? result : oldEntry, oldVal, value));

			// NB. It will cause another event. good.
			applyBreakpointRangeHack(lifespan, key, value, resolution);
			return result;
		}
	}

	@Override
	public TraceObjectValue setValue(Range<Long> lifespan, String key, Object value) {
		return setValue(lifespan, key, value, ConflictResolution.TRUNCATE);
	}

	@Override
	public TraceObjectValue setAttribute(Range<Long> lifespan, String name, Object value) {
		if (!PathUtils.isName(name)) {
			throw new IllegalArgumentException("Attribute name must not be an index");
		}
		return setValue(lifespan, name, value);
	}

	@Override
	public TraceObjectValue setElement(Range<Long> lifespan, String index, Object value) {
		return setValue(lifespan, PathUtils.makeKey(index), value);
	}

	@Override
	public TraceObjectValue setElement(Range<Long> lifespan, long index, Object value) {
		return setElement(lifespan, PathUtils.makeIndex(index), value);
	}

	@Override
	public TargetObjectSchema getTargetSchema() {
		return manager.rootSchema.getSuccessorSchema(path.getKeyList());
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryAncestorsInterface(Range<Long> span,
			Class<I> ifClass) {
		Class<? extends TargetObject> targetIf = TraceObjectInterfaceUtils.toTargetIf(ifClass);
		// This is a sort of meet-in-the-middle. The type search must originate from the root
		PathMatcher matcher = getManager().getRootSchema().searchFor(targetIf, false);
		return getAncestors(span, matcher).map(p -> p.getFirstParent(this).queryInterface(ifClass));
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryCanonicalAncestorsInterface(
			Range<Long> span, Class<I> ifClass) {
		Class<? extends TargetObject> targetIf = TraceObjectInterfaceUtils.toTargetIf(ifClass);
		// This is a sort of meet-in-the-middle. The type search must originate from the root
		PathMatcher matcher = getManager().getRootSchema().searchFor(targetIf, false);
		List<String> parentPath = getCanonicalPath().getKeyList();
		if (!matcher.ancestorMatches(parentPath, false)) {
			return Stream.of();
		}
		for (; !parentPath.isEmpty(); parentPath = PathUtils.parent(parentPath)) {
			if (matcher.matches(parentPath)) {
				return manager.getObjectsByCanonicalPath(TraceObjectKeyPath.of(parentPath))
						.stream()
						.filter(o -> DBTraceUtils.intersect(span, o.getLifespan()))
						.map(o -> o.queryInterface(ifClass))
						.filter(i -> i != null);
			}
		}
		return Stream.of();
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> querySuccessorsInterface(Range<Long> span,
			Class<I> ifClass) {
		Class<? extends TargetObject> targetIf = TraceObjectInterfaceUtils.toTargetIf(ifClass);
		PathMatcher matcher = getTargetSchema().searchFor(targetIf, true);
		return getSuccessors(span, matcher).map(p -> p.getLastChild(this).queryInterface(ifClass))
				.filter(i -> i != null); // because GP-1301
	}

	protected void doDelete() {
		manager.doDeleteObject(this);
	}

	protected void doDeleteReferringValues() {
		for (InternalTraceObjectValue child : getValues()) {
			child.doDelete();
		}
		for (DBTraceObjectValue parent : getParents()) {
			parent.doDelete();
		}
	}

	protected void doDeleteSuccessors() {
		List<DBTraceObjectValue> children = new ArrayList<>();
		collectNonRangedValues(children);
		for (DBTraceObjectValue child : children) {
			child.doDeleteSuccessors();
		}
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			doDeleteReferringValues();
			doDelete();
		}
	}

	protected void doDeleteTree() {
		doDeleteSuccessors();
		doDeleteReferringValues();
		doDelete();
	}

	@Override
	public void deleteTree() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			doDeleteTree();
		}
	}

	@Override
	public DBTraceObject truncateOrDelete(Range<Long> span) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			List<Range<Long>> removed = DBTraceUtils.subtract(lifespan, span);
			if (removed.isEmpty()) {
				doDelete();
				return null;
			}
			if (removed.size() == 2) {
				throw new IllegalArgumentException("Cannot create a gap in an object's lifespan");
			}
			doSetLifespan(removed.get(0));
			return this;
		}
	}

	protected void emitEvents(TraceChangeRecord<?, ?> rec) {
		manager.trace.setChanged(rec);
		for (TraceObjectInterface iface : ifaces.values()) {
			DBTraceObjectInterface dbIface = (DBTraceObjectInterface) iface;
			TraceChangeRecord<?, ?> evt = dbIface.translateEvent(rec);
			if (evt != null) {
				manager.trace.setChanged(evt);
			}
		}
	}
}
