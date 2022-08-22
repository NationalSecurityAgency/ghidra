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

import com.google.common.collect.*;

import db.DBRecord;
import db.StringField;
import ghidra.dbg.target.TargetBreakpointLocation;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.schema.TargetObjectSchema;
import ghidra.dbg.util.*;
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
import ghidra.trace.database.target.InternalTreeTraversal.Visitor;
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

	@DBAnnotatedColumn(PATH_COLUMN_NAME)
	static DBObjectColumn PATH_COLUMN;

	@DBAnnotatedField(
		column = PATH_COLUMN_NAME,
		codec = ObjectPathDBFieldCodec.class,
		indexed = true)
	private TraceObjectKeyPath path;

	protected final DBTraceObjectManager manager;

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
	public RangeSet<Long> getLife() {
		// TODO: This should really be cached
		try (LockHold hold = manager.trace.lockRead()) {
			RangeSet<Long> result = TreeRangeSet.create();
			// NOTE: connected ranges should already be coalesced
			// No need to apply discreet domain
			getCanonicalParents(Range.all()).forEach(v -> result.add(v.getLifespan()));
			return result;
		}
	}

	protected DBTraceObject doCreateCanonicalParentObject() {
		return manager.doCreateObject(path.parent());
	}

	protected DBTraceObject doGetCanonicalParentObject() {
		return manager.doGetObject(path.parent());
	}

	protected DBTraceObjectValPath doInsert(Range<Long> lifespan, ConflictResolution resolution) {
		if (path.isRoot()) {
			return DBTraceObjectValPath.of();
		}
		DBTraceObject parent = doCreateCanonicalParentObject();
		InternalTraceObjectValue value = parent.setValue(lifespan, path.key(), this, resolution);
		DBTraceObjectValPath path = parent.doInsert(lifespan, resolution);
		return path.append(value);
	}

	@Override
	public DBTraceObjectValPath insert(Range<Long> lifespan, ConflictResolution resolution) {
		try (LockHold hold = manager.trace.lockWrite()) {
			return doInsert(lifespan, resolution);
		}
	}

	protected void doRemove(Range<Long> span) {
		if (isRoot()) {
			throw new IllegalArgumentException("Cannot remove the root object");
		}
		DBTraceObject parent = doGetCanonicalParentObject();
		parent.setValue(span, path.key(), null);
		// Do not recurse on parent
	}

	@Override
	public void remove(Range<Long> span) {
		try (LockHold hold = manager.trace.lockWrite()) {
			doRemove(span);
		}
	}

	protected void doRemoveTree(Range<Long> span) {
		for (DBTraceObjectValue parent : getParents()) {
			parent.doTruncateOrDeleteAndEmitLifeChange(span);
		}
		for (InternalTraceObjectValue value : getValues()) {
			value.doTruncateOrDeleteAndEmitLifeChange(span);
			if (value.isCanonical()) {
				value.getChild().doRemoveTree(span);
			}
		}
	}

	@Override
	public void removeTree(Range<Long> span) {
		try (LockHold hold = manager.trace.lockWrite()) {
			doRemoveTree(span);
		}
	}

	@Override
	public TraceObjectValue getCanonicalParent(long snap) {
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return manager.valueStore.getObjectAt(0);
			}
			return getCanonicalParents(Range.singleton(snap)).findAny().orElse(null);
		}
	}

	@Override
	public Stream<? extends DBTraceObjectValue> getCanonicalParents(Range<Long> lifespan) {
		// TODO: If this is invoked often, perhaps index
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return Stream.of(manager.valueStore.getObjectAt(0));
			}
			String canonicalKey = path.key();
			TraceObjectKeyPath canonicalTail = path.parent();
			return manager.valuesByChild.getLazily(this)
					.stream()
					.filter(v -> canonicalKey.equals(v.getEntryKey()))
					.filter(v -> DBTraceUtils.intersect(v.getLifespan(), lifespan))
					.filter(v -> canonicalTail.equals(v.getParent().getCanonicalPath()));
		}
	}

	@Override
	public boolean isRoot() {
		try (LockHold hold = manager.trace.lockRead()) {
			return path.isRoot();
		}
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getAllPaths(Range<Long> span) {
		try (LockHold hold = manager.trace.lockRead()) {
			if (isRoot()) {
				return Stream.of(DBTraceObjectValPath.of());
			}
			return doStreamVisitor(span, InternalAllPathsVisitor.INSTANCE);
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

	protected Collection<? extends DBTraceObjectValue> doGetParents() {
		return manager.valuesByChild.get(this);
	}

	@Override
	public Collection<? extends DBTraceObjectValue> getParents() {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetParents();
		}
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

	protected void collectNonRangedAttributes(List<? super DBTraceObjectValue> result) {
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
	}

	protected void collectNonRangedElements(List<? super DBTraceObjectValue> result) {
		for (DBTraceObjectValue val : manager.valuesByTriple
				.sub(new PrimaryTriple(this, "[", Long.MIN_VALUE), true,
					new PrimaryTriple(this, "\\", Long.MIN_VALUE), false)
				.values()) {
			result.add(val);
		}
	}

	protected boolean doHasAnyNonRangedValues() {
		for (DBTraceObjectValue val : manager.valuesByTriple
				.tail(new PrimaryTriple(this, "", Long.MIN_VALUE), true)
				.values()) {
			if (val.getParent() != this) {
				return false;
			}
			return true;
		}
		return false;
	}

	protected void collectRangedValues(Collection<? super DBTraceObjectAddressRangeValue> result) {
		for (DBTraceAddressSnapRangePropertyMapSpace<DBTraceObjectAddressRangeValue, ?> space //
		: manager.rangeValueMap.getActiveMemorySpaces()) {
			for (DBTraceObjectAddressRangeValue val : space.values()) {
				if (val.getParent() != this) {
					continue;
				}
				result.add(val);
			}
		}
	}

	protected void collectRangedAttributes(
			Collection<? super DBTraceObjectAddressRangeValue> result) {
		for (DBTraceAddressSnapRangePropertyMapSpace<DBTraceObjectAddressRangeValue, ?> space //
		: manager.rangeValueMap.getActiveMemorySpaces()) {
			for (DBTraceObjectAddressRangeValue val : space.values()) {
				if (val.getParent() != this) {
					continue;
				}
				if (!PathUtils.isName(val.getEntryKey())) {
					continue;
				}
				result.add(val);
			}
		}
	}

	protected void collectRangedElements(
			Collection<? super DBTraceObjectAddressRangeValue> result) {
		for (DBTraceAddressSnapRangePropertyMapSpace<DBTraceObjectAddressRangeValue, ?> space //
		: manager.rangeValueMap.getActiveMemorySpaces()) {
			for (DBTraceObjectAddressRangeValue val : space.values()) {
				if (val.getParent() != this) {
					continue;
				}
				if (!PathUtils.isIndex(val.getEntryKey())) {
					continue;
				}
				result.add(val);
			}
		}
	}

	protected boolean doHasAnyRangedValues() {
		for (DBTraceAddressSnapRangePropertyMapSpace<DBTraceObjectAddressRangeValue, ?> space //
		: manager.rangeValueMap.getActiveMemorySpaces()) {
			for (DBTraceObjectAddressRangeValue val : space.values()) {
				if (val.getParent() == this) {
					return true;
				}
			}
		}
		return false;
	}

	protected Collection<? extends InternalTraceObjectValue> doGetValues() {
		List<InternalTraceObjectValue> result = new ArrayList<>();
		collectNonRangedValues(result);
		collectRangedValues(result);
		return result;
	}

	protected boolean doHasAnyValues() {
		return doHasAnyNonRangedValues() || doHasAnyRangedValues();
	}

	protected boolean doHasAnyParents() {
		return manager.valuesByChild.containsKey(this);
	}

	protected boolean doIsConnected() {
		return doHasAnyParents() || doHasAnyValues();
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getValues() {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetValues();
		}
	}

	protected Collection<? extends InternalTraceObjectValue> doGetElements() {
		List<InternalTraceObjectValue> result = new ArrayList<>();
		collectNonRangedElements(result);
		collectRangedElements(result);
		return result;
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getElements() {
		try (LockHold hold = manager.trace.lockRead()) {
			return doGetElements();
		}
	}

	protected Collection<? extends InternalTraceObjectValue> doGetAttributes() {
		List<InternalTraceObjectValue> result = new ArrayList<>();
		collectNonRangedAttributes(result);
		collectRangedAttributes(result);
		return result;
	}

	@Override
	public Collection<? extends InternalTraceObjectValue> getAttributes() {
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

	// TODO: Could/should this return Stream instead?
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

	protected Stream<DBTraceObjectValue> doGetOrderedNonRangedValues(Range<Long> span, String key,
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

	protected Stream<DBTraceObjectAddressRangeValue> doGetOrderedRangedValues(Range<Long> span,
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
		Stream<DBTraceObjectValue> nrVals = doGetOrderedNonRangedValues(span, key, forward);
		Stream<DBTraceObjectAddressRangeValue> rVals = doGetOrderedRangedValues(span, key, forward);
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

	protected Stream<? extends DBTraceObjectValPath> doStreamVisitor(Range<Long> span,
			Visitor visitor) {
		return InternalTreeTraversal.INSTANCE.walkObject(visitor, this, span,
			DBTraceObjectValPath.of());
	}

	@Override
	public Stream<? extends TraceObjectValPath> getAncestors(Range<Long> span,
			PathPredicates relativePredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends DBTraceObjectValPath> ancestors =
				doStreamVisitor(span, new InternalAncestorsRelativeVisitor(relativePredicates));
			if (relativePredicates.matches(List.of())) {
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), ancestors);
			}
			return ancestors;
		}
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getAncestorsRoot(
			Range<Long> span, PathPredicates rootPredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			return doStreamVisitor(span, new InternalAncestorsRootVisitor(rootPredicates));
		}
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getSuccessors(
			Range<Long> span, PathPredicates relativePredicates) {
		try (LockHold hold = manager.trace.lockRead()) {
			Stream<? extends DBTraceObjectValPath> succcessors =
				doStreamVisitor(span, new InternalSuccessorsRelativeVisitor(relativePredicates));
			if (relativePredicates.matches(List.of())) {
				// Pre-cat the empty path (not the empty stream)
				return Stream.concat(Stream.of(DBTraceObjectValPath.of()), succcessors);
			}
			return succcessors;
		}
	}

	@Override
	public Stream<? extends DBTraceObjectValPath> getOrderedSuccessors(Range<Long> span,
			TraceObjectKeyPath relativePath, boolean forward) {
		DBTraceObjectValPath empty = DBTraceObjectValPath.of();
		try (LockHold hold = manager.trace.lockRead()) {
			if (relativePath.isRoot()) {
				return Stream.of(empty); // Not the empty stream
			}
			return doStreamVisitor(span,
				new InternalOrderedSuccessorsVisitor(relativePath, forward));
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
			InternalTraceObjectValue lengthObj = getValue(DBTraceUtils.lowerEndpoint(lifespan),
				TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME);
			if (lengthObj == null || !(lengthObj.getValue() instanceof Integer)) {
				return;
			}
			length = (Integer) lengthObj.getValue();
		}
		else if (key == TargetBreakpointLocation.LENGTH_ATTRIBUTE_NAME &&
			value instanceof Integer) {
			length = (Integer) value;
			InternalTraceObjectValue addressObj = getValue(DBTraceUtils.lowerEndpoint(lifespan),
				TargetBreakpointLocation.ADDRESS_ATTRIBUTE_NAME);
			if (addressObj == null || !(addressObj.getValue() instanceof Address)) {
				return;
			}
			address = (Address) addressObj.getValue();
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
			if (resolution == ConflictResolution.DENY) {
				doCheckConflicts(lifespan, key, value);
			}
			var setter = new ValueLifespanSetter(lifespan, value) {
				DBTraceObject canonicalLifeChanged = null;

				@Override
				protected Iterable<InternalTraceObjectValue> getIntersecting(Long lower,
						Long upper) {
					return Collections.unmodifiableCollection(doGetValues(lower, upper, key));
				}

				@Override
				protected void remove(InternalTraceObjectValue entry) {
					if (entry.isCanonical()) {
						canonicalLifeChanged = entry.getChild();
					}
					super.remove(entry);
				}

				@Override
				protected InternalTraceObjectValue put(Range<Long> range, Object value) {
					InternalTraceObjectValue entry = super.put(range, value);
					if (entry != null && entry.isCanonical()) {
						canonicalLifeChanged = entry.getChild();
					}
					return entry;
				}

				@Override
				protected InternalTraceObjectValue create(Range<Long> range, Object value) {
					return doCreateValue(range, key, value);
				}
			};
			InternalTraceObjectValue result = setter.set(lifespan, value);

			// NB. This hack will cause more value events. good.
			applyBreakpointRangeHack(lifespan, key, value, resolution);
			DBTraceObject child = setter.canonicalLifeChanged;
			if (child != null) {
				child.emitEvents(
					new TraceChangeRecord<>(TraceObjectChangeType.LIFE_CHANGED, null, child));
			}
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
	public Stream<? extends DBTraceObjectValPath> queryAncestorsTargetInterface(Range<Long> span,
			Class<? extends TargetObject> targetIf) {
		// This is a sort of meet-in-the-middle. The type search must originate from the root
		PathMatcher matcher = getManager().getRootSchema().searchFor(targetIf, false);
		return getAncestorsRoot(span, matcher);
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> queryAncestorsInterface(Range<Long> span,
			Class<I> ifClass) {
		return queryAncestorsTargetInterface(span, TraceObjectInterfaceUtils.toTargetIf(ifClass))
				.map(p -> p.getSource(this).queryInterface(ifClass));
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

	@Override
	public Stream<? extends DBTraceObjectValPath> querySuccessorsTargetInterface(Range<Long> span,
			Class<? extends TargetObject> targetIf) {
		PathMatcher matcher = getTargetSchema().searchFor(targetIf, true);
		// TODO: Post filter until GP-1301
		return getSuccessors(span, matcher).filter(
			p -> p.getDestination(this).getTargetSchema().getInterfaces().contains(targetIf));
	}

	@Override
	public <I extends TraceObjectInterface> Stream<I> querySuccessorsInterface(Range<Long> span,
			Class<I> ifClass) {
		return querySuccessorsTargetInterface(span, TraceObjectInterfaceUtils.toTargetIf(ifClass))
				.map(p -> p.getDestination(this).queryInterface(ifClass));
	}

	protected void doDelete() {
		manager.doDeleteObject(this);
	}

	protected void doDeleteReferringValues() {
		for (InternalTraceObjectValue child : getValues()) {
			child.doDeleteAndEmit();
		}
		for (DBTraceObjectValue parent : getParents()) {
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
				Msg.error(this, "Error while translating event " + rec + " for interface " + iface);
			}
		}
	}
}
