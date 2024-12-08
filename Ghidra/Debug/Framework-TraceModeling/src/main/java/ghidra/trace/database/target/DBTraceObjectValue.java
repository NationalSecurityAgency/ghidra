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

import java.util.*;
import java.util.stream.Stream;

import ghidra.trace.database.DBTraceUtils.LifespanMapSetter;
import ghidra.trace.database.target.visitors.TreeTraversal;
import ghidra.trace.database.target.visitors.TreeTraversal.Visitor;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace;
import ghidra.trace.model.target.*;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.trace.util.TraceEvents;
import ghidra.util.LockHold;
import ghidra.util.StreamUtils;

public class DBTraceObjectValue implements TraceObjectValue {

	static abstract class ValueLifespanSetter
			extends LifespanMapSetter<DBTraceObjectValue, Object> {
		protected final Lifespan range;
		protected final Object value;
		protected DBTraceObjectValue keep = null;
		protected Collection<DBTraceObjectValue> kept = new ArrayList<>(2);

		public ValueLifespanSetter(Lifespan range, Object value) {
			this.range = range;
			this.value = value;
		}

		public ValueLifespanSetter(Lifespan range, Object value,
				DBTraceObjectValue keep) {
			this(range, value);
			this.keep = keep;
		}

		@Override
		protected Lifespan getRange(DBTraceObjectValue entry) {
			return entry.getLifespan();
		}

		@Override
		protected Object getValue(DBTraceObjectValue entry) {
			return entry.getValue();
		}

		@Override
		protected boolean valuesEqual(Object v1, Object v2) {
			if (Objects.equals(v1, v2)) {
				return true;
			}
			if (v1 == null || !v1.getClass().isArray()) {
				return false;
			}
			if (v1 instanceof boolean[] a1 && v2 instanceof boolean[] a2) {
				return Arrays.equals(a1, a2);
			}
			if (v1 instanceof byte[] a1 && v2 instanceof byte[] a2) {
				return Arrays.equals(a1, a2);
			}
			if (v1 instanceof char[] a1 && v2 instanceof char[] a2) {
				return Arrays.equals(a1, a2);
			}
			if (v1 instanceof double[] a1 && v2 instanceof double[] a2) {
				return Arrays.equals(a1, a2);
			}
			if (v1 instanceof float[] a1 && v2 instanceof float[] a2) {
				return Arrays.equals(a1, a2);
			}
			if (v1 instanceof int[] a1 && v2 instanceof int[] a2) {
				return Arrays.equals(a1, a2);
			}
			if (v1 instanceof long[] a1 && v2 instanceof long[] a2) {
				return Arrays.equals(a1, a2);
			}
			if (v1 instanceof short[] a1 && v2 instanceof short[] a2) {
				return Arrays.equals(a1, a2);
			}
			return false;
		}

		@Override
		protected void remove(DBTraceObjectValue entry) {
			if (valuesEqual(entry.getValue(), value)) {
				if (keep == null) {
					keep = entry;
				}
				else {
					entry.doDeleteAndEmit();
				}
			}
			else {
				DBTraceObjectValue created = entry.doTruncateOrDelete(range);
				if (!entry.isDeleted()) {
					kept.add(entry);
				}
				if (created != null) {
					kept.add(created);
				}
			}
		}

		@Override
		protected DBTraceObjectValue put(Lifespan range, Object value) {
			if (value == null) {
				return null;
			}
			if (keep != null && valuesEqual(this.value, value)) {
				keep.doSetLifespanAndEmit(range);
				return keep;
			}
			for (DBTraceObjectValue k : kept) {
				if (valuesEqual(value, k.getValue()) && Objects.equals(range, k.getLifespan())) {
					kept.remove(k);
					return k;
				}
			}
			return create(range, value);
		}

		protected abstract DBTraceObjectValue create(Lifespan range, Object value);
	}

	private final DBTraceObjectManager manager;

	private volatile TraceObjectValueStorage wrapped;

	public DBTraceObjectValue(DBTraceObjectManager manager,
			TraceObjectValueStorage wrapped) {
		this.manager = manager;
		this.wrapped = wrapped;
	}

	@Override
	public String toString() {
		return wrapped.toString();
	}

	void setWrapped(TraceObjectValueStorage wrapped) {
		this.wrapped = wrapped;
		if (wrapped instanceof DBTraceObjectValueData data) {
			data.setWrapper(this);
		}
	}

	void doSetLifespanAndEmit(Lifespan lifespan) {
		Lifespan oldLifespan = getLifespan();
		doSetLifespan(lifespan);
		getParent().emitEvents(new TraceChangeRecord<>(TraceEvents.VALUE_LIFESPAN_CHANGED,
			null, this, oldLifespan, lifespan));
	}

	@Override
	public Trace getTrace() {
		return manager.trace;
	}

	@Override
	public String getEntryKey() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return wrapped.getEntryKey();
		}
	}

	protected TraceObjectKeyPath doGetCanonicalPath() {
		DBTraceObject parent = wrapped.getParent();
		if (parent == null) {
			return TraceObjectKeyPath.of();
		}
		return parent.getCanonicalPath().extend(wrapped.getEntryKey());
	}

	@Override
	public TraceObjectKeyPath getCanonicalPath() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return doGetCanonicalPath();
		}
	}

	@Override
	public Object getValue() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return wrapped.getValue();
		}
	}

	@Override
	public boolean isObject() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return wrapped.getChildOrNull() != null;
		}
	}

	protected boolean doIsCanonical() {
		DBTraceObject child = wrapped.getChildOrNull();
		if (child == null) {
			return false;
		}
		if (wrapped.getParent() == null) { // We're the root
			return true;
		}
		return doGetCanonicalPath().equals(child.getCanonicalPath());
	}

	@Override
	public boolean isCanonical() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return doIsCanonical();
		}
	}

	@Override
	public Lifespan getLifespan() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return wrapped.getLifespan();
		}
	}

	@Override
	public void setMinSnap(long minSnap) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			setLifespan(Lifespan.span(minSnap, getLifespan().lmax()));
		}
	}

	@Override
	public long getMinSnap() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return wrapped.getLifespan().lmin();
		}
	}

	@Override
	public void setMaxSnap(long maxSnap) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			setLifespan(Lifespan.span(getLifespan().lmin(), maxSnap));
		}
	}

	@Override
	public long getMaxSnap() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return wrapped.getLifespan().lmax();
		}
	}

	void doDelete() {
		getParent().notifyValueDeleted(this);
		DBTraceObject child = wrapped.getChildOrNull();
		if (child != null) {
			child.notifyParentValueDeleted(this);
		}
		wrapped.doDelete();
	}

	void doDeleteAndEmit() {
		DBTraceObject parent = getParent();
		doDelete();
		parent.emitEvents(new TraceChangeRecord<>(TraceEvents.VALUE_DELETED, null, this));
	}

	@Override
	public void delete() {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (getParent() == null) {
				throw new IllegalArgumentException("Cannot delete root value");
			}
			doDeleteAndEmit();
		}
	}

	@Override
	public boolean isDeleted() {
		try (LockHold hold = LockHold.lock(manager.lock.readLock())) {
			return wrapped.isDeleted();
		}
	}

	@Override
	public DBTraceObjectValue truncateOrDelete(Lifespan span) {
		try (LockHold hold = LockHold.lock(manager.lock.writeLock())) {
			if (wrapped.getParent() == null) {
				throw new IllegalArgumentException("Cannot truncate or delete root value");
			}
			return doTruncateOrDeleteAndEmitLifeChange(span);
		}
	}

	@Override
	public DBTraceObject getChild() {
		try (LockHold hold = manager.trace.lockRead()) {
			return (DBTraceObject) wrapped.getValue();
		}
	}

	@Override
	public void setLifespan(Lifespan lifespan) {
		setLifespan(lifespan, ConflictResolution.TRUNCATE);
	}

	@Override
	public void setLifespan(Lifespan lifespan, ConflictResolution resolution) {
		try (LockHold hold = getTrace().lockWrite()) {
			if (getParent() == null) {
				throw new IllegalArgumentException("Cannot set lifespan of root value");
			}
			if (resolution == ConflictResolution.DENY) {
				getParent().doCheckConflicts(lifespan, getEntryKey(), getValue());
			}
			else if (resolution == ConflictResolution.ADJUST) {
				lifespan = getParent().doAdjust(lifespan, getEntryKey(), getValue());
			}
			new ValueLifespanSetter(lifespan, getValue(), this) {
				@Override
				protected Iterable<DBTraceObjectValue> getIntersecting(Long lower,
						Long upper) {
					return StreamUtils.iter(getParent().streamValuesR(
						Lifespan.span(lower, upper), getEntryKey(), true).filter(v -> v != keep));
				}

				@Override
				protected DBTraceObjectValue create(Lifespan range, Object value) {
					return getParent().doCreateValue(range, getEntryKey(), value);
				}
			}.set(lifespan, getValue());
			if (isObject()) {
				DBTraceObject child = getChild();
				child.emitEvents(
					new TraceChangeRecord<>(TraceEvents.OBJECT_LIFE_CHANGED, null, child));
			}
		}
	}

	void doSetLifespan(Lifespan lifespan) {
		if (wrapped.getLifespan().equals(lifespan)) {
			return;
		}
		DBTraceObject parent = wrapped.getParent();
		DBTraceObject child = wrapped.getChildOrNull();
		parent.notifyValueDeleted(this);
		if (child != null) {
			child.notifyParentValueDeleted(this);
		}
		wrapped.doSetLifespan(lifespan);
		parent.notifyValueCreated(this);
		if (child != null) {
			child.notifyParentValueCreated(this);
		}
	}

	DBTraceObjectValue doTruncateOrDeleteAndEmitLifeChange(Lifespan span) {
		if (!isCanonical()) {
			return doTruncateOrDelete(span);
		}
		DBTraceObject child = wrapped.getChildOrNull();
		DBTraceObjectValue result = doTruncateOrDelete(span);
		child.emitEvents(new TraceChangeRecord<>(TraceEvents.OBJECT_LIFE_CHANGED, null, child));
		return result;
	}

	DBTraceObjectValue doTruncateOrDelete(Lifespan span) {
		List<Lifespan> removed = getLifespan().subtract(span);
		if (removed.isEmpty()) {
			doDeleteAndEmit();
			return null;
		}
		doSetLifespanAndEmit(removed.get(0));
		if (removed.size() == 2) {
			return getParent().doCreateValue(removed.get(1), getEntryKey(), getValue());
		}
		return this;
	}

	@Override
	public DBTraceObject getParent() {
		try (LockHold hold = manager.trace.lockRead()) {
			return wrapped.getParent();
		}
	}

	protected Stream<? extends TraceObjectValPath> doStreamVisitor(Lifespan span,
			Visitor visitor) {
		return TreeTraversal.INSTANCE.walkValue(visitor, this, span, null);
	}

	public TraceObjectValueStorage getWrapped() {
		return wrapped;
	}
}
