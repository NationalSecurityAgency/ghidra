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

import org.apache.commons.collections4.IterableUtils;

import ghidra.trace.database.DBTraceUtils.LifespanMapSetter;
import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.target.TraceObject.ConflictResolution;
import ghidra.trace.model.target.TraceObjectValue;
import ghidra.trace.util.TraceChangeRecord;
import ghidra.util.LockHold;

interface InternalTraceObjectValue extends TraceObjectValue {
	abstract class ValueLifespanSetter
			extends LifespanMapSetter<InternalTraceObjectValue, Object> {
		protected final Lifespan range;
		protected final Object value;
		protected InternalTraceObjectValue keep = null;
		protected Collection<InternalTraceObjectValue> kept = new ArrayList<>(2);

		public ValueLifespanSetter(Lifespan range, Object value) {
			this.range = range;
			this.value = value;
		}

		public ValueLifespanSetter(Lifespan range, Object value,
				InternalTraceObjectValue keep) {
			this(range, value);
			this.keep = keep;
		}

		@Override
		protected Lifespan getRange(InternalTraceObjectValue entry) {
			return entry.getLifespan();
		}

		@Override
		protected Object getValue(InternalTraceObjectValue entry) {
			return entry.getValue();
		}

		@Override
		protected void remove(InternalTraceObjectValue entry) {
			if (Objects.equals(entry.getValue(), value)) {
				if (keep == null) {
					keep = entry;
				}
				else {
					entry.doDeleteAndEmit();
				}
			}
			else {
				InternalTraceObjectValue created = entry.doTruncateOrDelete(range);
				if (!entry.isDeleted()) {
					kept.add(entry);
				}
				if (created != null) {
					kept.add(created);
				}
			}
		}

		@Override
		protected InternalTraceObjectValue put(Lifespan range, Object value) {
			if (value == null) {
				return null;
			}
			if (keep != null && Objects.equals(this.value, value)) {
				keep.doSetLifespanAndEmit(range);
				return keep;
			}
			for (InternalTraceObjectValue k : kept) {
				if (Objects.equals(value, k.getValue()) && Objects.equals(range, k.getLifespan())) {
					kept.remove(k);
					return k;
				}
			}
			return create(range, value);
		}

		protected abstract InternalTraceObjectValue create(Lifespan range, Object value);
	}

	DBTraceObjectManager getManager();

	/**
	 * Get the database key
	 * 
	 * @return the key
	 */
	long getKey();

	@Override
	DBTraceObject getChild();

	DBTraceObject getChildOrNull();

	void doSetLifespan(Lifespan lifespan);

	default void doSetLifespanAndEmit(Lifespan lifespan) {
		Lifespan oldLifespan = getLifespan();
		doSetLifespan(lifespan);
		getParent().emitEvents(new TraceChangeRecord<>(
			TraceObjectChangeType.VALUE_LIFESPAN_CHANGED, null, this, oldLifespan, lifespan));
	}

	@Override
	default void setLifespan(Lifespan lifespan) {
		setLifespan(lifespan, ConflictResolution.TRUNCATE);
	}

	@Override
	default void setLifespan(Lifespan lifespan, ConflictResolution resolution) {
		try (LockHold hold = getTrace().lockWrite()) {
			if (getParent() == null) {
				throw new IllegalArgumentException("Cannot set lifespan of root value");
			}
			if (resolution == ConflictResolution.DENY) {
				getParent().doCheckConflicts(lifespan, getEntryKey(), getValue());
			}
			new ValueLifespanSetter(lifespan, getValue(), this) {
				@Override
				protected Iterable<InternalTraceObjectValue> getIntersecting(Long lower,
						Long upper) {
					Collection<InternalTraceObjectValue> col = Collections.unmodifiableCollection(
						getParent().doGetValues(lower, upper, getEntryKey()));
					return IterableUtils.filteredIterable(col, v -> v != keep);
				}

				@Override
				protected InternalTraceObjectValue create(Lifespan range, Object value) {
					return getParent().doCreateValue(range, getEntryKey(), value);
				}
			}.set(lifespan, getValue());
			if (isObject()) {
				DBTraceObject child = getChild();
				child.emitEvents(new TraceChangeRecord<>(TraceObjectChangeType.LIFE_CHANGED, null, child));
			}
		}
	}

	void doDelete();

	default void doDeleteAndEmit() {
		DBTraceObject parent = getParent();
		doDelete();
		parent.emitEvents(new TraceChangeRecord<>(TraceObjectChangeType.VALUE_DELETED, null, this));
	}

	@Override
	DBTraceObject getParent();

	default InternalTraceObjectValue doTruncateOrDeleteAndEmitLifeChange(Lifespan span) {
		if (!isCanonical()) {
			return doTruncateOrDelete(span);
		}
		DBTraceObject child = getChildOrNull();
		InternalTraceObjectValue result = doTruncateOrDelete(span);
		child.emitEvents(new TraceChangeRecord<>(TraceObjectChangeType.LIFE_CHANGED, null, child));
		return result;
	}

	default InternalTraceObjectValue doTruncateOrDelete(Lifespan span) {
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
}
