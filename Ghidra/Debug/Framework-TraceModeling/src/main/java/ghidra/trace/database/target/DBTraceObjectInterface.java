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

import ghidra.trace.model.Lifespan;
import ghidra.trace.model.Lifespan.*;
import ghidra.trace.model.Trace.TraceObjectChangeType;
import ghidra.trace.model.TraceUniqueObject;
import ghidra.trace.model.target.*;
import ghidra.trace.util.*;
import ghidra.util.database.ObjectKey;

public interface DBTraceObjectInterface extends TraceObjectInterface, TraceUniqueObject {

	abstract class Translator<T> {
		private final String spaceValueKey;
		private final DBTraceObject object;
		private final T iface;
		// TODO: Memorizing life is not optimal.
		// GP-1887 means to expose multiple lifespans in, e.g., TraceThread
		private LifeSet life = new DefaultLifeSet();

		public Translator(String spaceValueKey, DBTraceObject object, T iface) {
			this.spaceValueKey = spaceValueKey;
			this.object = object;
			this.iface = iface;
		}

		protected abstract TraceChangeType<T, Void> getAddedType();

		protected abstract TraceChangeType<T, Lifespan> getLifespanChangedType();

		protected abstract TraceChangeType<T, ?> getChangedType();

		protected abstract boolean appliesToKey(String key);

		protected abstract TraceChangeType<T, Void> getDeletedType();

		protected void emitExtraAdded() {
			// Extension point
		}

		protected void emitExtraLifespanChanged(Lifespan oldLifespan, Lifespan newLifespan) {
			// Extension point
		}

		protected void emitExtraValueChanged(Lifespan lifespan, String key, Object oldValue,
				Object newValue) {
			// Extension point
		}

		protected void emitExtraDeleted() {
			// Extension point
		}

		protected TraceAddressSpace getSpace(LifeSet life) {
			if (life.isEmpty()) {
				return null;
			}
			return spaceValueKey == null ? null
					: spaceForValue(object, life.bound().lmin(), spaceValueKey);
		}

		protected TraceChangeRecord<?, ?> translateAdded() {
			TraceChangeType<T, Void> type = getAddedType();
			if (type == null) {
				return null;
			}
			emitExtraAdded();
			return new TraceChangeRecord<>(type, getSpace(life), iface, null, null);
		}

		protected TraceChangeRecord<?, ?> translateLifespanChanged(LifeSet oldLife) {
			TraceChangeType<T, Lifespan> type = getLifespanChangedType();
			if (type == null) {
				return null;
			}
			Lifespan oldLifespan = oldLife.bound();
			Lifespan newLifespan = life.bound();
			emitExtraLifespanChanged(oldLifespan, newLifespan);
			return new TraceChangeRecord<>(type, getSpace(life), iface, oldLifespan, newLifespan);
		}

		protected TraceChangeRecord<?, ?> translateDeleted(LifeSet life) {
			TraceChangeType<T, Void> type = getDeletedType();
			if (type == null) {
				return null;
			}
			emitExtraDeleted();
			return new TraceChangeRecord<>(type, getSpace(life), iface, null, null);
		}

		public TraceChangeRecord<?, ?> translate(TraceChangeRecord<?, ?> rec) {
			if (rec.getEventType() == TraceObjectChangeType.LIFE_CHANGED.getType()) {
				if (object.isDeleted()) {
					return null;
				}
				assert rec.getAffectedObject() == object;
				LifeSet oldLife = life;
				life = object.getLife();
				boolean oldHasLife = !oldLife.isEmpty();
				boolean newHasLife = !life.isEmpty();
				if (newHasLife && oldHasLife) {
					return translateLifespanChanged(oldLife);
				}
				else if (newHasLife) {
					return translateAdded();
				}
				else if (oldHasLife) {
					return translateDeleted(oldLife);
				}
				else {
					throw new AssertionError("Life changed from empty to empty?");
				}
			}
			if (rec.getEventType() == TraceObjectChangeType.VALUE_CREATED.getType()) {
				if (object.isDeleted()) {
					return null;
				}
				TraceChangeType<T, ?> type = getChangedType();
				if (type == null) {
					return null;
				}
				TraceChangeRecord<TraceObjectValue, Void> cast =
					TraceObjectChangeType.VALUE_CREATED.cast(rec);
				TraceObjectValue affected = cast.getAffectedObject();
				String key = affected.getEntryKey();
				if (!appliesToKey(key)) {
					return null;
				}
				assert affected.getParent() == object;
				if (object.getCanonicalParent(affected.getMaxSnap()) == null) {
					return null; // Object is not complete
				}
				emitExtraValueChanged(affected.getLifespan(), key, cast.getOldValue(),
					cast.getNewValue());
				return new TraceChangeRecord<>(type, getSpace(life), iface, null, null);
			}
			if (rec.getEventType() == TraceObjectChangeType.DELETED.getType()) {
				return translateDeleted(life);
			}
			return null;
		}
	}

	/**
	 * Translate an object event into the interface-specific event
	 * 
	 * <p>
	 * Both the object event and the interface-specific event, if applicable, will be emitted. If
	 * multiple events need to be emitted, then this method may emit them directly via its object's
	 * trace. If exactly one event needs to be emitted, then this method should return the
	 * translated record. If no translation applies, or if the translated event(s) were emitted
	 * directly, this method returns {@code null}.
	 * 
	 * @param rec the object event
	 * @return the interface-specific event to emit, or {@code null}
	 */
	TraceChangeRecord<?, ?> translateEvent(TraceChangeRecord<?, ?> rec);

	static TraceAddressSpace spaceForValue(TraceObject object, long snap, String key) {
		TraceObjectValue val = object.getAttribute(snap, key);
		if (val instanceof DBTraceObjectAddressRangeValue) {
			DBTraceObjectAddressRangeValue addrVal = (DBTraceObjectAddressRangeValue) val;
			return addrVal.getTraceAddressSpace();
		}
		return null;
	}

	default TraceAddressSpace spaceForValue(long snap, String key) {
		return spaceForValue(getObject(), snap, key);
	}

	@Override
	default ObjectKey getObjectKey() {
		return getObject().getObjectKey();
	}

	@Override
	default boolean isDeleted() {
		return getObject().getLife().isEmpty();
	}
}
