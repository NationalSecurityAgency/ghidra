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

import com.google.common.collect.Range;

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

		public Translator(String spaceValueKey, DBTraceObject object, T iface) {
			this.spaceValueKey = spaceValueKey;
			this.object = object;
			this.iface = iface;
		}

		protected abstract TraceChangeType<T, Void> getAddedType();

		protected abstract TraceChangeType<T, Range<Long>> getLifespanChangedType();

		protected abstract TraceChangeType<T, Void> getChangedType();

		protected abstract boolean appliesToKey(String key);

		protected abstract TraceChangeType<T, Void> getDeletedType();

		public TraceChangeRecord<?, ?> translate(TraceChangeRecord<?, ?> rec) {
			TraceAddressSpace space = spaceValueKey == null ? null
					: spaceForValue(object, object.getMinSnap(), spaceValueKey);
			if (rec.getEventType() == TraceObjectChangeType.CREATED.getType()) {
				TraceChangeType<T, Void> type = getAddedType();
				if (type == null) {
					return null;
				}
				assert rec.getAffectedObject() == object;
				return new TraceChangeRecord<>(type, space, iface, null,
					null);
			}
			if (rec.getEventType() == TraceObjectChangeType.LIFESPAN_CHANGED.getType()) {
				if (object.isDeleted()) {
					return null;
				}
				TraceChangeType<T, Range<Long>> type = getLifespanChangedType();
				if (type == null) {
					return null;
				}
				assert rec.getAffectedObject() == object;
				TraceChangeRecord<TraceObject, Range<Long>> cast =
					TraceObjectChangeType.LIFESPAN_CHANGED.cast(rec);
				return new TraceChangeRecord<>(type, space, iface,
					cast.getOldValue(), cast.getNewValue());
			}
			if (rec.getEventType() == TraceObjectChangeType.VALUE_CHANGED.getType()) {
				if (object.isDeleted()) {
					return null;
				}
				TraceChangeType<T, Void> type = getChangedType();
				if (type == null) {
					return null;
				}
				TraceChangeRecord<TraceObjectValue, Object> cast =
					TraceObjectChangeType.VALUE_CHANGED.cast(rec);
				String key = cast.getAffectedObject().getEntryKey();
				if (!appliesToKey(key)) {
					return null;
				}
				assert cast.getAffectedObject().getParent() == object;
				return new TraceChangeRecord<>(type, space, iface, null, null);
			}
			if (rec.getEventType() == TraceObjectChangeType.DELETED.getType()) {
				TraceChangeType<T, Void> type = getDeletedType();
				if (type == null) {
					return null;
				}
				assert rec.getAffectedObject() == object;
				return new TraceChangeRecord<>(type, space, iface, null, null);
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
		return getObject().isDeleted();
	}
}
