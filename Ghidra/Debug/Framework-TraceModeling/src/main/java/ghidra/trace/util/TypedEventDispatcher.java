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
package ghidra.trace.util;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Consumer;

import ghidra.framework.model.*;
import ghidra.program.model.address.AddressSpace;

public class TypedEventDispatcher {

	public interface EventRecordHandler<T, U> {
		void handle(TraceChangeRecord<T, U> record);
	}

	public interface FullEventRecordHandler<T, U> extends EventRecordHandler<T, U> {
		void handle(AddressSpace space, T affectedObject, U oldValue, U newValue);

		@Override
		default void handle(TraceChangeRecord<T, U> record) {
			handle(record.getAddressSpace(), record.getAffectedObject(), record.getOldValue(),
				record.getNewValue());
		}
	}

	public interface AffectedObjectHandler<T> extends EventRecordHandler<T, Void> {
		void handle(AddressSpace space, T affectedObject);

		@Override
		default void handle(TraceChangeRecord<T, Void> record) {
			handle(record.getAddressSpace(), record.getAffectedObject());
		}
	}

	public interface AffectedObjectOnlyHandler<T> extends EventRecordHandler<T, Void> {
		void handle(T affectedObject);

		@Override
		default void handle(TraceChangeRecord<T, Void> record) {
			handle(record.getAffectedObject());
		}
	}

	public interface AffectedAndValuesOnlyHandler<T, U> extends EventRecordHandler<T, U> {
		void handle(T affectedObject, U oldValue, U newValue);

		@Override
		default void handle(TraceChangeRecord<T, U> record) {
			handle(record.getAffectedObject(), record.getOldValue(), record.getNewValue());
		}
	}

	public interface SpaceValuesHandler<U> extends EventRecordHandler<Void, U> {
		void handle(AddressSpace space, U oldValue, U newValue);

		@Override
		default void handle(TraceChangeRecord<Void, U> record) {
			handle(record.getAddressSpace(), record.getOldValue(), record.getNewValue());
		}
	}

	public interface ValuesOnlyHandler<U> extends EventRecordHandler<Void, U> {
		void handle(U oldValue, U newValue);

		@Override
		default void handle(TraceChangeRecord<Void, U> record) {
			handle(record.getOldValue(), record.getNewValue());
		}
	}

	public interface IgnoreValuesHandler extends EventRecordHandler<Object, Object> {
		void handle(AddressSpace space);

		@Override
		default void handle(TraceChangeRecord<Object, Object> record) {
			handle(record.getAddressSpace());
		}
	}

	public interface IgnoreAllHandler extends EventRecordHandler<Object, Object> {
		void handle();

		@Override
		default void handle(TraceChangeRecord<Object, Object> record) {
			handle();
		}
	}

	private Map<TraceEvent<?, ?>, EventRecordHandler<?, ?>> typedMap = new HashMap<>();
	private Map<EventType, Consumer<DomainObjectChangeRecord>> untypedMap = new HashMap<>();
	protected Consumer<DomainObjectChangeRecord> restoredHandler = null;

	protected <T, U> void listenFor(TraceEvent<T, U> type, EventRecordHandler<T, U> handler) {
		typedMap.put(type, handler);
	}

	protected <T, U> void listenFor(TraceEvent<T, U> type,
			FullEventRecordHandler<? super T, ? super U> handler) {
		typedMap.put(type, handler);
	}

	protected <T, U> void listenFor(TraceEvent<T, U> type,
			AffectedObjectHandler<? super T> handler) {
		typedMap.put(type, handler);
	}

	protected <T, U> void listenFor(TraceEvent<T, U> type,
			AffectedObjectOnlyHandler<? super T> handler) {
		typedMap.put(type, handler);
	}

	/**
	 * Listen for the given event, taking the affected object, the old value, and the new value
	 * 
	 * @param <T> the type of the affected object
	 * @param <U> the type of the values
	 * @param type the event type
	 * @param handler the handler
	 */
	protected <T, U> void listenFor(TraceEvent<T, U> type,
			AffectedAndValuesOnlyHandler<? super T, ? super U> handler) {
		typedMap.put(type, handler);
	}

	protected <T, U> void listenFor(TraceEvent<T, U> type,
			ValuesOnlyHandler<? super U> handler) {
		typedMap.put(type, handler);
	}

	protected <T, U> void listenFor(TraceEvent<T, U> type,
			SpaceValuesHandler<? super U> handler) {
		typedMap.put(type, handler);
	}

	protected void listenFor(TraceEvent<?, ?> type, IgnoreValuesHandler handler) {
		typedMap.put(type, handler);
	}

	protected void listenFor(TraceEvent<?, ?> type, IgnoreAllHandler handler) {
		typedMap.put(type, handler);
	}

	protected void listenForUntyped(EventType type, Consumer<DomainObjectChangeRecord> handler) {
		if (type == DomainObjectEvent.RESTORED) {
			restoredHandler = handler;
		}
		else {
			untypedMap.put(type, handler);
		}
	}

	public void handleChangeRecord(DomainObjectChangeRecord rec) {
		//String typeName = DefaultTraceChangeType.getName(rec.getEventType());
		//CountsByType.compute(typeName, (k, v) -> v == null ? 1 : v + 1);
		if (rec.getEventType() == DomainObjectEvent.RESTORED && restoredHandler != null) {
			restoredHandler.accept(rec);
			return;
		}
		if (rec instanceof TraceChangeRecord<?, ?> cr) {
			handleTraceChangeRecord(cr);
			return;
		}
		Consumer<DomainObjectChangeRecord> handler;
		if (null != (handler = untypedMap.get(rec.getEventType()))) {
			handler.accept(rec);
			return;
		}
		unhandled(rec);
	}

	@SuppressWarnings("unchecked")
	public void handleTraceChangeRecord(TraceChangeRecord<?, ?> rec) {
		@SuppressWarnings("rawtypes")
		EventRecordHandler handler = typedMap.get(rec.getEventType());
		if (handler != null) {
			handler.handle(rec);
		}
	}

	protected void unhandled(DomainObjectChangeRecord rec) {
		// Extension point
	}
}
