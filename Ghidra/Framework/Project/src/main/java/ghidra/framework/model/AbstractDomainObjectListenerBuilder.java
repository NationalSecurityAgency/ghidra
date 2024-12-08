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
package ghidra.framework.model;

import java.util.*;
import java.util.function.*;

import ghidra.util.Msg;
import utilities.util.reflection.ReflectionUtilities;
import utility.function.Callback;

/**
 * Base class for creating a compact and efficient {@link DomainObjectListener}s. See
 * {@link DomainObjectListenerBuilder} for full documentation.
 * 
 * @param <R> The DomainObjectChangeRecord type
 * @param <B> The AbstractDomainObjectListeBuilder type (the only difference is R, the record type)
 */

public abstract class AbstractDomainObjectListenerBuilder<R extends DomainObjectChangeRecord, B extends AbstractDomainObjectListenerBuilder<R, B>> {
	private String name;
	private BooleanSupplier ignoreCheck;
	private List<EventTrigger> terminateList = new ArrayList<>();
	private List<EventTrigger> onAnyList = new ArrayList<>();
	private Map<EventType, TypedRecordConsumer<? extends DomainObjectChangeRecord>> onEachMap =
		new HashMap<>();

	private Class<? extends DomainObjectChangeRecord> activeRecordType;

	/**
	 * Creates a builder with the given recordClass as the default record class
	 * @param name the name of the client class that created this builder
	 * @param recordClass the class of event records consumers will be using in any calls that
	 * take a consumer
	 */
	public AbstractDomainObjectListenerBuilder(String name, Class<R> recordClass) {
		this.name = name;
		activeRecordType = recordClass;
	}

	/**
	 * Returns the name that will be associated with the domainObjectListener. this is for
	 * debugging purposes so that you can tell where this listener came from (since it is
	 * no longer implemented by the client class)
	 * @return the name assigned to this builder (and ultimately the listener)
	 */
	public String getName() {
		return name;
	}

	protected abstract B self();

	/**
	 * Sets a boolean supplier that can be checked to see if the client is in a state where
	 * they don't want events to be processed at this time.
	 * @param supplier the boolean supplier that if returns true, events are not processed
	 * @return this builder (for chaining)
	 */
	public B ignoreWhen(BooleanSupplier supplier) {
		this.ignoreCheck = supplier;
		return self();
	}

	/**
	 * Allows for specifying multiple event types that if the event contains any records with
	 * and of the given types, then a callback or callback with terminate will be triggered, 
	 * depending on if the next builder operation is either a call or terminate respectively.
	 * @param eventTypes the list of events to trigger on
	 * @return A sub-builder for specifying the call or call with terminate
	 */
	public AnyBuilder any(EventType... eventTypes) {
		return new AnyBuilder(eventTypes);
	}

	/**
	 * Allows for specifying multiple event types that for each record with one of the specified
	 * types, the follow on consumer will be called.
	 * @param eventTypes the list of events to trigger on
	 * @return A sub-builder for specifying the consumer to be used for records with any of
	 * these types
	 */
	public EachBuilder each(EventType... eventTypes) {
		return new EachBuilder(eventTypes);
	}

	/** 
	 * Allows for specifying a new record type that any follow on consumers will use for any
	 * defined "each" handlers.
	 * @param <R2> the new record type
	 * @param <B2> the new builder type that expects consumers of the new record type
	 * @param clazz the class of the new record type
	 * @return this builder with its consumer record type changed
	 */
	public <R2 extends DomainObjectChangeRecord, B2 extends AbstractDomainObjectListenerBuilder<R2, B2>> B2 with(
			Class<R2> clazz) {

		activeRecordType = clazz;
		@SuppressWarnings("unchecked")
		B2 newSelf = (B2) self();
		return newSelf;
	}

	/**
	 * Builds and returns a new DomainObjectEventHandler
	 * @return a new DomainObjectEventHandler from this builder
	 */
	public DomainObjectListener build() {

		BuilderDomainObjectListener listener = new BuilderDomainObjectListener(name);
		listener.setIgnoreCheck(ignoreCheck);
		if (!terminateList.isEmpty()) {
			listener.setTerminateList(terminateList);
		}
		if (!onAnyList.isEmpty()) {
			listener.setOnAnyList(onAnyList);
		}
		if (!onEachMap.isEmpty()) {
			listener.setOnEachMap(onEachMap);
		}

		return listener;
	}

	/**
	 * Sub-builder for collection eventTypes before eventually being association with a
	 * callback or callback with termination
	 */
	public class AnyBuilder {
		List<EventType> eventTypeList = new ArrayList<>();

		public AnyBuilder(EventType[] eventTypes) {
			eventTypeList.addAll(Arrays.asList(eventTypes));
		}

		/**
		 * Provides the callback to be associated with this collection of event types.
		 * @param callback the callback for this collection of event types
		 * @return the main event builder that created this sub-builder
		 */
		public B call(Callback callback) {
			EventType[] eventTypes = eventTypeList.toArray(new EventType[eventTypeList.size()]);
			onAnyList.add(new EventTrigger(callback, eventTypes));
			return self();
		}

		/**
		 * Provides the callback to be associated with this collection of event types.
		 * @param consumer the callback for this collection of event types
		 * @return the main event builder that created this sub-builder
		 */
		public B call(Consumer<DomainObjectChangedEvent> consumer) {
			EventType[] eventTypes = eventTypeList.toArray(new EventType[eventTypeList.size()]);
			onAnyList.add(new EventTrigger(consumer, eventTypes));
			return self();
		}

		/**
		 * Provides the callback with termination to be associated with this collection of event
		 * types.
		 * @param callback the callback for this collection of event types
		 * @return the main event builder that created this sub-builder
		 */
		public B terminate(Callback callback) {
			EventType[] eventTypes = eventTypeList.toArray(new EventType[eventTypeList.size()]);
			terminateList.add(new EventTrigger(callback, eventTypes));
			return self();
		}

		/**
		 * Provides the consumer with termination to be associated with this collection of event
		 * types. This form of terminate includes the event when performing the callback.
		 * @param consumer the consumer for this collection of event types
		 * @return the main event builder that created this sub-builder
		 */
		public B terminate(Consumer<DomainObjectChangedEvent> consumer) {
			EventType[] eventTypes = eventTypeList.toArray(new EventType[eventTypeList.size()]);
			terminateList.add(new EventTrigger(consumer, eventTypes));
			return self();
		}
	}

	/**
	 * Sub-builder for collection eventTypes before eventually being associated with a
	 * consumer for records with those types
	 */
	public class EachBuilder {
		List<EventType> eventTypeList = new ArrayList<>();

		public EachBuilder(EventType[] eventTypes) {
			eventTypeList.addAll(Arrays.asList(eventTypes));
		}

		/**
		 * Provides the consumer to be associated with this collection of event types.
		 * @param consumer the consumer for this collection of event types
		 * @return the main event builder that created this sub-builder
		 */
		public B call(Consumer<R> consumer) {
			TypedRecordConsumer<R> trc = new TypedRecordConsumer<R>(consumer, activeRecordType);
			for (EventType eventType : eventTypeList) {
				onEachMap.put(eventType, trc);
			}
			return self();
		}

		/**
		 * Provides the consumer to be associated with this collection of event types.
		 * @param biConsumer the consumer for this collection of event types
		 * @return the main event builder that created this sub-builder
		 */
		public B call(BiConsumer<DomainObjectChangedEvent, R> biConsumer) {
			TypedRecordConsumer<R> trc = new TypedRecordConsumer<R>(biConsumer, activeRecordType);
			for (EventType eventType : eventTypeList) {
				onEachMap.put(eventType, trc);
			}
			return self();
		}
	}

	static class EventTrigger implements Consumer<DomainObjectChangedEvent> {
		private final Consumer<DomainObjectChangedEvent> consumer;
		private final EventType[] eventTypes;

		EventTrigger(Consumer<DomainObjectChangedEvent> consumer, EventType... eventTypes) {
			this.consumer = consumer;
			this.eventTypes = eventTypes;
		}

		EventTrigger(Callback callback, EventType... eventTypes) {
			this(e -> callback.call(), eventTypes);
		}

		public boolean isTriggered(DomainObjectChangedEvent event) {
			return event.contains(eventTypes);
		}

		@Override
		public void accept(DomainObjectChangedEvent e) {
			consumer.accept(e);
		}
	}

	/**
	 * Class for tracking the record classes and consumers for records of that type. Also
	 * contains inception information if the consumers and record classes don't match up.
	 *
	 * @param <RR> The type of record and consumer for this class. 
	 */
	static class TypedRecordConsumer<RR>
			implements BiConsumer<DomainObjectChangedEvent, DomainObjectChangeRecord> {
		private Class<? extends DomainObjectChangeRecord> recordClass;
		private BiConsumer<DomainObjectChangedEvent, RR> consumer;
		private String inceptionInformation;

		TypedRecordConsumer(Consumer<RR> consumerX,
				Class<? extends DomainObjectChangeRecord> recordClass) {
			this((a, b) -> consumerX.accept(b), recordClass);
		}

		TypedRecordConsumer(BiConsumer<DomainObjectChangedEvent, RR> consumer,
				Class<? extends DomainObjectChangeRecord> recordClass) {
			this.consumer = consumer;
			this.recordClass = recordClass;
			recordInception();
		}

		private void recordInception() {
			inceptionInformation = getInceptionFromTheFirstClassThatIsNotUsOrABuilder();
		}

		private String getInceptionFromTheFirstClassThatIsNotUsOrABuilder() {
			Throwable t = ReflectionUtilities.createThrowableWithStackOlderThan(getClass());
			StackTraceElement[] trace =
				ReflectionUtilities.filterStackTrace(t.getStackTrace(), "ListenerBuilder");
			String classInfo = trace[0].toString();
			return classInfo;
		}

		@SuppressWarnings("unchecked")
		@Override
		public void accept(DomainObjectChangedEvent event, DomainObjectChangeRecord rec) {
			if (recordClass.isInstance(rec)) {
				consumer.accept(event, (RR) rec);
			}
			else {
				Msg.error(this,
					"Registered incorrect record class for event type: " + inceptionInformation);
			}
		}

	}

	static class BuilderDomainObjectListener implements DomainObjectListener {
		private String name;
		private BooleanSupplier ignoreCheck = () -> false;
		private List<EventTrigger> terminateList;
		private List<EventTrigger> onAnyList;
		private Map<EventType, TypedRecordConsumer<? extends DomainObjectChangeRecord>> onEachMap;
		private EventType[] eachEventTypes;		// all the "onEach" event types

		BuilderDomainObjectListener(String name) {
			this.name = name;
		}

		public String getName() {
			return name;
		}

		void setIgnoreCheck(BooleanSupplier supplier) {
			this.ignoreCheck = supplier != null ? supplier : () -> false;
		}

		void setTerminateList(List<EventTrigger> terminatEventList) {
			this.terminateList = terminatEventList;
		}

		void setOnAnyList(List<EventTrigger> onAnyList) {
			this.onAnyList = onAnyList;
		}

		void setOnEachMap(
				Map<EventType, TypedRecordConsumer<? extends DomainObjectChangeRecord>> onEachMap) {
			this.onEachMap = onEachMap;
			eachEventTypes = onEachMap.keySet().toArray(new EventType[onEachMap.size()]);
		}

		@Override
		public void domainObjectChanged(DomainObjectChangedEvent event) {
			// check if events are being ignored
			if (ignoreCheck.getAsBoolean()) {
				return;
			}
			// check for terminating events first
			if (terminateList != null && processTerminateList(event)) {
				return;
			}
			if (onAnyList != null) {
				processOnAnyList(event);
			}
			if (onEachMap != null) {
				processOnEachMap(event);
			}
		}

		/**
		 * Checks if the given event contains any of the terminate event type triggers and calls the
		 * associated callback if it does and terminates the event processing for this event.
		 * @param event the event to process
		 * @return true if a terminate event type is found
		 */
		private boolean processTerminateList(DomainObjectChangedEvent event) {
			for (EventTrigger trigger : terminateList) {
				if (trigger.isTriggered(event)) {
					trigger.accept(event);
					return true;
				}
			}
			return false;
		}

		/**
		 * Checks if the given event contains any of the event type triggers and calls the
		 * associated callback if it does.
		 * @param event the event to process
		 */
		private void processOnAnyList(DomainObjectChangedEvent event) {
			for (EventTrigger trigger : onAnyList) {
				if (trigger.isTriggered(event)) {
					trigger.accept(event);
				}
			}
		}

		/**
		 * If there is at least one record with a type that has to be processed for each record,
		 * then loop through the records and call the corresponding consumer.
		 * @param event the event being processed
		 */
		private void processOnEachMap(DomainObjectChangedEvent event) {
			// if lots of records, first check if any event types of interest are in the event,
			// otherwise, faster to just loop through records anyway
			if (event.numRecords() > onEachMap.size()) {
				if (!event.contains(eachEventTypes)) {
					return;
				}
			}

			for (DomainObjectChangeRecord record : event) {
				EventType type = record.getEventType();
				TypedRecordConsumer<?> typedRecordConsumer = onEachMap.get(type);
				if (typedRecordConsumer != null) {
					typedRecordConsumer.accept(event, record);
				}
			}
		}

	}

}
