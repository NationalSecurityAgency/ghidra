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
import java.util.function.Consumer;

/**
 * An event indicating a DomainObject has changed.  This event is actually
 * a list of DomainObjectChangeRecords.
 *  
 * NOTE: This object is TRANSIENT - it is only valid during the life of calls
 * to all the DomainObjectChangeListeners.  Listeners who need to retain
 * any of this event information past the listener call should save the 
 * DomainObjectChangeRecords, which will remain valid always.
 */

public class DomainObjectChangedEvent extends EventObject
		implements Iterable<DomainObjectChangeRecord> {

	private final static long serialVersionUID = 1;

	private List<DomainObjectChangeRecord> subEvents;
	private BitSet eventBits = new BitSet(255);

	/**
	 * Constructor
	 * 
	 * @param src the object which has changed
	 * @param subEvents a List of DomainObjectChangeRecords;
	 */
	public DomainObjectChangedEvent(DomainObject src, List<DomainObjectChangeRecord> subEvents) {
		super(src);
		this.subEvents = subEvents;
		for (DomainObjectChangeRecord record : subEvents) {
			eventBits.set(record.getEventType().getId());
		}
	}

	/**
	 * Return the number of change records contained within this event.
	 * @return the number of change records contained within this event 
	 */
	public int numRecords() {
		return subEvents.size();
	}

	/**
	 * Returns true if this event contains a record with the given event type
	 * @param eventType the event type to check
	 * @return the number of change records contained within this event.
	 */
	public boolean contains(EventType eventType) {
		return eventBits.get(eventType.getId());
	}

	/**
	 * Returns true if this event contains a record with any of the given event types.
	 * @param types the event types to check for
	 * @return true if this event contains a record with any of the given event types
	 */
	public boolean contains(EventType... types) {
		for (EventType eventType : types) {
			if (eventBits.get(eventType.getId())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns true if this event contains a record with the given event type. 
	 * @param eventType the event type to check
	 * @return the number of change records contained within this event.
	 * @deprecated use {@link #contains(EventType)} instead. This is here to help
	 * transition older code from using integer constants for even types to the new enum way
	 * that uses enums instead.
	 */
	@Deprecated
	public boolean containsEvent(EventType eventType) {
		return eventBits.get(eventType.getId());
	}

	/**
	 * Get the specified change record within this event.
	 * @param i change record number
	 * @return change record
	 */
	public DomainObjectChangeRecord getChangeRecord(int i) {
		return subEvents.get(i);
	}

	/**
	 * Returns iterator over all sub-events
	 */
	@Override
	public Iterator<DomainObjectChangeRecord> iterator() {
		return subEvents.iterator();
	}

	/**
	 * Loops over all records in this event and calls the consumer for each record that matches
	 * the given type.
	 * @param type the event type to apply the consumer
	 * @param consumer the consumer to call for each record of the given type
	 */
	public void forEach(EventType type, Consumer<DomainObjectChangeRecord> consumer) {
		if (!contains(type)) {
			return;
		}
		for (DomainObjectChangeRecord docr : subEvents) {
			if (docr.getEventType() == type) {
				consumer.accept(docr);
			}
		}
	}
}
