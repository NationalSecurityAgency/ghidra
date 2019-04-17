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
			eventBits.set(record.getEventType());
		}
	}

	/**
	 * Return the number of change records contained within this event.
	 */
	public int numRecords() {
		return subEvents.size();
	}

	public boolean containsEvent(int eventType) {
		return eventBits.get(eventType);
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
}
