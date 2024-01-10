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

import java.io.Serializable;

/**
 * Information about a change that was made to a domain object. The
 * record is delivered as part of the change notification. The event types
 * correspond to Enums defined in {@link DomainObjectEvent} and
 * other Enums or objects that implement the {@link EventType} interface.
 * 
 * Each event record contains the event type and optionally an old value and a new value. 
 * The old value and new value meaning are determined by the event type.
 */
public class DomainObjectChangeRecord implements Serializable {

	private EventType eventType;
	private Object oldValue;
	private Object newValue;

	/**
	 * Construct a new DomainObjectChangeRecord.
	 * @param eventType the type of event
	 */
	public DomainObjectChangeRecord(EventType eventType) {
		this(eventType, null, null);
	}

	/**
	 * Construct a new DomainObjectChangeRecord.
	 * @param eventType the type of 
	 * @param oldValue old value
	 * @param newValue new value
	 */
	public DomainObjectChangeRecord(EventType eventType, Object oldValue, Object newValue) {
		this.eventType = eventType;
		this.oldValue = oldValue;
		this.newValue = newValue;
	}

	/**
	 * Returns the event type for this change.
	 * @return the event type for this change
	 */
	public EventType getEventType() {
		return eventType;
	}

	/**
	 * Return the old value for this event or null if not applicable.
	 * @return the old value or null if not applicable
	 */
	public Object getOldValue() {
		return oldValue;
	}

	/**
	 * Return the new value for this event or null if not applicable.
	 * @return the old value or null if not applicable for this event. 
	 */
	public Object getNewValue() {
		return newValue;
	}

	@Override
	public String toString() {
		StringBuilder buf = new StringBuilder();
		buf.append(getClass().getSimpleName());
		buf.append(": event = ");
		buf.append(eventType);
		if (oldValue != null) {
			buf.append(", old = ");
			buf.append(oldValue);
		}
		if (newValue != null) {
			buf.append(", new = ");
			buf.append(newValue);
		}
		return buf.toString();
	}
}
