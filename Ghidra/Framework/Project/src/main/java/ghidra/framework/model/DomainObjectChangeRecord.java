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
 * record is delivered as part of the change notification. The event
 * types correspond to the constants in
 * {@link ghidra.program.util.ChangeManager ChangeManager}.
 * @see ghidra.program.util.ChangeManager ChangeManager
 */
public class DomainObjectChangeRecord implements Serializable {
	private final static long serialVersionUID = 1;

	private int eventType;
	private int subEventType;
	private Object oldValue;
	private Object newValue;

	/**
	 * Construct a new DomainObjectChangeRecord.
	 */
	public DomainObjectChangeRecord() {
		this(0, 0, null, null);
	}

	/**
	 * Construct a new DomainObjectChangeRecord.
	 * @param type event type
	 */
	public DomainObjectChangeRecord(int type) {
		this(type, 0, null, null);
	}

	/**
	 * Construct a new DomainObjectChangeRecord.
	 * @param type event type
	 * @param oldValue old value
	 * @param newValue new value
	 */
	public DomainObjectChangeRecord(int type, Object oldValue, Object newValue) {
		this(type, 0, oldValue, newValue);
	}

	/**
	 * Construct a new DomainObjectChangeRecord.
	 * @param type event type
	 * @param subType sub-event type (use 0 if unspecified)
	 * @param oldValue old value
	 * @param newValue new value
	 */
	public DomainObjectChangeRecord(int type, int subType, Object oldValue, Object newValue) {
		eventType = type;
		subEventType = subType;
		this.oldValue = oldValue;
		this.newValue = newValue;
	}

	/**
	 * Return the event type for this change record.
	 */
	public int getEventType() {
		return eventType;
	}

	/**
	 * Return the sub-event type for this change record.
	 * A value of 0 is the default if unspecified.
	 */
	public int getSubEventType() {
		return subEventType;
	}

	/**
	 * Return the old value.
	 */
	public Object getOldValue() {
		return oldValue;
	}

	/**
	 * Return the new value.
	 */
	public Object getNewValue() {
		return newValue;
	}

	@Override
	public String toString() {
		//@formatter:off
		return "{\n" +
			"\tnewValue: " + newValue + ",\n" +
			"\toldValue: " + oldValue + ",\n" +
			"\teventType: " + eventType + ",\n" +
			"\tsubEventType: " + subEventType + "\n" +
			"\n}";
		//@formatter:on
	}
}
