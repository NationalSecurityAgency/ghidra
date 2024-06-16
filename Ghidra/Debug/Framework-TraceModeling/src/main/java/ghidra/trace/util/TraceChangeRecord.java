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

import ghidra.framework.model.DomainObjectChangeRecord;

public class TraceChangeRecord<T, U> extends DomainObjectChangeRecord {
	private static final long serialVersionUID = 1;

	private final TraceAddressSpace space;
	private final T affectedObject;
	private final boolean oldKnown;

	public TraceChangeRecord(TraceEvent<T, U> type, TraceAddressSpace space, T affectedObject,
			U oldValue, U newValue) {
		super(type, oldValue, newValue);
		this.space = space;
		this.affectedObject = affectedObject;
		this.oldKnown = true;
	}

	public TraceChangeRecord(TraceEvent<T, U> type, TraceAddressSpace space, T affectedObject,
			U newValue) {
		super(type, null, newValue);
		this.space = space;
		this.affectedObject = affectedObject;
		this.oldKnown = false;
	}

	public TraceChangeRecord(TraceEvent<T, U> type, TraceAddressSpace space,
			T affectedObject) {
		super(type, null, null);
		this.space = space;
		this.affectedObject = affectedObject;
		this.oldKnown = false;
	}

	public TraceChangeRecord(TraceEvent<T, U> type, TraceAddressSpace space) {
		super(type, null, null);
		this.space = space;
		this.affectedObject = null;
		this.oldKnown = false;
	}

	public TraceAddressSpace getSpace() {
		return space;
	}

	public T getAffectedObject() {
		return affectedObject;
	}

	public boolean isOldKnown() {
		return oldKnown;
	}

	@Override
	@SuppressWarnings("unchecked")
	public U getOldValue() {
		return (U) super.getOldValue();
	}

	@Override
	@SuppressWarnings("unchecked")
	public U getNewValue() {
		return (U) super.getNewValue();
	}
}
