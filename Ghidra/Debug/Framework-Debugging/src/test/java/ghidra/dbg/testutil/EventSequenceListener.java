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
package ghidra.dbg.testutil;

import java.util.*;

import ghidra.dbg.DebuggerModelListener;
import ghidra.dbg.target.TargetEventScope.TargetEventType;
import ghidra.dbg.target.TargetObject;
import ghidra.dbg.target.TargetThread;

public class EventSequenceListener implements DebuggerModelListener {
	public static class EventRecord {
		public final TargetObject object;
		public final TargetThread eventThread;
		public final TargetEventType type;
		public final String description;
		public final List<Object> parameters;

		public EventRecord(TargetObject object, TargetThread eventThread, TargetEventType type,
				String description, List<Object> parameters) {
			this.object = object;
			this.eventThread = eventThread;
			this.type = type;
			this.description = description;
			this.parameters = parameters;
		}

		@Override
		public String toString() {
			return String.format("<EventRecord obj=%s thread=%s type=%s desc='%s' params=%s",
				object, eventThread, type, description, parameters);
		}

		@Override
		public boolean equals(Object obj) {
			if (!(obj instanceof EventRecord)) {
				return false;
			}
			EventRecord that = (EventRecord) obj;
			if (!Objects.equals(this.object, that.object)) {
				return false;
			}
			if (!Objects.equals(this.eventThread, that.eventThread)) {
				return false;
			}
			if (!Objects.equals(this.type, that.type)) {
				return false;
			}
			if (!Objects.equals(this.description, that.description)) {
				return false;
			}
			if (!Objects.equals(this.parameters, that.parameters)) {
				return false;
			}
			return true;
		}

		@Override
		public int hashCode() {
			return Objects.hash(object, eventThread, type, description, parameters);
		}
	}

	public final List<EventRecord> events = new ArrayList<>();

	@Override
	public void event(TargetObject object, TargetThread eventThread, TargetEventType type,
			String description, List<Object> parameters) {
		events.add(new EventRecord(object, eventThread, type, description, parameters));
	}
}
