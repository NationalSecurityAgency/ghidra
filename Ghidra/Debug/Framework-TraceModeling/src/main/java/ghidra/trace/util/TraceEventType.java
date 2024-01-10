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

import ghidra.framework.model.DomainObjectEventIdGenerator;
import ghidra.framework.model.EventType;

/**
 * EventTypes for trace events. This implementation exists because trace event types are not 
 * currently structured as enums. This current implementation will not give a very good toString as
 * its actual event name is unknown, so it uses its event category class + its actual assigned
 * numerical id.
 */
public class TraceEventType implements EventType {

	private final int id = DomainObjectEventIdGenerator.next();
	private String name;

	TraceEventType(String name) {
		this.name = name + "(" + id + ")";
	}

	@Override
	public int getId() {
		return id;
	}

	@Override
	public String toString() {
		return name;
	}
}
