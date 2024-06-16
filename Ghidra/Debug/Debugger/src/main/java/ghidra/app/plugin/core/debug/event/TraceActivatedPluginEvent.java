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
package ghidra.app.plugin.core.debug.event;

import ghidra.app.services.DebuggerTraceManagerService.ActivationCause;
import ghidra.debug.api.tracemgr.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginEvent;

public class TraceActivatedPluginEvent extends PluginEvent {
	
	static final String NAME = "Trace Location";

	private final DebuggerCoordinates coordinates;
	private final ActivationCause cause;

	public TraceActivatedPluginEvent(String source, DebuggerCoordinates coordinates, ActivationCause cause) {
		super(source, NAME);
		this.coordinates = coordinates;
		this.cause = cause;
	}

	public DebuggerCoordinates getActiveCoordinates() {
		return coordinates;
	}

	public ActivationCause getCause() {
		return cause;
	}
}
