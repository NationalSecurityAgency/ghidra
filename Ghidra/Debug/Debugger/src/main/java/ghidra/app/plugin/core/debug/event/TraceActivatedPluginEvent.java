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

import ghidra.app.plugin.core.debug.DebuggerCoordinates;
import ghidra.framework.plugintool.PluginEvent;

public class TraceActivatedPluginEvent extends PluginEvent {
	static final String NAME = "Trace Location";

	private final DebuggerCoordinates coordinates;

	public TraceActivatedPluginEvent(String source, DebuggerCoordinates coordinates) {
		super(source, NAME);
		this.coordinates = coordinates;
	}

	public DebuggerCoordinates getActiveCoordinates() {
		return coordinates;
	}
}
