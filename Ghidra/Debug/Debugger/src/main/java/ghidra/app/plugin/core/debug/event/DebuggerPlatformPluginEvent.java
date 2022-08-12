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

import ghidra.app.plugin.core.debug.mapping.DebuggerPlatformMapper;
import ghidra.framework.plugintool.PluginEvent;
import ghidra.trace.model.Trace;

public class DebuggerPlatformPluginEvent extends PluginEvent {
	static final String NAME = "Platform";

	private final Trace trace;
	private final DebuggerPlatformMapper mapper;

	public DebuggerPlatformPluginEvent(String sourceName, Trace trace,
			DebuggerPlatformMapper mapper) {
		super(sourceName, NAME);
		this.trace = trace;
		this.mapper = mapper;
	}

	public Trace getTrace() {
		return trace;
	}

	public DebuggerPlatformMapper getMapper() {
		return mapper;
	}
}
