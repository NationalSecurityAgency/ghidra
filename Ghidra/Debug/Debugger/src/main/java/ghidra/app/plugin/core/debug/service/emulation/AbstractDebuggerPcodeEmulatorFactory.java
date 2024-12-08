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
package ghidra.app.plugin.core.debug.service.emulation;

import ghidra.app.plugin.core.debug.service.emulation.data.DefaultPcodeDebuggerAccess;
import ghidra.debug.api.emulation.DebuggerPcodeEmulatorFactory;
import ghidra.debug.api.emulation.DebuggerPcodeMachine;
import ghidra.debug.api.target.Target;
import ghidra.framework.plugintool.PluginTool;
import ghidra.trace.model.guest.TracePlatform;

public abstract class AbstractDebuggerPcodeEmulatorFactory implements DebuggerPcodeEmulatorFactory {
	@Override
	public DebuggerPcodeMachine<?> create(PluginTool tool, TracePlatform platform, long snap,
			Target target) {
		return create(new DefaultPcodeDebuggerAccess(tool, target, platform, snap));
	}
}
