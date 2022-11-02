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

import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;

/**
 * The Debugger's default emulator factory
 */
public class BytesDebuggerPcodeEmulatorFactory implements DebuggerPcodeEmulatorFactory {
	// TODO: Config options:
	// 1) userop library

	@Override
	public String getTitle() {
		return "Default Concrete P-code Emulator";
	}

	@Override
	public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess access) {
		return new BytesDebuggerPcodeEmulator(access);
	}
}
