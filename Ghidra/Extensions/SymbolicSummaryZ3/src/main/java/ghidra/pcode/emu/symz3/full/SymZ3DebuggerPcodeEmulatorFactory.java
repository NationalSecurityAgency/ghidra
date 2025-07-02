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
package ghidra.pcode.emu.symz3.full;

import ghidra.app.plugin.core.debug.service.emulation.AbstractDebuggerPcodeEmulatorFactory;
import ghidra.debug.api.emulation.DebuggerPcodeMachine;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;

/**
 * An emulator factory for making the {@link SymZ3DebuggerPcodeEmulator} discoverable to the UI
 * 
 * <p>
 * This is the final class to create a full Debugger-integrated emulator. This class is what makes
 * it appear in the menu of possible emulators the user may configure.
 */
public class SymZ3DebuggerPcodeEmulatorFactory extends AbstractDebuggerPcodeEmulatorFactory {

	@Override
	public String getTitle() {
		return "Symbolic Z3 Summary with Concrete Emulation";
	}

	@Override
	public DebuggerPcodeMachine<?> create(PcodeDebuggerAccess access) {
		return new SymZ3DebuggerPcodeEmulator(access);
	}
}
