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
package ghidra.pcode.emu.symz3;

import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.symz3.state.SymZ3PcodeEmulator;
import ghidra.pcode.emu.symz3.state.SymZ3PieceHandler;
import ghidra.pcode.exec.trace.TraceEmulationIntegration;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;

/**
 * An emulator factory for making the {@link SymZ3DebuggerPcodeEmulator} discoverable to the UI
 * 
 * <p>
 * This is the final class to create a full Debugger-integrated emulator. This class is what makes
 * it appear in the menu of possible emulators the user may configure.
 */
public class SymZ3EmulatorFactory implements EmulatorFactory {

	public static Writer delayedWriteTrace(PcodeTraceAccess access) {
		Writer writer = TraceEmulationIntegration.bytesDelayedWrite(access);
		addHandlers(writer);
		return writer;
	}

	public static void addHandlers(Writer writer) {
		writer.putHandler(new SymZ3PieceHandler());
	}

	@Override
	public String getTitle() {
		return "Symbolic Z3 Summary with Concrete Emulation";
	}

	@Override
	public PcodeMachine<?> create(PcodeDebuggerAccess access, Writer writer) {
		addHandlers(writer);
		return new SymZ3PcodeEmulator(access.getLanguage(), writer.callbacks());
	}
}
