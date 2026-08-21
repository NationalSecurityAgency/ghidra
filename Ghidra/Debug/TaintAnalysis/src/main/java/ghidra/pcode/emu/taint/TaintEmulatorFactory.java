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
package ghidra.pcode.emu.taint;

import ghidra.debug.api.emulation.EmulatorFactory;
import ghidra.debug.api.emulation.PcodeDebuggerAccess;
import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.emu.taint.state.TaintPieceHandler;
import ghidra.pcode.exec.trace.TraceEmulationIntegration;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.pcode.exec.trace.data.PcodeTraceAccess;

/**
 * An emulator factory for making the {@link TaintPcodeEmulator} discoverable to the UI
 * 
 * <p>
 * This is the final class to create a full Debugger-integrated emulator. This class is what makes
 * it appear in the menu of possible emulators the user may configure.
 */
public class TaintEmulatorFactory implements EmulatorFactory {

	/**
	 * This is conventionally available for testing and for scripts that would like to create a
	 * trace-integrated emulator without using the service.
	 * 
	 * @param access the means of accessing the integrated trace
	 * @return a writer with callbacks for trace integration
	 */
	public static Writer delayedWriteTrace(PcodeTraceAccess access) {
		Writer writer = TraceEmulationIntegration.bytesDelayedWrite(access);
		addHandlers(writer);
		return writer;
	}

	/**
	 * A common place to factor addition of the required handler.
	 * 
	 * <p>
	 * It is presumed something else has or will add the other handlers, e.g., for the bytes.
	 * 
	 * @param writer the writer to add handlers to
	 */
	public static void addHandlers(Writer writer) {
		writer.putHandler(new TaintPieceHandler());
	}

	@Override
	public String getTitle() {
		return "Taint Analyzer with Concrete Emulation";
	}

	@Override
	public PcodeMachine<?> create(PcodeDebuggerAccess access, Writer writer) {
		addHandlers(writer);
		return new TaintPcodeEmulator(access.getLanguage(), writer.callbacks());
	}
}
