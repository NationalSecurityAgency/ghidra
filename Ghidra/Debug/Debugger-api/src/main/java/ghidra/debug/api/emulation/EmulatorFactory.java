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
package ghidra.debug.api.emulation;

import ghidra.pcode.emu.PcodeMachine;
import ghidra.pcode.exec.trace.TraceEmulationIntegration.Writer;
import ghidra.util.classfinder.ExtensionPoint;

/**
 * A factory for configuring and creating a Debugger-integrated emulator
 */
public interface EmulatorFactory extends ExtensionPoint {
	// TODO: Config options, use ModelFactory as a model

	/**
	 * Get the title, to appear in menus and dialogs
	 * 
	 * @return the title
	 */
	String getTitle();

	/**
	 * Create the emulator
	 * 
	 * @param access the trace-and-debugger access shim
	 * @param writer the Debugger's emulation callbacks for UI integration
	 * @return the emulator with callbacks installed
	 */
	PcodeMachine<?> create(PcodeDebuggerAccess access, Writer writer);
}
