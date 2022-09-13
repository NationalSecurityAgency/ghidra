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

import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerEmulatorPartsFactory;
import ghidra.pcode.exec.debug.auxiliary.AuxDebuggerPcodeEmulator;
import ghidra.pcode.exec.trace.TracePcodeMachine;

/**
 * A Debugger-integrated emulator (or p-code machine)
 *
 * <p>
 * A common implementation is an emulator with concrete plus some auxiliary state. To realize such a
 * machine, please see {@link AuxDebuggerPcodeEmulator} and {@link AuxDebuggerEmulatorPartsFactory}.
 *
 * @param <T> the type of values in the machine's memory and registers
 */
public interface DebuggerPcodeMachine<T> extends TracePcodeMachine<T> {
}
