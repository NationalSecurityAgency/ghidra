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

import ghidra.app.plugin.core.debug.service.emulation.data.*;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.trace.BytesTracePcodeEmulator;
import ghidra.pcode.exec.trace.TracePcodeExecutorState;

/**
 * A trace emulator that knows how to read target memory when necessary
 * 
 * <p>
 * This is the default emulator used by the Debugger UI to perform interpolation and extrapolation.
 * For standalone scripting, consider using {@link BytesTracePcodeEmulator} or {@link PcodeEmulator}
 * instead. The former readily reads and records its state to traces, while the latter is the
 * simplest use case. See scripts ending in {@code EmuExampleScript} for example uses.
 * 
 * <p>
 * This emulator must always be run in its own thread, or at least a thread that can never lock the
 * UI. It blocks on target reads so that execution can proceed synchronously. Probably the most
 * suitable option is to use a background task.
 */
public class BytesDebuggerPcodeEmulator extends BytesTracePcodeEmulator
		implements DebuggerPcodeMachine<byte[]> {

	protected final PcodeDebuggerAccess access;

	/**
	 * Create the emulator
	 * 
	 * @param access the trace-and-debugger access shim
	 */
	public BytesDebuggerPcodeEmulator(PcodeDebuggerAccess access) {
		super(access);
		this.access = access;
	}

	@Override
	public TracePcodeExecutorState<byte[]> createSharedState() {
		return new RWTargetMemoryPcodeExecutorState(access.getDataForSharedState(), Mode.RO);
	}

	@Override
	public TracePcodeExecutorState<byte[]> createLocalState(PcodeThread<byte[]> emuThread) {
		return new RWTargetRegistersPcodeExecutorState(access.getDataForLocalState(emuThread, 0),
			Mode.RO);
	}
}
