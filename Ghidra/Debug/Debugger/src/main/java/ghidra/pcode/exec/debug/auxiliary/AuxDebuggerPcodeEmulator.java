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
package ghidra.pcode.exec.debug.auxiliary;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.app.plugin.core.debug.service.emulation.*;
import ghidra.app.plugin.core.debug.service.emulation.data.PcodeDebuggerAccess;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.exec.trace.TracePcodeExecutorState;
import ghidra.pcode.exec.trace.auxiliary.AuxTraceEmulatorPartsFactory;
import ghidra.pcode.exec.trace.auxiliary.AuxTracePcodeEmulator;

/**
 * An Debugger-integrated emulator whose parts are manufactured by a
 * {@link AuxDebuggerEmulatorPartsFactory}
 * 
 * <p>
 * See the parts factory interface and its super interfaces:
 * <ul>
 * <li>{@link AuxDebuggerEmulatorPartsFactory}</li>
 * <li>{@link AuxTraceEmulatorPartsFactory}</li>
 * <li>{@link AuxEmulatorPartsFactory}</li>
 * </ul>
 * 
 * @param <U> the type of auxiliary values
 */
public abstract class AuxDebuggerPcodeEmulator<U> extends AuxTracePcodeEmulator<U>
		implements DebuggerPcodeMachine<Pair<byte[], U>> {

	protected final PcodeDebuggerAccess access;

	/**
	 * Create a new emulator
	 * 
	 * @param access the trace-and-debugger access shim
	 */
	public AuxDebuggerPcodeEmulator(PcodeDebuggerAccess access) {
		super(access);
		this.access = access;
	}

	@Override
	protected abstract AuxDebuggerEmulatorPartsFactory<U> getPartsFactory();

	@Override
	public TracePcodeExecutorState<Pair<byte[], U>> createSharedState() {
		return getPartsFactory().createDebuggerSharedState(this,
			new RWTargetMemoryPcodeExecutorStatePiece(access.getDataForSharedState(), Mode.RO));
	}

	@Override
	public TracePcodeExecutorState<Pair<byte[], U>> createLocalState(
			PcodeThread<Pair<byte[], U>> thread) {
		return getPartsFactory().createDebuggerLocalState(this, thread,
			new RWTargetRegistersPcodeExecutorStatePiece(access.getDataForLocalState(thread, 0),
				Mode.RO));
	}
}
