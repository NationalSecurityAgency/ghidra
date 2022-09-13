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
package ghidra.pcode.exec.trace.auxiliary;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.exec.trace.*;
import ghidra.pcode.exec.trace.data.*;
import ghidra.trace.model.guest.TracePlatform;

/**
 * An trace-integrated emulator whose parts are manufactured by a
 * {@link AuxTraceEmulatorPartsFactory}
 * 
 * <p>
 * See the parts factory interface and its super interfaces:
 * <ul>
 * <li>{@link AuxTraceEmulatorPartsFactory}</li>
 * <li>{@link AuxEmulatorPartsFactory}</li>
 * </ul>
 * 
 * @param <U> the type of auxiliary values
 */
public abstract class AuxTracePcodeEmulator<U> extends AuxPcodeEmulator<U>
		implements TracePcodeMachine<Pair<byte[], U>> {

	protected final PcodeTraceAccess access;

	/**
	 * Create a new emulator
	 * 
	 * @param access the trace access shim
	 */
	public AuxTracePcodeEmulator(PcodeTraceAccess access) {
		super(access.getLanguage());
		this.access = access;
	}

	/**
	 * Create a new emulator
	 * 
	 * @param platform the platform to emulate
	 * @param snap the source snap
	 */
	public AuxTracePcodeEmulator(TracePlatform platform, long snap) {
		this(new DefaultPcodeTraceAccess(platform, snap));
	}

	@Override
	protected abstract AuxTraceEmulatorPartsFactory<U> getPartsFactory();

	@Override
	protected PcodeThread<Pair<byte[], U>> createThread(String name) {
		PcodeThread<Pair<byte[], U>> thread = super.createThread(name);
		access.getDataForLocalState(thread, 0).initializeThreadContext(thread);
		return thread;
	}

	@Override
	public TracePcodeExecutorState<Pair<byte[], U>> createSharedState() {
		return getPartsFactory().createTraceSharedState(this,
			new BytesTracePcodeExecutorStatePiece(access.getDataForSharedState()));
	}

	@Override
	public TracePcodeExecutorState<Pair<byte[], U>> createLocalState(
			PcodeThread<Pair<byte[], U>> thread) {
		return getPartsFactory().createTraceLocalState(this, thread,
			new BytesTracePcodeExecutorStatePiece(access.getDataForLocalState(thread, 0)));
	}
}
