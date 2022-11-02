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
package ghidra.pcode.emu.auxiliary;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.AbstractPcodeMachine;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.*;
import ghidra.program.model.lang.Language;

/**
 * A stand-alone emulator whose parts are manufactured by a {@link AuxEmulatorPartsFactory}
 * 
 * <p>
 * See the parts factory interface: {@link AuxEmulatorPartsFactory}. Also see the Taint Analyzer for
 * a complete solution based on this class.
 * 
 * @param <U> the type of auxiliary values
 */
public abstract class AuxPcodeEmulator<U> extends AbstractPcodeMachine<Pair<byte[], U>> {
	/**
	 * Create a new emulator
	 * 
	 * @param language the language (processor model)
	 */
	public AuxPcodeEmulator(Language language) {
		super(language);
	}

	/**
	 * Get the factory that manufactures parts for this emulator
	 * 
	 * @implNote This should just return a singleton, since it is called repeatedly (without
	 *           caching) during emulator and thread construction. If, for some reason, a singleton
	 *           is not suitable, then this should instantiate it just once and cache the factory
	 *           itself. If cached, it should be done in a thread-safe manner.
	 * 
	 * @return the factory
	 */
	protected abstract AuxEmulatorPartsFactory<U> getPartsFactory();

	@Override
	protected PcodeArithmetic<Pair<byte[], U>> createArithmetic() {
		return new PairedPcodeArithmetic<>(
			BytesPcodeArithmetic.forLanguage(language),
			getPartsFactory().getArithmetic(language));
	}

	@Override
	protected PcodeUseropLibrary<Pair<byte[], U>> createUseropLibrary() {
		return getPartsFactory().createSharedUseropLibrary(this);
	}

	@Override
	protected PcodeUseropLibrary<Pair<byte[], U>> createThreadStubLibrary() {
		return getPartsFactory().createLocalUseropStub(this);
	}

	@Override
	protected PcodeExecutorState<Pair<byte[], U>> createSharedState() {
		return getPartsFactory().createSharedState(this,
			new BytesPcodeExecutorStatePiece(language));
	}

	@Override
	protected PcodeExecutorState<Pair<byte[], U>> createLocalState(
			PcodeThread<Pair<byte[], U>> thread) {
		return getPartsFactory().createLocalState(this, thread,
			new BytesPcodeExecutorStatePiece(language));
	}

	@Override
	protected PcodeThread<Pair<byte[], U>> createThread(String name) {
		return getPartsFactory().createThread(this, name);
	}
}
