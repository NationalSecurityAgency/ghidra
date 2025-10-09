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

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.emu.taint.state.TaintPcodeExecutorState;
import ghidra.program.model.lang.Language;
import ghidra.taint.model.TaintVec;

/**
 * An emulator with taint analysis
 */
public class TaintPcodeEmulator extends AuxPcodeEmulator<TaintVec> {
	/**
	 * Create an emulator
	 * 
	 * @param language the language (processor model)
	 * @param cb callbacks to receive emulation events
	 */
	public TaintPcodeEmulator(Language language,
			PcodeEmulationCallbacks<Pair<byte[], TaintVec>> cb) {
		super(language, cb);
	}

	/**
	 * Create an emulator
	 * 
	 * @param language the language (processor model)
	 */
	public TaintPcodeEmulator(Language language) {
		this(language, PcodeEmulationCallbacks.none());
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here, we just return the singleton parts factory. This appears simple because all the
	 * complexity is encapsulated in the factory. See {@link TaintPartsFactory} to see everything
	 * the implementation actually entails.
	 */
	@Override
	protected AuxEmulatorPartsFactory<TaintVec> getPartsFactory() {
		return TaintPartsFactory.INSTANCE;
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * We override this here so that clients don't have to cast the state.
	 */
	@Override
	public TaintPcodeExecutorState getSharedState() {
		return (TaintPcodeExecutorState) super.getSharedState();
	}
}
