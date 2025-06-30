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
package ghidra.pcode.emu.symz3.plain;

import java.util.Collection;

import ghidra.pcode.emu.auxiliary.AuxEmulatorPartsFactory;
import ghidra.pcode.emu.auxiliary.AuxPcodeEmulator;
import ghidra.pcode.emu.symz3.*;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;

/**
 * A stand-alone emulator with symbolic Z3 summarization analysis
 */
public class SymZ3PcodeEmulator extends AuxPcodeEmulator<SymValueZ3>
		implements SymZ3PcodeEmulatorTrait {
	/**
	 * Create an emulator
	 * 
	 * @param language the language (processor model)
	 */
	public SymZ3PcodeEmulator(Language language) {
		super(language);
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here, we just return the singleton parts factory. This appears simple because all the
	 * complexity is encapsulated in the factory. See {@link SymZ3PartsFactory} to see everything
	 * the implementation actually entails.
	 */
	@Override
	protected AuxEmulatorPartsFactory<SymValueZ3> getPartsFactory() {
		return SymZ3PartsFactory.INSTANCE;
	}

	@Override
	public SymZ3PcodeThread newThread() {
		return (SymZ3PcodeThread) super.newThread();
	}

	@Override
	public SymZ3PcodeThread newThread(String name) {
		return (SymZ3PcodeThread) super.newThread(name);
	}

	@Override
	@SuppressWarnings("unchecked")
	public Collection<? extends SymZ3PcodeThread> getAllThreads() {
		return (Collection<? extends SymZ3PcodeThread>) super.getAllThreads();
	}

	@Override
	public SymZ3PcodeExecutorState getSharedState() {
		return (SymZ3PcodeExecutorState) super.getSharedState();
	}
}
