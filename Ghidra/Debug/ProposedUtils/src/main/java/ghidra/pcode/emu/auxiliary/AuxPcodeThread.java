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

import ghidra.pcode.emu.ModifiedPcodeThread;
import ghidra.pcode.exec.PcodeUseropLibrary;

/**
 * The default thread for {@link AuxPcodeEmulator}
 *
 * <p>
 * Generally, extending this class should not be necessary, as it already defers to the emulator's
 * parts factory
 *
 * @param <U> the type of auxiliary values
 */
public class AuxPcodeThread<U> extends ModifiedPcodeThread<Pair<byte[], U>> {

	public AuxPcodeThread(String name, AuxPcodeEmulator<U> emulator) {
		super(name, emulator);
	}

	@Override
	public AuxPcodeEmulator<U> getMachine() {
		return (AuxPcodeEmulator<U>) super.getMachine();
	}

	protected AuxEmulatorPartsFactory<U> getPartsFactory() {
		return getMachine().getPartsFactory();
	}

	@Override
	protected PcodeUseropLibrary<Pair<byte[], U>> createUseropLibrary() {
		return super.createUseropLibrary().compose(
			getPartsFactory().createLocalUseropLibrary(getMachine(), this));
	}

	@Override
	protected PcodeThreadExecutor<Pair<byte[], U>> createExecutor() {
		return getPartsFactory().createExecutor(getMachine(), this);
	}
}
