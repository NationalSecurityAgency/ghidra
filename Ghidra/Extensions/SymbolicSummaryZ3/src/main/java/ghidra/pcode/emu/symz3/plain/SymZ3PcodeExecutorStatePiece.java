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

import java.util.Map;

import ghidra.pcode.emu.symz3.AbstractSymZ3PcodeExecutorStatePiece;
import ghidra.pcode.emu.symz3.SymZ3PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.Register;
import ghidra.symz3.model.SymValueZ3;

/**
 * The state piece for holding symbolic values in the emulator's machine state
 * 
 */
public class SymZ3PcodeExecutorStatePiece extends AbstractSymZ3PcodeExecutorStatePiece<SymZ3Space> {
	/**
	 * Create the SymZ3 piece
	 * 
	 * @param language the language of the emulator
	 * @param addressArithmetic the address arithmetic, likely taken from the concrete piece
	 */
	public SymZ3PcodeExecutorStatePiece(Language language,
			PcodeArithmetic<SymValueZ3> addressArithmetic) {
		super(language, addressArithmetic, SymZ3PcodeArithmetic.forLanguage(language));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we use the simplest scheme for creating a map of {@link SymZ3Space}s. This is
	 * essentially a lazy map from address space to some object for managing symbolic values in that
	 * address space. The space could be a memory space, register space, unique space, etc. This
	 * piece will look up the space, creating it if necessary, and then delegate the get and set
	 * methods.
	 */
	@Override
	protected AbstractSpaceMap<SymZ3Space> newSpaceMap(Language language) {
		return new SimpleSpaceMap<SymZ3Space>() {
			@Override
			protected SymZ3Space newSpace(AddressSpace space) {
				if (space.isConstantSpace()) {
					throw new AssertionError();
				}
				else if (space.isRegisterSpace()) {
					return new SymZ3RegisterSpace(space, language);
				}
				else if (space.isUniqueSpace()) {
					return new SymZ3UniqueSpace();
				}
				else if (space.isLoadedMemorySpace()) {
					return new SymZ3MemorySpace(language);
				}
				else {
					throw new AssertionError("not yet supported space: " + space.toString());
				}
			}
		};
	}

	@Override
	public String printableSummary() {
		StringBuilder result = new StringBuilder();
		for (SymZ3Space space : spaceMap.values()) {
			result.append(space.printableSummary());
		}
		result.append(this.preconditions.printableSummary());
		return result.toString();
	}

	@Override
	public Map<Register, SymValueZ3> getRegisterValues() {
		throw new UnsupportedOperationException();
	}

	@Override
	public void clear() {
		/**
		 * In addition to clearing out all the state, you would probably also want to clear the
		 * instruction and op lists.
		 */
		throw new UnsupportedOperationException();
	}
}
