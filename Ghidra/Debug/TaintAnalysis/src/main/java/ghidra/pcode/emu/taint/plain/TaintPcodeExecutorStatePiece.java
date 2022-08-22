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
package ghidra.pcode.emu.taint.plain;

import org.apache.commons.lang3.tuple.Pair;

import ghidra.pcode.emu.taint.AbstractTaintPcodeExecutorStatePiece;
import ghidra.pcode.emu.taint.TaintPcodeArithmetic;
import ghidra.pcode.exec.*;
import ghidra.pcode.exec.trace.TracePcodeExecutorState;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.Language;

/**
 * The state piece for holding taint marks in the emulator's machine state
 * 
 * <p>
 * Because this is already a working solution, most of the logic has already been abstracted into a
 * super class {@link AbstractTaintPcodeExecutorStatePiece}. This class serves only to choose the
 * type {@link TaintSpace}, which implements the real storage logic, and provide a map from address
 * space to that type. Note the concept of a space map is introduced by
 * {@link AbstractLongOffsetPcodeExecutorStatePiece}, which is provided by the p-code emulation
 * framework. This is suitable for state pieces with concrete addresses. This likely fits your
 * auxiliary piece, but may not. If you choose to use abstract addresses for your auxiliary piece,
 * then your implementation of state will not follow the archetype presented here. You'll instead
 * want to implement {@link TracePcodeExecutorState} directly, take the concrete piece provided, and
 * wrap it as you see fit. You may still benefit by referring to the implementation of
 * {@link PairedPcodeExecutorState}. When implementing your flavor of
 * {@link PairedPcodeExecutorState#getVar(AddressSpace, Pair, int, boolean)}, still consider that
 * you could benefit from the concrete element of the offset pair passed in.
 */
public class TaintPcodeExecutorStatePiece extends AbstractTaintPcodeExecutorStatePiece<TaintSpace> {
	/**
	 * Create the taint piece
	 * 
	 * @param language the language of the emulator
	 * @param addressArithmetic the address arithmetic, likely taken from the concrete piece
	 */
	public TaintPcodeExecutorStatePiece(Language language,
			PcodeArithmetic<byte[]> addressArithmetic) {
		super(language, addressArithmetic, TaintPcodeArithmetic.forLanguage(language));
	}

	/**
	 * {@inheritDoc}
	 * 
	 * <p>
	 * Here we use the simplest scheme for creating a map of {@link TaintSpace}s. This is
	 * essentially a lazy map from address space to some object for managing taint marks in that
	 * address space. The space could be a memory space, register space, unique space, etc. This
	 * piece will look up the space, creating it if necessary, and then delegate the get and set
	 * methods.
	 */
	@Override
	protected AbstractSpaceMap<TaintSpace> newSpaceMap() {
		return new SimpleSpaceMap<TaintSpace>() {
			@Override
			protected TaintSpace newSpace(AddressSpace space) {
				return new TaintSpace();
			}
		};
	}
}
