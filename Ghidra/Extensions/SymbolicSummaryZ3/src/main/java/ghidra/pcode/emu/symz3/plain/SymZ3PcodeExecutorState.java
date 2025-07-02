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

import ghidra.pcode.emu.symz3.*;
import ghidra.pcode.exec.BytesPcodeExecutorStatePiece;
import ghidra.pcode.exec.IndependentPairedPcodeExecutorState;
import ghidra.program.model.lang.Language;
import ghidra.symz3.model.SymValueZ3;

/**
 * A paired concrete-plus-symz3 state
 * 
 * <p>
 * This contains the emulator's machine state along with symbolic expressions. Technically, one of
 * these will hold the machine's memory, while another (for each thread) will hold the machine's
 * registers. It's composed of two pieces. The concrete piece holds the actual concrete bytes, while
 * the SymValueZ3 piece holds the symbolic values. A request to get a variable's value from this
 * state will return a pair where the left element comes from the concrete piece and the right
 * element comes from the symbolic piece.
 */
public class SymZ3PcodeExecutorState
		extends IndependentPairedPcodeExecutorState<byte[], SymValueZ3>
		implements SymZ3PairedPcodeExecutorState {

	/**
	 * Create a state from the two given pieces
	 * 
	 * @param concrete the concrete piece
	 * @param symz3 the symbolic z3 piece
	 */
	protected SymZ3PcodeExecutorState(BytesPcodeExecutorStatePiece concrete,
			SymZ3PcodeExecutorStatePiece symz3) {
		super(concrete, symz3);
	}

	/**
	 * Create a state from the given concrete piece and a symbolic piece
	 * 
	 * @param language the language for creating the symz3 piece
	 * @param concrete the concrete piece
	 */
	public SymZ3PcodeExecutorState(Language language, BytesPcodeExecutorStatePiece concrete) {
		this(concrete,
			new SymZ3PcodeExecutorStatePiece(language, SymZ3PcodeArithmetic.forLanguage(language)));
	}

	@Override
	public AbstractSymZ3PcodeExecutorStatePiece<? extends SymZ3Space> getRight() {
		return (SymZ3PcodeExecutorStatePiece) super.getRight();
	}
}
