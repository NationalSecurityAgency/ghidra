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
package ghidra.pcode.emu.symz3.trace;

import ghidra.pcode.emu.symz3.SymZ3PairedPcodeExecutorState;
import ghidra.pcode.emu.symz3.plain.SymZ3PcodeExecutorState;
import ghidra.pcode.exec.trace.BytesTracePcodeExecutorStatePiece;
import ghidra.pcode.exec.trace.IndependentPairedTracePcodeExecutorState;
import ghidra.symz3.model.SymValueZ3;

/**
 * A paired concrete-plus-symz3 trace-integrated state
 *
 * <p>
 * This contains the emulator's machine state along with the symbolic values, just like
 * {@link SymZ3PcodeExecutorState}, except that it can read and write state from a trace. In
 * reality, this just composes concrete and symz3 state pieces, which actually do all the work.
 */
public class SymZ3TracePcodeExecutorState
		extends IndependentPairedTracePcodeExecutorState<byte[], SymValueZ3>
		implements SymZ3PairedPcodeExecutorState {

	/**
	 * Create a state from the two given pieces
	 * 
	 * @param concrete the concrete piece
	 * @param symz3 the symz3 piece
	 */
	public SymZ3TracePcodeExecutorState(BytesTracePcodeExecutorStatePiece concrete,
			AbstractSymZ3TracePcodeExecutorStatePiece symz3) {
		super(concrete, symz3);
	}

	/**
	 * Create a state from the given concrete piece and an internally constructed symz3 piece
	 * 
	 * <p>
	 * We take all the parameters needed by the symz3 piece from the concrete piece.
	 * 
	 * @param concrete the concrete piece
	 */
	public SymZ3TracePcodeExecutorState(BytesTracePcodeExecutorStatePiece concrete) {
		this(concrete, new SymZ3TracePcodeExecutorStatePiece(concrete.getData()));
	}
	
	@Override
	public SymZ3TracePcodeExecutorStatePiece getRight() {
		return (SymZ3TracePcodeExecutorStatePiece) super.getRight();
	}
}
