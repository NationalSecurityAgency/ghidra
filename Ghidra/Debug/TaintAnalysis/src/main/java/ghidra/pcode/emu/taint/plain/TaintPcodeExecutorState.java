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

import ghidra.pcode.exec.*;
import ghidra.program.model.lang.Language;
import ghidra.taint.model.TaintVec;

/**
 * A paired concrete-plus-taint state
 * 
 * <p>
 * This contains the emulator's machine state along with the taint markings. Technically, one of
 * these will hold the machine's memory, while another (for each thread) will hold the machine's
 * registers. It's composed of two pieces. The concrete piece holds the actual concrete bytes, while
 * the taint piece holds the taint markings. A request to get a variable's value from this state
 * will return a pair where the left element comes from the concrete piece and the right element
 * comes from the taint piece.
 */
public class TaintPcodeExecutorState extends PairedPcodeExecutorState<byte[], TaintVec> {

	/**
	 * Create a state from the two given pieces
	 * 
	 * @param concrete the concrete piece
	 * @param taint the taint piece
	 */
	protected TaintPcodeExecutorState(BytesPcodeExecutorStatePiece concrete,
			TaintPcodeExecutorStatePiece taint) {
		super(new PairedPcodeExecutorStatePiece<>(concrete, taint));
	}

	/**
	 * Create a state from the given concrete piece and an internally constructed taint piece
	 * 
	 * @param language the language for creating the taint piece
	 * @param concrete the concrete piece
	 */
	public TaintPcodeExecutorState(Language language, BytesPcodeExecutorStatePiece concrete) {
		this(concrete, new TaintPcodeExecutorStatePiece(language, concrete.getAddressArithmetic()));
	}
}
