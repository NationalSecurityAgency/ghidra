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
package ghidra.pcode.emu.taint.trace;

import ghidra.pcode.emu.taint.plain.TaintPcodeExecutorState;
import ghidra.pcode.exec.trace.*;
import ghidra.taint.model.TaintVec;

/**
 * A paired concrete-plus-taint trace-integrated state
 *
 * <p>
 * This contains the emulator's machine state along with the taint markings, just like
 * {@link TaintPcodeExecutorState}, except that it can read and write state from a trace. In
 * reality, this just composes concrete and taint state pieces, which actually do all the work.
 */
public class TaintTracePcodeExecutorState extends PairedTracePcodeExecutorState<byte[], TaintVec> {

	/**
	 * Create a state from the two given pieces
	 * 
	 * @param concrete the concrete piece
	 * @param taint the taint piece
	 */
	public TaintTracePcodeExecutorState(BytesTracePcodeExecutorStatePiece concrete,
			AbstractTaintTracePcodeExecutorStatePiece<?> taint) {
		super(new PairedTracePcodeExecutorStatePiece<>(concrete, taint));
	}

	/**
	 * Create a state from the given concrete piece and an internally constructed taint piece
	 * 
	 * <p>
	 * We take all the parameters needed by the taint piece from the concrete piece.
	 * 
	 * @param concrete the concrete piece
	 */
	public TaintTracePcodeExecutorState(BytesTracePcodeExecutorStatePiece concrete) {
		this(concrete,
			new TaintTracePcodeExecutorStatePiece(concrete.getTrace(), concrete.getSnap(),
				concrete.getThread(), concrete.getFrame()));
	}
}
