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
package ghidra.pcode.emu.taint.full;

import ghidra.app.plugin.core.debug.service.emulation.ReadsTargetMemoryPcodeExecutorStatePiece;
import ghidra.pcode.emu.taint.trace.TaintTracePcodeExecutorState;

/**
 * A paired concrete-plus-taint Debugger-integrated state
 *
 * <p>
 * This contains the emulator's machine state along with the taint markings, just like
 * {@link TaintTracePcodeExecutorState}, except that it can also read state from mapped static
 * programs. In reality, this just composes concrete and taint state pieces, which actually do all
 * the work.
 */
public class TaintDebuggerPcodeExecutorState extends TaintTracePcodeExecutorState {

	/**
	 * Create a state from the two given pieces
	 * 
	 * @param concrete the concrete piece
	 * @param the taint piece
	 */
	public TaintDebuggerPcodeExecutorState(ReadsTargetMemoryPcodeExecutorStatePiece concrete,
			TaintDebuggerPcodeExecutorStatePiece taint) {
		super(concrete, taint);
	}

	/**
	 * Create a state from the given concrete piece and an internally constructed taint piece
	 * 
	 * @param concrete the concrete piece
	 */
	public TaintDebuggerPcodeExecutorState(ReadsTargetMemoryPcodeExecutorStatePiece concrete) {
		super(concrete, new TaintDebuggerPcodeExecutorStatePiece(
			concrete.getTool(), concrete.getTrace(), concrete.getSnap(), concrete.getThread(),
			concrete.getFrame(), concrete.getRecorder()));
	}
}
